"""Repository for the coverage ledger — idempotent, tenant-verified writes.

Turns the pure foundation into durable rows:
- ``persist_policy``  — insert-if-absent the immutable ``scan_policy`` (never updated).
- ``persist_catalog`` — insert-if-absent the applicable detectors (``scan_policy_templates``).
- ``record_pass_coverage`` — atomic per-asset upsert of ``scan_coverage`` for one pass,
  after verifying the run and every asset belong to the tenant (fail-closed).

Conservative mapping (Step 2D): a whole pass declares one status for all its assets —
completed → covered, truncated → partial, errored → failed, not-run → skipped. Real
per-asset/batch granularity comes with the pass wiring.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.orm import Session

from app.models.coverage import CoverageStatus, ScanCoverage, ScanPolicy, ScanPolicyTemplate
from app.models.database import Asset
from app.models.scanning import ScanRun
from app.services.rule_catalog import ApplicableRuleSet
from app.services.scan_policy import ScanPolicyManifest


class CoverageWriteError(Exception):
    """Raised when a coverage write cannot be trusted (tenant/asset/run mismatch)."""


def conservative_pass_status(*, ran: bool, errored: bool, truncated: bool) -> CoverageStatus:
    """Pure conservative mapping from a pass outcome to a single coverage status.

    Precedence: not run → SKIPPED; errored → FAILED; truncated → PARTIAL; else COVERED.
    Fail-safe: anything short of a clean complete run is NOT declared COVERED, so an
    over-eager auto-close can never key off a partial/failed pass.
    """
    if not ran:
        return CoverageStatus.SKIPPED
    if errored:
        return CoverageStatus.FAILED
    if truncated:
        return CoverageStatus.PARTIAL
    return CoverageStatus.COVERED


class CoverageRepository:
    """Data access for scan_policy / scan_policy_templates / scan_coverage."""

    def __init__(self, db: Session):
        self.db = db

    # --- immutable policy identity -------------------------------------------

    def persist_policy(self, manifest: ScanPolicyManifest) -> str:
        """Insert the policy if absent and return its ``policy_hash``. Immutable:
        a conflict is a no-op (identical identity), never an update."""
        stmt = (
            insert(ScanPolicy)
            .values(
                policy_hash=manifest.policy_hash,
                schema_version=manifest.schema_version,
                engine_name=manifest.engine_name,
                engine_version=manifest.engine_version,
                rule_revision=manifest.rule_revision,
                phase=manifest.phase,
                pass_name=manifest.pass_name,
                tier=manifest.tier,
                severity=list(manifest.severity),
                rule_roots=list(manifest.rule_roots),
                exclude_tags=list(manifest.exclude_tags),
                relevant_flags=dict(manifest.relevant_flags),
                created_at=datetime.now(timezone.utc),
            )
            .on_conflict_do_nothing(index_elements=["policy_hash"])
        )
        self.db.execute(stmt)
        self.db.commit()
        return manifest.policy_hash

    # --- applicable detector catalog -----------------------------------------

    def persist_catalog(self, ruleset: ApplicableRuleSet) -> int:
        """Insert the applicable detectors if absent (idempotent per
        (policy_hash, detector_id)). Returns the number of rows attempted."""
        rows = [
            {
                "policy_hash": ruleset.policy_hash,
                "detector_id": r.detector_id,
                "relative_path": r.relative_path,
                "content_digest": r.content_digest,
                "severity": r.severity,
                "tags": list(r.tags),
            }
            for r in ruleset.rules
        ]
        if not rows:
            return 0
        stmt = insert(ScanPolicyTemplate).values(rows).on_conflict_do_nothing(
            constraint="uq_policy_template"
        )
        self.db.execute(stmt)
        self.db.commit()
        return len(rows)

    # --- per-pass coverage ----------------------------------------------------

    def record_pass_coverage(
        self,
        *,
        tenant_id: int,
        scan_run_id: int,
        phase: str,
        pass_name: str,
        policy_hash: str,
        asset_ids: Iterable[int],
        status: CoverageStatus,
    ) -> int:
        """Atomically upsert one coverage verdict per asset for a pass.

        Fail-closed verification before any write: the run must belong to ``tenant_id``;
        the policy must exist; every asset must belong to ``tenant_id``. Returns the
        number of coverage rows written (0 if ``asset_ids`` is empty).
        """
        asset_ids = sorted({int(a) for a in asset_ids})
        if not asset_ids:
            return 0

        run = self.db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
        if run is None or run.tenant_id != tenant_id:
            raise CoverageWriteError(f"scan_run {scan_run_id} does not belong to tenant {tenant_id}")

        if self.db.query(ScanPolicy.policy_hash).filter(ScanPolicy.policy_hash == policy_hash).first() is None:
            raise CoverageWriteError(f"unknown policy_hash {policy_hash!r} (persist the policy first)")

        owned = {
            row[0]
            for row in self.db.query(Asset.id)
            .filter(Asset.id.in_(asset_ids), Asset.tenant_id == tenant_id)
            .all()
        }
        stray = [a for a in asset_ids if a not in owned]
        if stray:
            raise CoverageWriteError(f"assets {stray} do not belong to tenant {tenant_id}")

        now = datetime.now(timezone.utc)
        rows = [
            {
                "tenant_id": tenant_id,
                "scan_run_id": scan_run_id,
                "asset_id": asset_id,
                "phase": phase,
                "pass_name": pass_name,
                "policy_hash": policy_hash,
                "status": status.value,
                "created_at": now,
                "updated_at": now,
            }
            for asset_id in asset_ids
        ]
        stmt = insert(ScanCoverage).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_coverage_run_pass_asset",
            set_={
                "status": stmt.excluded.status,
                "policy_hash": stmt.excluded.policy_hash,
                "updated_at": stmt.excluded.updated_at,
            },
        )
        self.db.execute(stmt)
        self.db.commit()
        return len(rows)

    # --- read helpers (for the auto-close consumer, later) -------------------

    def covered_asset_ids(self, scan_run_id: int, pass_name: str) -> set[int]:
        """Asset ids with a COVERED verdict for a pass in a run (auto-close input)."""
        return {
            row[0]
            for row in self.db.query(ScanCoverage.asset_id)
            .filter(
                ScanCoverage.scan_run_id == scan_run_id,
                ScanCoverage.pass_name == pass_name,
                ScanCoverage.status == CoverageStatus.COVERED,
            )
            .all()
        }

    def applicable_detector_ids(self, policy_hash: str) -> set[str]:
        """Detector ids applicable to a policy (from the persisted catalog)."""
        return {
            row[0]
            for row in self.db.query(ScanPolicyTemplate.detector_id)
            .filter(ScanPolicyTemplate.policy_hash == policy_hash)
            .all()
        }


__all__ = ["CoverageRepository", "CoverageWriteError", "conservative_pass_status"]
