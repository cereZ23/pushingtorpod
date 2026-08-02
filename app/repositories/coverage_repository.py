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

from sqlalchemy import case
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


# authorisation rank — higher = more authorising (only COVERED authorises auto-close).
def _rank_expr(col):
    return case(
        (col == CoverageStatus.COVERED, 5),
        (col == CoverageStatus.PARTIAL, 4),
        (col == CoverageStatus.SKIPPED, 3),
        (col == CoverageStatus.FAILED, 2),
        (col == CoverageStatus.UNSTARTED, 1),
        else_=0,
    )


def _conservative_merge(new):
    """SQL CASE for on-conflict: the LESS-authorising status wins, so a late/concurrent
    write can never promote a PARTIAL/FAILED/SKIPPED verdict to COVERED. UNSTARTED is a
    pure placeholder — any real verdict replaces it, and it never replaces a real one."""
    old = ScanCoverage.status
    return case(
        (old == CoverageStatus.UNSTARTED, new),
        (new == CoverageStatus.UNSTARTED, old),
        (_rank_expr(new) < _rank_expr(old), new),
        else_=old,
    )


class CoverageRepository:
    """Data access for scan_policy / scan_policy_templates / scan_coverage."""

    def __init__(self, db: Session):
        self.db = db

    # --- immutable policy identity -------------------------------------------

    def persist_policy(self, manifest: ScanPolicyManifest) -> str:
        """Insert the policy if absent and return its ``policy_hash``. Immutable AND
        verified: after the insert-if-absent, the stored row is re-read and every
        canonical field compared to the manifest — a divergent row (corruption, a bad
        migration, a manual insert) raises instead of being silently accepted."""
        expected = {
            "schema_version": manifest.schema_version,
            "engine_name": manifest.engine_name,
            "engine_version": manifest.engine_version,
            "rule_revision": manifest.rule_revision,
            "phase": manifest.phase,
            "pass_name": manifest.pass_name,
            "tier": manifest.tier,
            "severity": list(manifest.severity),
            "rule_roots": list(manifest.rule_roots),
            "exclude_tags": list(manifest.exclude_tags),
            "relevant_flags": dict(manifest.relevant_flags),
        }
        stmt = insert(ScanPolicy).values(policy_hash=manifest.policy_hash, created_at=datetime.now(timezone.utc), **expected)
        stmt = stmt.on_conflict_do_nothing(index_elements=["policy_hash"])
        self.db.execute(stmt)
        self.db.commit()

        row = self.db.query(ScanPolicy).filter(ScanPolicy.policy_hash == manifest.policy_hash).one()
        diffs = [f for f, v in expected.items() if getattr(row, f) != v]
        if diffs:
            raise CoverageWriteError(
                f"policy_hash {manifest.policy_hash} exists with a different manifest (fields: {diffs})"
            )
        return manifest.policy_hash

    # --- applicable detector catalog -----------------------------------------

    def persist_catalog(self, ruleset: ApplicableRuleSet) -> int:
        """Insert the applicable detectors if absent, then VERIFY the persisted catalog
        matches the ruleset exactly. The catalog is as immutable as the policy: a stored
        detector with a divergent digest/path/severity/tags, a missing rule, or an extra
        rule raises ``CoverageWriteError``. Returns the number of ruleset detectors."""
        if self.db.query(ScanPolicy.policy_hash).filter(ScanPolicy.policy_hash == ruleset.policy_hash).first() is None:
            raise CoverageWriteError(f"unknown policy_hash {ruleset.policy_hash!r} (persist the policy first)")

        expected = {
            r.detector_id: (r.relative_path, r.content_digest, r.severity, tuple(r.tags)) for r in ruleset.rules
        }
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
        if rows:
            stmt = insert(ScanPolicyTemplate).values(rows).on_conflict_do_nothing(constraint="uq_policy_template")
            self.db.execute(stmt)
            self.db.commit()

        stored = {
            t.detector_id: (t.relative_path, t.content_digest, t.severity, tuple(t.tags or []))
            for t in self.db.query(ScanPolicyTemplate).filter(ScanPolicyTemplate.policy_hash == ruleset.policy_hash).all()
        }
        if stored != expected:
            missing = sorted(set(expected) - set(stored))
            extra = sorted(set(stored) - set(expected))
            divergent = sorted(d for d in set(expected) & set(stored) if expected[d] != stored[d])
            raise CoverageWriteError(
                f"catalog for {ruleset.policy_hash} diverges (missing={missing}, extra={extra}, divergent={divergent})"
            )
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

        policy = self.db.query(ScanPolicy).filter(ScanPolicy.policy_hash == policy_hash).first()
        if policy is None:
            raise CoverageWriteError(f"unknown policy_hash {policy_hash!r} (persist the policy first)")
        if policy.phase != phase or policy.pass_name != pass_name:
            raise CoverageWriteError(
                f"policy {policy_hash} is for phase {policy.phase!r}/pass {policy.pass_name!r}, "
                f"not {phase!r}/{pass_name!r}"
            )

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
                "status": status,
                "created_at": now,
                "updated_at": now,
            }
            for asset_id in asset_ids
        ]
        stmt = insert(ScanCoverage).values(rows)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_coverage_run_pass_asset",
            set_={"status": _conservative_merge(stmt.excluded.status), "updated_at": stmt.excluded.updated_at},
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
