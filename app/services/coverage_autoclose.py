"""Coverage-aware auto-close — the per-finding decision (pure) + a DRY-RUN runner.

This is the consumer the whole coverage foundation was built for, but it does NOT close
anything yet. ``decide_finding_auto_close`` is a pure function returning an explicit
verdict; ``dry_run_auto_close`` walks a run's open findings, computes what it WOULD do,
and records metrics/logs — without mutating a single finding. Real closes (and disabling
the old tenant-wide auto-close) come only after two live dry-runs are validated.

A finding is *eligible* to advance toward a close on a given run ONLY when all four hold:
  1. discovery is healthy enough to authorise closing (``auto_close_allowed``);
  2. the asset is COVERED by the pass that owns the finding's detector;
  3. that pass's applicable-detector catalog is intact (fingerprint == stamped build);
  4. the finding's detector is IN that applicable set.
Anything short of all four is fail-closed: the streak resets, never advances. A finding
that WAS detected this run resets too (it is still live). Only two *distinct* consecutive
eligible misses reach ``WOULD_CLOSE``.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_CLOSE_THRESHOLD = 2


class AutoCloseDecision(str, enum.Enum):
    INELIGIBLE = "ineligible"  # can't prove coverage this run → reset streak (fail-closed)
    DETECTED_RESET = "detected_reset"  # still detected → reset streak, attribute detection
    ELIGIBLE_MISS = "eligible_miss"  # eligible + missed, but below the close threshold
    WOULD_CLOSE = "would_close"  # eligible miss reached the threshold → a real run would close


@dataclass(frozen=True)
class AutoCloseVerdict:
    """What a run WOULD do to one finding. The runner applies ``new_streak`` and, when set,
    the run attributions; in dry-run it only records them. ``*_run_id`` of ``None`` means
    "leave unchanged" (there is no path here that clears an existing attribution)."""

    decision: AutoCloseDecision
    new_streak: int
    set_last_eligible_run_id: Optional[int] = None
    set_last_detected_run_id: Optional[int] = None

    @property
    def would_close(self) -> bool:
        return self.decision is AutoCloseDecision.WOULD_CLOSE


def decide_finding_auto_close(
    *,
    this_run_id: int,
    detected_this_run: bool,
    discovery_auto_close_allowed: bool,
    coverage_covered: bool,
    catalog_intact: bool,
    detector_applicable: bool,
    current_streak: int,
    last_eligible_run_id: Optional[int],
    close_threshold: int = DEFAULT_CLOSE_THRESHOLD,
) -> AutoCloseVerdict:
    """Pure per-finding decision. ``this_run_id`` is always a real run (the runner only
    operates inside a scan). See the module docstring for the eligibility contract."""
    # 1. Detected this run → the finding is live: reset the streak and attribute detection.
    if detected_this_run:
        return AutoCloseVerdict(
            AutoCloseDecision.DETECTED_RESET,
            new_streak=0,
            set_last_detected_run_id=this_run_id,
        )

    # 2. Fail-closed eligibility gate: every condition must hold to count a miss.
    eligible = discovery_auto_close_allowed and coverage_covered and catalog_intact and detector_applicable
    if not eligible:
        return AutoCloseVerdict(AutoCloseDecision.INELIGIBLE, new_streak=0)

    # 3. Eligible miss. A retried run must not double-count: if this run already advanced
    #    the streak, keep it as-is rather than incrementing again.
    if last_eligible_run_id == this_run_id:
        streak = current_streak
    else:
        streak = current_streak + 1

    decision = AutoCloseDecision.WOULD_CLOSE if streak >= close_threshold else AutoCloseDecision.ELIGIBLE_MISS
    return AutoCloseVerdict(decision, new_streak=streak, set_last_eligible_run_id=this_run_id)


def dry_run_auto_close(
    db,
    *,
    tenant_id: int,
    project_id: Optional[int],
    scan_run_id: int,
    close_threshold: int = DEFAULT_CLOSE_THRESHOLD,
) -> dict:
    """Walk a run's open findings and compute what a real close WOULD do — writing nothing.

    For each open nuclei/misconfig finding: is it detected this run? is its detector in a
    COVERED pass whose applicable catalog is intact? Feed that to
    ``decide_finding_auto_close`` and tally the decisions. Findings are NOT modified — this
    only records metrics/logs so two live runs can be compared against reality before the
    real close (and the disabling of the old auto-close) is enabled.

    Detection signal: the explicit ``last_detected_scan_run_id`` marker when present, else
    the ``last_seen >= run.started_at`` fallback (until detection attribution is wired).
    """
    from app.models.coverage import CoverageStatus, ScanCoverage
    from app.models.database import Asset, Finding, FindingStatus
    from app.models.scanning import ScanRun
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.discovery_health import evaluate_and_persist_discovery_health

    run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if run is None or run.tenant_id != tenant_id:
        return {"scan_run_id": scan_run_id, "skipped": "run not found or wrong tenant"}

    # Discovery gate, evaluated once for the whole run (fail-closed when unknown).
    auto_close_allowed = False
    if project_id is not None:
        auto_close_allowed = evaluate_and_persist_discovery_health(
            db, tenant_id, project_id, scan_run_id
        ).auto_close_allowed

    repo = CoverageRepository(db)
    applicable_cache: dict[str, set] = {}

    def _applicable(policy_hash: str) -> set:
        if policy_hash not in applicable_cache:
            # returns {} on a missing/partial/tampered catalog → fail-closed
            applicable_cache[policy_hash] = repo.applicable_detector_ids(policy_hash)
        return applicable_cache[policy_hash]

    coverage_by_asset: dict[int, list] = {}
    for c in db.query(ScanCoverage).filter(ScanCoverage.scan_run_id == scan_run_id).all():
        coverage_by_asset.setdefault(c.asset_id, []).append(c)

    findings = (
        db.query(Finding)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
            Finding.source.in_(("nuclei", "misconfig")),
        )
        .all()
    )

    decisions = {d.value: 0 for d in AutoCloseDecision}
    would_close_ids: list[int] = []

    for f in findings:
        detected = f.last_detected_scan_run_id == scan_run_id or (
            f.last_detected_scan_run_id is None
            and run.started_at is not None
            and f.last_seen is not None
            and f.last_seen >= run.started_at
        )

        covered = False
        applicable = False
        for c in coverage_by_asset.get(f.asset_id, ()):
            if f.template_id and f.template_id in _applicable(c.policy_hash):
                applicable = True  # detector in an INTACT catalog (empty set on tamper)
                if c.status == CoverageStatus.COVERED:
                    covered = True
                    break

        verdict = decide_finding_auto_close(
            this_run_id=scan_run_id,
            detected_this_run=detected,
            discovery_auto_close_allowed=auto_close_allowed,
            coverage_covered=covered,
            catalog_intact=applicable,
            detector_applicable=applicable,
            current_streak=f.eligible_miss_streak or 0,
            last_eligible_run_id=f.last_eligible_run_id,
            close_threshold=close_threshold,
        )
        decisions[verdict.decision.value] += 1
        if verdict.would_close:
            would_close_ids.append(f.id)

    result = {
        "scan_run_id": scan_run_id,
        "auto_close_allowed": auto_close_allowed,
        "open_findings": len(findings),
        "decisions": decisions,
        "would_close_ids": would_close_ids,
    }
    logger.info(
        "coverage auto-close DRY-RUN: run %s allowed=%s decisions=%s would_close=%d",
        scan_run_id,
        auto_close_allowed,
        decisions,
        len(would_close_ids),
    )
    return result


__all__ = [
    "AutoCloseDecision",
    "AutoCloseVerdict",
    "decide_finding_auto_close",
    "dry_run_auto_close",
    "DEFAULT_CLOSE_THRESHOLD",
]
