"""Discovery-health guard (auto-close pre-condition).

The pipeline auto-closes findings that were "not seen this run". That is only
safe if discovery actually worked this run — a broken/partial discovery makes
every asset look "gone", which would flip real open findings to FIXED
(fabricated remediation). This module computes a structured discovery-health
verdict that the auto-close (and, later, incremental scanning) must consult.

Design contract:
  - ``compute_discovery_health`` is PURE (no DB / no persistence) → trivially
    testable; the caller gathers inputs and persists the result.
  - Explicit failures (FAILED/PARTIAL discovery) short-circuit BEFORE the
    ">N% assets missing" heuristic — you don't wait for a 50% drop when the
    phase already failed.
  - No comparable baseline (first run, changed scope) is NOT suspicious.
  - Result is structured with a stable ``reason_code`` (never parse strings),
    and always carries the raw counts so a policy can later combine ratio +
    absolute without changing the signal.
  - Fail-closed downstream: absent / unhealthy / degraded → DO NOT auto-close.
"""

from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Optional


class ReasonCode(str, enum.Enum):
    OK = "ok"
    NO_COMPARABLE_BASELINE = "no_comparable_baseline"
    DISCOVERY_FAILED = "discovery_failed"
    DISCOVERY_PARTIAL = "discovery_partial"
    DISCOVERY_INCOMPLETE = "discovery_incomplete"  # missing / non-terminal discovery phase
    EMPTY_OUTPUT = "empty_output"
    ASSET_DROP_THRESHOLD = "asset_drop_threshold"


@dataclass
class DiscoveryHealth:
    healthy: bool
    degraded: bool
    reason_code: str
    reason: str
    comparison_performed: bool
    # auto_close_allowed is STRICTER than healthy: closing findings requires a real
    # baseline comparison to have happened. "Not suspicious" (e.g. first run / scope
    # change → NO_COMPARABLE_BASELINE, healthy=True) is NOT authorization to close.
    auto_close_allowed: bool
    previous_count: Optional[int]
    observed_count: int
    missing_count: int
    missing_ratio: float
    baseline_scan_run_id: Optional[int]

    def to_dict(self) -> dict:
        return asdict(self)


def discovery_scope_hash(seeds, scope_rules, discovery_config: Optional[dict] = None) -> str:
    """Stable hash of what defines the discovery *scope*.

    Two runs are only comparable for the asset-drop heuristic if this matches —
    changing seeds / include-exclude rules / discovery config legitimately changes
    the observed set and must NOT read as a degraded discovery.
    """
    payload = {
        "seeds": sorted(str(s) for s in (seeds or [])),
        "scopes": sorted(str(s) for s in (scope_rules or [])),
        "config": discovery_config or {},
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()[:16]


def compute_discovery_health(
    *,
    discovery_phase_status: Optional[str],
    baseline_available: bool,
    previous_count: Optional[int],
    observed_count: int,
    baseline_scan_run_id: Optional[int] = None,
    drop_ratio_threshold: float = 0.5,
) -> DiscoveryHealth:
    """Pure verdict. See module docstring for the precedence contract."""

    def make(healthy, degraded, code: ReasonCode, reason, comparison, missing=0, ratio=0.0) -> DiscoveryHealth:
        return DiscoveryHealth(
            healthy=healthy,
            degraded=degraded,
            reason_code=code.value,
            reason=reason,
            comparison_performed=comparison,
            auto_close_allowed=bool(healthy and comparison),
            previous_count=previous_count,
            observed_count=observed_count,
            missing_count=missing,
            missing_ratio=ratio,
            baseline_scan_run_id=baseline_scan_run_id,
        )

    status = (discovery_phase_status or "").upper()

    # 1-3. Explicit failure / non-terminal state precedes the heuristic (fail-closed:
    # a missing or PENDING/RUNNING discovery phase is UNKNOWN, not COMPLETED).
    if status == "FAILED":
        return make(False, True, ReasonCode.DISCOVERY_FAILED, "discovery phase FAILED", False)
    if status == "PARTIAL":
        return make(False, True, ReasonCode.DISCOVERY_PARTIAL, "discovery phase PARTIAL", False)
    if status != "COMPLETED":
        # UNKNOWN / INCOMPLETE / PENDING / RUNNING / SKIPPED / "" → don't trust the
        # run. A required discovery phase that was SKIPPED did NOT prove coverage.
        return make(
            False, True, ReasonCode.DISCOVERY_INCOMPLETE, f"discovery not COMPLETED ({status or 'MISSING'})", False
        )

    # 4. No comparable baseline → not suspicious, but NOT authorized to close.
    #    A baseline that observed ZERO assets is not a usable comparison either
    #    (else a broken first run would authorize closing everything next time).
    if not baseline_available or not previous_count or previous_count <= 0:
        return make(True, False, ReasonCode.NO_COMPARABLE_BASELINE, "no comparable baseline run", False)

    # 4. Unexpected empty output when the baseline had assets.
    if observed_count == 0 and previous_count > 0:
        return make(
            False,
            True,
            ReasonCode.EMPTY_OUTPUT,
            f"0 assets observed vs {previous_count} in baseline",
            True,
            missing=previous_count,
            ratio=1.0,
        )

    # 5. Large drop vs baseline.
    missing = max(previous_count - observed_count, 0)
    ratio = round(missing / previous_count, 4) if previous_count > 0 else 0.0
    if ratio > drop_ratio_threshold:
        return make(
            False,
            True,
            ReasonCode.ASSET_DROP_THRESHOLD,
            f"{missing}/{previous_count} previously observed assets are missing",
            True,
            missing=missing,
            ratio=ratio,
        )

    # 6. Healthy.
    return make(True, False, ReasonCode.OK, "discovery healthy", True, missing=missing, ratio=ratio)


# ---------------------------------------------------------------------------
# Impure wiring (DB) — kept separate from the pure verdict above.
# ---------------------------------------------------------------------------

_REQUIRED_DISCOVERY_PHASES = ("1", "3")  # Passive Discovery + DNS Resolution
_TERMINAL = {"COMPLETED", "PARTIAL", "FAILED", "SKIPPED"}


def _discovery_phase_status(db, scan_run_id) -> str:
    """Worst status among the required discovery phases, fail-closed.

    Returns FAILED/PARTIAL/COMPLETED only when BOTH required phases are present and
    terminal; otherwise UNKNOWN (missing row, or PENDING/RUNNING) so the verdict
    can refuse to trust the run.
    """
    from app.models.scanning import PhaseResult

    rows = {
        r.phase: (r.status.value if hasattr(r.status, "value") else str(r.status)).upper()
        for r in db.query(PhaseResult.phase, PhaseResult.status).filter(
            PhaseResult.scan_run_id == scan_run_id,
            PhaseResult.phase.in_(_REQUIRED_DISCOVERY_PHASES),
        )
    }
    if any(p not in rows for p in _REQUIRED_DISCOVERY_PHASES):
        return "UNKNOWN"
    vals = set(rows.values())
    if vals - _TERMINAL:  # any non-terminal (PENDING/RUNNING/…)
        return "UNKNOWN"
    if "FAILED" in vals:
        return "FAILED"
    if "PARTIAL" in vals:
        return "PARTIAL"
    if "SKIPPED" in vals:  # a required discovery phase skipped ≠ coverage
        return "SKIPPED"
    return "COMPLETED"


def _observed_count(db, scan_run_id) -> int:
    """Assets discovery actually confirmed THIS run — run-scoped and reliable.

    Uses phase 3 (DNS Resolution) items_succeeded (hosts that resolved this run)
    from its PhaseResult.stats. This is tied to scan_run_id (immune to other
    projects / enrichment / concurrent scans) and drops when discovery breaks.
    """
    from app.models.scanning import PhaseResult

    row = db.query(PhaseResult.stats).filter(PhaseResult.scan_run_id == scan_run_id, PhaseResult.phase == "3").first()
    stats = (row.stats if row else None) or {}
    for key in ("items_succeeded", "hosts_resolved", "records_resolved"):
        v = stats.get(key)
        if isinstance(v, int):
            return v
    return 0


def evaluate_and_persist_discovery_health(db, tenant_id: int, project_id: int, scan_run_id: int) -> DiscoveryHealth:
    """Compute the verdict for this run and persist it to scan_run.stats (idempotent).

    Called once, early (before any auto-close). Both the nuclei and misconfig closes
    then read scan_run.stats["discovery_health"]["auto_close_allowed"].
    """
    from app.models.scanning import Project, Scope, ScanRun, ScanRunStatus

    run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if run is None:
        return DiscoveryHealth(
            healthy=False,
            degraded=True,
            reason_code=ReasonCode.DISCOVERY_INCOMPLETE.value,
            reason="scan run missing",
            comparison_performed=False,
            auto_close_allowed=False,
            previous_count=None,
            observed_count=0,
            missing_count=0,
            missing_ratio=0.0,
            baseline_scan_run_id=None,
        )

    # Idempotent: if already computed for this run, reuse it (same verdict for both closes).
    existing = (run.stats or {}).get("discovery_health") if isinstance(run.stats, dict) else None
    if existing:
        return DiscoveryHealth(**existing)

    project = db.query(Project).filter(Project.id == project_id).first()
    seeds = [str(s) for s in (project.seeds or [])] if project and project.seeds else []
    scopes = [
        f"{sc.rule_type}:{sc.match_type}:{sc.pattern}" for sc in db.query(Scope).filter(Scope.project_id == project_id)
    ]
    scope_hash = discovery_scope_hash(seeds, scopes)

    # observed = assets DNS-confirmed this run (run-scoped, from phase 3 stats).
    observed_count = _observed_count(db, scan_run_id)
    disc_status = _discovery_phase_status(db, scan_run_id)

    # Most recent prior COMPLETED run with the SAME scope + a healthy discovery.
    previous_count = None
    baseline_id = None
    for r in (
        db.query(ScanRun)
        .filter(ScanRun.project_id == project_id, ScanRun.id != scan_run_id, ScanRun.status == ScanRunStatus.COMPLETED)
        .order_by(ScanRun.id.desc())
        .limit(20)
    ):
        st = r.stats if isinstance(r.stats, dict) else {}
        dh = st.get("discovery_health")
        if not dh or st.get("discovery_scope_hash") != scope_hash or not dh.get("healthy"):
            continue
        previous_count = dh.get("observed_count")
        baseline_id = r.id
        break

    health = compute_discovery_health(
        discovery_phase_status=disc_status,
        baseline_available=previous_count is not None,
        previous_count=previous_count,
        observed_count=observed_count,
        baseline_scan_run_id=baseline_id,
    )

    # Persist (merge, so a later full-stats write can't clobber it).
    stats = dict(run.stats or {})
    stats["discovery_health"] = health.to_dict()
    stats["discovery_scope_hash"] = scope_hash
    if health.degraded:
        stats["completeness"] = "partial"
    run.stats = stats
    db.commit()
    return health
