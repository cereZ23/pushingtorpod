"""Customer-facing ``operational_summary`` for a scan run (UI-1, PR 1b).

Normalizes the raw scan run + the persisted ``endpoint_verification`` snapshot + the authoritative
``scan_endpoint_coverage`` ledger + ``finding_lifecycle_events`` counts into ONE closed-enum object,
so the UI only LABELS it and never re-derives outcome/state. The backend owns every decision here.

Invariant table (scan status × endpoint state → customer outcome):

  scan status   endpoint state                     outcome
  ───────────   ────────────────────────────────   ────────────────────────────
  pending       (any)                              pending
  running       (any)                              running
  cancelled     (any)                              cancelled
  failed        (any)                              failed
  completed     disabled  (feature off)            completed
  completed     no_targets                         completed
  completed     complete                           completed
  completed     limited   (unresponsive origins)   completed_with_limitations
  completed     incomplete (budget/timeout/…)      completed_with_limitations
  completed     failed    (endpoint pass failed)   completed_with_limitations
  completed     (legacy: no snapshot)              completed
  completed     (ledger↔snapshot count mismatch)   completed_with_limitations

Rules:
* A ``failed`` scan is ``failed`` regardless of endpoint state.
* ``feature_disabled`` / ``no_targets`` are NOT limitations — a completed scan stays ``completed``.
* Counts shown come from the AUTHORITATIVE ledger (``scan_endpoint_coverage``), re-aggregated here;
  the snapshot's own counts are cross-checked and a disagreement sets ``data_inconsistent`` (never
  hidden). ``coverage_percent`` = covered / selected; ``None`` when selected == 0 (never 100).
* Nothing sensitive is emitted: no URL, endpoint, hostname, policy_hash, shape_hash, or raw error —
  only closed-enum codes + integer counts. The frontend maps codes → human text.
* Conservative on uncertainty: an inconsistency downgrades a ``completed`` outcome to
  ``completed_with_limitations`` and never reports ``complete`` endpoint state.
"""

from __future__ import annotations

from typing import Optional

from app.services.endpoint_verification import (
    STATE_COMPLETE,
    STATE_DISABLED,
    STATE_FAILED,
    STATE_INCOMPLETE,
    STATE_LIMITED,
    STATE_NO_TARGETS,
    VALID_LIMITATIONS,
    VALID_STATES,
)

SUMMARY_SCHEMA_VERSION = 1

# Customer-facing scan outcome (distinct from the raw scan_runs.status).
OUTCOME_PENDING = "pending"
OUTCOME_RUNNING = "running"
OUTCOME_COMPLETED = "completed"
OUTCOME_COMPLETED_WITH_LIMITATIONS = "completed_with_limitations"
OUTCOME_FAILED = "failed"
OUTCOME_CANCELLED = "cancelled"

VALID_OUTCOMES = frozenset(
    {
        OUTCOME_PENDING,
        OUTCOME_RUNNING,
        OUTCOME_COMPLETED,
        OUTCOME_COMPLETED_WITH_LIMITATIONS,
        OUTCOME_FAILED,
        OUTCOME_CANCELLED,
    }
)

# endpoint states that mean the pass verified everything it should have (no limitation to surface).
_CLEAN_ENDPOINT_STATES = frozenset({STATE_DISABLED, STATE_NO_TARGETS, STATE_COMPLETE})
# endpoint states that degrade a completed scan to completed_with_limitations.
_LIMITING_ENDPOINT_STATES = frozenset({STATE_LIMITED, STATE_INCOMPLETE, STATE_FAILED})

_LEDGER_COUNT_KEYS = ("covered", "partial", "failed", "skipped", "unstarted")


def _valid_count(v) -> bool:
    """A count is a non-negative int and NOT a bool (bool is an int subclass)."""
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _int(v) -> int:
    return v if _valid_count(v) else 0


def _ledger_selected(ledger_counts: dict) -> int:
    """Total endpoints the ledger recorded a verdict for = the authoritative ``selected``."""
    return sum(_int(ledger_counts.get(k, 0)) for k in _LEDGER_COUNT_KEYS)


def _coverage_percent(covered: int, selected: int) -> Optional[int]:
    """Whole-percent covered/selected; ``None`` when selected == 0 (NEVER 100 for an empty set)."""
    if selected <= 0:
        return None
    return round(covered * 100 / selected)


def _counts_agree(snapshot: dict, ledger_counts: dict) -> bool:
    """The snapshot's audit counts must reconcile with the authoritative ledger. ``partial`` in the
    snapshot maps to the ledger's ``partial`` (surfaced as ``not_verifiable``). ``unstarted`` ledger
    rows count toward ``selected`` but the snapshot never emits them separately, so we compare on the
    dimensions the snapshot carries and on the total."""
    if not isinstance(snapshot, dict):
        return False
    ledger_selected = _ledger_selected(ledger_counts)
    if _int(snapshot.get("selected")) != ledger_selected:
        return False
    for key in ("covered", "partial", "failed", "skipped"):
        if _int(snapshot.get(key)) != _int(ledger_counts.get(key, 0)):
            return False
    return True


def _derive_outcome(scan_status: str, endpoint_state: Optional[str], data_inconsistent: bool) -> str:
    """Map (scan status, endpoint state) to the customer outcome per the invariant table."""
    status = (scan_status or "").lower()
    if status in ("pending", "queued"):
        return OUTCOME_PENDING
    if status in ("running", "in_progress"):
        return OUTCOME_RUNNING
    if status in ("cancelled", "canceled"):
        return OUTCOME_CANCELLED
    if status in ("failed", "error"):
        return OUTCOME_FAILED
    # completed (or any other terminal-success alias) — endpoint state decides limitations.
    if data_inconsistent:
        return OUTCOME_COMPLETED_WITH_LIMITATIONS
    if endpoint_state in _LIMITING_ENDPOINT_STATES:
        return OUTCOME_COMPLETED_WITH_LIMITATIONS
    return OUTCOME_COMPLETED


def build_operational_summary(
    *,
    scan_status: str,
    scan_tier: Optional[int],
    trigger_type: Optional[str],
    trigger_label: Optional[str],
    snapshot: Optional[dict],
    ledger_counts: dict,
    lifecycle_counts: dict,
) -> dict:
    """Build the schema-1 ``operational_summary``. ``snapshot`` is the persisted
    ``endpoint_verification`` (or ``None`` for a legacy run). ``ledger_counts`` is the AUTHORITATIVE
    per-status tally re-aggregated from ``scan_endpoint_coverage`` for this run. ``lifecycle_counts``
    is the per-event tally from ``finding_lifecycle_events`` for this run. Emits only closed-enum
    codes + integer counts — never a URL/hash/raw error."""
    has_snapshot = isinstance(snapshot, dict)
    enabled = bool(snapshot.get("enabled")) if has_snapshot else False

    # Authoritative display counts from the ledger.
    covered = _int(ledger_counts.get("covered", 0))
    not_verifiable = _int(ledger_counts.get("partial", 0))
    failed = _int(ledger_counts.get("failed", 0))
    skipped = _int(ledger_counts.get("skipped", 0))
    selected = _ledger_selected(ledger_counts)

    # data_inconsistent = snapshot present but its audit counts disagree with the ledger, OR the
    # snapshot marks itself inconsistent. Legacy runs (no snapshot) are NOT inconsistent — just absent.
    snapshot_state = snapshot.get("state") if has_snapshot else None
    snapshot_state = snapshot_state if snapshot_state in VALID_STATES else None
    data_inconsistent = False
    if has_snapshot:
        if snapshot.get("limitation") == "data_inconsistent" or "data_inconsistent" in (
            snapshot.get("limitations") or []
        ):
            data_inconsistent = True
        elif not _counts_agree(snapshot, ledger_counts):
            data_inconsistent = True

    # Conservative endpoint state: never report `complete` under an inconsistency.
    effective_state = snapshot_state
    if data_inconsistent and effective_state == STATE_COMPLETE:
        effective_state = STATE_INCOMPLETE

    limitation = snapshot.get("limitation") if has_snapshot else None
    limitation = limitation if limitation in VALID_LIMITATIONS else None
    limitations = [r for r in (snapshot.get("limitations") or []) if r in VALID_LIMITATIONS] if has_snapshot else []
    if data_inconsistent:
        limitation = "data_inconsistent"
        limitations = ["data_inconsistent"] + [r for r in limitations if r != "data_inconsistent"]

    outcome = _derive_outcome(scan_status, effective_state, data_inconsistent)

    endpoint_verification = {
        "available": has_snapshot,
        "enabled": enabled,
        "state": effective_state,  # None for a legacy run (no snapshot)
        "limitation": limitation,
        "limitations": limitations,
        "selected": selected,
        "covered": covered,
        "not_verifiable": not_verifiable,
        "failed": failed,
        "skipped": skipped,
        "coverage_percent": _coverage_percent(covered, selected),
        "data_inconsistent": data_inconsistent,
    }

    auto_close = {
        "detected": _int(lifecycle_counts.get("detected", 0)),
        "eligible_miss": _int(lifecycle_counts.get("eligible_miss", 0)),
        "would_close": _int(lifecycle_counts.get("would_close", 0)),
        "closed": _int(lifecycle_counts.get("auto_closed", 0)),
        "reopened": _int(lifecycle_counts.get("reopened", 0)),
    }

    summary = {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "outcome": outcome,
        "tier": scan_tier if isinstance(scan_tier, int) else None,
        "trigger_type": trigger_type,
        "trigger_label": trigger_label,
        "endpoint_verification": endpoint_verification,
        "auto_close": auto_close,
    }

    # Construction-time invariants (executable, not just documented).
    assert summary["outcome"] in VALID_OUTCOMES
    assert effective_state is None or effective_state in VALID_STATES
    assert limitation is None or limitation in VALID_LIMITATIONS
    assert all(r in VALID_LIMITATIONS for r in limitations)
    assert not (data_inconsistent and effective_state == STATE_COMPLETE)
    # A completed scan with a limiting/failed/inconsistent endpoint state is never plain `completed`.
    if outcome == OUTCOME_COMPLETED:
        assert not data_inconsistent
        assert effective_state not in _LIMITING_ENDPOINT_STATES
    cp = endpoint_verification["coverage_percent"]
    assert cp is None or (isinstance(cp, int) and 0 <= cp <= 100)
    assert not (selected == 0 and cp is not None)  # empty set → percent None, never 100
    return summary


def _endpoint_ledger_counts(db, scan_run_id: int) -> dict:
    """Re-aggregate the AUTHORITATIVE per-status endpoint coverage tally for this run, keyed by the
    ledger's own status values (covered/partial/failed/skipped/unstarted). Counts only — no hashes."""
    from sqlalchemy import func

    from app.models.coverage import ScanEndpointCoverage

    rows = (
        db.query(ScanEndpointCoverage.status, func.count(ScanEndpointCoverage.id))
        .filter(ScanEndpointCoverage.scan_run_id == scan_run_id)
        .group_by(ScanEndpointCoverage.status)
        .all()
    )
    counts: dict = {}
    for status_val, n in rows:
        key = status_val.value if hasattr(status_val, "value") else str(status_val)
        counts[key] = int(n)
    return counts


def _lifecycle_counts(db, scan_run_id: int) -> dict:
    """Per-event lifecycle tally for THIS run (what this scan did), from finding_lifecycle_events."""
    from sqlalchemy import func

    from app.models.database import FindingLifecycleEvent

    rows = (
        db.query(FindingLifecycleEvent.event_type, func.count(FindingLifecycleEvent.id))
        .filter(FindingLifecycleEvent.scan_run_id == scan_run_id)
        .group_by(FindingLifecycleEvent.event_type)
        .all()
    )
    return {str(event_type): int(n) for event_type, n in rows}


def get_operational_summary(db, scan_run) -> dict:
    """DB wrapper: load the authoritative ledger + lifecycle counts for ``scan_run`` and build the
    normalized ``operational_summary``. The persisted snapshot (``scan_run.stats.endpoint_verification``)
    supplies state/limitation; counts come from the ledger and are cross-checked against the snapshot."""
    stats = scan_run.stats if isinstance(scan_run.stats, dict) else {}
    snapshot = stats.get("endpoint_verification")
    status = scan_run.status.value if hasattr(scan_run.status, "value") else str(scan_run.status)
    return build_operational_summary(
        scan_status=status,
        scan_tier=scan_run.scan_tier,
        trigger_type=scan_run.trigger_type,
        trigger_label=scan_run.trigger_label,
        snapshot=snapshot if isinstance(snapshot, dict) else None,
        ledger_counts=_endpoint_ledger_counts(db, scan_run.id),
        lifecycle_counts=_lifecycle_counts(db, scan_run.id),
    )


__all__ = [
    "SUMMARY_SCHEMA_VERSION",
    "OUTCOME_PENDING",
    "OUTCOME_RUNNING",
    "OUTCOME_COMPLETED",
    "OUTCOME_COMPLETED_WITH_LIMITATIONS",
    "OUTCOME_FAILED",
    "OUTCOME_CANCELLED",
    "VALID_OUTCOMES",
    "build_operational_summary",
    "get_operational_summary",
]
