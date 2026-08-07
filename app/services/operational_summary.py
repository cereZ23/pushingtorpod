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
OUTCOME_UNKNOWN = "unknown"  # an unrecognized scan status — never silently reported as success

VALID_OUTCOMES = frozenset(
    {
        OUTCOME_PENDING,
        OUTCOME_RUNNING,
        OUTCOME_COMPLETED,
        OUTCOME_COMPLETED_WITH_LIMITATIONS,
        OUTCOME_FAILED,
        OUTCOME_CANCELLED,
        OUTCOME_UNKNOWN,
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


def _ledger_has_uncovered(ledger_counts: dict) -> bool:
    """True when the ledger has any non-COVERED endpoint verdict (partial/failed/skipped/unstarted).
    Evidence that some endpoints were NOT fully verified — even without a historical reason."""
    return any(_int(ledger_counts.get(k, 0)) > 0 for k in ("partial", "failed", "skipped", "unstarted"))


def _snapshot_is_valid(snapshot) -> bool:
    """A persisted snapshot is trustworthy only if it matches the schema-1 contract EXACTLY: right
    schema version, a known state, a known (or null) limitation, an all-enum limitations list, and
    valid non-negative integer counts. A dict that fails any check is treated as corrupt (fail-closed)
    — NOT silently rendered as a clean ``completed``."""
    if not isinstance(snapshot, dict):
        return False
    if snapshot.get("schema_version") != 1:
        return False
    if snapshot.get("state") not in VALID_STATES:
        return False
    limitation = snapshot.get("limitation")
    if limitation is not None and limitation not in VALID_LIMITATIONS:
        return False
    limitations = snapshot.get("limitations")
    if not isinstance(limitations, list) or any(r not in VALID_LIMITATIONS for r in limitations):
        return False
    for key in ("selected", "covered", "partial", "failed", "skipped"):
        if not _valid_count(snapshot.get(key)):
            return False
    return True


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


_COMPLETED_STATUSES = frozenset({"completed", "complete", "success", "succeeded", "done"})


def _derive_outcome(scan_status: str, endpoint_state: Optional[str], data_inconsistent: bool) -> str:
    """Map (scan status, endpoint state) to the customer outcome per the invariant table. An
    UNRECOGNIZED status is ``unknown`` — never silently reported as success."""
    status = (scan_status or "").lower()
    if status in ("pending", "queued"):
        return OUTCOME_PENDING
    if status in ("running", "in_progress"):
        return OUTCOME_RUNNING
    if status in ("cancelled", "canceled"):
        return OUTCOME_CANCELLED
    if status in ("failed", "error"):
        return OUTCOME_FAILED
    if status not in _COMPLETED_STATUSES:
        return OUTCOME_UNKNOWN
    # completed — endpoint state decides limitations.
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
    per-status tally re-aggregated from the http_endpoint ``scan_endpoint_coverage`` rows for this run.
    ``lifecycle_counts`` is the per-event tally from ``finding_lifecycle_events`` for this run. Emits
    only closed-enum codes + integer counts — never a URL/hash/raw error.

    Three snapshot dispositions (fail-closed):
    * VALID snapshot → trust its state/limitation, reconcile counts against the ledger.
    * MALFORMED snapshot (a dict that fails the schema-1 contract) → data_inconsistent, incomplete, CWL
      — never rendered as a clean ``completed``.
    * ABSENT snapshot (legacy run) → if the ledger shows any non-COVERED endpoint we know something was
      NOT verified but lack the historical reason → incomplete + ``unknown`` (NOT unresponsive_origins);
      an empty or all-COVERED ledger → clean ``completed``.
    """
    snapshot_present = isinstance(snapshot, dict)
    snapshot_valid = _snapshot_is_valid(snapshot)
    snapshot_malformed = snapshot_present and not snapshot_valid

    # Authoritative display counts from the ledger (http_endpoint rows only — see the DB wrapper).
    covered = _int(ledger_counts.get("covered", 0))
    not_verifiable = _int(ledger_counts.get("partial", 0))
    failed = _int(ledger_counts.get("failed", 0))
    skipped = _int(ledger_counts.get("skipped", 0))
    unstarted = _int(ledger_counts.get("unstarted", 0))
    selected = _ledger_selected(ledger_counts)

    # Only a VALID snapshot supplies state/limitation and the enabled flag.
    enabled = bool(snapshot.get("enabled")) if snapshot_valid else False
    snapshot_state = snapshot.get("state") if snapshot_valid else None

    data_inconsistent = False
    if snapshot_malformed:
        data_inconsistent = True
    elif snapshot_valid:
        if snapshot.get("limitation") == "data_inconsistent" or "data_inconsistent" in (
            snapshot.get("limitations") or []
        ):
            data_inconsistent = True
        elif not _counts_agree(snapshot, ledger_counts):
            data_inconsistent = True

    # Establish state + limitations by disposition.
    if data_inconsistent:
        # malformed OR valid-but-inconsistent → conservative incomplete + data_inconsistent headline.
        effective_state = STATE_INCOMPLETE
        limitation = "data_inconsistent"
        limitations = ["data_inconsistent"]
        if snapshot_valid:
            limitations += [
                r for r in (snapshot.get("limitations") or []) if r in VALID_LIMITATIONS and r != "data_inconsistent"
            ]
    elif snapshot_valid:
        effective_state = snapshot_state
        limitation = snapshot.get("limitation") if snapshot.get("limitation") in VALID_LIMITATIONS else None
        limitations = [r for r in (snapshot.get("limitations") or []) if r in VALID_LIMITATIONS]
    elif _ledger_has_uncovered(ledger_counts):
        # Legacy run, no snapshot, but the ledger proves some endpoints were NOT fully verified —
        # surface a limitation with an UNKNOWN reason (never guess unresponsive_origins).
        effective_state = STATE_INCOMPLETE
        limitation = "unknown"
        limitations = ["unknown"]
    else:
        # Legacy run with an empty or all-COVERED ledger → nothing to flag.
        effective_state = None
        limitation = None
        limitations = []

    outcome = _derive_outcome(scan_status, effective_state, data_inconsistent)

    endpoint_verification = {
        "available": snapshot_valid,  # a well-formed snapshot exists (malformed/absent → False)
        "enabled": enabled,
        "state": effective_state,  # None only for a legacy clean run
        "limitation": limitation,
        "limitations": limitations,
        "selected": selected,
        "covered": covered,
        "not_verifiable": not_verifiable,
        "failed": failed,
        "skipped": skipped,
        "unstarted": unstarted,
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
    # A malformed/absent snapshot is never reported as available.
    assert endpoint_verification["available"] == snapshot_valid
    # A non-conclusive endpoint state must carry a reason (fail-closed), and vice-versa.
    assert not (effective_state in _LIMITING_ENDPOINT_STATES and limitation is None)
    # A completed scan with a limiting/failed/inconsistent endpoint state is never plain `completed`.
    if outcome == OUTCOME_COMPLETED:
        assert not data_inconsistent
        assert effective_state not in _LIMITING_ENDPOINT_STATES
    # selected reconciles with the exposed component counts (incl. unstarted).
    assert selected == covered + not_verifiable + failed + skipped + unstarted
    cp = endpoint_verification["coverage_percent"]
    assert cp is None or (isinstance(cp, int) and 0 <= cp <= 100)
    assert not (selected == 0 and cp is not None)  # empty set → percent None, never 100
    return summary


def _endpoint_ledger_counts(db, tenant_id: int, scan_run_id: int) -> dict:
    """Re-aggregate the AUTHORITATIVE per-status endpoint coverage tally for this run, keyed by the
    ledger's own status values (covered/partial/failed/skipped/unstarted). Counts only — no hashes.

    Scoped to ``pass_name == PASS_HTTP_ENDPOINT`` — the summary is ABOUT the http_endpoint snapshot, so
    rows from any other endpoint pass in the same run must not inflate ``selected`` or fake an
    inconsistency. Tenant is filtered explicitly (defense-in-depth beyond RLS; the run id is global)."""
    from sqlalchemy import func

    from app.models.coverage import ScanEndpointCoverage
    from app.services.scan_policy import PASS_HTTP_ENDPOINT

    rows = (
        db.query(ScanEndpointCoverage.status, func.count(ScanEndpointCoverage.id))
        .filter(
            ScanEndpointCoverage.tenant_id == tenant_id,
            ScanEndpointCoverage.scan_run_id == scan_run_id,
            ScanEndpointCoverage.pass_name == PASS_HTTP_ENDPOINT,
        )
        .group_by(ScanEndpointCoverage.status)
        .all()
    )
    counts: dict = {}
    for status_val, n in rows:
        key = status_val.value if hasattr(status_val, "value") else str(status_val)
        counts[key] = int(n)
    return counts


def _lifecycle_counts(db, tenant_id: int, scan_run_id: int) -> dict:
    """Per-event lifecycle tally for THIS run (what this scan did), from finding_lifecycle_events.
    Tenant filtered explicitly (defense-in-depth beyond RLS; the run id is global)."""
    from sqlalchemy import func

    from app.models.database import FindingLifecycleEvent

    rows = (
        db.query(FindingLifecycleEvent.event_type, func.count(FindingLifecycleEvent.id))
        .filter(
            FindingLifecycleEvent.tenant_id == tenant_id,
            FindingLifecycleEvent.scan_run_id == scan_run_id,
        )
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
        ledger_counts=_endpoint_ledger_counts(db, scan_run.tenant_id, scan_run.id),
        lifecycle_counts=_lifecycle_counts(db, scan_run.tenant_id, scan_run.id),
    )


__all__ = [
    "SUMMARY_SCHEMA_VERSION",
    "OUTCOME_PENDING",
    "OUTCOME_RUNNING",
    "OUTCOME_COMPLETED",
    "OUTCOME_COMPLETED_WITH_LIMITATIONS",
    "OUTCOME_FAILED",
    "OUTCOME_CANCELLED",
    "OUTCOME_UNKNOWN",
    "VALID_OUTCOMES",
    "build_operational_summary",
    "get_operational_summary",
]
