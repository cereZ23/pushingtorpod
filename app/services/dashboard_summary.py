"""Tenant-level operational dashboard aggregate (UI-3, U3-1).

Aggregates ALREADY-PERSISTED data — scan snapshots, the endpoint coverage ledger, and finding
lifecycle events — into one tenant-scoped summary. It introduces NO new scan/auto-close logic and
reuses the canonical vocabulary (``operational_summary`` for the per-scan outcome, the coverage-
autoclose threshold + ``is_awaiting_confirmation`` for current finding state).

Semantics that matter (these are the reviewed decisions):
* Time window: ``days`` clamped to [1, 365]; ``from``/``to`` are UTC; scans are placed in the window
  by their TERMINAL timestamp (``completed_at``), never ``created_at``. Pending/running scans are not
  terminal and are excluded from every outcome count.
* Scan outcomes: ``total = completed + completed_with_limitations + failed``. ``cancelled`` is a
  separate explicit field (NOT in ``total``) so there is never an unexplained difference. A real
  ``status == failed`` stays ``failed`` — never reinterpreted as completed_with_limitations.
* Endpoints: NOT a sum over every scan in the window (that double-counts frequently-scanned projects).
  We take the LAST terminal scan per (project_id, scan_tier) among certified tiers {1, 2}, then
  aggregate the ``http_endpoint`` ledger rows for exactly those runs. ``selected = verified +
  not_verifiable + failed + skipped``; ``coverage_percent`` is null when selected == 0 (never 100).
* Findings: ``auto_closed``/``reopened`` = DISTINCT findings with that event in-window (the lifecycle
  unique constraint makes retries idempotent). ``awaiting_confirmation`` is CURRENT state (the
  canonical ``is_awaiting_confirmation`` predicate: open + 0 < streak < threshold) — NOT derived from
  historical events (a past eligible_miss may since have been re-detected/closed/reopened).
* By-tier: always returns keys "1" and "2" (zeros allowed), same schema as the totals. T3 is excluded
  until certified. Finding tier attribution resolves ``detail['tier']`` (the ORIGIN policy tier
  stamped on the event) first, then ``origin_policy_hash → scan_policy.tier``; the RUN tier is never
  used (a T2 run may re-detect a T1-origin finding). Findings with no certified tier appear only in
  the tenant-wide total (an explained difference).
* Emits only integers/floats + UTC ISO strings — no URL, hash, or finding name. Typed + extra=forbid.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional

from app.services.operational_summary import (
    OUTCOME_COMPLETED,
    OUTCOME_COMPLETED_WITH_LIMITATIONS,
    _derive_outcome,
    _snapshot_is_valid,
)

SCHEMA_VERSION = 1
CERTIFIED_TIERS = (1, 2)
MIN_DAYS = 1
MAX_DAYS = 365


def clamp_days(days) -> int:
    """Clamp the requested window to [1, 365]; a non-int defaults to 30."""
    if not isinstance(days, int) or isinstance(days, bool):
        return 30
    return max(MIN_DAYS, min(MAX_DAYS, days))


def _valid_count(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _int(v) -> int:
    return v if _valid_count(v) else 0


def scan_outcome_bucket(status: str, snapshot: Optional[dict]) -> Optional[str]:
    """Canonical dashboard bucket for ONE terminal scan, reusing operational_summary's snapshot
    validation + state→outcome mapping. Returns one of completed / completed_with_limitations /
    failed / cancelled, or None for a non-terminal (pending/running) scan.

    A legacy/malformed snapshot never invents a limitation: its state is treated as unknown → the
    scan counts as ``completed`` (the dashboard does NOT flag data_inconsistent — that is a per-scan
    concern, not an aggregate outcome)."""
    s = (status or "").lower()
    if s in ("failed", "error"):
        return "failed"
    if s in ("cancelled", "canceled"):
        return "cancelled"
    if s not in ("completed", "complete", "success", "succeeded", "done"):
        return None  # pending / running / unknown non-terminal → excluded from outcome counts
    state = snapshot.get("state") if _snapshot_is_valid(snapshot) else None
    outcome = _derive_outcome("completed", state, data_inconsistent=False)
    # _derive_outcome only returns completed / completed_with_limitations here.
    return outcome if outcome in (OUTCOME_COMPLETED, OUTCOME_COMPLETED_WITH_LIMITATIONS) else OUTCOME_COMPLETED


def _empty_scans() -> dict:
    return {"total": 0, "completed": 0, "completed_with_limitations": 0, "failed": 0, "cancelled": 0}


def _coverage_percent(verified: int, selected: int) -> Optional[float]:
    if selected <= 0:
        return None
    return round(verified * 100 / selected, 1)


def build_scans_block(outcomes: list[Optional[str]]) -> dict:
    """Bucket a list of per-scan outcomes into the scans block. ``total`` excludes cancelled."""
    block = _empty_scans()
    for o in outcomes:
        if o == OUTCOME_COMPLETED:
            block["completed"] += 1
        elif o == OUTCOME_COMPLETED_WITH_LIMITATIONS:
            block["completed_with_limitations"] += 1
        elif o == "failed":
            block["failed"] += 1
        elif o == "cancelled":
            block["cancelled"] += 1
        # None (non-terminal) contributes nothing
    block["total"] = block["completed"] + block["completed_with_limitations"] + block["failed"]
    return block


def build_endpoints_block(ledger_counts: dict) -> dict:
    """Aggregate the http_endpoint ledger tally (over the selected runs) into the endpoints block."""
    verified = _int(ledger_counts.get("covered", 0))
    not_verifiable = _int(ledger_counts.get("partial", 0))
    failed = _int(ledger_counts.get("failed", 0))
    skipped = _int(ledger_counts.get("skipped", 0))
    unstarted = _int(ledger_counts.get("unstarted", 0))
    selected = verified + not_verifiable + failed + skipped + unstarted
    return {
        "selected": selected,
        "verified": verified,
        "not_verifiable": not_verifiable,
        "failed": failed,
        "skipped": skipped + unstarted,  # 'not reached' folds into skipped for the aggregate view
        "coverage_percent": _coverage_percent(verified, selected),
    }


def build_findings_block(auto_closed: int, reopened: int, awaiting_confirmation: int) -> dict:
    return {
        "auto_closed": _int(auto_closed),
        "reopened": _int(reopened),
        "awaiting_confirmation": _int(awaiting_confirmation),
    }


def build_dashboard_summary(
    *,
    now: datetime,
    days: int,
    scans_total_outcomes: list[Optional[str]],
    endpoints_total_ledger: dict,
    findings_total: dict,
    per_tier: dict,
) -> dict:
    """Assemble the schema-1 dashboard summary from pre-aggregated primitives (pure + unit-testable).

    ``per_tier`` maps tier(int in CERTIFIED_TIERS) → {"outcomes": [...], "ledger": {...},
    "findings": {auto_closed, reopened, awaiting_confirmation}}. ``now`` is an aware UTC datetime.
    """
    clamped = clamp_days(days)
    to_dt = now.astimezone(timezone.utc)
    from_dt = to_dt - timedelta(days=clamped)

    by_tier = {}
    for tier in CERTIFIED_TIERS:
        t = per_tier.get(tier, {})
        by_tier[str(tier)] = {
            "scans": build_scans_block(t.get("outcomes", [])),
            "endpoints": build_endpoints_block(t.get("ledger", {})),
            "findings": build_findings_block(
                t.get("findings", {}).get("auto_closed", 0),
                t.get("findings", {}).get("reopened", 0),
                t.get("findings", {}).get("awaiting_confirmation", 0),
            ),
        }

    summary = {
        "schema_version": SCHEMA_VERSION,
        "period_days": clamped,
        "from": from_dt.isoformat().replace("+00:00", "Z"),
        "to": to_dt.isoformat().replace("+00:00", "Z"),
        "scans": build_scans_block(scans_total_outcomes),
        "endpoints": build_endpoints_block(endpoints_total_ledger),
        "findings": build_findings_block(
            findings_total.get("auto_closed", 0),
            findings_total.get("reopened", 0),
            findings_total.get("awaiting_confirmation", 0),
        ),
        "by_tier": by_tier,
    }

    # Construction-time invariants.
    for block in [summary["scans"], *[by_tier[str(t)]["scans"] for t in CERTIFIED_TIERS]]:
        assert block["total"] == block["completed"] + block["completed_with_limitations"] + block["failed"]
    for block in [summary["endpoints"], *[by_tier[str(t)]["endpoints"] for t in CERTIFIED_TIERS]]:
        assert block["selected"] == (block["verified"] + block["not_verifiable"] + block["failed"] + block["skipped"])
        cp = block["coverage_percent"]
        assert cp is None or (isinstance(cp, float) and 0.0 <= cp <= 100.0)
        assert not (block["selected"] == 0 and cp is not None)
    # certified tiers only, always present
    assert set(summary["by_tier"].keys()) == {str(t) for t in CERTIFIED_TIERS}
    return summary


def _status_str(status) -> str:
    return status.value if hasattr(status, "value") else str(status)


def _ledger_for_runs(db, tenant_id: int, run_ids: list[int]) -> dict:
    """Aggregate the http_endpoint coverage tally over exactly the given (selected) runs."""
    if not run_ids:
        return {}
    from sqlalchemy import func

    from app.models.coverage import ScanEndpointCoverage
    from app.services.scan_policy import PASS_HTTP_ENDPOINT

    rows = (
        db.query(ScanEndpointCoverage.status, func.count(ScanEndpointCoverage.id))
        .filter(
            ScanEndpointCoverage.tenant_id == tenant_id,
            ScanEndpointCoverage.scan_run_id.in_(run_ids),
            ScanEndpointCoverage.pass_name == PASS_HTTP_ENDPOINT,
        )
        .group_by(ScanEndpointCoverage.status)
        .all()
    )
    return {(k.value if hasattr(k, "value") else str(k)): int(n) for k, n in rows}


def _to_tier(v) -> Optional[int]:
    """Coerce a tier value (int or text) to a certified tier int, else None."""
    try:
        t = int(v)
    except (TypeError, ValueError):
        return None
    return t if t in CERTIFIED_TIERS else None


def _distinct_findings_by_event(db, tenant_id: int, event_type: str, from_dt, to_dt) -> tuple[int, dict]:
    """DISTINCT findings with ``event_type`` in-window. Each finding is attributed to at most ONE
    tier in the breakdown, resolved DETERMINISTICALLY from its LATEST in-window event of this type
    (``ORDER BY created_at DESC, id DESC`` — equal timestamps break by the higher id): that event's
    ``detail['tier']`` (the ORIGIN policy tier stamped on it) first, then the finding's CURRENT
    ``origin_policy_hash → scan_policy.tier``. The run tier is NEVER used (a T2 run may re-detect a
    T1-origin finding). Findings with no certified tier appear only in the tenant-wide total — an
    explained difference. This matters because a finding auto-closed by T1 and then again by T2 in
    the same window must not attribute non-deterministically.

    Aggregated in SQL via a ``row_number()`` window keeping one (latest) row per finding; only three
    scalar columns (finding_id, the extracted detail tier, the joined origin tier) are read — the
    full event JSON is never materialized."""
    from sqlalchemy import func

    from app.models.coverage import ScanPolicy
    from app.models.database import Finding, FindingLifecycleEvent

    in_window = (
        FindingLifecycleEvent.tenant_id == tenant_id,
        FindingLifecycleEvent.event_type == event_type,
        FindingLifecycleEvent.created_at >= from_dt,
        FindingLifecycleEvent.created_at < to_dt,
    )

    detail_tier = func.json_extract_path_text(FindingLifecycleEvent.detail, "tier")
    rn = func.row_number().over(
        partition_by=FindingLifecycleEvent.finding_id,
        order_by=(FindingLifecycleEvent.created_at.desc(), FindingLifecycleEvent.id.desc()),
    )
    ranked = (
        db.query(
            FindingLifecycleEvent.finding_id.label("fid"),
            detail_tier.label("detail_tier"),
            rn.label("rn"),
        )
        .filter(*in_window)
        .subquery()
    )
    # rn == 1 → exactly one (latest) event row per finding.
    rows = (
        db.query(ranked.c.fid, ranked.c.detail_tier, ScanPolicy.tier)
        .join(Finding, Finding.id == ranked.c.fid)
        .outerjoin(ScanPolicy, ScanPolicy.policy_hash == Finding.origin_policy_hash)
        .filter(ranked.c.rn == 1)
        .all()
    )

    total = len(rows)  # one row per distinct finding
    tier_counts = {t: 0 for t in CERTIFIED_TIERS}
    for _fid, dtier, otier in rows:
        tier = _to_tier(dtier)
        if tier is None:
            tier = _to_tier(otier)
        if tier in CERTIFIED_TIERS:
            tier_counts[tier] += 1
    return total, tier_counts


def _awaiting_confirmation(db, tenant_id: int) -> tuple[int, dict]:
    """CURRENT-state open findings that are awaiting confirmation — the canonical
    ``is_awaiting_confirmation`` predicate (OPEN and ``0 < streak < threshold``). Per-tier is
    attributed via the finding's ORIGIN policy (``origin_policy_hash`` → ``scan_policy.tier``), the
    same source the lifecycle card uses for origin_tier; never the run tier."""
    from app.models.coverage import ScanPolicy
    from app.models.database import Asset, Finding, FindingStatus
    from app.services.coverage_autoclose import DEFAULT_CLOSE_THRESHOLD

    threshold = DEFAULT_CLOSE_THRESHOLD
    # SQL filter mirrors is_awaiting_confirmation(is_open=True, streak, threshold).
    rows = (
        db.query(Finding.id, Finding.origin_policy_hash)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
            Finding.eligible_miss_streak > 0,
            Finding.eligible_miss_streak < threshold,
        )
        .all()
    )
    total = len(rows)
    hashes = {h for (_id, h) in rows if h}
    tier_by_hash: dict = {}
    if hashes:
        for h, tier in (
            db.query(ScanPolicy.policy_hash, ScanPolicy.tier).filter(ScanPolicy.policy_hash.in_(hashes)).all()
        ):
            tier_by_hash[h] = tier
    tier_counts = {t: 0 for t in CERTIFIED_TIERS}
    for _id, h in rows:
        t = tier_by_hash.get(h)
        if t in CERTIFIED_TIERS:
            tier_counts[t] += 1
    return total, tier_counts


def get_dashboard_summary(db, tenant_id: int, days, now: datetime) -> dict:
    """Load + aggregate the tenant's operational dashboard summary for the ``days`` window ending at
    ``now`` (aware UTC). Tenant-scoped throughout; counts come only from persisted rows."""
    clamped = clamp_days(days)
    to_dt = now.astimezone(timezone.utc)
    from_dt = to_dt - timedelta(days=clamped)

    from app.models.scanning import ScanRun

    scans = (
        db.query(
            ScanRun.id,
            ScanRun.project_id,
            ScanRun.scan_tier,
            ScanRun.status,
            ScanRun.completed_at,
            ScanRun.stats,
        )
        .filter(
            ScanRun.tenant_id == tenant_id,
            ScanRun.completed_at.isnot(None),
            ScanRun.completed_at >= from_dt,
            ScanRun.completed_at < to_dt,
        )
        .all()
    )

    total_outcomes: list = []
    per_tier_outcomes = {t: [] for t in CERTIFIED_TIERS}
    last_scan: dict = {}  # (project_id, tier) -> (completed_at, run_id)  [selected endpoint source]
    for s in scans:
        snap = s.stats.get("endpoint_verification") if isinstance(s.stats, dict) else None
        outcome = scan_outcome_bucket(_status_str(s.status), snap if isinstance(snap, dict) else None)
        total_outcomes.append(outcome)
        if s.scan_tier in CERTIFIED_TIERS:
            per_tier_outcomes[s.scan_tier].append(outcome)
            # Endpoint ledger source = the LAST TERMINAL, non-cancelled run per (project, tier). An
            # incoherent running/pending row (outcome None) never supplants a real terminal scan;
            # cancelled runs are excluded (no meaningful coverage); failed runs ARE kept (they can
            # carry useful partial coverage). Ties on completed_at break deterministically by the
            # higher run id — the (completed_at, id) tuple comparison guarantees it.
            if outcome is not None and outcome != "cancelled":
                key = (s.project_id, s.scan_tier)
                candidate = (s.completed_at, s.id)
                if key not in last_scan or candidate > last_scan[key]:
                    last_scan[key] = candidate

    selected_run_ids = [rid for (_ts, rid) in last_scan.values()]
    selected_by_tier = {t: [] for t in CERTIFIED_TIERS}
    for (_proj, tier), (_ts, rid) in last_scan.items():
        selected_by_tier[tier].append(rid)

    ac_total, ac_tier = _distinct_findings_by_event(db, tenant_id, "auto_closed", from_dt, to_dt)
    ro_total, ro_tier = _distinct_findings_by_event(db, tenant_id, "reopened", from_dt, to_dt)
    aw_total, aw_tier = _awaiting_confirmation(db, tenant_id)

    per_tier = {}
    for t in CERTIFIED_TIERS:
        per_tier[t] = {
            "outcomes": per_tier_outcomes[t],
            "ledger": _ledger_for_runs(db, tenant_id, selected_by_tier[t]),
            "findings": {
                "auto_closed": ac_tier.get(t, 0),
                "reopened": ro_tier.get(t, 0),
                "awaiting_confirmation": aw_tier.get(t, 0),
            },
        }

    return build_dashboard_summary(
        now=now,
        days=days,
        scans_total_outcomes=total_outcomes,
        endpoints_total_ledger=_ledger_for_runs(db, tenant_id, selected_run_ids),
        findings_total={"auto_closed": ac_total, "reopened": ro_total, "awaiting_confirmation": aw_total},
        per_tier=per_tier,
    )


__all__ = [
    "SCHEMA_VERSION",
    "CERTIFIED_TIERS",
    "clamp_days",
    "scan_outcome_bucket",
    "build_scans_block",
    "build_endpoints_block",
    "build_findings_block",
    "build_dashboard_summary",
    "get_dashboard_summary",
]
