"""DB boundary for the UI-3 dashboard aggregate (U3-1): window by terminal timestamp, last-scan-per
project+tier endpoint selection, distinct-finding lifecycle counts (retry-safe), current-state
awaiting_confirmation, tier split, and tenant isolation — over REAL rows.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.models.coverage import CoverageStatus
from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingLifecycleEvent,
    FindingSeverity,
    FindingStatus,
    Tenant,
)
from app.models.scanning import Project, ScanRun
from app.repositories.coverage_repository import CoverageRepository
from app.services.endpoint_identity import endpoint_shape_hash as _esh
from app.services.dashboard_summary import get_dashboard_summary
from app.services.scan_policy import PASS_HTTP_ENDPOINT, build_nuclei_policy_manifest

NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)
IN_WINDOW = NOW - timedelta(days=5)
OLD = NOW - timedelta(days=10)
OUT_OF_WINDOW = NOW - timedelta(days=40)

_seq = 0


def _manifest(tier=1):
    return build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision=f"rev-{tier}",
        pass_name=PASS_HTTP_ENDPOINT,
        tier=tier,
        severity=["critical", "high"],
        template_roots=["http/cves"],
        exclude_tags=["fuzz"],
        catalog_digest="d" * 64,
        classifier_version=1,
    )


def _project(db, tenant):
    global _seq
    _seq += 1
    p = Project(tenant_id=tenant.id, name=f"dash-proj-{_seq}")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _asset(db, tenant, ident):
    a = Asset(tenant_id=tenant.id, identifier=ident, type=AssetType.SUBDOMAIN, is_active=True)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _snap(state, selected=1, covered=1, partial=0):
    return {
        "schema_version": 1,
        "enabled": True,
        "state": state,
        "limitation": None,
        "limitations": [],
        "selected": selected,
        "covered": covered,
        "partial": partial,
        "failed": 0,
        "skipped": 0,
    }


def _run(db, tenant, *, project_id, tier, status, completed_at, snapshot=None):
    r = ScanRun(
        tenant_id=tenant.id,
        project_id=project_id,
        status=status,
        scan_tier=tier,
        trigger_type="manual",
        started_at=completed_at,
        completed_at=completed_at,
        stats={"endpoint_verification": snapshot} if snapshot else {},
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _rec(repo, tenant, run, m, asset_id, url, status):
    return repo.record_endpoint_coverage(
        tenant_id=tenant.id,
        scan_run_id=run.id,
        phase=m.phase,
        pass_name=m.pass_name,
        policy_hash=m.policy_hash,
        entries=[(asset_id, _esh(url))],
        status=status,
    )


def _finding(db, tenant, asset, *, status=FindingStatus.OPEN, streak=0, origin_policy_hash=None):
    f = Finding(
        asset_id=asset.id,
        source="nuclei",
        name="x",
        severity=FindingSeverity.HIGH,
        status=status,
        eligible_miss_streak=streak,
        origin_policy_hash=origin_policy_hash,
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def _event(db, tenant, finding, event_type, created_at, tier=None):
    e = FindingLifecycleEvent(
        tenant_id=tenant.id,
        finding_id=finding.id,
        scan_run_id=None,
        event_type=event_type,
        detail={"tier": tier} if tier is not None else {},
        created_at=created_at,
    )
    db.add(e)
    db.commit()
    return e


def test_scans_window_and_outcome_buckets(db_session, test_tenant):
    p = _project(db_session, test_tenant)
    # in-window terminal scans of each outcome
    _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=IN_WINDOW,
        snapshot=_snap("complete"),
    )
    _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=IN_WINDOW,
        snapshot=_snap("limited"),
    )
    _run(db_session, test_tenant, project_id=p.id, tier=1, status="failed", completed_at=IN_WINDOW)
    _run(db_session, test_tenant, project_id=p.id, tier=1, status="cancelled", completed_at=IN_WINDOW)
    # pending/running excluded (no completed_at)
    r_pending = ScanRun(tenant_id=test_tenant.id, project_id=p.id, status="running", scan_tier=1, started_at=IN_WINDOW)
    db_session.add(r_pending)
    # out-of-window terminal scan excluded
    _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=OUT_OF_WINDOW,
        snapshot=_snap("complete"),
    )
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    sc = s["scans"]
    assert sc == {"total": 3, "completed": 1, "completed_with_limitations": 1, "failed": 1, "cancelled": 1}
    assert sc["total"] == sc["completed"] + sc["completed_with_limitations"] + sc["failed"]


def test_endpoints_use_last_scan_per_project_tier(db_session, test_tenant):
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.ep.com")
    repo = CoverageRepository(db_session)
    m = _manifest(tier=1)
    repo.persist_policy(m)
    # OLD scan for (project, tier1): 1 partial — must be SUPERSEDED by the newer scan
    old = _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=OLD,
        snapshot=_snap("limited"),
    )
    _rec(repo, test_tenant, old, m, a.id, "https://dash.ep.com/old", CoverageStatus.PARTIAL)
    # NEW scan for the same (project, tier1): 2 covered — this is the selected one
    new = _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=IN_WINDOW,
        snapshot=_snap("complete", selected=2, covered=2),
    )
    _rec(repo, test_tenant, new, m, a.id, "https://dash.ep.com/a", CoverageStatus.COVERED)
    _rec(repo, test_tenant, new, m, a.id, "https://dash.ep.com/b", CoverageStatus.COVERED)
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    ep = s["endpoints"]
    # only the newest scan's ledger counts (2 covered), the old partial is gone
    assert (ep["selected"], ep["verified"], ep["not_verifiable"]) == (2, 2, 0)
    assert ep["coverage_percent"] == 100.0
    assert s["by_tier"]["1"]["endpoints"]["verified"] == 2


def test_findings_distinct_and_retry_safe(db_session, test_tenant):
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.find.com")
    f1 = _finding(db_session, test_tenant, a)
    f2 = _finding(db_session, test_tenant, a)
    # f1 auto_closed twice in-window (two runs) → still ONE distinct finding
    _event(db_session, test_tenant, f1, "auto_closed", IN_WINDOW, tier=1)
    _event(db_session, test_tenant, f1, "auto_closed", IN_WINDOW - timedelta(hours=1), tier=1)
    _event(db_session, test_tenant, f2, "auto_closed", IN_WINDOW, tier=2)
    # a reopened event, and one OUT of window (ignored)
    _event(db_session, test_tenant, f1, "reopened", IN_WINDOW, tier=1)
    _event(db_session, test_tenant, f2, "auto_closed", OUT_OF_WINDOW, tier=1)
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    fnd = s["findings"]
    assert fnd["auto_closed"] == 2  # f1 + f2 distinct, retry not double-counted
    assert fnd["reopened"] == 1
    # tier split by the event's detail.tier
    assert s["by_tier"]["1"]["findings"]["auto_closed"] == 1
    assert s["by_tier"]["2"]["findings"]["auto_closed"] == 1


def test_findings_tier_attribution_fallback(db_session, test_tenant):
    # Blocker 1: detail.tier first, else origin_policy_hash → scan_policy.tier, else total-only.
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.tier.com")
    repo = CoverageRepository(db_session)
    m1 = _manifest(tier=1)
    m2 = _manifest(tier=2)
    repo.persist_policy(m1)
    repo.persist_policy(m2)

    # (a) auto_closed WITH detail.tier=1
    f_detail = _finding(db_session, test_tenant, a)
    _event(db_session, test_tenant, f_detail, "auto_closed", IN_WINDOW, tier=1)

    # (b) reopened WITHOUT tier, but finding origin policy is T1 → attributed via origin
    f_origin1 = _finding(db_session, test_tenant, a, origin_policy_hash=m1.policy_hash)
    _event(db_session, test_tenant, f_origin1, "reopened", IN_WINDOW, tier=None)

    # (c) manual reopen (no detail tier, scan_run_id None) but origin policy T2 → attributed via origin
    f_origin2 = _finding(db_session, test_tenant, a, origin_policy_hash=m2.policy_hash)
    e = FindingLifecycleEvent(
        tenant_id=test_tenant.id,
        finding_id=f_origin2.id,
        scan_run_id=None,
        event_type="reopened",
        detail={"reason": "manual_reopen"},
        created_at=IN_WINDOW,
    )
    db_session.add(e)

    # (d) truly unattributable: no detail tier, no origin policy → total only
    f_none = _finding(db_session, test_tenant, a, origin_policy_hash=None)
    _event(db_session, test_tenant, f_none, "reopened", IN_WINDOW, tier=None)
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    # auto_closed: only f_detail (tier 1)
    assert s["findings"]["auto_closed"] == 1
    assert s["by_tier"]["1"]["findings"]["auto_closed"] == 1
    # reopened: f_origin1 (T1), f_origin2 (T2), f_none (untiered) → total 3
    assert s["findings"]["reopened"] == 3
    assert s["by_tier"]["1"]["findings"]["reopened"] == 1  # f_origin1 via origin policy
    assert s["by_tier"]["2"]["findings"]["reopened"] == 1  # f_origin2 via origin policy
    # f_none is in the total but neither tier — explained difference (3 total, 2 attributed)
    assert (
        s["by_tier"]["1"]["findings"]["reopened"] + s["by_tier"]["2"]["findings"]["reopened"]
        == s["findings"]["reopened"] - 1
    )


def test_finding_tier_uses_latest_event_deterministically(db_session, test_tenant):
    # Residual blocker: a finding auto-closed by T1 (older) then T2 (newer) in the same window must be
    # attributed to the LATEST event's tier (T2) exactly once, regardless of DB row order.
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.latest.com")
    f = _finding(db_session, test_tenant, a)
    _event(db_session, test_tenant, f, "auto_closed", IN_WINDOW - timedelta(hours=2), tier=1)  # older T1
    _event(db_session, test_tenant, f, "auto_closed", IN_WINDOW, tier=2)  # newer T2 wins
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    assert s["findings"]["auto_closed"] == 1  # one distinct finding
    assert s["by_tier"]["2"]["findings"]["auto_closed"] == 1  # latest event's tier
    assert s["by_tier"]["1"]["findings"]["auto_closed"] == 0  # NOT double-attributed to the older tier


def test_finding_tier_latest_event_tie_breaks_by_id(db_session, test_tenant):
    # Equal timestamps → the event with the higher id is the "latest" and decides the tier.
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.latesttie.com")
    f = _finding(db_session, test_tenant, a)
    ts = IN_WINDOW
    e1 = FindingLifecycleEvent(
        tenant_id=test_tenant.id,
        finding_id=f.id,
        scan_run_id=None,
        event_type="auto_closed",
        detail={"tier": 1},
        created_at=ts,
    )
    db_session.add(e1)
    db_session.commit()
    e2 = FindingLifecycleEvent(
        tenant_id=test_tenant.id,
        finding_id=f.id,
        scan_run_id=None,
        event_type="auto_closed",
        detail={"tier": 2},
        created_at=ts,
    )
    db_session.add(e2)
    db_session.commit()
    assert e2.id > e1.id

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    assert s["by_tier"]["2"]["findings"]["auto_closed"] == 1  # higher-id event (tier 2) wins
    assert s["by_tier"]["1"]["findings"]["auto_closed"] == 0


def test_endpoint_selection_ignores_non_terminal_and_cancelled(db_session, test_tenant):
    # Blocker 2: a running/pending row with completed_at, or a newer cancelled run, must NOT supplant
    # the last TERMINAL non-cancelled scan as the ledger source.
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.sel.com")
    repo = CoverageRepository(db_session)
    m = _manifest(tier=1)
    repo.persist_policy(m)

    # the real terminal completed scan (older) with 2 covered
    good = _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=IN_WINDOW - timedelta(hours=2),
        snapshot=_snap("complete", selected=2, covered=2),
    )
    _rec(repo, test_tenant, good, m, a.id, "https://dash.sel.com/a", CoverageStatus.COVERED)
    _rec(repo, test_tenant, good, m, a.id, "https://dash.sel.com/b", CoverageStatus.COVERED)
    # a NEWER incoherent running row with completed_at set (no ledger) — must NOT supplant `good`
    running = _run(db_session, test_tenant, project_id=p.id, tier=1, status="running", completed_at=IN_WINDOW)
    # a NEWER cancelled run — must NOT supplant `good`
    _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="cancelled",
        completed_at=IN_WINDOW + timedelta(hours=1),
    )
    db_session.commit()
    assert running.completed_at > good.completed_at

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    ep = s["endpoints"]
    assert (ep["selected"], ep["verified"]) == (2, 2)  # still the good terminal scan's ledger


def test_endpoint_selection_tie_breaks_by_higher_id(db_session, test_tenant):
    # Blocker 2: two terminal runs with the SAME completed_at → the higher id wins deterministically.
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.tie.com")
    repo = CoverageRepository(db_session)
    m = _manifest(tier=1)
    repo.persist_policy(m)
    ts = IN_WINDOW
    r1 = _run(
        db_session, test_tenant, project_id=p.id, tier=1, status="completed", completed_at=ts, snapshot=_snap("limited")
    )
    _rec(repo, test_tenant, r1, m, a.id, "https://dash.tie.com/old", CoverageStatus.PARTIAL)
    r2 = _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=ts,
        snapshot=_snap("complete", selected=1, covered=1),
    )
    _rec(repo, test_tenant, r2, m, a.id, "https://dash.tie.com/new", CoverageStatus.COVERED)
    db_session.commit()
    assert r2.id > r1.id

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    # r2 (higher id) wins → 1 covered, not the partial from r1
    assert (s["endpoints"]["selected"], s["endpoints"]["verified"], s["endpoints"]["not_verifiable"]) == (1, 1, 0)


def test_failed_run_can_source_the_ledger(db_session, test_tenant):
    # Blocker 2: a failed run may carry useful partial coverage and IS kept as a ledger source.
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.failed.com")
    repo = CoverageRepository(db_session)
    m = _manifest(tier=1)
    repo.persist_policy(m)
    fr = _run(db_session, test_tenant, project_id=p.id, tier=1, status="failed", completed_at=IN_WINDOW)
    _rec(repo, test_tenant, fr, m, a.id, "https://dash.failed.com/x", CoverageStatus.PARTIAL)
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    assert s["scans"]["failed"] == 1
    assert (s["endpoints"]["selected"], s["endpoints"]["not_verifiable"]) == (1, 1)


def test_awaiting_confirmation_current_state(db_session, test_tenant):
    p = _project(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "dash.await.com")
    repo = CoverageRepository(db_session)
    m1 = _manifest(tier=1)
    repo.persist_policy(m1)
    # OPEN with streak 1 (0 < 1 < threshold=2) → awaiting; tier from origin_policy_hash
    _finding(db_session, test_tenant, a, status=FindingStatus.OPEN, streak=1, origin_policy_hash=m1.policy_hash)
    # OPEN with streak 0 → NOT awaiting
    _finding(db_session, test_tenant, a, status=FindingStatus.OPEN, streak=0)
    # FIXED with streak 1 → NOT awaiting (not open)
    _finding(db_session, test_tenant, a, status=FindingStatus.FIXED, streak=1)
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    assert s["findings"]["awaiting_confirmation"] == 1
    assert s["by_tier"]["1"]["findings"]["awaiting_confirmation"] == 1


def test_tenant_isolation(db_session, test_tenant):
    other = Tenant(name="Other", slug="other-dash", contact_policy="x@y.com")
    db_session.add(other)
    db_session.commit()
    db_session.refresh(other)
    po = _project(db_session, other)
    ao = _asset(db_session, other, "other.dash.com")
    # other tenant's terminal scan + finding events — must NOT appear in test_tenant's summary
    _run(db_session, other, project_id=po.id, tier=1, status="failed", completed_at=IN_WINDOW)
    fo = _finding(db_session, other, ao)
    _event(db_session, other, fo, "auto_closed", IN_WINDOW, tier=1)
    db_session.commit()

    s = get_dashboard_summary(db_session, test_tenant.id, 30, NOW)
    assert s["scans"]["total"] == 0
    assert s["findings"]["auto_closed"] == 0


def test_api_endpoint_returns_typed_summary(authenticated_client, db_session, test_tenant):
    # API boundary: the endpoint uses real now(), so place a scan just before now and assert the HTTP
    # path + typed (extra=forbid) serialization + tenant scoping. Counts kept loose (timing-robust).
    real_now = datetime.now(timezone.utc)
    p = _project(db_session, test_tenant)
    _run(
        db_session,
        test_tenant,
        project_id=p.id,
        tier=1,
        status="completed",
        completed_at=real_now - timedelta(hours=1),
        snapshot=_snap("limited"),
    )
    db_session.commit()

    resp = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/dashboard/operational-summary?days=30")
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["schema_version"] == 1
    assert body["period_days"] == 30
    assert set(body["by_tier"].keys()) == {"1", "2"}
    assert set(body["scans"].keys()) == {"total", "completed", "completed_with_limitations", "failed", "cancelled"}
    assert "from" in body and "to" in body
    # the scan we placed is a completed+limited → completed_with_limitations
    assert body["scans"]["completed_with_limitations"] >= 1


def test_api_days_clamped(authenticated_client, db_session, test_tenant):
    resp = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/dashboard/operational-summary?days=9999")
    assert resp.status_code == 200, resp.text
    assert resp.json()["period_days"] == 365
