"""Boundary test (UI-1 PR 1b): get_operational_summary reads the AUTHORITATIVE scan_endpoint_coverage
ledger + finding_lifecycle_events for a real run and reconciles them with the persisted snapshot.
Uses real repository writes (production-shaped), not synthetic count dicts.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.coverage import CoverageStatus
from app.models.database import Asset, AssetType, Finding, FindingLifecycleEvent, FindingSeverity, FindingStatus
from app.models.scanning import Project, ScanRun
from app.repositories.coverage_repository import CoverageRepository
from app.services.endpoint_identity import endpoint_shape_hash as _esh
from app.services.operational_summary import get_operational_summary
from app.services.scan_policy import PASS_HTTP_ENDPOINT, build_nuclei_policy_manifest

_proj_seq = 0


def _project(db, tenant):
    global _proj_seq
    _proj_seq += 1
    p = Project(tenant_id=tenant.id, name=f"opsum-proj-{_proj_seq}")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _manifest(pass_name=PASS_HTTP_ENDPOINT, roots=("http/cves",)):
    # A REAL http_endpoint manifest (carries catalog_digest + classifier_version, required by the
    # endpoint-refinement CHECK) so the summary's pass_name filter is exercised as in production.
    kw = {}
    if pass_name == PASS_HTTP_ENDPOINT:
        kw = {"catalog_digest": "d" * 64, "classifier_version": 1}
    return build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="rev-1b",
        pass_name=pass_name,
        tier=1,
        severity=["critical", "high"],
        template_roots=list(roots),
        exclude_tags=["fuzz"],
        **kw,
    )


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


def _run(db, tenant, stats=None, status="completed", tier=1, project_id=None):
    r = ScanRun(
        tenant_id=tenant.id,
        project_id=project_id,
        status=status,
        scan_tier=tier,
        trigger_type="manual",
        started_at=datetime.now(timezone.utc),
        stats=stats or {},
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _asset(db, tenant, ident):
    a = Asset(tenant_id=tenant.id, identifier=ident, type=AssetType.SUBDOMAIN, is_active=True)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _snapshot(state, limitation=None, selected=3, covered=2, partial=1, failed=0, skipped=0):
    return {
        "schema_version": 1,
        "enabled": True,
        "state": state,
        "limitation": limitation,
        "limitations": [] if limitation is None else [limitation],
        "selected": selected,
        "covered": covered,
        "partial": partial,
        "failed": failed,
        "skipped": skipped,
    }


def test_summary_reconciles_with_real_ledger(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    asset = _asset(db_session, test_tenant, "ep.summary.com")
    # snapshot says limited/unresponsive with 2 covered + 1 partial of 3 selected
    run = _run(db_session, test_tenant, stats={"endpoint_verification": _snapshot("limited", "unresponsive_origins")})
    # write the AUTHORITATIVE ledger to match: 2 covered, 1 partial
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.summary.com/a", CoverageStatus.COVERED)
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.summary.com/b", CoverageStatus.COVERED)
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.summary.com/c?q=1", CoverageStatus.PARTIAL)
    db_session.commit()

    summary = get_operational_summary(db_session, run)
    assert summary["outcome"] == "completed_with_limitations"
    ev = summary["endpoint_verification"]
    assert ev["state"] == "limited"
    assert ev["limitation"] == "unresponsive_origins"
    assert (ev["selected"], ev["covered"], ev["not_verifiable"]) == (3, 2, 1)
    assert ev["coverage_percent"] == 67
    assert ev["data_inconsistent"] is False


def test_summary_flags_inconsistency_when_ledger_disagrees(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    asset = _asset(db_session, test_tenant, "ep.mismatch.com")
    # snapshot claims complete 3/3, but ledger will only have 1 covered row → mismatch
    run = _run(
        db_session,
        test_tenant,
        stats={"endpoint_verification": _snapshot("complete", selected=3, covered=3, partial=0)},
    )
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.mismatch.com/only", CoverageStatus.COVERED)
    db_session.commit()

    summary = get_operational_summary(db_session, run)
    ev = summary["endpoint_verification"]
    assert ev["data_inconsistent"] is True
    assert ev["state"] != "complete"
    assert summary["outcome"] == "completed_with_limitations"
    # displayed counts come from the ledger (1 covered), not the snapshot's claimed 3
    assert ev["covered"] == 1
    assert ev["selected"] == 1


def test_summary_counts_only_http_endpoint_pass(db_session, test_tenant):
    # Blocker 1: a run may hold rows from MULTIPLE endpoint passes; the summary must count ONLY the
    # http_endpoint rows — other passes/tenants must not inflate selected or fake an inconsistency.
    repo = CoverageRepository(db_session)
    m_ep = _manifest(pass_name=PASS_HTTP_ENDPOINT)
    m_stock = _manifest(pass_name="http_stock")
    repo.persist_policy(m_ep)
    repo.persist_policy(m_stock)
    asset = _asset(db_session, test_tenant, "ep.multipass.com")
    run = _run(
        db_session,
        test_tenant,
        stats={"endpoint_verification": _snapshot("complete", selected=2, covered=2, partial=0)},
    )
    # http_endpoint: 2 covered (matches the snapshot)
    _rec(repo, test_tenant, run, m_ep, asset.id, "https://ep.multipass.com/a", CoverageStatus.COVERED)
    _rec(repo, test_tenant, run, m_ep, asset.id, "https://ep.multipass.com/b", CoverageStatus.COVERED)
    # http_stock rows on the SAME run — must be ignored by the summary
    _rec(repo, test_tenant, run, m_stock, asset.id, "https://ep.multipass.com/x", CoverageStatus.PARTIAL)
    _rec(repo, test_tenant, run, m_stock, asset.id, "https://ep.multipass.com/y", CoverageStatus.FAILED)
    db_session.commit()

    summary = get_operational_summary(db_session, run)
    ev = summary["endpoint_verification"]
    # only the 2 http_endpoint COVERED rows count — stock's partial/failed are excluded
    assert (ev["selected"], ev["covered"], ev["not_verifiable"], ev["failed"]) == (2, 2, 0, 0)
    assert ev["data_inconsistent"] is False
    assert ev["state"] == "complete"
    assert summary["outcome"] == "completed"


def test_summary_ignores_other_run_and_tenant(db_session, test_tenant):
    # Rows from a different run must never contribute to this run's summary.
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    asset = _asset(db_session, test_tenant, "ep.otherrun.com")
    run = _run(
        db_session,
        test_tenant,
        stats={"endpoint_verification": _snapshot("complete", selected=1, covered=1, partial=0)},
    )
    other = _run(db_session, test_tenant)
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.otherrun.com/mine", CoverageStatus.COVERED)
    _rec(repo, test_tenant, other, m, asset.id, "https://ep.otherrun.com/theirs", CoverageStatus.FAILED)
    db_session.commit()

    ev = get_operational_summary(db_session, run)["endpoint_verification"]
    assert (ev["selected"], ev["covered"], ev["failed"]) == (1, 1, 0)
    assert ev["data_inconsistent"] is False


def test_summary_counts_lifecycle_events_for_this_run(db_session, test_tenant):
    run = _run(
        db_session,
        test_tenant,
        stats={"endpoint_verification": _snapshot("complete", selected=0, covered=0, partial=0)},
    )
    finding = Finding(
        asset_id=_asset(db_session, test_tenant, "lc.summary.com").id,
        source="nuclei",
        name="x",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
    )
    db_session.add(finding)
    db_session.commit()
    for et in ("detected", "eligible_miss", "would_close", "auto_closed"):
        db_session.add(
            FindingLifecycleEvent(
                tenant_id=test_tenant.id, finding_id=finding.id, scan_run_id=run.id, event_type=et, detail={}
            )
        )
    # an event on a DIFFERENT run must NOT be counted
    other = _run(db_session, test_tenant)
    db_session.add(
        FindingLifecycleEvent(
            tenant_id=test_tenant.id, finding_id=finding.id, scan_run_id=other.id, event_type="auto_closed", detail={}
        )
    )
    db_session.commit()

    ac = get_operational_summary(db_session, run)["auto_close"]
    assert ac["detected"] == 1
    assert ac["eligible_miss"] == 1
    assert ac["would_close"] == 1
    assert ac["closed"] == 1  # only THIS run's auto_closed, not the other run's
    assert ac["reopened"] == 0


def test_summary_legacy_run_without_snapshot(db_session, test_tenant):
    run = _run(db_session, test_tenant, stats={})  # no endpoint_verification
    summary = get_operational_summary(db_session, run)
    assert summary["outcome"] == "completed"
    ev = summary["endpoint_verification"]
    assert ev["available"] is False
    assert ev["state"] is None
    assert ev["coverage_percent"] is None
    assert ev["data_inconsistent"] is False


def test_scan_detail_endpoint_returns_operational_summary(authenticated_client, db_session, test_tenant):
    # API boundary: the scan-detail (progress) endpoint the frontend calls actually returns the
    # normalized operational_summary — exercised over a real reconciling ledger (2 covered + 1 partial).
    proj = _project(db_session, test_tenant)
    run = _run(
        db_session,
        test_tenant,
        stats={"endpoint_verification": _snapshot("limited", "unresponsive_origins")},
        project_id=proj.id,
    )
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    asset = _asset(db_session, test_tenant, "ep.api.com")
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.api.com/a", CoverageStatus.COVERED)
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.api.com/b", CoverageStatus.COVERED)
    _rec(repo, test_tenant, run, m, asset.id, "https://ep.api.com/c?q=1", CoverageStatus.PARTIAL)
    db_session.commit()

    resp = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/scans/{run.id}/progress")
    assert resp.status_code == 200, resp.text
    scan_run = resp.json()["scan_run"]
    summary = scan_run["operational_summary"]
    assert summary is not None
    assert summary["outcome"] == "completed_with_limitations"
    ev = summary["endpoint_verification"]
    assert ev["state"] == "limited"
    assert ev["limitation"] == "unresponsive_origins"
    assert ev["data_inconsistent"] is False
    assert (ev["selected"], ev["covered"], ev["not_verifiable"]) == (3, 2, 1)


def test_scan_detail_by_id_includes_operational_summary(authenticated_client, db_session, test_tenant):
    proj = _project(db_session, test_tenant)
    run = _run(db_session, test_tenant, stats={"endpoint_verification": _snapshot("complete")}, project_id=proj.id)
    resp = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/scans/{run.id}")
    assert resp.status_code == 200, resp.text
    assert resp.json()["operational_summary"] is not None
