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
from app.services.scan_policy import build_nuclei_policy_manifest

_proj_seq = 0


def _project(db, tenant):
    global _proj_seq
    _proj_seq += 1
    p = Project(tenant_id=tenant.id, name=f"opsum-proj-{_proj_seq}")
    db.add(p)
    db.commit()
    db.refresh(p)
    return p


def _manifest():
    # http_stock avoids the endpoint-refinement CHECK (catalog_digest/classifier_version); the summary
    # aggregates coverage by STATUS regardless of pass_name, so this is representative.
    return build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="rev-1b",
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        template_roots=["http/cves"],
        exclude_tags=["fuzz"],
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
    for path in ("https://ep.summary.com/a", "https://ep.summary.com/b"):
        repo.record_endpoint_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=run.id,
            phase=m.phase,
            pass_name=m.pass_name,
            policy_hash=m.policy_hash,
            entries=[(asset.id, _esh(path))],
            status=CoverageStatus.COVERED,
        )
    repo.record_endpoint_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase=m.phase,
        pass_name=m.pass_name,
        policy_hash=m.policy_hash,
        entries=[(asset.id, _esh("https://ep.summary.com/c?q=1"))],
        status=CoverageStatus.PARTIAL,
    )
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
    repo.record_endpoint_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase=m.phase,
        pass_name=m.pass_name,
        policy_hash=m.policy_hash,
        entries=[(asset.id, _esh("https://ep.mismatch.com/only"))],
        status=CoverageStatus.COVERED,
    )
    db_session.commit()

    summary = get_operational_summary(db_session, run)
    ev = summary["endpoint_verification"]
    assert ev["data_inconsistent"] is True
    assert ev["state"] != "complete"
    assert summary["outcome"] == "completed_with_limitations"
    # displayed counts come from the ledger (1 covered), not the snapshot's claimed 3
    assert ev["covered"] == 1
    assert ev["selected"] == 1


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
    for path in ("https://ep.api.com/a", "https://ep.api.com/b"):
        repo.record_endpoint_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=run.id,
            phase=m.phase,
            pass_name=m.pass_name,
            policy_hash=m.policy_hash,
            entries=[(asset.id, _esh(path))],
            status=CoverageStatus.COVERED,
        )
    repo.record_endpoint_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase=m.phase,
        pass_name=m.pass_name,
        policy_hash=m.policy_hash,
        entries=[(asset.id, _esh("https://ep.api.com/c?q=1"))],
        status=CoverageStatus.PARTIAL,
    )
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
