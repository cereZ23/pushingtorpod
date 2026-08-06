"""Finding lifecycle event WRITER + reopen wiring (UI-2 backend, step 2).

Covers the load-bearing invariants of the durable auto-close audit:
  * record_lifecycle_event is idempotent, never commits internally, sanitizes detail;
  * the (finding, type, run) UNIQUE constraint is a real backstop;
  * bulk_upsert_findings reopens a re-detected FIXED finding (OPEN) and writes `reopened`
    atomically — but only on a real scan run.
The consumer-side event emission (detected/eligible_miss/would_close/auto_closed/miss_reset)
lives in test_coverage_autoclose.py where the coverage fixtures already exist.
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError


def _asset(db_session, test_tenant, ident="lcw.test.com"):
    from app.models.database import Asset, AssetType

    a = Asset(tenant_id=test_tenant.id, type=AssetType.DOMAIN, identifier=ident, is_active=True)
    db_session.add(a)
    db_session.flush()
    return a


def _finding(db_session, test_tenant, asset=None):
    from app.models.database import Finding, FindingSeverity, FindingStatus

    asset = asset or _asset(db_session, test_tenant)
    f = Finding(
        asset_id=asset.id,
        template_id="CVE-LCW",
        name="lcw",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
    )
    db_session.add(f)
    db_session.commit()
    return f


def _run(db_session, test_tenant):
    from app.models.scanning import ScanRun

    from datetime import datetime, timezone

    r = ScanRun(tenant_id=test_tenant.id, project_id=None, status="running", started_at=datetime.now(timezone.utc))
    db_session.add(r)
    db_session.commit()
    return r


def _events(db_session, finding_id, event_type=None):
    from app.models.database import FindingLifecycleEvent

    q = db_session.query(FindingLifecycleEvent).filter_by(finding_id=finding_id)
    if event_type is not None:
        q = q.filter_by(event_type=event_type)
    return q.all()


# --- writer unit -----------------------------------------------------------
def test_writer_idempotent_same_key(db_session, test_tenant):
    from app.services.lifecycle_events import record_lifecycle_event

    f = _finding(db_session, test_tenant)
    run = _run(db_session, test_tenant)
    assert record_lifecycle_event(
        db_session, tenant_id=test_tenant.id, finding_id=f.id, scan_run_id=run.id, event_type="eligible_miss"
    )
    # same (finding, type, run) again → no-op, no duplicate
    assert not record_lifecycle_event(
        db_session, tenant_id=test_tenant.id, finding_id=f.id, scan_run_id=run.id, event_type="eligible_miss"
    )
    db_session.commit()
    assert len(_events(db_session, f.id, "eligible_miss")) == 1


def test_writer_does_not_commit(db_session, test_tenant):
    # The writer flushes but must not commit; a caller rollback discards the event.
    from app.services.lifecycle_events import record_lifecycle_event

    f = _finding(db_session, test_tenant)
    run = _run(db_session, test_tenant)
    record_lifecycle_event(
        db_session, tenant_id=test_tenant.id, finding_id=f.id, scan_run_id=run.id, event_type="would_close"
    )
    db_session.rollback()
    assert _events(db_session, f.id) == []


def test_writer_sanitizes_url_and_hash(db_session, test_tenant):
    from app.services.lifecycle_events import record_lifecycle_event

    f = _finding(db_session, test_tenant)
    run = _run(db_session, test_tenant)
    record_lifecycle_event(
        db_session,
        tenant_id=test_tenant.id,
        finding_id=f.id,
        scan_run_id=run.id,
        event_type="auto_closed",
        detail={"streak": 2, "url": "https://x/y", "policy_hash": "a" * 64, "reason": "coverage_miss_streak"},
    )
    db_session.commit()
    detail = _events(db_session, f.id, "auto_closed")[0].detail
    assert "url" not in detail and "policy_hash" not in detail
    assert detail == {"streak": 2, "reason": "coverage_miss_streak"}


def test_writer_rejects_unknown_type(db_session, test_tenant):
    from app.services.lifecycle_events import record_lifecycle_event

    f = _finding(db_session, test_tenant)
    with pytest.raises(ValueError):
        record_lifecycle_event(
            db_session, tenant_id=test_tenant.id, finding_id=f.id, scan_run_id=None, event_type="bogus"
        )


def test_unique_constraint_is_a_backstop(db_session, test_tenant):
    # Bypassing the writer's re-check, the DB UNIQUE(finding, type, run) still forbids duplicates.
    from app.models.database import FindingLifecycleEvent

    f = _finding(db_session, test_tenant)
    run = _run(db_session, test_tenant)
    db_session.add(
        FindingLifecycleEvent(tenant_id=test_tenant.id, finding_id=f.id, scan_run_id=run.id, event_type="detected")
    )
    db_session.add(
        FindingLifecycleEvent(tenant_id=test_tenant.id, finding_id=f.id, scan_run_id=run.id, event_type="detected")
    )
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# --- reopen wiring in bulk_upsert_findings ---------------------------------
def _upsert(db_session, test_tenant, asset, run_id):
    from app.repositories.finding_repository import FindingRepository

    return FindingRepository(db_session).bulk_upsert_findings(
        [{"asset_id": asset.id, "template_id": "CVE-RE", "name": "re", "severity": "high", "source": "nuclei"}],
        tenant_id=test_tenant.id,
        scan_run_id=run_id,
    )


def test_bulk_upsert_reopens_fixed_on_redetection(db_session, test_tenant):
    from app.models.database import Finding, FindingStatus

    asset = _asset(db_session, test_tenant, "reopen.test.com")
    db_session.commit()
    run1 = _run(db_session, test_tenant)
    _upsert(db_session, test_tenant, asset, run1.id)

    f = db_session.query(Finding).filter_by(asset_id=asset.id, template_id="CVE-RE").one()
    f.status = FindingStatus.FIXED
    db_session.commit()

    run2 = _run(db_session, test_tenant)
    res = _upsert(db_session, test_tenant, asset, run2.id)
    assert res["reopened"] == 1
    db_session.refresh(f)
    assert f.status == FindingStatus.OPEN
    ev = _events(db_session, f.id, "reopened")
    assert len(ev) == 1 and ev[0].scan_run_id == run2.id and ev[0].detail == {"reason": "re_detected"}


def test_bulk_upsert_no_reopen_without_run(db_session, test_tenant):
    # A manual upsert (no scan_run_id) must NOT reopen a deliberately-FIXED finding.
    from app.models.database import Finding, FindingStatus

    asset = _asset(db_session, test_tenant, "noreopen.test.com")
    db_session.commit()
    run1 = _run(db_session, test_tenant)
    _upsert(db_session, test_tenant, asset, run1.id)
    f = db_session.query(Finding).filter_by(asset_id=asset.id, template_id="CVE-RE").one()
    f.status = FindingStatus.FIXED
    db_session.commit()

    res = _upsert(db_session, test_tenant, asset, None)  # manual: scan_run_id=None
    assert res["reopened"] == 0
    db_session.refresh(f)
    assert f.status == FindingStatus.FIXED
    assert _events(db_session, f.id, "reopened") == []
