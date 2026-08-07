"""GET /findings/{id}/lifecycle (UI-2 step 3) — tenant isolation, chronological events,
synthetic auto-close state, no URL/hash. The endpoint function is called directly with a real
db_session (membership is unused in the body), so no TestClient/auth harness is needed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException

from app.api.routers.findings import get_finding_lifecycle


def _asset(db_session, test_tenant, ident="lcapi.test.com"):
    from app.models.database import Asset, AssetType

    a = Asset(tenant_id=test_tenant.id, type=AssetType.DOMAIN, identifier=ident, is_active=True)
    db_session.add(a)
    db_session.flush()
    return a


def _finding(db_session, test_tenant, *, status=None, streak=0, shape=None):
    from app.models.database import Finding, FindingSeverity, FindingStatus

    f = Finding(
        asset_id=_asset(db_session, test_tenant).id,
        source="nuclei",
        template_id="CVE-LCAPI",
        name="lcapi",
        severity=FindingSeverity.HIGH,
        status=status or FindingStatus.OPEN,
        eligible_miss_streak=streak,
        endpoint_shape_hash=shape,
    )
    db_session.add(f)
    db_session.commit()
    return f


def _event(db_session, test_tenant, finding, etype, *, run_id=None, when=None, detail=None):
    from app.models.database import FindingLifecycleEvent

    e = FindingLifecycleEvent(
        tenant_id=test_tenant.id,
        finding_id=finding.id,
        scan_run_id=run_id,
        event_type=etype,
        detail=detail,
        created_at=when,
    )
    db_session.add(e)
    db_session.commit()
    return e


def test_lifecycle_tenant_isolation_404(db_session, test_tenant):
    f = _finding(db_session, test_tenant)
    with pytest.raises(HTTPException) as exc:
        get_finding_lifecycle(tenant_id=test_tenant.id + 999, finding_id=f.id, db=db_session, membership=None)
    assert exc.value.status_code == 404


def test_lifecycle_events_chronological(db_session, test_tenant):
    f = _finding(db_session, test_tenant, streak=1)
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    # insert out of order; endpoint must return ascending by created_at
    _event(db_session, test_tenant, f, "eligible_miss", run_id=2, when=base + timedelta(hours=2))
    _event(db_session, test_tenant, f, "detected", run_id=1, when=base)
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    assert [e.type for e in resp.events] == ["detected", "eligible_miss"]
    assert resp.has_history is True
    assert resp.auto_close.threshold == 2


@pytest.mark.parametrize(
    "status_name,streak,has_ac,expected",
    [
        ("OPEN", 0, False, "open"),
        ("OPEN", 1, False, "eligible_miss"),
        ("OPEN", 2, False, "awaiting_confirmation"),
        ("FIXED", 2, True, "auto_fixed"),
        ("FIXED", 0, False, "manually_fixed"),
        ("SUPPRESSED", 0, False, "suppressed"),
    ],
)
def test_synthetic_state(db_session, test_tenant, status_name, streak, has_ac, expected):
    from app.models.database import FindingStatus

    f = _finding(db_session, test_tenant, status=FindingStatus[status_name], streak=streak)
    if has_ac:
        _event(db_session, test_tenant, f, "auto_closed", run_id=5, detail={"reason": "coverage_miss_streak"})
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    assert resp.auto_close.state == expected
    assert resp.auto_close.current_streak == streak


def test_lifecycle_reason_code_only_no_url_or_hash(db_session, test_tenant):
    # detail may carry sanitized context; the API must only surface reason_code, never URL/hash.
    f = _finding(db_session, test_tenant, status=None, streak=2)
    _event(
        db_session,
        test_tenant,
        f,
        "auto_closed",
        run_id=7,
        detail={"reason": "coverage_miss_streak", "streak": 2, "tier": 2, "scope": "endpoint"},
    )
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    ev = resp.events[0]
    assert ev.reason_code == "coverage_miss_streak"
    blob = resp.model_dump_json()
    assert "://" not in blob
    # no 32+ char hex hash leaked anywhere in the payload
    import re

    assert not re.search(r"[a-f0-9]{32,}", blob)


def test_lifecycle_legacy_no_history(db_session, test_tenant):
    f = _finding(db_session, test_tenant)
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    assert resp.has_history is False
    assert resp.events == []
    assert resp.auto_close.state == "open"


def test_lifecycle_coverage_scope_endpoint(db_session, test_tenant):
    f = _finding(db_session, test_tenant, shape="a" * 64)  # endpoint provenance
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    assert resp.auto_close.coverage_scope == "endpoint"
