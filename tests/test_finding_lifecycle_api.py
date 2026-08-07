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


_run_seq = 0


def _run(db_session, test_tenant):
    # scan_run_id on the event is FK-constrained to scan_runs, so use a real run. Project has a
    # UNIQUE(tenant_id, name), so give each run its own project name.
    global _run_seq
    _run_seq += 1
    from app.models.scanning import Project, ScanRun, ScanRunStatus

    p = Project(tenant_id=test_tenant.id, name=f"lcapi-proj-{_run_seq}")
    db_session.add(p)
    db_session.flush()
    r = ScanRun(project_id=p.id, tenant_id=test_tenant.id, status=ScanRunStatus.COMPLETED)
    db_session.add(r)
    db_session.commit()
    return r.id


def _finding(db_session, test_tenant, *, status=None, streak=0, shape=None, source="nuclei"):
    from app.models.database import Finding, FindingSeverity, FindingStatus

    f = Finding(
        asset_id=_asset(db_session, test_tenant).id,
        source=source,
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
    r1, r2 = _run(db_session, test_tenant), _run(db_session, test_tenant)
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    # insert out of order; endpoint must return ascending by created_at
    _event(db_session, test_tenant, f, "eligible_miss", run_id=r2, when=base + timedelta(hours=2))
    _event(db_session, test_tenant, f, "detected", run_id=r1, when=base)
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    assert [e.type for e in resp.events] == ["detected", "eligible_miss"]
    assert resp.events[0].scan_run_id == r1
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
        _event(
            db_session,
            test_tenant,
            f,
            "auto_closed",
            run_id=_run(db_session, test_tenant),
            detail={"reason": "coverage_miss_streak"},
        )
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
        run_id=_run(db_session, test_tenant),
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


def test_reason_code_rejects_unsafe_values(db_session, test_tenant):
    # Value-level sanitization: only a short machine token survives; URL/hash/spaces/non-string → None.
    from app.models.database import FindingStatus

    f = _finding(db_session, test_tenant, status=FindingStatus.OPEN, streak=2)
    r = _run(db_session, test_tenant)
    cases = [
        ({"reason": "coverage_miss_streak"}, "coverage_miss_streak"),  # valid short token
        ({"reason": "https://secret.example/path"}, None),  # URL
        ({"reason": "a" * 65}, None),  # 65 chars → exceeds the {1,64} limit
        ({"reason": "deadbeef" * 9}, None),  # 72-char hash-ish → too long
        ({"reason": "has spaces"}, None),  # spaces not allowed
        ({"reason": 123}, None),  # non-string
    ]
    # de-dup per (finding,type,run) → use distinct types so each event persists
    types = ["auto_closed", "detected", "eligible_miss", "would_close", "miss_reset", "reopened"]
    from app.models.database import FindingLifecycleEvent

    for i, (detail, _expected) in enumerate(cases[:6]):
        db_session.add(
            FindingLifecycleEvent(
                tenant_id=test_tenant.id,
                finding_id=f.id,
                scan_run_id=r,
                event_type=types[i],
                detail=detail,
            )
        )
    db_session.commit()
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    by_type = {e.type: e.reason_code for e in resp.events}
    assert by_type["auto_closed"] == "coverage_miss_streak"
    assert by_type["detected"] is None  # URL rejected
    assert by_type["eligible_miss"] is None  # 65 chars → over the limit
    assert by_type["would_close"] is None  # too long
    assert by_type["miss_reset"] is None  # spaces
    assert by_type["reopened"] is None  # non-string
    # and nothing hash/url-looking leaked
    blob = resp.model_dump_json()
    assert "://" not in blob
    import re

    assert not re.search(r"[a-f0-9]{32,}", blob)


def test_auto_closed_then_reopened_then_manual_fix_is_manually_fixed(db_session, test_tenant):
    # Historical correctness: last close-lineage event is `reopened`, then a human sets FIXED →
    # the state must be manually_fixed, NOT auto_fixed.
    from app.models.database import FindingStatus

    f = _finding(db_session, test_tenant, status=FindingStatus.FIXED, streak=0)
    r1, r2 = _run(db_session, test_tenant), _run(db_session, test_tenant)
    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    _event(db_session, test_tenant, f, "auto_closed", run_id=r1, when=base, detail={"reason": "coverage_miss_streak"})
    _event(
        db_session,
        test_tenant,
        f,
        "reopened",
        run_id=r2,
        when=base + timedelta(hours=1),
        detail={"reason": "re_detected"},
    )
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    assert resp.auto_close.state == "manually_fixed"


def test_events_limit_and_pagination(db_session, test_tenant):
    f = _finding(db_session, test_tenant, streak=1)
    from app.models.database import FindingLifecycleEvent

    base = datetime(2026, 8, 1, tzinfo=timezone.utc)
    # 5 events with distinct (type,run) so all persist
    runs = [_run(db_session, test_tenant) for _ in range(5)]
    types = ["detected", "eligible_miss", "miss_reset", "would_close", "reopened"]
    for i in range(5):
        db_session.add(
            FindingLifecycleEvent(
                tenant_id=test_tenant.id,
                finding_id=f.id,
                scan_run_id=runs[i],
                event_type=types[i],
                created_at=base + timedelta(hours=i),
            )
        )
    db_session.commit()
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None, limit=3)
    assert resp.total_events == 5
    assert len(resp.events) == 3
    assert resp.has_more is True
    # most-recent 3, returned chronologically (asc)
    assert [e.type for e in resp.events] == ["miss_reset", "would_close", "reopened"]


def test_coverage_scope_null_for_non_coverage_source(db_session, test_tenant):
    f = _finding(db_session, test_tenant, source="manual")  # not driven by the consumer
    resp = get_finding_lifecycle(tenant_id=test_tenant.id, finding_id=f.id, db=db_session, membership=None)
    assert resp.auto_close.coverage_scope is None
