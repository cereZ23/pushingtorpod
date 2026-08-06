"""finding_lifecycle_events table (UI-2 backend, step 1) — insert + event_type CHECK.

Only the table/model contract here; step 2 wires the atomic event writes into the consumer.
"""

from __future__ import annotations

import pytest
from sqlalchemy.exc import IntegrityError


def _finding(db_session, test_tenant):
    from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus

    asset = Asset(tenant_id=test_tenant.id, type=AssetType.DOMAIN, identifier="lc.test.com", is_active=True)
    db_session.add(asset)
    db_session.flush()
    f = Finding(
        asset_id=asset.id,
        template_id="CVE-LC",
        name="lc",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
    )
    db_session.add(f)
    db_session.commit()
    return f


def test_lifecycle_event_insert_and_query(db_session, test_tenant):
    from app.models.database import FindingLifecycleEvent

    f = _finding(db_session, test_tenant)
    db_session.add(
        FindingLifecycleEvent(
            tenant_id=test_tenant.id,
            finding_id=f.id,
            scan_run_id=None,
            event_type="eligible_miss",
            detail={"streak": 1, "threshold": 2, "scope": "endpoint", "tier": 2},
        )
    )
    db_session.commit()
    rows = db_session.query(FindingLifecycleEvent).filter_by(finding_id=f.id).all()
    assert len(rows) == 1
    assert rows[0].event_type == "eligible_miss"
    assert rows[0].detail["streak"] == 1


def test_invalid_event_type_is_rejected(db_session, test_tenant):
    from app.models.database import FindingLifecycleEvent

    f = _finding(db_session, test_tenant)
    db_session.add(FindingLifecycleEvent(tenant_id=test_tenant.id, finding_id=f.id, event_type="bogus"))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_all_six_event_types_accepted(db_session, test_tenant):
    from app.models.database import FindingLifecycleEvent

    f = _finding(db_session, test_tenant)
    for et in ("detected", "eligible_miss", "miss_reset", "would_close", "auto_closed", "reopened"):
        db_session.add(FindingLifecycleEvent(tenant_id=test_tenant.id, finding_id=f.id, event_type=et))
    db_session.commit()
    assert db_session.query(FindingLifecycleEvent).filter_by(finding_id=f.id).count() == 6
