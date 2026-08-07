"""scan trigger provenance split — apply_trigger writes all three fields consistently from a single
place, the label is normalized/display-only, and the DB CHECK bounds trigger_type.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError

from app.services.scan_triggers import apply_trigger, normalize_trigger_label


def test_apply_trigger_manual_no_label():
    r = SimpleNamespace()
    apply_trigger(r, "manual")
    assert r.trigger_type == "manual"
    assert r.trigger_label is None
    assert r.triggered_by == "manual"


def test_apply_trigger_scheduled_maps_legacy_scheduler():
    r = SimpleNamespace()
    apply_trigger(r, "scheduled")
    assert r.trigger_type == "scheduled"
    assert r.triggered_by == "scheduler"  # legacy compat value


def test_apply_trigger_retest():
    r = SimpleNamespace()
    apply_trigger(r, "retest")
    assert r.trigger_type == "retest"
    assert r.triggered_by == "retest"


def test_apply_trigger_with_label_normalizes_and_sets_legacy():
    r = SimpleNamespace()
    apply_trigger(r, "manual", "  My   Custom  Label ")
    assert r.trigger_type == "manual"
    assert r.trigger_label == "My Custom Label"  # collapsed whitespace
    assert r.triggered_by == "My Custom Label"  # legacy = the label when present


def test_apply_trigger_unknown_type_raises():
    with pytest.raises(ValueError):
        apply_trigger(SimpleNamespace(), "bogus")


def test_normalize_trigger_label():
    assert normalize_trigger_label(None) is None
    assert normalize_trigger_label("") is None
    assert normalize_trigger_label("   ") is None
    assert normalize_trigger_label(123) is None  # non-string
    assert normalize_trigger_label("a" * 200) == "a" * 100  # bounded to 100
    assert normalize_trigger_label("multi\nline\t text") == "multi line text"


def test_trigger_type_check_rejects_bad_value(db_session, test_tenant):
    from app.models.scanning import Project, ScanRun, ScanRunStatus

    p = Project(tenant_id=test_tenant.id, name="tt-proj")
    db_session.add(p)
    db_session.flush()
    run = ScanRun(
        project_id=p.id,
        tenant_id=test_tenant.id,
        status=ScanRunStatus.PENDING,
        trigger_type="bogus",
    )
    db_session.add(run)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
