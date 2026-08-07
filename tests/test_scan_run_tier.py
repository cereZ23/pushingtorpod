"""scan_runs.scan_tier — snapshot-at-creation, immutability, CHECK, retest/legacy = NULL.

The tier lived only on the linked profile; the UI could not tell T1/T2/T3 apart. These tests pin
the fix: trigger_scan snapshots the tier from the profile that runs (so a later profile edit never
rewrites history), out-of-range is rejected, and untiered/legacy runs stay NULL (→ UI "Unknown").
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy.exc import IntegrityError


def _project(db_session, test_tenant, name="p-tier"):
    from app.models.scanning import Project

    p = Project(tenant_id=test_tenant.id, name=name)
    db_session.add(p)
    db_session.flush()
    return p


def _profile(db_session, project, tier):
    from app.models.scanning import ScanProfile

    sp = ScanProfile(project_id=project.id, name=f"prof-t{tier}", scan_tier=tier, enabled=True)
    db_session.add(sp)
    db_session.flush()
    return sp


def _trigger(db_session, test_tenant, project, profile, *, scan_tier, trigger_type):
    from app.services.scan_run_service import ScanRunService

    # Patch the Celery dispatch (imported inside trigger_scan) so nothing is enqueued.
    with patch("app.tasks.pipeline.run_scan_pipeline") as m:
        m.delay.return_value = MagicMock(id="task-test")
        svc = ScanRunService(db_session)
        run, _ = svc.trigger_scan(
            tenant_id=test_tenant.id,
            project=project,
            profile_id=profile.id if profile else None,
            scan_tier=scan_tier,
            trigger_type=trigger_type,
        )
    return run


def test_trigger_scan_snapshots_tier_from_profile(db_session, test_tenant):
    project = _project(db_session, test_tenant)
    profile = _profile(db_session, project, tier=2)
    # scan_tier param is 1 but the profile is T2 → the RUN tier must follow the profile (authoritative).
    run = _trigger(db_session, test_tenant, project, profile, scan_tier=1, trigger_type="scheduled")
    assert run.scan_tier == 2
    assert run.trigger_type == "scheduled"
    assert run.triggered_by == "scheduler"  # legacy compat mapping


def test_tier_snapshot_survives_later_profile_edit(db_session, test_tenant):
    project = _project(db_session, test_tenant, name="p-immut")
    profile = _profile(db_session, project, tier=2)
    run = _trigger(db_session, test_tenant, project, profile, scan_tier=2, trigger_type="manual")
    assert run.scan_tier == 2
    # A later profile edit must NOT retro-change the historical run tier.
    profile.scan_tier = 3
    db_session.commit()
    db_session.refresh(run)
    assert run.scan_tier == 2


def test_profileless_tier_uses_requested_value(db_session, test_tenant):
    # No profile_id → trigger_scan auto-creates a default profile for the requested tier.
    project = _project(db_session, test_tenant, name="p-auto")
    run = _trigger(db_session, test_tenant, project, None, scan_tier=3, trigger_type="api")
    assert run.scan_tier == 3


def test_untiered_run_stays_null(db_session, test_tenant):
    # A run created without a tier (e.g. a retest) is NULL → the UI shows "Unknown", never a guess.
    from app.models.scanning import ScanRun, ScanRunStatus

    project = _project(db_session, test_tenant, name="p-retest")
    run = ScanRun(project_id=project.id, tenant_id=test_tenant.id, status=ScanRunStatus.PENDING, triggered_by="retest")
    db_session.add(run)
    db_session.commit()
    assert run.scan_tier is None


def test_tier_check_rejects_out_of_range(db_session, test_tenant):
    from app.models.scanning import ScanRun, ScanRunStatus

    project = _project(db_session, test_tenant, name="p-bad")
    run = ScanRun(
        project_id=project.id,
        tenant_id=test_tenant.id,
        status=ScanRunStatus.PENDING,
        triggered_by="manual",
        scan_tier=5,
    )
    db_session.add(run)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# --- _resolve_scan_tier: snapshot is source of truth for EXECUTION too --------
def _db_with_profile(tier):
    from types import SimpleNamespace as NS

    db = MagicMock()
    db.query.return_value.filter.return_value.first.return_value = NS(scan_tier=tier) if tier is not None else None
    return db


def test_execution_uses_snapshot_not_edited_profile():
    # Blocker fix: profile edited T2->T3 after creation → pipeline must still run the snapshot (T2).
    from types import SimpleNamespace as NS

    from app.tasks.pipeline import _resolve_scan_tier

    run = NS(scan_tier=2, profile_id=5, stats=None)
    assert _resolve_scan_tier(run, _db_with_profile(3)) == 2


def test_execution_snapshot_over_stats_config():
    from types import SimpleNamespace as NS

    from app.tasks.pipeline import _resolve_scan_tier

    run = NS(scan_tier=2, profile_id=None, stats={"config": {"tier": 3}})
    assert _resolve_scan_tier(run, MagicMock()) == 2


def test_execution_legacy_null_resolves_from_profile():
    from types import SimpleNamespace as NS

    from app.tasks.pipeline import _resolve_scan_tier

    run = NS(scan_tier=None, profile_id=5, stats=None)
    assert _resolve_scan_tier(run, _db_with_profile(3)) == 3


def test_execution_legacy_null_stats_config_overrides_profile():
    # Historical fallback order preserved: profile → stats.config.tier.
    from types import SimpleNamespace as NS

    from app.tasks.pipeline import _resolve_scan_tier

    run = NS(scan_tier=None, profile_id=5, stats={"config": {"tier": 2}})
    assert _resolve_scan_tier(run, _db_with_profile(3)) == 2


def test_execution_legacy_null_defaults_to_1():
    from types import SimpleNamespace as NS

    from app.tasks.pipeline import _resolve_scan_tier

    run = NS(scan_tier=None, profile_id=None, stats=None)
    assert _resolve_scan_tier(run, MagicMock()) == 1
