"""Persistence boundary (UI-1 PR 1a, blocker 3): the endpoint_verification snapshot rides the SAME
transaction as the phase-completion record — no autonomous commit inside detection. `_update_phase`
promotes stats["endpoint_verification"] onto scan_run.stats, replacing ONLY that key, and a re-run
deterministically overwrites a stale snapshot (never leaves the old one as the current outcome).
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.models.scanning import PhaseResult, PhaseStatus, ScanRun
from app.tasks.pipeline import _update_phase


def _run(db_session, test_tenant, stats=None):
    run = ScanRun(
        tenant_id=test_tenant.id,
        status="running",
        started_at=datetime.now(timezone.utc),
        stats=stats or {},
    )
    db_session.add(run)
    db_session.commit()
    return run


def _snap(state="complete", limitation=None):
    return {
        "schema_version": 1,
        "enabled": True,
        "execution_complete": True,
        "state": state,
        "limitation": limitation,
        "limitations": [] if limitation is None else [limitation],
        "selected": 3,
        "covered": 3,
        "partial": 0,
        "failed": 0,
        "skipped": 0,
    }


def test_snapshot_promoted_onto_scan_stats_same_boundary(db_session, test_tenant):
    run = _run(db_session, test_tenant, stats={"existing": "keep"})
    snap = _snap()
    _update_phase(
        db_session,
        run.id,
        "9",
        PhaseStatus.COMPLETED,
        stats={"findings_created": 1, "endpoint_verification": snap},
    )
    db_session.refresh(run)
    # snapshot lands on scan_run.stats, and ONLY that key is touched
    assert run.stats["endpoint_verification"] == snap
    assert run.stats["existing"] == "keep"
    # the phase record committed in the same boundary
    pr = db_session.query(PhaseResult).filter_by(scan_run_id=run.id, phase="9").first()
    assert pr is not None and pr.status is PhaseStatus.COMPLETED


def test_no_snapshot_key_leaves_scan_stats_untouched(db_session, test_tenant):
    run = _run(db_session, test_tenant, stats={"existing": "keep"})
    _update_phase(db_session, run.id, "9", PhaseStatus.COMPLETED, stats={"findings_created": 2})
    db_session.refresh(run)
    assert "endpoint_verification" not in (run.stats or {})
    assert run.stats["existing"] == "keep"


def test_rerun_overwrites_stale_snapshot_deterministically(db_session, test_tenant):
    run = _run(db_session, test_tenant)
    _update_phase(db_session, run.id, "9", PhaseStatus.PARTIAL, stats={"endpoint_verification": _snap()})
    db_session.refresh(run)
    assert run.stats["endpoint_verification"]["state"] == "complete"
    # a retry of the phase must REPLACE the prior snapshot, not leave it as the current outcome
    new_snap = _snap(state="incomplete", limitation="timeout")
    _update_phase(db_session, run.id, "9", PhaseStatus.PARTIAL, stats={"endpoint_verification": new_snap})
    db_session.refresh(run)
    assert run.stats["endpoint_verification"]["state"] == "incomplete"
    assert run.stats["endpoint_verification"]["limitation"] == "timeout"
