"""Persistence boundary (UI-1 PR 1a, blocker 3): the endpoint_verification snapshot rides the SAME
transaction as the phase-completion record — no autonomous commit inside detection. `_update_phase`
promotes stats["endpoint_verification"] onto scan_run.stats, replacing ONLY that key, and a re-run
deterministically overwrites a stale snapshot (never leaves the old one as the current outcome).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

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
    _update_phase(db_session, run.id, "9", PhaseStatus.COMPLETED, stats={"endpoint_verification": _snap()})
    db_session.refresh(run)
    assert run.stats["endpoint_verification"]["state"] == "complete"
    # a retry of the phase must REPLACE the prior snapshot, not leave it as the current outcome
    new_snap = _snap(state="incomplete", limitation="timeout")
    _update_phase(db_session, run.id, "9", PhaseStatus.PARTIAL, stats={"endpoint_verification": new_snap})
    db_session.refresh(run)
    assert run.stats["endpoint_verification"]["state"] == "incomplete"
    assert run.stats["endpoint_verification"]["limitation"] == "timeout"


def test_phase9_running_clears_stale_snapshot(db_session, test_tenant):
    # A prior COMPLETE snapshot must NOT linger while phase 9 is re-running — the UI would show the old
    # attempt as the current result. RUNNING (no stats) clears it.
    run = _run(db_session, test_tenant, stats={"endpoint_verification": _snap(), "other": "keep"})
    _update_phase(db_session, run.id, "9", PhaseStatus.RUNNING)
    db_session.refresh(run)
    assert "endpoint_verification" not in run.stats
    assert run.stats["other"] == "keep"


def test_phase9_failed_without_snapshot_clears_stale(db_session, test_tenant):
    # A retry that FAILS before producing a snapshot must remove the previous complete one.
    run = _run(db_session, test_tenant, stats={"endpoint_verification": _snap()})
    _update_phase(db_session, run.id, "9", PhaseStatus.FAILED, error="boom")
    db_session.refresh(run)
    assert "endpoint_verification" not in run.stats


def test_other_phase_update_retains_snapshot(db_session, test_tenant):
    # Updates to phases OTHER than 9 must never touch phase 9's snapshot.
    run = _run(db_session, test_tenant, stats={"endpoint_verification": _snap()})
    _update_phase(db_session, run.id, "10", PhaseStatus.COMPLETED, stats={"findings_created": 3})
    _update_phase(db_session, run.id, "8", PhaseStatus.RUNNING)
    db_session.refresh(run)
    assert run.stats["endpoint_verification"]["state"] == "complete"


def test_snapshot_and_phase_roll_back_together_on_commit_failure(db_session, test_tenant, monkeypatch):
    # The snapshot replacement and the phase record share ONE commit — if it fails, BOTH are discarded
    # (the old snapshot stands, no phase-completed record persists). No half-applied state.
    run = _run(db_session, test_tenant, stats={"endpoint_verification": _snap()})

    def boom():
        raise RuntimeError("commit failed")

    monkeypatch.setattr(db_session, "commit", boom)
    with pytest.raises(RuntimeError):
        _update_phase(
            db_session,
            run.id,
            "9",
            PhaseStatus.COMPLETED,
            stats={"endpoint_verification": _snap(state="incomplete", limitation="timeout")},
        )
    monkeypatch.undo()
    db_session.rollback()
    db_session.refresh(run)
    # old snapshot survives; the failed COMPLETED phase record did not persist
    assert run.stats["endpoint_verification"]["state"] == "complete"
    assert db_session.query(PhaseResult).filter_by(scan_run_id=run.id, phase="9").first() is None
