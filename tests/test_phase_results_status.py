"""phase_results.status CHECK constraint — regression for the missing 'partial' value.

PhaseStatus.PARTIAL became first-class but the DB CHECK (migration 018) never allowed
'partial', so a truncated phase raised CheckViolation and failed the whole pipeline. The
model now mirrors the CHECK (migration 027 adds 'partial') so create_all test DBs enforce
it too — these tests would have caught the bug.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models.scanning import PhaseResult, PhaseStatus, ScanRun


def _run(db_session, test_tenant):
    run = ScanRun(tenant_id=test_tenant.id, status="running", started_at=datetime.now(timezone.utc))
    db_session.add(run)
    db_session.commit()
    return run


def test_phase_result_partial_status_is_allowed(db_session, test_tenant):
    run = _run(db_session, test_tenant)
    pr = PhaseResult(scan_run_id=run.id, phase="9", status=PhaseStatus.PARTIAL)
    db_session.add(pr)
    db_session.commit()  # must NOT raise (this is the prod regression)
    db_session.refresh(pr)
    assert pr.status is PhaseStatus.PARTIAL


def test_phase_result_bogus_status_is_rejected(db_session, test_tenant):
    run = _run(db_session, test_tenant)
    with pytest.raises(IntegrityError):
        db_session.execute(
            text("INSERT INTO phase_results (scan_run_id, phase, status) VALUES (:r, '9', 'bogus')"),
            {"r": run.id},
        )
        db_session.commit()
    db_session.rollback()
