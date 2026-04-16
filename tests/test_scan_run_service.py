"""Tests for scan run service (app/services/scan_run_service.py).

Uses MagicMock for DB session — no database required.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.models.scanning import ScanRunStatus
from app.services.scan_run_service import (
    ScanRunService,
    _serialize_phase_result,
    _serialize_scan_run,
)


def _enum(value: str):
    """Create a mock enum-like object with a .value attribute."""
    m = MagicMock()
    m.value = value
    return m


class TestSerializeScanRun:
    def test_serialize_full_run(self):
        run = SimpleNamespace(
            id=1,
            project_id=10,
            profile_id=5,
            tenant_id=2,
            status=ScanRunStatus.COMPLETED,
            triggered_by="manual",
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
            stats={"assets": 10},
            error_message=None,
            celery_task_id="task-abc",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_seconds=3600,
        )
        out = _serialize_scan_run(run)
        assert out["id"] == 1
        assert out["project_id"] == 10
        assert out["status"] == "completed"
        assert out["triggered_by"] == "manual"
        assert out["stats"] == {"assets": 10}
        assert out["celery_task_id"] == "task-abc"
        assert out["duration_seconds"] == 3600

    def test_serialize_string_status_fallback(self):
        # If status doesn't have .value, fall back to str()
        run = SimpleNamespace(
            id=1,
            project_id=10,
            profile_id=None,
            tenant_id=2,
            status="weird-status",
            triggered_by="cron",
            started_at=None,
            completed_at=None,
            stats=None,
            error_message="err",
            celery_task_id=None,
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_seconds=None,
        )
        out = _serialize_scan_run(run)
        assert out["status"] == "weird-status"
        assert out["error_message"] == "err"


class TestSerializePhaseResult:
    def test_serialize_phase(self):
        phase = SimpleNamespace(
            id=1,
            scan_run_id=10,
            phase="discovery",
            status=_enum("completed"),
            started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            completed_at=datetime(2026, 1, 1, 0, 5, tzinfo=timezone.utc),
            stats={"found": 5},
            error_message=None,
            duration_seconds=300,
        )
        out = _serialize_phase_result(phase)
        assert out["phase"] == "discovery"
        assert out["status"] == "completed"
        assert out["stats"] == {"found": 5}
        assert out["duration_seconds"] == 300

    def test_serialize_phase_string_status(self):
        phase = SimpleNamespace(
            id=1,
            scan_run_id=10,
            phase="enrichment",
            status="plain-string",
            started_at=None,
            completed_at=None,
            stats={},
            error_message=None,
            duration_seconds=None,
        )
        out = _serialize_phase_result(phase)
        assert out["status"] == "plain-string"


class TestCancelScanRun:
    def test_cancel_not_found_raises_404(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        svc = ScanRunService(db)

        with pytest.raises(HTTPException) as exc:
            svc.cancel_scan_run(tenant_id=1, project_id=2, run_id=3)
        assert exc.value.status_code == 404

    def test_cancel_wrong_status_raises_400(self):
        db = MagicMock()
        scan_run = SimpleNamespace(
            id=3,
            status=ScanRunStatus.COMPLETED,
        )
        db.query.return_value.filter.return_value.first.return_value = scan_run
        svc = ScanRunService(db)

        with pytest.raises(HTTPException) as exc:
            svc.cancel_scan_run(tenant_id=1, project_id=2, run_id=3)
        assert exc.value.status_code == 400
        assert "completed" in exc.value.detail.lower()

    def test_cancel_pending_dispatches_task(self):
        db = MagicMock()
        scan_run = SimpleNamespace(id=3, status=ScanRunStatus.PENDING)
        db.query.return_value.filter.return_value.first.return_value = scan_run
        svc = ScanRunService(db)

        with patch("app.tasks.pipeline.cancel_scan") as mock_cancel:
            svc.cancel_scan_run(tenant_id=1, project_id=2, run_id=3)
            mock_cancel.delay.assert_called_once_with(3)

    def test_cancel_running_dispatches_task(self):
        db = MagicMock()
        scan_run = SimpleNamespace(id=3, status=ScanRunStatus.RUNNING)
        db.query.return_value.filter.return_value.first.return_value = scan_run
        svc = ScanRunService(db)

        with patch("app.tasks.pipeline.cancel_scan") as mock_cancel:
            svc.cancel_scan_run(tenant_id=1, project_id=2, run_id=3)
            mock_cancel.delay.assert_called_once_with(3)


class TestCancelScanRunByTenant:
    def test_cancel_by_tenant_not_found(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        svc = ScanRunService(db)

        with pytest.raises(HTTPException) as exc:
            svc.cancel_scan_run_by_tenant(tenant_id=1, run_id=3)
        assert exc.value.status_code == 404

    def test_cancel_by_tenant_wrong_status(self):
        db = MagicMock()
        scan_run = SimpleNamespace(id=3, status=ScanRunStatus.FAILED)
        db.query.return_value.filter.return_value.first.return_value = scan_run
        svc = ScanRunService(db)

        with pytest.raises(HTTPException) as exc:
            svc.cancel_scan_run_by_tenant(tenant_id=1, run_id=3)
        assert exc.value.status_code == 400

    def test_cancel_by_tenant_dispatches(self):
        db = MagicMock()
        scan_run = SimpleNamespace(id=3, status=ScanRunStatus.PENDING)
        db.query.return_value.filter.return_value.first.return_value = scan_run
        svc = ScanRunService(db)

        with patch("app.tasks.pipeline.cancel_scan") as mock_cancel:
            svc.cancel_scan_run_by_tenant(tenant_id=1, run_id=3)
            mock_cancel.delay.assert_called_once_with(3)


class TestGetScanProgress:
    def test_not_found_raises_404(self):
        db = MagicMock()
        # First query: scan_run — returns None
        db.query.return_value.filter.return_value.first.return_value = None
        svc = ScanRunService(db)

        with pytest.raises(HTTPException) as exc:
            svc.get_scan_progress(tenant_id=1, project_id=2, run_id=3)
        assert exc.value.status_code == 404

    def test_returns_enriched_progress(self):
        db = MagicMock()
        scan_run = SimpleNamespace(
            id=3,
            project_id=2,
            profile_id=1,
            tenant_id=1,
            status=ScanRunStatus.RUNNING,
            triggered_by="api",
            started_at=None,
            completed_at=None,
            stats=None,
            error_message=None,
            celery_task_id="task",
            created_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
            duration_seconds=None,
        )
        phase1 = SimpleNamespace(
            id=10,
            scan_run_id=3,
            phase="discovery",
            status=_enum("completed"),
            started_at=None,
            completed_at=None,
            stats={"found": 5},
            error_message=None,
            duration_seconds=60,
        )

        # First .first() call returns scan_run;
        # .all() call returns phases
        mock_scan_query = MagicMock()
        mock_scan_query.filter.return_value.first.return_value = scan_run

        mock_phase_query = MagicMock()
        mock_phase_query.filter.return_value.order_by.return_value.all.return_value = [phase1]

        # Return scan_run query first, then phases query
        db.query.side_effect = [mock_scan_query, mock_phase_query]

        svc = ScanRunService(db)
        out = svc.get_scan_progress(tenant_id=1, project_id=2, run_id=3)

        assert out["scan_run"]["id"] == 3
        assert out["scan_run"]["status"] == "running"
        assert len(out["phases"]) == 1
        assert out["phases"][0]["phase"] == "discovery"


class TestTriggerScanInvalidProfile:
    def test_invalid_profile_id_raises_400(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None  # No profile
        svc = ScanRunService(db)

        project = SimpleNamespace(id=10)
        with pytest.raises(HTTPException) as exc:
            svc.trigger_scan(
                tenant_id=1,
                project=project,
                profile_id=999,
                scan_tier=1,
                triggered_by="manual",
            )
        assert exc.value.status_code == 400
        assert "not found" in exc.value.detail.lower()
