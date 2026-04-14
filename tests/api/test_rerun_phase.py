"""
Tests for POST /scan/runs/{id}/phases/{phase}/rerun endpoint.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest

from app.models import Tenant
from app.models.scanning import ScanRun


class TestRerunPhase:
    """Test phase rerun API endpoint."""

    def test_rerun_queues_task(self, authenticated_client, test_tenant, db_session):
        """Rerun returns 200 with task_id."""
        scan_run = ScanRun(tenant_id=test_tenant.id, project_id=None, status="completed")
        db_session.add(scan_run)
        db_session.commit()
        db_session.refresh(scan_run)

        with patch("app.tasks.pipeline.run_single_phase") as mock_task:
            mock_result = MagicMock()
            mock_result.id = "fake-task-id"
            mock_task.delay.return_value = mock_result

            response = authenticated_client.post(
                f"/api/v1/tenants/{test_tenant.id}/scan/runs/{scan_run.id}/phases/9/rerun"
            )

        assert response.status_code == 200
        data = response.json()
        assert data["task_id"] == "fake-task-id"
        assert data["status"] == "queued"
        assert data["data"]["phase_id"] == "9"

    def test_rerun_scan_not_found_returns_404(self, authenticated_client, test_tenant):
        """Non-existent scan_run returns 404."""
        response = authenticated_client.post(f"/api/v1/tenants/{test_tenant.id}/scan/runs/99999/phases/9/rerun")
        assert response.status_code == 404

    def test_rerun_wrong_tenant_returns_404(self, authenticated_client, test_tenant, db_session):
        """Scan run belonging to a different tenant returns 404."""
        # Create a real second tenant to avoid FK violation
        other_tenant = Tenant(name="Other Rerun", slug="other-rerun", contact_policy="x@test.com")
        db_session.add(other_tenant)
        db_session.commit()
        db_session.refresh(other_tenant)

        scan_run = ScanRun(tenant_id=other_tenant.id, project_id=None, status="completed")
        db_session.add(scan_run)
        db_session.commit()
        db_session.refresh(scan_run)

        response = authenticated_client.post(f"/api/v1/tenants/{test_tenant.id}/scan/runs/{scan_run.id}/phases/9/rerun")
        assert response.status_code == 404
