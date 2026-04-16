"""
Report Schedule API Endpoint Tests

Tests for /api/v1/tenants/{tenant_id}/report-schedules CRUD:
- GET    list
- POST   create
- PATCH  partial update
- DELETE soft delete

Covers app/api/routers/report_schedules.py
"""

from __future__ import annotations

import json

import pytest

from app.models.report_schedule import ReportSchedule


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def schedule(db_session, test_tenant):
    """A single active schedule for the test tenant."""
    s = ReportSchedule(
        tenant_id=test_tenant.id,
        name="Weekly Exec",
        report_type="executive",
        format="pdf",
        schedule="weekly",
        recipients=json.dumps(["ciso@example.com"]),
        is_active=True,
    )
    db_session.add(s)
    db_session.commit()
    db_session.refresh(s)
    return s


@pytest.fixture
def inactive_schedule(db_session, test_tenant):
    s = ReportSchedule(
        tenant_id=test_tenant.id,
        name="Old Report",
        report_type="technical",
        format="docx",
        schedule="monthly",
        recipients=json.dumps(["ops@example.com"]),
        is_active=False,
    )
    db_session.add(s)
    db_session.commit()
    db_session.refresh(s)
    return s


@pytest.fixture
def other_tenant_schedule(db_session, other_tenant):
    s = ReportSchedule(
        tenant_id=other_tenant.id,
        name="Other Tenant Schedule",
        report_type="executive",
        format="pdf",
        schedule="daily",
        recipients=json.dumps(["x@example.com"]),
        is_active=True,
    )
    db_session.add(s)
    db_session.commit()
    db_session.refresh(s)
    return s


# ---------------------------------------------------------------------------
# List endpoint
# ---------------------------------------------------------------------------


class TestListReportSchedules:
    def test_list_empty(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/report-schedules")
        assert response.status_code == 200
        assert response.json() == []

    def test_list_returns_schedules(self, authenticated_client, test_tenant, schedule, inactive_schedule):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/report-schedules")
        assert response.status_code == 200
        data = response.json()
        assert len(data) == 2
        ids = {item["id"] for item in data}
        assert schedule.id in ids
        assert inactive_schedule.id in ids
        # Recipients decoded from JSON string
        for item in data:
            assert isinstance(item["recipients"], list)

    @pytest.mark.security
    def test_list_tenant_isolation(
        self,
        authenticated_client,
        test_tenant,
        schedule,
        other_tenant_schedule,
    ):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/report-schedules")
        assert response.status_code == 200
        ids = {item["id"] for item in response.json()}
        assert other_tenant_schedule.id not in ids
        assert schedule.id in ids

    def test_list_unauthenticated(self, client, test_tenant):
        response = client.get(f"/api/v1/tenants/{test_tenant.id}/report-schedules")
        assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Create endpoint
# ---------------------------------------------------------------------------


class TestCreateReportSchedule:
    def test_create_success(self, authenticated_client, test_tenant):
        body = {
            "name": "Daily Exec",
            "report_type": "executive",
            "format": "pdf",
            "schedule": "daily",
            "recipients": ["ciso@example.com", "sec@example.com"],
        }
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules",
            json=body,
        )
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == "Daily Exec"
        assert data["is_active"] is True
        assert data["recipients"] == body["recipients"]
        assert data["tenant_id"] == test_tenant.id

    def test_create_invalid_report_type(self, authenticated_client, test_tenant):
        body = {
            "name": "X",
            "report_type": "banana",
            "format": "pdf",
            "schedule": "weekly",
            "recipients": ["a@b.com"],
        }
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules",
            json=body,
        )
        assert response.status_code == 422

    def test_create_invalid_format(self, authenticated_client, test_tenant):
        body = {
            "name": "X",
            "report_type": "executive",
            "format": "txt",
            "schedule": "weekly",
            "recipients": ["a@b.com"],
        }
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules",
            json=body,
        )
        assert response.status_code == 422

    def test_create_invalid_schedule_cadence(self, authenticated_client, test_tenant):
        body = {
            "name": "X",
            "report_type": "executive",
            "format": "pdf",
            "schedule": "whenever",
            "recipients": ["a@b.com"],
        }
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules",
            json=body,
        )
        assert response.status_code == 422

    def test_create_empty_recipients_returns_422(self, authenticated_client, test_tenant):
        body = {
            "name": "X",
            "report_type": "executive",
            "format": "pdf",
            "schedule": "weekly",
            "recipients": [],
        }
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules",
            json=body,
        )
        assert response.status_code == 422

    def test_create_invalid_email(self, authenticated_client, test_tenant):
        body = {
            "name": "X",
            "report_type": "executive",
            "format": "pdf",
            "schedule": "weekly",
            "recipients": ["not-an-email"],
        }
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules",
            json=body,
        )
        assert response.status_code == 422

    def test_create_persists_to_db(self, authenticated_client, test_tenant, db_session):
        body = {
            "name": "Persist me",
            "report_type": "technical",
            "format": "docx",
            "schedule": "monthly",
            "recipients": ["persist@example.com"],
        }
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules",
            json=body,
        )
        assert response.status_code == 201
        schedule_id = response.json()["id"]
        row = db_session.query(ReportSchedule).filter(ReportSchedule.id == schedule_id).first()
        assert row is not None
        assert row.name == "Persist me"


# ---------------------------------------------------------------------------
# Update endpoint
# ---------------------------------------------------------------------------


class TestUpdateReportSchedule:
    def test_update_name_and_schedule(self, authenticated_client, test_tenant, schedule):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules/{schedule.id}",
            json={"name": "Renamed", "schedule": "monthly"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Renamed"
        assert data["schedule"] == "monthly"

    def test_update_recipients(self, authenticated_client, test_tenant, schedule):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules/{schedule.id}",
            json={"recipients": ["new@example.com"]},
        )
        assert response.status_code == 200
        assert response.json()["recipients"] == ["new@example.com"]

    def test_update_is_active_toggle(self, authenticated_client, test_tenant, schedule):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules/{schedule.id}",
            json={"is_active": False},
        )
        assert response.status_code == 200
        assert response.json()["is_active"] is False

    def test_update_invalid_schedule_returns_422(self, authenticated_client, test_tenant, schedule):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules/{schedule.id}",
            json={"schedule": "whenever"},
        )
        assert response.status_code == 422

    def test_update_nonexistent_returns_404(self, authenticated_client, test_tenant):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules/999999",
            json={"name": "x"},
        )
        assert response.status_code == 404

    @pytest.mark.security
    def test_update_tenant_isolation(self, authenticated_client, test_tenant, other_tenant_schedule):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules/{other_tenant_schedule.id}",
            json={"name": "hijacked"},
        )
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Delete endpoint (soft delete)
# ---------------------------------------------------------------------------


class TestDeleteReportSchedule:
    def test_delete_soft_sets_inactive(self, authenticated_client, test_tenant, schedule, db_session):
        response = authenticated_client.delete(f"/api/v1/tenants/{test_tenant.id}/report-schedules/{schedule.id}")
        assert response.status_code == 204
        # Row still exists, but inactive
        db_session.expire_all()
        db_session.refresh(schedule)
        assert schedule.is_active is False

    def test_delete_unknown_returns_404(self, authenticated_client, test_tenant):
        response = authenticated_client.delete(f"/api/v1/tenants/{test_tenant.id}/report-schedules/999999")
        assert response.status_code == 404

    @pytest.mark.security
    def test_delete_tenant_isolation(self, authenticated_client, test_tenant, other_tenant_schedule):
        response = authenticated_client.delete(
            f"/api/v1/tenants/{test_tenant.id}/report-schedules/{other_tenant_schedule.id}"
        )
        assert response.status_code == 404
