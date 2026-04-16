"""
Issue Lifecycle API Endpoint Tests

Tests for /api/v1/tenants/{tenant_id}/issues and nested endpoints:
- List/filter/search/sort
- Get issue detail (with findings, activity, comments)
- Update (status transitions, severity, assignment)
- Comments
- Activity timeline
- Assign endpoint

Covers app/api/routers/issues.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus
from app.models.issues import Issue, IssueActivity, IssueFinding, IssueStatus


# ---------------------------------------------------------------------------
# Fixtures (local to this module)
# ---------------------------------------------------------------------------


@pytest.fixture
def tenant_asset(db_session, test_tenant):
    """A single asset owned by test_tenant, used to anchor findings."""
    asset = Asset(
        tenant_id=test_tenant.id,
        identifier="issue-asset.example.com",
        type=AssetType.SUBDOMAIN,
        risk_score=40.0,
        is_active=True,
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)
    return asset


@pytest.fixture
def open_issue(db_session, test_tenant):
    """A single open Issue for the test tenant."""
    issue = Issue(
        tenant_id=test_tenant.id,
        title="Missing HSTS across web assets",
        description="Multiple web assets lack HSTS headers.",
        root_cause="missing-hsts",
        severity="medium",
        status=IssueStatus.OPEN,
        affected_assets_count=3,
        finding_count=3,
        risk_score=45.0,
    )
    db_session.add(issue)
    db_session.commit()
    db_session.refresh(issue)
    return issue


@pytest.fixture
def triaged_issue(db_session, test_tenant):
    """A triaged Issue with higher severity."""
    issue = Issue(
        tenant_id=test_tenant.id,
        title="Exposed admin panels",
        description="Login panels reachable from the internet.",
        root_cause="exposed-admin",
        severity="high",
        status=IssueStatus.TRIAGED,
        affected_assets_count=2,
        finding_count=2,
        risk_score=70.0,
    )
    db_session.add(issue)
    db_session.commit()
    db_session.refresh(issue)
    return issue


@pytest.fixture
def mixed_issues(db_session, test_tenant):
    """Several issues with varied severities and statuses for filter tests."""
    issues = [
        Issue(
            tenant_id=test_tenant.id,
            title=f"Issue-{i}",
            description=f"desc-{i}",
            root_cause=f"root-{i}",
            severity=sev,
            status=st,
            affected_assets_count=i,
            finding_count=i,
            risk_score=float(10 * (i + 1)),
        )
        for i, (sev, st) in enumerate(
            [
                ("critical", IssueStatus.OPEN),
                ("high", IssueStatus.OPEN),
                ("medium", IssueStatus.TRIAGED),
                ("low", IssueStatus.CLOSED),
            ]
        )
    ]
    db_session.add_all(issues)
    db_session.commit()
    for i in issues:
        db_session.refresh(i)
    return issues


@pytest.fixture
def other_tenant_issue(db_session, other_tenant):
    """An issue belonging to other_tenant for isolation testing."""
    issue = Issue(
        tenant_id=other_tenant.id,
        title="Other-tenant issue",
        description="not visible",
        severity="high",
        status=IssueStatus.OPEN,
    )
    db_session.add(issue)
    db_session.commit()
    db_session.refresh(issue)
    return issue


@pytest.fixture
def issue_with_finding(db_session, test_tenant, tenant_asset, open_issue):
    """An issue with a linked open finding to exercise the cascade/detail path."""
    finding = Finding(
        asset_id=tenant_asset.id,
        source="nuclei",
        template_id="http-missing-security-headers",
        name="Missing HSTS Header",
        severity=FindingSeverity.MEDIUM,
        cvss_score=5.3,
        status=FindingStatus.OPEN,
        evidence={"header": "missing"},
    )
    db_session.add(finding)
    db_session.commit()
    db_session.refresh(finding)

    link = IssueFinding(issue_id=open_issue.id, finding_id=finding.id)
    db_session.add(link)
    db_session.commit()

    return open_issue, finding


# ---------------------------------------------------------------------------
# List endpoint
# ---------------------------------------------------------------------------


class TestListIssues:
    def test_list_returns_envelope(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues")
        assert response.status_code == 200
        body = response.json()
        assert "data" in body
        assert "meta" in body
        assert body["meta"]["total"] >= 1
        assert isinstance(body["data"], list)
        ids = [i["id"] for i in body["data"]]
        assert open_issue.id in ids

    def test_list_filter_by_severity(self, authenticated_client, test_tenant, mixed_issues):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues", params={"severity": "critical"})
        assert response.status_code == 200
        body = response.json()
        assert all(item["severity"] == "critical" for item in body["data"])
        assert body["meta"]["total"] >= 1

    def test_list_invalid_severity_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/issues", params={"severity": "ultra-critical"}
        )
        assert response.status_code == 400
        assert "Invalid severity" in response.json()["detail"]

    def test_list_filter_by_status(self, authenticated_client, test_tenant, mixed_issues):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues", params={"status": "triaged"})
        assert response.status_code == 200
        body = response.json()
        assert all(item["status"] == "triaged" for item in body["data"])

    def test_list_invalid_status_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/issues", params={"status": "pending-review"}
        )
        assert response.status_code == 400
        assert "Invalid status" in response.json()["detail"]

    def test_list_search_matches_title(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues", params={"search": "HSTS"})
        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] >= 1
        assert any("HSTS" in i["title"] for i in body["data"])

    def test_list_search_matches_root_cause(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/issues", params={"search": "missing-hsts"}
        )
        assert response.status_code == 200
        body = response.json()
        assert body["meta"]["total"] >= 1

    def test_list_sort_by_severity_asc(self, authenticated_client, test_tenant, mixed_issues):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/issues",
            params={"sort_by": "severity", "order": "asc"},
        )
        assert response.status_code == 200
        body = response.json()
        assert len(body["data"]) >= 2

    def test_list_invalid_order_returns_422(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues", params={"order": "sideways"})
        # Regex validation happens at FastAPI level (422)
        assert response.status_code == 422

    def test_list_pagination(self, authenticated_client, test_tenant, mixed_issues):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/issues",
            params={"page": 1, "page_size": 2},
        )
        assert response.status_code == 200
        body = response.json()
        assert len(body["data"]) <= 2
        assert body["meta"]["page_size"] == 2
        assert body["meta"]["total"] >= 3

    def test_list_requires_authentication(self, client, test_tenant, open_issue):
        """Without JWT, the endpoint must reject (401/403)."""
        response = client.get(f"/api/v1/tenants/{test_tenant.id}/issues")
        assert response.status_code in (401, 403)

    @pytest.mark.security
    def test_list_enforces_tenant_isolation(self, authenticated_client, test_tenant, other_tenant, other_tenant_issue):
        """Listing test_tenant's issues must not include other_tenant issues."""
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues")
        assert response.status_code == 200
        body = response.json()
        ids = {i["id"] for i in body["data"]}
        assert other_tenant_issue.id not in ids


# ---------------------------------------------------------------------------
# Get issue detail
# ---------------------------------------------------------------------------


class TestGetIssueDetail:
    def test_get_detail_returns_full_structure(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == open_issue.id
        assert data["title"] == open_issue.title
        # Detail fields
        assert "findings" in data
        assert "activity" in data
        assert "comments" in data
        assert isinstance(data["findings"], list)
        assert isinstance(data["activity"], list)
        assert isinstance(data["comments"], list)

    def test_get_detail_includes_linked_findings(
        self, authenticated_client, test_tenant, issue_with_finding, tenant_asset
    ):
        issue, finding = issue_with_finding
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues/{issue.id}")
        assert response.status_code == 200
        data = response.json()
        assert len(data["findings"]) >= 1
        found = data["findings"][0]
        assert found["id"] == finding.id
        # asset identifier should have been joined in
        assert found.get("asset_identifier") == tenant_asset.identifier

    def test_get_detail_nonexistent_returns_404(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues/9999999")
        assert response.status_code == 404

    @pytest.mark.security
    def test_get_detail_tenant_isolation(self, authenticated_client, test_tenant, other_tenant_issue):
        """Cannot read another tenant's issue via our tenant path."""
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues/{other_tenant_issue.id}")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Update / transitions
# ---------------------------------------------------------------------------


class TestUpdateIssue:
    def test_valid_status_transition_open_to_triaged(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"status": "triaged"},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "triaged"

    def test_invalid_transition_returns_409(self, authenticated_client, test_tenant, open_issue):
        """open -> closed is not an allowed direct transition."""
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"status": "closed"},
        )
        assert response.status_code == 409

    def test_false_positive_requires_comment(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"status": "false_positive"},
        )
        assert response.status_code == 422

    def test_false_positive_with_comment_succeeds(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={
                "status": "false_positive",
                "comment": "Confirmed benign configuration.",
            },
        )
        assert response.status_code == 200
        assert response.json()["status"] == "false_positive"

    def test_accepted_risk_requires_comment(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"status": "accepted_risk"},
        )
        assert response.status_code == 422

    def test_invalid_status_value_returns_400(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"status": "parking_lot"},
        )
        assert response.status_code == 400

    def test_update_severity_recalculates_sla(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"severity": "critical"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["severity"] == "critical"
        # SLA window for critical is 48h - must have been populated
        assert data["sla_due_at"] is not None

    def test_invalid_severity_returns_400(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"severity": "hyper"},
        )
        assert response.status_code == 400

    def test_update_title_and_description(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"title": "New Title", "description": "Updated"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["title"] == "New Title"
        assert data["description"] == "Updated"

    def test_update_assign_records_activity(self, authenticated_client, test_tenant, open_issue, test_user, db_session):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"assigned_to": test_user.id},
        )
        assert response.status_code == 200
        assert response.json()["assigned_to"] == test_user.id
        acts = (
            db_session.query(IssueActivity)
            .filter(IssueActivity.issue_id == open_issue.id, IssueActivity.action == "assign")
            .all()
        )
        assert len(acts) >= 1

    def test_update_nonexistent_issue_returns_404(self, authenticated_client, test_tenant):
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/9999999",
            json={"title": "x"},
        )
        assert response.status_code == 404

    def test_cascade_false_positive_suppresses_findings(
        self, authenticated_client, test_tenant, issue_with_finding, db_session
    ):
        issue, finding = issue_with_finding
        response = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{issue.id}",
            json={"status": "false_positive", "comment": "FP"},
        )
        assert response.status_code == 200
        db_session.expire_all()
        db_session.refresh(finding)
        assert finding.status == FindingStatus.SUPPRESSED


# ---------------------------------------------------------------------------
# Comments
# ---------------------------------------------------------------------------


class TestIssueComments:
    def test_add_comment(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/comments",
            json={"comment": "Looking into this now."},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["content"] == "Looking into this now."
        assert data["issue_id"] == open_issue.id

    def test_add_comment_via_content_field(self, authenticated_client, test_tenant, open_issue):
        """The endpoint accepts both 'comment' and 'content'."""
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/comments",
            json={"content": "Via content field."},
        )
        assert response.status_code == 200
        assert response.json()["content"] == "Via content field."

    def test_add_empty_comment_returns_422(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/comments",
            json={},
        )
        # Pydantic rejects both fields None
        assert response.status_code == 422

    def test_add_comment_nonexistent_issue_returns_404(self, authenticated_client, test_tenant):
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/9999999/comments",
            json={"comment": "hi"},
        )
        assert response.status_code == 404

    def test_singular_comment_path_works(self, authenticated_client, test_tenant, open_issue):
        """The router registers both /comment and /comments."""
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/comment",
            json={"comment": "singular path"},
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Activities timeline
# ---------------------------------------------------------------------------


class TestListActivities:
    def test_empty_activities(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/activities")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] == 0
        assert body["items"] == []

    def test_activities_reflect_status_change(self, authenticated_client, test_tenant, open_issue):
        # First, perform a status change to generate an activity
        patch_resp = authenticated_client.patch(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}",
            json={"status": "triaged"},
        )
        assert patch_resp.status_code == 200

        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/activities")
        assert response.status_code == 200
        body = response.json()
        assert body["total"] >= 1
        actions = {item["action"] for item in body["items"]}
        assert "status_change" in actions

    def test_activities_404_for_unknown_issue(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/issues/9999999/activities")
        assert response.status_code == 404


# ---------------------------------------------------------------------------
# Assign endpoint
# ---------------------------------------------------------------------------


class TestAssignIssue:
    def test_assign_issue(self, authenticated_client, test_tenant, open_issue, test_user):
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/assign",
            json={"assigned_to": test_user.id, "comment": "Please handle"},
        )
        assert response.status_code == 200
        assert response.json()["assigned_to"] == test_user.id

    def test_assign_nonexistent_issue_returns_404(self, authenticated_client, test_tenant, test_user):
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/9999999/assign",
            json={"assigned_to": test_user.id},
        )
        assert response.status_code == 404

    def test_assign_missing_field_returns_422(self, authenticated_client, test_tenant, open_issue):
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/{open_issue.id}/assign",
            json={},
        )
        assert response.status_code == 422

    @pytest.mark.security
    def test_assign_tenant_isolation(self, authenticated_client, test_tenant, other_tenant_issue, test_user):
        response = authenticated_client.post(
            f"/api/v1/tenants/{test_tenant.id}/issues/{other_tenant_issue.id}/assign",
            json={"assigned_to": test_user.id},
        )
        assert response.status_code == 404
