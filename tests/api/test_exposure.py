"""
Exposure Management API Endpoint Tests

Tests for /api/v1/tenants/{tenant_id}/exposure endpoints:
- GET /summary
- GET /assets (with filters, pagination)
- GET /changes

Covers app/api/routers/exposure.py
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
    Service,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def exposure_assets(db_session, test_tenant):
    """Create a set of assets with varied types and risk scores."""
    assets = [
        Asset(
            tenant_id=test_tenant.id,
            identifier=f"exposure{i}.example.com",
            type=AssetType.SUBDOMAIN if i < 3 else AssetType.DOMAIN,
            risk_score=20.0 + i * 15,
            is_active=True,
        )
        for i in range(5)
    ]
    db_session.add_all(assets)
    db_session.commit()
    for a in assets:
        db_session.refresh(a)
    return assets


@pytest.fixture
def exposed_with_findings(db_session, test_tenant, exposure_assets):
    """Attach open findings of different severities to the first 3 assets."""
    severities = [FindingSeverity.CRITICAL, FindingSeverity.HIGH, FindingSeverity.MEDIUM]
    findings = []
    for asset, sev in zip(exposure_assets[:3], severities):
        f = Finding(
            asset_id=asset.id,
            source="nuclei",
            template_id=f"TPL-{sev.value}",
            name=f"{sev.value} issue on {asset.identifier}",
            severity=sev,
            cvss_score=9.0 if sev == FindingSeverity.CRITICAL else 6.0,
            status=FindingStatus.OPEN,
            evidence={"proof": "data"},
        )
        findings.append(f)
    db_session.add_all(findings)
    db_session.commit()
    for f in findings:
        db_session.refresh(f)
    return findings


@pytest.fixture
def exposure_service(db_session, exposure_assets):
    """A service on the first exposed asset."""
    service = Service(
        asset_id=exposure_assets[0].id,
        port=443,
        protocol="https",
        product="nginx",
        version="1.21.0",
    )
    db_session.add(service)
    db_session.commit()
    db_session.refresh(service)
    return service


@pytest.fixture
def recent_and_old_findings(db_session, test_tenant):
    """A mix of recent and old findings to test the changes endpoint."""
    asset = Asset(
        tenant_id=test_tenant.id,
        identifier="change.example.com",
        type=AssetType.SUBDOMAIN,
        risk_score=50.0,
        is_active=True,
    )
    db_session.add(asset)
    db_session.commit()
    db_session.refresh(asset)

    now = datetime.now(timezone.utc)
    findings = [
        # Recent open finding (within 24h)
        Finding(
            asset_id=asset.id,
            source="nuclei",
            template_id="new-1",
            name="Fresh open finding",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            status=FindingStatus.OPEN,
            first_seen=now - timedelta(hours=1),
            last_seen=now - timedelta(hours=1),
            evidence={},
        ),
        # Recent fixed finding
        Finding(
            asset_id=asset.id,
            source="nuclei",
            template_id="fixed-1",
            name="Recently fixed",
            severity=FindingSeverity.MEDIUM,
            cvss_score=5.0,
            status=FindingStatus.FIXED,
            first_seen=now - timedelta(days=5),
            last_seen=now - timedelta(hours=2),
            evidence={},
        ),
        # Old open finding (beyond 24h)
        Finding(
            asset_id=asset.id,
            source="nuclei",
            template_id="old-1",
            name="Old finding",
            severity=FindingSeverity.LOW,
            cvss_score=3.0,
            status=FindingStatus.OPEN,
            first_seen=now - timedelta(days=60),
            last_seen=now - timedelta(days=30),
            evidence={},
        ),
    ]
    db_session.add_all(findings)
    db_session.commit()
    for f in findings:
        db_session.refresh(f)
    return asset, findings


# ---------------------------------------------------------------------------
# Summary endpoint
# ---------------------------------------------------------------------------


class TestExposureSummary:
    def test_summary_empty(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/exposure/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_exposed_assets"] == 0
        assert data["exposure_score"] == 0.0
        assert data["severity_breakdown"]["critical"] == 0
        assert isinstance(data["most_exposed"], list)

    def test_summary_with_findings(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/exposure/summary")
        assert response.status_code == 200
        data = response.json()
        assert data["total_exposed_assets"] >= 3
        assert data["severity_breakdown"]["critical"] >= 1
        assert data["severity_breakdown"]["high"] >= 1
        assert data["severity_breakdown"]["medium"] >= 1
        assert data["exposure_score"] > 0

    def test_summary_includes_most_exposed(
        self, authenticated_client, test_tenant, exposed_with_findings, exposure_service
    ):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/exposure/summary")
        data = response.json()
        assert len(data["most_exposed"]) >= 1
        top = data["most_exposed"][0]
        assert "identifier" in top
        assert "risk_score" in top
        assert "open_findings_count" in top

    def test_summary_unknown_tenant_returns_404(self, authenticated_client):
        response = authenticated_client.get("/api/v1/tenants/999999/exposure/summary")
        # Superuser check bypasses tenant access, so _verify_tenant_exists handles it.
        # Non-admin test_user receives 403 first from verify_tenant_access.
        assert response.status_code in (403, 404)

    def test_summary_requires_authentication(self, client, test_tenant):
        response = client.get(f"/api/v1/tenants/{test_tenant.id}/exposure/summary")
        assert response.status_code in (401, 403)


# ---------------------------------------------------------------------------
# Assets list endpoint
# ---------------------------------------------------------------------------


class TestExposedAssets:
    def test_list_empty(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/exposure/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 0
        assert data["items"] == []

    def test_list_with_findings(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/exposure/assets")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] >= 3
        assert len(data["items"]) >= 3
        item = data["items"][0]
        for key in ["id", "identifier", "type", "risk_score", "open_findings_count", "highest_severity"]:
            assert key in item

    def test_list_filter_by_asset_type(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"asset_type": "subdomain"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["type"] == "subdomain"

    def test_list_invalid_asset_type_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"asset_type": "satellite"},
        )
        assert response.status_code == 400

    def test_list_filter_by_min_severity(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"min_severity": "high"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["items"]:
            assert item["highest_severity"] in ("high", "critical")

    def test_list_invalid_min_severity_returns_400(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"min_severity": "nuclear"},
        )
        assert response.status_code == 400

    def test_list_search_by_identifier(self, authenticated_client, test_tenant, exposed_with_findings, exposure_assets):
        target = exposure_assets[0].identifier
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"search": "exposure0"},
        )
        assert response.status_code == 200
        data = response.json()
        assert any(target in i["identifier"] for i in data["items"])

    def test_list_pagination(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"page": 1, "page_size": 2},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["items"]) <= 2
        assert data["page_size"] == 2

    def test_list_sort_by_risk_score(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"sort_by": "risk_score", "sort_order": "asc"},
        )
        assert response.status_code == 200
        data = response.json()
        scores = [i["risk_score"] for i in data["items"]]
        assert scores == sorted(scores)

    def test_list_sort_by_findings_count(self, authenticated_client, test_tenant, exposed_with_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/assets",
            params={"sort_by": "findings_count", "sort_order": "desc"},
        )
        assert response.status_code == 200


# ---------------------------------------------------------------------------
# Changes endpoint
# ---------------------------------------------------------------------------


class TestExposureChanges:
    def test_changes_24h_default(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/exposure/changes")
        assert response.status_code == 200
        data = response.json()
        assert data["period"] == "24h"
        assert "new_exposures" in data
        assert "resolved_exposures" in data

    def test_changes_reports_new(self, authenticated_client, test_tenant, recent_and_old_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/changes",
            params={"period": "24h"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["new_count"] >= 1
        names = [i["finding_name"] for i in data["new_exposures"]]
        assert "Fresh open finding" in names

    def test_changes_reports_resolved(self, authenticated_client, test_tenant, recent_and_old_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/changes",
            params={"period": "24h"},
        )
        data = response.json()
        assert data["resolved_count"] >= 1
        names = [i["finding_name"] for i in data["resolved_exposures"]]
        assert "Recently fixed" in names

    def test_changes_7d_period(self, authenticated_client, test_tenant, recent_and_old_findings):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/changes",
            params={"period": "7d"},
        )
        assert response.status_code == 200
        assert response.json()["period"] == "7d"

    def test_changes_invalid_period_returns_422(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/changes",
            params={"period": "1y"},
        )
        assert response.status_code == 422

    @pytest.mark.security
    def test_changes_tenant_isolation(
        self,
        authenticated_client,
        test_tenant,
        other_tenant,
        db_session,
    ):
        """Findings in other tenant must never appear in our changes feed."""
        other_asset = Asset(
            tenant_id=other_tenant.id,
            identifier="other-change.example.com",
            type=AssetType.SUBDOMAIN,
            is_active=True,
        )
        db_session.add(other_asset)
        db_session.commit()
        db_session.refresh(other_asset)

        now = datetime.now(timezone.utc)
        f = Finding(
            asset_id=other_asset.id,
            source="nuclei",
            template_id="otf-1",
            name="OTHER TENANT FINDING",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.5,
            status=FindingStatus.OPEN,
            first_seen=now - timedelta(hours=1),
            last_seen=now - timedelta(hours=1),
            evidence={},
        )
        db_session.add(f)
        db_session.commit()

        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/exposure/changes",
            params={"period": "24h"},
        )
        assert response.status_code == 200
        data = response.json()
        names = [i["finding_name"] for i in data["new_exposures"]]
        assert "OTHER TENANT FINDING" not in names
