"""Tests for risk summary, trend, and attack-surface endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus
from app.models.risk import RiskScore


class TestRiskSummary:
    def test_summary_returns_structure(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/summary")
        assert response.status_code == 200
        data = response.json()
        assert "risk_score" in data
        assert "findings" in data
        assert "assets" in data
        assert "top_risks" in data
        assert "expiring_certificates" in data

    def test_summary_findings_breakdown(self, authenticated_client, test_tenant, db_session):
        asset = Asset(tenant_id=test_tenant.id, identifier="risk.test.com", type=AssetType.SUBDOMAIN, is_active=True)
        db_session.add(asset)
        db_session.commit()
        db_session.refresh(asset)

        findings = [
            Finding(asset_id=asset.id, name="crit", severity=FindingSeverity.CRITICAL, status=FindingStatus.OPEN),
            Finding(asset_id=asset.id, name="high", severity=FindingSeverity.HIGH, status=FindingStatus.OPEN),
            Finding(asset_id=asset.id, name="fixed", severity=FindingSeverity.LOW, status=FindingStatus.FIXED),
        ]
        db_session.add_all(findings)
        db_session.commit()

        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/summary")
        data = response.json()

        assert data["findings"]["critical"] >= 1
        assert data["findings"]["high"] >= 1

    def test_summary_top_risks(self, authenticated_client, test_tenant, db_session):
        assets = [
            Asset(
                tenant_id=test_tenant.id,
                identifier=f"risky{i}.test.com",
                type=AssetType.SUBDOMAIN,
                is_active=True,
                risk_score=float(90 - i * 10),
            )
            for i in range(3)
        ]
        db_session.add_all(assets)
        db_session.commit()

        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/summary")
        data = response.json()

        assert len(data["top_risks"]) >= 2
        # Should be sorted by risk_score descending
        scores = [r["risk_score"] for r in data["top_risks"]]
        assert scores == sorted(scores, reverse=True)


class TestRiskTrend:
    def test_trend_returns_structure(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/trend")
        assert response.status_code == 200
        data = response.json()
        assert "days" in data
        assert "trend" in data
        assert isinstance(data["trend"], list)

    def test_trend_with_data(self, authenticated_client, test_tenant, db_session):
        for i in range(5):
            score = RiskScore(
                tenant_id=test_tenant.id,
                scope_type="organization",
                score=50.0 + i * 5,
                grade="C",
                delta=5.0,
                scored_at=datetime.now(timezone.utc) - timedelta(days=5 - i),
            )
            db_session.add(score)
        db_session.commit()

        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/trend?days=30")
        data = response.json()

        assert data["data_points"] >= 5
        assert len(data["trend"]) >= 5

    def test_trend_respects_days_param(self, authenticated_client, test_tenant, db_session):
        # Old score outside range
        old = RiskScore(
            tenant_id=test_tenant.id,
            scope_type="organization",
            score=30.0,
            scored_at=datetime.now(timezone.utc) - timedelta(days=60),
        )
        db_session.add(old)
        db_session.commit()

        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/trend?days=30")
        data = response.json()
        assert data["data_points"] == 0


class TestAttackSurfaceGroups:
    def test_groups_returns_structure(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/attack-surface")
        assert response.status_code == 200
        data = response.json()
        assert "total_findings" in data
        assert "groups" in data
        assert "web_vulnerabilities" in data["groups"]
        assert "tls_certificates" in data["groups"]

    def test_groups_categorize_findings(self, authenticated_client, test_tenant, db_session):
        asset = Asset(tenant_id=test_tenant.id, identifier="group.test.com", type=AssetType.SUBDOMAIN, is_active=True)
        db_session.add(asset)
        db_session.commit()
        db_session.refresh(asset)

        findings = [
            Finding(
                asset_id=asset.id,
                name="CVE-2021-44228",
                template_id="CVE-2021-44228",
                severity=FindingSeverity.CRITICAL,
                status=FindingStatus.OPEN,
            ),
            Finding(
                asset_id=asset.id,
                name="Missing HSTS",
                template_id="HDR-004",
                severity=FindingSeverity.MEDIUM,
                status=FindingStatus.OPEN,
            ),
            Finding(
                asset_id=asset.id,
                name="SPF record missing",
                template_id="EML-001",
                severity=FindingSeverity.MEDIUM,
                status=FindingStatus.OPEN,
            ),
        ]
        db_session.add_all(findings)
        db_session.commit()

        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/risk/attack-surface")
        data = response.json()

        assert data["total_findings"] >= 3
        assert data["groups"]["web_vulnerabilities"]["count"] >= 1
        assert data["groups"]["dns_email"]["count"] >= 1
