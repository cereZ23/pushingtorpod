"""
Reports API Endpoint Tests

Tests for /api/v1/tenants/{tenant_id}/reports:
- GET /executive
- GET /technical
- GET /export/pdf   (mocked)
- GET /export/docx  (mocked)
- GET /export/json
- GET /export/csv
- GET /export/assets-csv

Covers app/api/routers/reports.py
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
)
from app.models.risk import RiskScore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def report_dataset(db_session, test_tenant):
    """Seed the tenant with diverse findings and a risk score history."""
    assets = [
        Asset(
            tenant_id=test_tenant.id,
            identifier="www.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=60.0,
            is_active=True,
        ),
        Asset(
            tenant_id=test_tenant.id,
            identifier="api.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=90.0,
            is_active=True,
        ),
        Asset(
            tenant_id=test_tenant.id,
            identifier="1.2.3.4",
            type=AssetType.IP,
            risk_score=40.0,
            is_active=True,
        ),
    ]
    db_session.add_all(assets)
    db_session.commit()
    for a in assets:
        db_session.refresh(a)

    now = datetime.now(timezone.utc)
    findings = [
        Finding(
            asset_id=assets[1].id,
            source="nuclei",
            template_id="CVE-2024-CRIT",
            name="Critical RCE",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cve_id="CVE-2024-CRIT",
            status=FindingStatus.OPEN,
            first_seen=now - timedelta(days=5),
            last_seen=now,
            evidence={"proof": "x"},
        ),
        Finding(
            asset_id=assets[0].id,
            source="nuclei",
            template_id="http-missing-security-headers:strict-transport-security",
            name="Missing HSTS",
            severity=FindingSeverity.MEDIUM,
            cvss_score=5.3,
            status=FindingStatus.OPEN,
            first_seen=now - timedelta(days=2),
            last_seen=now,
            evidence={"header": "missing"},
        ),
        Finding(
            asset_id=assets[0].id,
            source="nuclei",
            template_id="exposed-panels/admin-panel",
            name="Exposed Admin Panel",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            status=FindingStatus.SUPPRESSED,
            first_seen=now - timedelta(days=10),
            last_seen=now - timedelta(days=1),
            evidence={"url": "/admin"},
        ),
        Finding(
            asset_id=assets[2].id,
            source="nuclei",
            template_id="low-1",
            name="Low finding",
            severity=FindingSeverity.LOW,
            cvss_score=3.0,
            status=FindingStatus.FIXED,
            first_seen=now - timedelta(days=20),
            last_seen=now - timedelta(days=15),
            evidence=None,
        ),
    ]
    db_session.add_all(findings)
    db_session.commit()

    # Risk score trend
    for i in range(3):
        rs = RiskScore(
            tenant_id=test_tenant.id,
            scope_type="organization",
            score=50.0 + i * 5,
            grade="C",
            scored_at=now - timedelta(days=10 - i * 2),
        )
        db_session.add(rs)
    db_session.commit()

    return {"assets": assets, "findings": findings}


# ---------------------------------------------------------------------------
# Executive report
# ---------------------------------------------------------------------------


class TestExecutiveReport:
    def test_executive_empty_tenant(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/executive")
        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == test_tenant.id
        assert data["total_assets"] == 0
        assert data["total_findings"] == 0
        assert data["risk_score"] == 0.0
        assert data["risk_grade"] == "N/A"
        assert data["top_issues"] == []
        assert isinstance(data["recommendations"], list)
        # Recommendation to enable continuous monitoring always included
        assert any("monitoring" in r["title"].lower() for r in data["recommendations"])

    def test_executive_with_data(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/executive")
        assert response.status_code == 200
        data = response.json()
        assert data["total_assets"] >= 3
        assert data["total_findings"] >= 4
        assert data["open_findings"] >= 2
        # Severity breakdown reflects the seeded findings
        assert data["finding_counts_by_severity"]["critical"] >= 1
        assert data["finding_counts_by_severity"]["medium"] >= 1
        # Top issues include at least the critical finding
        top_names = [t["name"] for t in data["top_issues"]]
        assert "Critical RCE" in top_names
        # Recommendations include specific remediation advice
        titles = [r["title"] for r in data["recommendations"]]
        assert any("critical" in t.lower() for t in titles)

    def test_executive_score_trend(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/executive")
        data = response.json()
        assert len(data["score_trend"]) >= 1
        # Risk score should take the latest value
        assert data["risk_score"] > 0


# ---------------------------------------------------------------------------
# Technical report
# ---------------------------------------------------------------------------


class TestTechnicalReport:
    def test_technical_returns_findings(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/technical")
        assert response.status_code == 200
        data = response.json()
        assert data["tenant_id"] == test_tenant.id
        assert data["total_findings"] >= 4
        assert isinstance(data["findings"], list)
        first = data["findings"][0]
        for key in ("id", "name", "severity", "status", "asset_identifier", "asset_type"):
            assert key in first

    def test_technical_filter_severity(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/technical",
            params={"severity": "critical"},
        )
        assert response.status_code == 200
        data = response.json()
        for item in data["findings"]:
            assert item["severity"] == "critical"

    def test_technical_invalid_severity_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/technical",
            params={"severity": "ultra"},
        )
        assert response.status_code == 400

    def test_technical_filter_status(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/technical",
            params={"status": "open"},
        )
        assert response.status_code == 200
        for item in response.json()["findings"]:
            assert item["status"] == "open"

    def test_technical_invalid_status_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/technical",
            params={"status": "dreaming"},
        )
        assert response.status_code == 400

    def test_technical_limit_query(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/technical",
            params={"limit": 2},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["findings"]) <= 2

    def test_technical_remediation_populated_for_known_templates(
        self, authenticated_client, test_tenant, report_dataset
    ):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/technical")
        data = response.json()
        # The HSTS finding should get specific remediation guidance
        for f in data["findings"]:
            if f["template_id"] and f["template_id"].startswith("http-missing-security-headers"):
                assert f["remediation"] is not None
                break
        else:
            pytest.fail("Expected HSTS finding not found")


# ---------------------------------------------------------------------------
# JSON / CSV exports
# ---------------------------------------------------------------------------


class TestExportJson:
    def test_export_json_returns_stream(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/json")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        # Content-Disposition filename
        assert "attachment" in response.headers.get("content-disposition", "")
        payload = json.loads(response.content)
        assert payload["tenant_id"] == test_tenant.id
        assert payload["total"] >= 4

    def test_export_json_severity_filter(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/json",
            params={"severity": "medium"},
        )
        assert response.status_code == 200
        payload = json.loads(response.content)
        for f in payload["findings"]:
            assert f["severity"] == "medium"

    def test_export_json_invalid_severity_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/json",
            params={"severity": "oops"},
        )
        assert response.status_code == 400

    def test_export_json_invalid_status_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/json",
            params={"status": "oops"},
        )
        assert response.status_code == 400


class TestExportCsv:
    def test_export_csv_returns_stream(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/csv")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        reader = csv.reader(io.StringIO(response.content.decode("utf-8")))
        rows = list(reader)
        # Header + at least 4 findings
        assert len(rows) >= 5
        # Header columns
        assert "id" in rows[0]
        assert "severity" in rows[0]

    def test_export_csv_severity_filter(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/csv",
            params={"severity": "critical"},
        )
        assert response.status_code == 200
        rows = list(csv.reader(io.StringIO(response.content.decode("utf-8"))))
        # Header + 1 critical row (or more)
        severity_col = rows[0].index("severity")
        for row in rows[1:]:
            assert row[severity_col] == "critical"

    def test_export_csv_invalid_filter_returns_400(self, authenticated_client, test_tenant):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/csv",
            params={"severity": "junk"},
        )
        assert response.status_code == 400


class TestExportAssetsCsv:
    def test_export_assets_csv(self, authenticated_client, test_tenant, report_dataset):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/assets-csv")
        assert response.status_code == 200
        rows = list(csv.reader(io.StringIO(response.content.decode("utf-8"))))
        assert rows[0][0] == "id"
        assert len(rows) >= 4  # header + 3 assets

    def test_export_assets_csv_empty(self, authenticated_client, test_tenant):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/assets-csv")
        assert response.status_code == 200
        rows = list(csv.reader(io.StringIO(response.content.decode("utf-8"))))
        # Only header row
        assert len(rows) == 1


# ---------------------------------------------------------------------------
# PDF / DOCX exports (ReportGenerator mocked)
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_report_generator():
    """Mock ReportGenerator class used by the PDF/DOCX endpoints."""
    with patch("app.services.report_generator.ReportGenerator") as gen_cls:
        instance = gen_cls.return_value
        instance.generate_pdf.return_value = b"%PDF-1.4 fake pdf bytes"
        instance.generate_docx.return_value = b"PK\x03\x04 fake docx bytes"
        yield instance


class TestExportPdf:
    def test_export_pdf_default_executive(
        self,
        authenticated_client,
        test_tenant,
        mock_report_generator,
    ):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/pdf")
        assert response.status_code == 200
        assert response.headers["content-type"] == "application/pdf"
        assert "attachment" in response.headers.get("content-disposition", "")
        assert response.content.startswith(b"%PDF")
        mock_report_generator.generate_pdf.assert_called_once()

    def test_export_pdf_technical_type(
        self,
        authenticated_client,
        test_tenant,
        mock_report_generator,
    ):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/pdf",
            params={"report_type": "technical", "severity": "critical", "limit": 100},
        )
        assert response.status_code == 200
        kwargs = mock_report_generator.generate_pdf.call_args.kwargs
        assert kwargs["report_type"] == "technical"
        assert kwargs["severity"] == "critical"
        assert kwargs["limit"] == 100

    def test_export_pdf_invalid_report_type(self, authenticated_client, test_tenant, mock_report_generator):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/pdf",
            params={"report_type": "oops"},
        )
        assert response.status_code == 422

    def test_export_pdf_handles_generator_failure(self, authenticated_client, test_tenant):
        with patch("app.services.report_generator.ReportGenerator") as gen_cls:
            gen_cls.return_value.generate_pdf.side_effect = RuntimeError("boom")
            response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/pdf")
            assert response.status_code == 500
            assert "boom" in response.json()["detail"]


class TestExportDocx:
    def test_export_docx_default(
        self,
        authenticated_client,
        test_tenant,
        mock_report_generator,
    ):
        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/docx")
        assert response.status_code == 200
        # Word uses a specific OOXML MIME type
        assert "wordprocessingml" in response.headers["content-type"]
        mock_report_generator.generate_docx.assert_called_once()

    def test_export_docx_invalid_report_type(self, authenticated_client, test_tenant, mock_report_generator):
        response = authenticated_client.get(
            f"/api/v1/tenants/{test_tenant.id}/reports/export/docx",
            params={"report_type": "oops"},
        )
        assert response.status_code == 422

    def test_export_docx_handles_generator_failure(self, authenticated_client, test_tenant):
        with patch("app.services.report_generator.ReportGenerator") as gen_cls:
            gen_cls.return_value.generate_docx.side_effect = RuntimeError("pow")
            response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/docx")
            assert response.status_code == 500


# ---------------------------------------------------------------------------
# Auth / isolation for report endpoints
# ---------------------------------------------------------------------------


class TestReportsAuth:
    def test_executive_unauthenticated(self, client, test_tenant):
        response = client.get(f"/api/v1/tenants/{test_tenant.id}/reports/executive")
        assert response.status_code in (401, 403)

    def test_export_json_unauthenticated(self, client, test_tenant):
        response = client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/json")
        assert response.status_code in (401, 403)

    @pytest.mark.security
    def test_export_csv_tenant_isolation(
        self,
        authenticated_client,
        test_tenant,
        other_tenant,
        db_session,
    ):
        """Findings from other_tenant must not appear in our CSV export."""
        asset = Asset(
            tenant_id=other_tenant.id,
            identifier="other-report.example.com",
            type=AssetType.SUBDOMAIN,
            risk_score=70.0,
            is_active=True,
        )
        db_session.add(asset)
        db_session.commit()
        db_session.refresh(asset)

        f = Finding(
            asset_id=asset.id,
            source="nuclei",
            template_id="OTHER",
            name="OTHER-TENANT-FINDING-REPORT",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.0,
            status=FindingStatus.OPEN,
            evidence={},
        )
        db_session.add(f)
        db_session.commit()

        response = authenticated_client.get(f"/api/v1/tenants/{test_tenant.id}/reports/export/csv")
        assert response.status_code == 200
        body = response.content.decode("utf-8")
        assert "OTHER-TENANT-FINDING-REPORT" not in body
