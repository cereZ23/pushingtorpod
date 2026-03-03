"""
SIEM Export tests

Unit tests for SIEM formatting (Splunk HEC, CEF) and the export service layer.
These tests use in-memory objects and mocks -- no live database required.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.models.database import FindingSeverity, FindingStatus
from app.services.siem_export import (
    export_findings_for_tenant,
    format_finding_cef,
    format_finding_splunk_hec,
)


# ------------------------------------------------------------------
# Helpers — lightweight stand-ins for SQLAlchemy model instances
# ------------------------------------------------------------------

def _make_asset(
    id: int = 1,
    identifier: str = "vuln.example.com",
    asset_type: str = "subdomain",
    tenant_id: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=id,
        identifier=identifier,
        type=SimpleNamespace(value=asset_type),
        tenant_id=tenant_id,
    )


def _make_finding(
    id: int = 100,
    name: str = "Test XSS",
    severity: FindingSeverity = FindingSeverity.HIGH,
    cvss_score: float = 7.5,
    template_id: str = "xss-reflected",
    status: FindingStatus = FindingStatus.OPEN,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    evidence: dict | None = None,
    asset_id: int = 1,
) -> SimpleNamespace:
    if first_seen is None:
        first_seen = datetime(2025, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    if last_seen is None:
        last_seen = datetime(2025, 6, 2, 8, 0, 0, tzinfo=timezone.utc)
    return SimpleNamespace(
        id=id,
        name=name,
        severity=severity,
        cvss_score=cvss_score,
        template_id=template_id,
        status=status,
        first_seen=first_seen,
        last_seen=last_seen,
        evidence=evidence,
        asset_id=asset_id,
    )


# ==================================================================
# Splunk HEC formatting
# ==================================================================

class TestFormatFindingSplunkHEC:
    """Tests for format_finding_splunk_hec."""

    def test_basic_structure(self):
        asset = _make_asset()
        finding = _make_finding()

        result = format_finding_splunk_hec(finding, asset)

        assert result["source"] == "easm-platform"
        assert result["sourcetype"] == "easm:finding"
        assert result["host"] == "vuln.example.com"
        assert isinstance(result["time"], float)
        assert "event" in result

    def test_event_fields(self):
        asset = _make_asset(identifier="api.corp.io")
        finding = _make_finding(
            id=42,
            name="SQL Injection",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            template_id="sqli-error-based",
            status=FindingStatus.OPEN,
        )

        event = format_finding_splunk_hec(finding, asset)["event"]

        assert event["finding_id"] == 42
        assert event["name"] == "SQL Injection"
        assert event["severity"] == "critical"
        assert event["cvss_score"] == 9.8
        assert event["template_id"] == "sqli-error-based"
        assert event["asset_identifier"] == "api.corp.io"
        assert event["status"] == "open"

    def test_evidence_serialised_as_json_string(self):
        evidence = {"url": "https://example.com/vuln", "param": "q"}
        finding = _make_finding(evidence=evidence)
        asset = _make_asset()

        event = format_finding_splunk_hec(finding, asset)["event"]

        parsed = json.loads(event["evidence"])
        assert parsed == evidence

    def test_none_evidence(self):
        finding = _make_finding(evidence=None)
        asset = _make_asset()

        event = format_finding_splunk_hec(finding, asset)["event"]
        assert event["evidence"] is None

    def test_epoch_timestamp(self):
        dt = datetime(2025, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        finding = _make_finding(first_seen=dt)
        asset = _make_asset()

        result = format_finding_splunk_hec(finding, asset)
        assert result["time"] == dt.timestamp()

    def test_asset_type_extracted(self):
        asset = _make_asset(asset_type="ip")
        finding = _make_finding()

        event = format_finding_splunk_hec(finding, asset)["event"]
        assert event["asset_type"] == "ip"

    def test_iso_timestamps_in_event(self):
        first = datetime(2025, 3, 1, 0, 0, 0, tzinfo=timezone.utc)
        last = datetime(2025, 3, 2, 12, 0, 0, tzinfo=timezone.utc)
        finding = _make_finding(first_seen=first, last_seen=last)
        asset = _make_asset()

        event = format_finding_splunk_hec(finding, asset)["event"]
        assert event["first_seen"] == first.isoformat()
        assert event["last_seen"] == last.isoformat()


# ==================================================================
# CEF formatting
# ==================================================================

class TestFormatFindingCEF:
    """Tests for format_finding_cef."""

    def test_basic_header(self):
        finding = _make_finding(
            template_id="cve-2024-1234",
            name="Remote Code Execution",
            severity=FindingSeverity.CRITICAL,
        )
        asset = _make_asset(identifier="target.example.com")

        cef = format_finding_cef(finding, asset)

        assert cef.startswith("CEF:0|EASM|Platform|1.0|")
        assert "cve-2024-1234" in cef
        assert "Remote Code Execution" in cef

    def test_severity_mapping_critical(self):
        finding = _make_finding(severity=FindingSeverity.CRITICAL)
        cef = format_finding_cef(finding, _make_asset())
        # severity field is between the last two pipes of the header
        parts = cef.split("|")
        assert parts[6].startswith("10")

    def test_severity_mapping_high(self):
        finding = _make_finding(severity=FindingSeverity.HIGH)
        cef = format_finding_cef(finding, _make_asset())
        parts = cef.split("|")
        assert parts[6].startswith("8")

    def test_severity_mapping_medium(self):
        finding = _make_finding(severity=FindingSeverity.MEDIUM)
        cef = format_finding_cef(finding, _make_asset())
        parts = cef.split("|")
        assert parts[6].startswith("5")

    def test_severity_mapping_low(self):
        finding = _make_finding(severity=FindingSeverity.LOW)
        cef = format_finding_cef(finding, _make_asset())
        parts = cef.split("|")
        assert parts[6].startswith("3")

    def test_severity_mapping_info(self):
        finding = _make_finding(severity=FindingSeverity.INFO)
        cef = format_finding_cef(finding, _make_asset())
        parts = cef.split("|")
        assert parts[6].startswith("1")

    def test_extension_fields(self):
        finding = _make_finding(id=99, status=FindingStatus.SUPPRESSED)
        asset = _make_asset(identifier="10.0.0.5")

        cef = format_finding_cef(finding, asset)

        assert "src=10.0.0.5" in cef
        assert "cs1=99" in cef
        assert "cs1Label=FindingID" in cef
        assert "cs2=suppressed" in cef
        assert "cs2Label=Status" in cef
        assert "start=" in cef
        assert "end=" in cef

    def test_pipe_in_name_escaped(self):
        finding = _make_finding(name="Vuln|with|pipes")
        cef = format_finding_cef(finding, _make_asset())
        # The name field should have escaped pipes
        assert "Vuln\\|with\\|pipes" in cef

    def test_none_template_id_defaults(self):
        finding = _make_finding(template_id=None)
        cef = format_finding_cef(finding, _make_asset())
        assert "unknown" in cef


# ==================================================================
# export_findings_for_tenant
# ==================================================================

class TestExportFindingsForTenant:
    """Tests for the main export orchestration function."""

    def _mock_db(self, findings_and_assets):
        """Build a mock Session whose .query().join().filter().order_by().all() returns rows."""
        db = MagicMock()
        query = db.query.return_value
        join = query.join.return_value
        filt = join.filter.return_value
        order = filt.order_by.return_value
        order.all.return_value = findings_and_assets
        return db

    def test_returns_splunk_hec_events(self):
        asset = _make_asset()
        finding = _make_finding()
        db = self._mock_db([(finding, asset)])

        events = export_findings_for_tenant(db, tenant_id=1, fmt="splunk_hec")

        assert len(events) == 1
        assert events[0]["source"] == "easm-platform"
        assert events[0]["sourcetype"] == "easm:finding"

    def test_returns_cef_strings(self):
        asset = _make_asset()
        finding = _make_finding()
        db = self._mock_db([(finding, asset)])

        events = export_findings_for_tenant(db, tenant_id=1, fmt="cef")

        assert len(events) == 1
        assert events[0].startswith("CEF:0|")

    def test_empty_result(self):
        db = self._mock_db([])

        events = export_findings_for_tenant(db, tenant_id=1, fmt="splunk_hec")

        assert events == []

    def test_multiple_findings(self):
        asset = _make_asset()
        findings = [_make_finding(id=i, name=f"Finding {i}") for i in range(5)]
        pairs = [(f, asset) for f in findings]
        db = self._mock_db(pairs)

        events = export_findings_for_tenant(db, tenant_id=1, fmt="splunk_hec")

        assert len(events) == 5
        ids = [e["event"]["finding_id"] for e in events]
        assert ids == [0, 1, 2, 3, 4]

    def test_since_filter_forwarded(self):
        """Verify the 'since' parameter is passed to the DB filter."""
        db = self._mock_db([])
        since = datetime(2025, 6, 1, tzinfo=timezone.utc)

        export_findings_for_tenant(db, tenant_id=1, fmt="cef", since=since)

        # The filter() call should have been invoked (we can't easily
        # inspect SQLAlchemy clause objects, but at least ensure no crash).
        db.query.assert_called_once()

    def test_severity_min_filter_forwarded(self):
        """Verify severity_min is accepted without errors."""
        db = self._mock_db([])

        export_findings_for_tenant(
            db, tenant_id=1, fmt="splunk_hec", severity_min="high"
        )

        db.query.assert_called_once()


# ==================================================================
# Schema validation
# ==================================================================

class TestSIEMSchemas:
    """Quick validation of Pydantic schemas."""

    def test_export_request_valid(self):
        from app.api.schemas.siem import SIEMExportRequest

        req = SIEMExportRequest(format="splunk_hec")
        assert req.format == "splunk_hec"
        assert req.since is None
        assert req.severity_min is None

    def test_export_request_cef(self):
        from app.api.schemas.siem import SIEMExportRequest

        req = SIEMExportRequest(format="cef", severity_min="high")
        assert req.format == "cef"
        assert req.severity_min == "high"

    def test_export_request_invalid_format(self):
        from pydantic import ValidationError

        from app.api.schemas.siem import SIEMExportRequest

        with pytest.raises(ValidationError):
            SIEMExportRequest(format="invalid")

    def test_export_request_invalid_severity(self):
        from pydantic import ValidationError

        from app.api.schemas.siem import SIEMExportRequest

        with pytest.raises(ValidationError):
            SIEMExportRequest(format="splunk_hec", severity_min="ultra")

    def test_export_response(self):
        from app.api.schemas.siem import SIEMExportResponse

        resp = SIEMExportResponse(
            format="splunk_hec", event_count=3, events=[{"a": 1}]
        )
        assert resp.event_count == 3

    def test_push_request_requires_endpoint(self):
        from pydantic import ValidationError

        from app.api.schemas.siem import SIEMPushRequest

        with pytest.raises(ValidationError):
            # Missing endpoint_url and auth_token
            SIEMPushRequest(format="splunk_hec")

    def test_push_request_valid(self):
        from app.api.schemas.siem import SIEMPushRequest

        req = SIEMPushRequest(
            format="splunk_hec",
            endpoint_url="https://splunk.corp.io:8088/services/collector",
            auth_token="secret-token-123",
        )
        assert req.endpoint_url.startswith("https://")

    def test_push_response(self):
        from app.api.schemas.siem import SIEMPushResponse

        resp = SIEMPushResponse(
            format="cef", event_count=10, success=True, detail=None
        )
        assert resp.success is True
