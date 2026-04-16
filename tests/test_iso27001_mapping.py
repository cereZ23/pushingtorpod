"""Tests for ISO 27001 mapping service."""

from __future__ import annotations

from unittest.mock import MagicMock

from app.services.iso27001_mapping import (
    ISO_CONTROLS,
    compute_compliance_coverage,
    get_control_info,
    map_finding_to_controls,
)


class TestMapFindingToControls:
    def test_cve_maps_to_a88(self):
        controls = map_finding_to_controls(template_id="CVE-2023-3460-ultimate-member")
        assert "A.8.8" in controls

    def test_tls_maps_to_a824(self):
        controls = map_finding_to_controls(template_id="TLS-001", name="Certificate expiring")
        assert "A.8.24" in controls

    def test_hsts_maps_to_a89_and_a823(self):
        controls = map_finding_to_controls(template_id="HDR-004", name="Missing HSTS header")
        assert "A.8.9" in controls
        assert "A.8.23" in controls

    def test_docker_compose_maps_to_a89_and_a812(self):
        controls = map_finding_to_controls(
            template_id="exposed-docker-compose-credentials",
            name="docker-compose.yml Exposed with Credentials",
        )
        assert "A.8.9" in controls
        assert "A.8.12" in controls

    def test_unknown_defaults_to_a88(self):
        controls = map_finding_to_controls(template_id="random-xyz", name="Random")
        assert controls == ["A.8.8"]

    def test_empty_returns_default(self):
        controls = map_finding_to_controls()
        assert controls == ["A.8.8"]

    def test_cloud_maps_to_a523(self):
        controls = map_finding_to_controls(name="AWS S3 bucket exposed")
        assert "A.5.23" in controls


class TestGetControlInfo:
    def test_valid_control(self):
        info = get_control_info("A.8.8")
        assert info is not None
        assert "name" in info
        assert "description" in info

    def test_invalid_control(self):
        assert get_control_info("X.99.99") is None


class TestComputeComplianceCoverage:
    def test_empty_findings_all_clean(self):
        coverage = compute_compliance_coverage([])
        for cid in ISO_CONTROLS.keys():
            assert coverage[cid]["status"] == "clean"
            assert coverage[cid]["findings_count"] == 0

    def test_finding_marks_control_affected(self):
        f = MagicMock()
        f.template_id = "CVE-2023-3460"
        f.name = "Ultimate Member RCE"
        f.source = "nuclei"
        f.severity = "critical"
        f.status = "open"

        coverage = compute_compliance_coverage([f])
        assert coverage["A.8.8"]["status"] == "findings_present"
        assert coverage["A.8.8"]["findings_count"] == 1
        assert coverage["A.8.8"]["critical_high"] == 1
        assert coverage["A.8.8"]["open"] == 1

    def test_multiple_findings_aggregate(self):
        findings = []
        for i in range(3):
            f = MagicMock()
            f.template_id = f"CVE-{i}"
            f.name = "Test CVE"
            f.source = "nuclei"
            f.severity = "high"
            f.status = "open"
            findings.append(f)

        coverage = compute_compliance_coverage(findings)
        assert coverage["A.8.8"]["findings_count"] == 3
        assert coverage["A.8.8"]["critical_high"] == 3
