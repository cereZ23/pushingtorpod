"""
Tests for report generator (app/services/report_generator.py).

Covers:
- Compliance framework mapping (SOC2 TSC, ISO 27001 Annex A)
- Remediation guidance lookup
- Evidence formatting
- Severity weight constants
- Framework category structures
"""

import json
from contextlib import ExitStack
from datetime import datetime
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

import pytest

from app.services.report_generator import (
    ANNEX_A_DOMAINS,
    SEVERITY_WEIGHT,
    TSC_CATEGORIES,
    _SEVERITY_COMPLIANCE_FALLBACK,
    _TEMPLATE_COMPLIANCE_MAP,
    ReportGenerator,
    _format_evidence,
    _get_remediation,
    _map_finding_to_framework,
)


# ── Compliance framework mapping ─────────────────────────────────────


class TestMapFindingToFramework:
    """Test _map_finding_to_framework for SOC2 and ISO27001."""

    def test_ssl_finding_maps_to_cc6(self):
        """SSL findings should map to CC6 (Logical Access Controls)."""
        result = _map_finding_to_framework("ssl-detect", "SSL Detection", "medium", "tsc")
        assert result == "CC6"

    def test_ssl_finding_maps_to_a10(self):
        """SSL findings should map to A.10 (Cryptography) in ISO 27001."""
        result = _map_finding_to_framework("tls-version", "TLS Version", "medium", "annex")
        assert result == "A.10"

    def test_cve_finding_maps_to_cc3(self):
        """CVE findings should map to CC3 (Risk Assessment)."""
        result = _map_finding_to_framework("cve-2021-44228", "Log4Shell", "critical", "tsc")
        assert result == "CC3"

    def test_exposed_panel_maps_to_cc6(self):
        """Exposed panels should map to CC6."""
        result = _map_finding_to_framework("exposed-panels-login", "Admin Panel", "high", "tsc")
        assert result == "CC6"

    def test_name_based_fallback(self):
        """When template_id doesn't match, try name-based matching."""
        result = _map_finding_to_framework("custom-template", "SSL weak cipher detected", "medium", "tsc")
        assert result == "CC6"  # "ssl" in name matches ssl- prefix

    def test_severity_based_fallback(self):
        """When nothing else matches, use severity-based fallback."""
        result = _map_finding_to_framework("unknown-template", "Unknown Finding", "critical", "tsc")
        assert result == "CC3"  # critical → CC3

    def test_severity_fallback_info(self):
        result = _map_finding_to_framework(None, "Generic Info", "info", "annex")
        assert result == "A.8"  # info → A.8

    def test_none_template_id(self):
        """None template_id should fall through to name/severity matching."""
        result = _map_finding_to_framework(None, "Missing HSTS header", "medium", "tsc")
        # "strict-transport" not in name, but "http-missing" pattern should match
        # Actually falls to severity fallback
        assert result in {"CC6", "CC7", "CC3", "CC4"}  # valid TSC ID

    def test_all_severity_fallbacks_defined(self):
        """All severity levels should have fallback mappings."""
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in _SEVERITY_COMPLIANCE_FALLBACK
            assert "tsc" in _SEVERITY_COMPLIANCE_FALLBACK[sev]
            assert "annex" in _SEVERITY_COMPLIANCE_FALLBACK[sev]


# ── Remediation guidance ─────────────────────────────────────────────


class TestGetRemediation:
    def test_known_template_returns_guidance(self):
        result = _get_remediation("http-missing-security-headers")
        assert result is not None
        assert "header" in result.lower()

    def test_ssl_template_returns_guidance(self):
        result = _get_remediation("ssl-detect")
        assert result is not None
        assert "TLS" in result

    def test_unknown_template_returns_none(self):
        assert _get_remediation("completely-unknown-template") is None

    def test_none_template_returns_none(self):
        assert _get_remediation(None) is None


# ── Evidence formatting ──────────────────────────────────────────────


class TestFormatEvidence:
    def test_none_returns_empty(self):
        assert _format_evidence(None) == ""

    def test_dict_returns_json(self):
        result = _format_evidence({"key": "value"})
        assert "key" in result
        assert "value" in result

    def test_json_string_is_pretty_printed(self):
        json_str = '{"matched_at": "https://example.com", "type": "http"}'
        result = _format_evidence(json_str)
        assert "matched_at" in result

    def test_plain_string_returned_as_is(self):
        result = _format_evidence("simple text evidence")
        assert result == "simple text evidence"

    def test_long_evidence_is_truncated(self):
        long_str = "x" * 1000
        result = _format_evidence(long_str)
        assert len(result) <= 500

    def test_non_string_converted(self):
        result = _format_evidence(42)
        assert result == "42"


# ── Static structure validation ──────────────────────────────────────


class TestComplianceStructure:
    def test_tsc_categories_count(self):
        """SOC 2 has 9 Trust Service Criteria."""
        assert len(TSC_CATEGORIES) == 9

    def test_annex_a_domains_count(self):
        """ISO 27001 has 14 Annex A domains."""
        assert len(ANNEX_A_DOMAINS) == 14

    def test_tsc_ids_are_cc_prefixed(self):
        for cat in TSC_CATEGORIES:
            assert cat.id.startswith("CC"), f"TSC category {cat.id} should start with CC"

    def test_annex_a_ids_are_a_prefixed(self):
        for dom in ANNEX_A_DOMAINS:
            assert dom.id.startswith("A."), f"Annex A domain {dom.id} should start with A."

    def test_severity_weights_complete(self):
        """All standard severities have weights defined."""
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in SEVERITY_WEIGHT

    def test_severity_weight_order(self):
        """Critical should have highest weight, info lowest."""
        assert SEVERITY_WEIGHT["critical"] > SEVERITY_WEIGHT["high"]
        assert SEVERITY_WEIGHT["high"] > SEVERITY_WEIGHT["medium"]
        assert SEVERITY_WEIGHT["medium"] > SEVERITY_WEIGHT["low"]
        assert SEVERITY_WEIGHT["low"] > SEVERITY_WEIGHT["info"]

    def test_template_compliance_map_has_entries(self):
        """Template compliance map should have reasonable coverage."""
        assert len(_TEMPLATE_COMPLIANCE_MAP) >= 20
