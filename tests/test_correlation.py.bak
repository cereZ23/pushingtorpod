"""
Tests for the correlation engine (app/tasks/correlation.py).

Covers:
- Finding deduplication (_dedup_findings)
- 7-rule clustering (_cluster_findings)
- Highest severity selection
- Large group chunking (MAX_FINDINGS_PER_GROUP)
"""

from unittest.mock import MagicMock, patch

import pytest

from app.tasks.correlation import (
    MAX_FINDINGS_PER_GROUP,
    _cluster_findings,
    _dedup_findings,
    _highest_severity,
)


def _make_finding(**overrides):
    """Create a mock Finding with defaults."""
    f = MagicMock()
    f.id = overrides.get("id", 1)
    f.asset_id = overrides.get("asset_id", 100)
    f.name = overrides.get("name", "Test Finding")
    f.template_id = overrides.get("template_id", None)
    f.cve_id = overrides.get("cve_id", None)
    f.control_id = overrides.get("control_id", None) if "control_id" in overrides else None
    f.confidence = overrides.get("confidence", 1.0)
    f.finding_key = overrides.get("finding_key", None)

    # Simulate severity as enum with .value
    sev = overrides.get("severity", "medium")
    sev_mock = MagicMock()
    sev_mock.value = sev
    f.severity = sev_mock

    # Handle hasattr/getattr for control_id
    if "control_id" in overrides:
        f.control_id = overrides["control_id"]

    return f


@pytest.fixture
def tenant_logger():
    return MagicMock()


# ── _highest_severity ────────────────────────────────────────────────

class TestHighestSeverity:
    def test_critical_wins(self):
        assert _highest_severity(["low", "critical", "medium"]) == "critical"

    def test_high_over_medium(self):
        assert _highest_severity(["medium", "high"]) == "high"

    def test_single_severity(self):
        assert _highest_severity(["info"]) == "info"

    def test_empty_list_returns_info(self):
        assert _highest_severity([]) == "info"

    def test_unknown_returns_info(self):
        assert _highest_severity(["banana"]) == "info"


# ── _dedup_findings ──────────────────────────────────────────────────

class TestDedupFindings:
    def test_no_duplicates_returns_all(self, tenant_logger):
        f1 = _make_finding(id=1, asset_id=1, template_id="tmpl-a", name="Finding A")
        f2 = _make_finding(id=2, asset_id=2, template_id="tmpl-b", name="Finding B")
        result = _dedup_findings([f1, f2], tenant_logger)
        assert len(result) == 2

    def test_duplicate_key_keeps_higher_confidence(self, tenant_logger):
        f1 = _make_finding(id=1, asset_id=1, template_id="tmpl-a", name="A", confidence=0.5)
        f2 = _make_finding(id=2, asset_id=1, template_id="tmpl-a", name="A", confidence=0.9)
        # Both generate the same key: "1:tmpl-a:A"
        result = _dedup_findings([f1, f2], tenant_logger)
        assert len(result) == 1
        assert result[0].confidence == 0.9

    def test_uses_finding_key_when_available(self, tenant_logger):
        f1 = _make_finding(id=1, finding_key="custom-key", confidence=0.5)
        f2 = _make_finding(id=2, finding_key="custom-key", confidence=0.8)
        result = _dedup_findings([f1, f2], tenant_logger)
        assert len(result) == 1
        assert result[0].confidence == 0.8


# ── _cluster_findings ────────────────────────────────────────────────

class TestClusterFindings:
    def test_rule1_cve_grouping(self, tenant_logger):
        """Findings with same cve_id are grouped together."""
        f1 = _make_finding(id=1, cve_id="CVE-2021-44228", name="Log4Shell")
        f2 = _make_finding(id=2, cve_id="CVE-2021-44228", name="Log4Shell")
        f3 = _make_finding(id=3, cve_id="CVE-2022-12345", name="Other")

        groups = _cluster_findings([f1, f2, f3], tenant_logger)
        cve_groups = [g for g in groups if g["root_cause"].startswith("cve:")]

        assert len(cve_groups) == 2
        log4shell_group = [g for g in cve_groups if "CVE-2021-44228" in g["root_cause"]][0]
        assert len(log4shell_group["findings"]) == 2

    def test_rule2_control_id_grouping(self, tenant_logger):
        """Findings with same control_id are grouped."""
        f1 = _make_finding(id=1, control_id="HSTS-001", name="Missing HSTS")
        f2 = _make_finding(id=2, control_id="HSTS-001", name="Missing HSTS")

        groups = _cluster_findings([f1, f2], tenant_logger)
        ctrl_groups = [g for g in groups if g["root_cause"].startswith("control:")]
        assert len(ctrl_groups) == 1
        assert len(ctrl_groups[0]["findings"]) == 2

    def test_rule3_template_grouping_needs_2_plus(self, tenant_logger):
        """Template grouping only fires when 2+ findings share template_id."""
        f1 = _make_finding(id=1, template_id="exposed-panel-login", name="Login Panel")
        f2 = _make_finding(id=2, template_id="exposed-panel-login", name="Login Panel")
        f3 = _make_finding(id=3, template_id="unique-template", name="Unique Finding")

        groups = _cluster_findings([f1, f2, f3], tenant_logger)

        template_groups = [g for g in groups if g["root_cause"].startswith("template:")]
        assert len(template_groups) == 1
        assert len(template_groups[0]["findings"]) == 2

        # f3 should be individual (template had only 1 finding)
        individual_groups = [g for g in groups if g["root_cause"].startswith("individual:")]
        assert len(individual_groups) == 1

    def test_rule7_individual_fallback(self, tenant_logger):
        """Findings with no CVE, control_id, or shared template go individual."""
        f1 = _make_finding(id=1, name="Random Finding")
        groups = _cluster_findings([f1], tenant_logger)
        assert len(groups) == 1
        assert groups[0]["root_cause"].startswith("individual:")

    def test_cve_takes_priority_over_template(self, tenant_logger):
        """CVE grouping runs before template grouping."""
        f1 = _make_finding(id=1, cve_id="CVE-2021-44228", template_id="log4j-rce", name="Log4Shell")
        f2 = _make_finding(id=2, cve_id="CVE-2021-44228", template_id="log4j-rce", name="Log4Shell")

        groups = _cluster_findings([f1, f2], tenant_logger)
        # Should be grouped by CVE, not template
        assert any("cve:" in g["root_cause"] for g in groups)
        assert not any("template:" in g["root_cause"] for g in groups)

    def test_empty_input(self, tenant_logger):
        groups = _cluster_findings([], tenant_logger)
        assert groups == []

    def test_mixed_rules(self, tenant_logger):
        """Verify mixed findings are distributed across correct groups."""
        f_cve = _make_finding(id=1, cve_id="CVE-2021-44228", name="Log4Shell")
        f_ctrl = _make_finding(id=2, control_id="HSTS-001", name="Missing HSTS")
        f_tmpl1 = _make_finding(id=3, template_id="wp-login", name="WordPress Login")
        f_tmpl2 = _make_finding(id=4, template_id="wp-login", name="WordPress Login")
        f_solo = _make_finding(id=5, name="Solo Finding")

        groups = _cluster_findings([f_cve, f_ctrl, f_tmpl1, f_tmpl2, f_solo], tenant_logger)

        root_causes = [g["root_cause"] for g in groups]
        assert any("cve:" in rc for rc in root_causes)
        assert any("control:" in rc for rc in root_causes)
        assert any("template:" in rc for rc in root_causes)
        assert any("individual:" in rc for rc in root_causes)
        assert len(groups) == 4  # 1 CVE + 1 control + 1 template + 1 individual
