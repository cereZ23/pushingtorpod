"""
Unit tests for NucleiService

Tests cover:
- Nuclei execution with various templates
- JSON output parsing
- Finding normalization
- Severity filtering
- Rate limiting
- Error handling
- Security controls (URL validation, output sanitization)
- Risk score calculation
- exclude_tags parameter (default fallback + explicit override)
- Tier-aware template directory selection (including custom/)
- -mhe 50 flag presence
"""

from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock, patch

from app.services.scanning.nuclei_service import (
    NucleiService,
    calculate_risk_score_from_findings,
)
from app.utils.secure_executor import ToolExecutionError

NUCLEI_TEMPLATES_DIR = "/home/appuser/nuclei-templates"
DEFAULT_EXCLUDE_TAGS = (
    "dos,headless,fuzz,osint,token-spray,intrusive,sqli,xss,ssrf,ssti,rce,upload,bruteforce,credential-stuffing"
)


class TestNucleiService:
    @pytest.fixture
    def nuclei_service(self):
        return NucleiService(tenant_id=1)

    @pytest.fixture
    def sample_nuclei_output(self):
        return json.dumps(
            {
                "template-id": "CVE-2021-12345",
                "info": {
                    "name": "Test Vulnerability",
                    "severity": "critical",
                    "description": "A test vulnerability",
                    "tags": ["cve", "test"],
                    "reference": ["https://example.com"],
                    "classification": {
                        "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "cvss-score": 9.8,
                        "cve-id": ["CVE-2021-12345"],
                    },
                },
                "matcher-name": "version-check",
                "type": "http",
                "host": "https://example.com",
                "matched-at": "https://example.com/vulnerable",
                "timestamp": "2024-01-01T12:00:00Z",
                "curl-command": "curl -X GET https://example.com/vulnerable",
            }
        )

    def test_init(self, nuclei_service):
        assert nuclei_service.tenant_id == 1
        assert nuclei_service.url_validator is not None

    def test_validate_urls_valid(self, nuclei_service):
        urls = ["https://example.com", "http://test.example.com:8080", "https://192.0.2.1"]
        valid_urls, errors = nuclei_service._validate_urls(urls)
        assert len(valid_urls) == 3
        assert len(errors) == 0

    def test_validate_urls_invalid(self, nuclei_service):
        urls = [
            "https://localhost",
            "http://127.0.0.1",
            "https://169.254.169.254",
            "ftp://example.com",
            "not-a-url",
        ]
        valid_urls, errors = nuclei_service._validate_urls(urls)
        assert len(valid_urls) == 0
        assert len(errors) == 5

    def test_validate_urls_mixed(self, nuclei_service):
        urls = ["https://example.com", "https://localhost", "http://test.com"]
        valid_urls, errors = nuclei_service._validate_urls(urls)
        assert len(valid_urls) == 2
        assert len(errors) == 1
        assert "https://example.com" in valid_urls
        assert "http://test.com" in valid_urls

    def test_build_nuclei_args_required_flags(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
        )
        assert "-l" in args
        assert "/tmp/urls.txt" in args
        assert "-jsonl" in args
        assert "-no-color" in args
        assert "-duc" in args
        assert "-no-httpx" in args

    def test_build_nuclei_args_rate_and_concurrency(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=150,
            concurrency=25,
        )
        assert "-rl" in args and "150" in args
        assert "-c" in args and "25" in args
        assert "-bs" in args

    def test_build_nuclei_args_mhe_is_50(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
        )
        assert "-mhe" in args
        assert args[args.index("-mhe") + 1] == "50"

    def test_build_nuclei_args_severity_filter(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
        )
        assert "-severity" in args
        assert args[args.index("-severity") + 1] == "critical,high"

    def test_build_nuclei_args_default_includes_standard_dirs(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
        )
        tpls = [args[i + 1] for i, a in enumerate(args) if a == "-t"]
        assert any("http/cves/" in t for t in tpls)
        assert any("http/exposed-panels/" in t for t in tpls)
        assert any("ssl/" in t for t in tpls)

    def test_build_nuclei_args_default_includes_custom_dir(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
        )
        tpls = [args[i + 1] for i, a in enumerate(args) if a == "-t"]
        assert any("custom-nuclei-templates" in t for t in tpls), "custom template dir missing from defaults"
        assert "/app/custom-nuclei-templates/" in tpls

    def test_build_nuclei_args_default_templates_are_absolute(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
        )
        tpls = [args[i + 1] for i, a in enumerate(args) if a == "-t"]
        for tpl in tpls:
            assert tpl.startswith("/"), f"Non-absolute: {tpl}"

    def test_build_nuclei_args_custom_relative_becomes_absolute(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=["custom-template.yaml", "takeovers/"],
            severity=["critical"],
            rate_limit=100,
            concurrency=25,
        )
        tpls = [args[i + 1] for i, a in enumerate(args) if a == "-t"]
        assert any("custom-template.yaml" in t for t in tpls)
        assert any("takeovers/" in t for t in tpls)
        for tpl in tpls:
            assert tpl.startswith("/"), f"Non-absolute: {tpl}"

    def test_build_nuclei_args_custom_absolute_unchanged(self, nuclei_service):
        abs_path = "/opt/custom-templates/my-check.yaml"
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=[abs_path],
            severity=["critical"],
            rate_limit=100,
            concurrency=25,
        )
        tpls = [args[i + 1] for i, a in enumerate(args) if a == "-t"]
        assert abs_path in tpls

    def test_build_nuclei_args_exclude_tags_default(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
            exclude_tags=None,
        )
        assert "-exclude-tags" in args
        assert args[args.index("-exclude-tags") + 1] == DEFAULT_EXCLUDE_TAGS

    def test_build_nuclei_args_exclude_tags_explicit(self, nuclei_service):
        tier2 = "dos,headless,fuzz"
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
            exclude_tags=tier2,
        )
        assert "-exclude-tags" in args
        assert args[args.index("-exclude-tags") + 1] == tier2

    def test_build_nuclei_args_exclude_tags_empty_string_no_flag(self, nuclei_service):
        """Empty string exclude_tags means 'no exclusions' — flag should be absent."""
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical", "high"],
            rate_limit=300,
            concurrency=50,
            exclude_tags="",
        )
        assert "-exclude-tags" not in args

    def test_build_nuclei_args_exclude_tags_always_present(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical"],
            rate_limit=100,
            concurrency=10,
        )
        assert "-exclude-tags" in args

    def test_build_nuclei_args_interactsh_server_forwarded(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical"],
            rate_limit=300,
            concurrency=50,
            interactsh_server="https://oast.me",
        )
        assert "-iserver" in args
        assert args[args.index("-iserver") + 1] == "https://oast.me"

    def test_build_nuclei_args_no_interactsh_by_default(self, nuclei_service):
        args = nuclei_service._build_nuclei_args(
            urls_file="/tmp/urls.txt",
            templates=None,
            severity=["critical"],
            rate_limit=300,
            concurrency=50,
        )
        assert "-iserver" not in args

    def test_parse_nuclei_result_valid(self, nuclei_service, sample_nuclei_output):
        finding = nuclei_service.parse_nuclei_result(json.loads(sample_nuclei_output))
        assert finding is not None
        assert finding["template_id"] == "CVE-2021-12345"
        assert finding["name"] == "Test Vulnerability"
        assert finding["severity"] == "critical"
        assert finding["cvss_score"] == 9.8
        assert finding["cve_id"] == "CVE-2021-12345"
        assert finding["matched_at"] == "https://example.com/vulnerable"
        assert finding["host"] == "example.com"
        assert finding["source"] == "nuclei"

    def test_parse_nuclei_result_missing_optional_fields(self, nuclei_service):
        result = {
            "template-id": "test-template",
            "info": {"name": "Test", "severity": "high"},
            "host": "https://example.com",
        }
        finding = nuclei_service.parse_nuclei_result(result)
        assert finding is not None
        assert finding["cvss_score"] is None
        assert finding["cve_id"] is None

    def test_parse_nuclei_result_invalid_severity_defaults_to_info(self, nuclei_service):
        result = {
            "template-id": "test",
            "info": {"name": "Test", "severity": "unknown-severity"},
            "host": "https://example.com",
        }
        finding = nuclei_service.parse_nuclei_result(result)
        assert finding is not None
        assert finding["severity"] == "info"

    def test_parse_nuclei_result_ssl_host_without_scheme(self, nuclei_service):
        result = {
            "template-id": "ssl-weak-cipher",
            "info": {"name": "Weak Cipher", "severity": "medium"},
            "host": "example.com:443",
            "matched-at": "example.com:443",
        }
        finding = nuclei_service.parse_nuclei_result(result)
        assert finding is not None
        assert finding["host"] == "example.com"

    def test_parse_nuclei_output_multiple_findings(self, nuclei_service, sample_nuclei_output):
        stdout = sample_nuclei_output + "\n" + sample_nuclei_output
        findings = nuclei_service._parse_nuclei_output(stdout)
        assert len(findings) == 2

    def test_parse_nuclei_output_skips_non_json_lines(self, nuclei_service, sample_nuclei_output):
        stdout = "[INF] Starting...\n" + sample_nuclei_output + "\n[INF] Done."
        findings = nuclei_service._parse_nuclei_output(stdout)
        assert len(findings) == 1

    def test_parse_nuclei_output_empty_stdout(self, nuclei_service):
        assert nuclei_service._parse_nuclei_output("") == []

    def test_parse_nuclei_output_invalid_json_skipped(self, nuclei_service):
        valid = json.dumps(
            {
                "template-id": "t1",
                "info": {"name": "x", "severity": "info"},
                "host": "https://example.com",
            }
        )
        stdout = "{}\ninvalid json line\n" + valid
        findings = nuclei_service._parse_nuclei_output(stdout)
        assert isinstance(findings, list)
        assert len(findings) >= 1

    def test_calculate_stats(self, nuclei_service):
        urls = ["https://example.com", "https://test.com"]
        findings = [
            {"severity": "critical"},
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        stats = nuclei_service._calculate_stats(urls, findings)
        assert stats["urls_scanned"] == 2
        assert stats["findings_count"] == 6
        assert stats["by_severity"]["critical"] == 2
        assert stats["by_severity"]["high"] == 1

    async def test_scan_urls_success(self, nuclei_service, sample_nuclei_output):
        urls = ["https://example.com"]
        with patch("app.services.scanning.nuclei_service.SecureToolExecutor") as mock_cls:
            mock_ctx = MagicMock()
            mock_cls.return_value.__enter__.return_value = mock_ctx
            mock_cls.return_value.__exit__.return_value = None
            mock_ctx.create_input_file.return_value = "/tmp/urls.txt"
            mock_ctx.execute.return_value = (0, sample_nuclei_output, "")
            with patch("app.services.scanning.nuclei_service.store_raw_output"):
                result = await nuclei_service.scan_urls(urls)
        assert result["stats"]["urls_scanned"] == 1
        assert result["stats"]["findings_count"] == 1
        assert result["findings"][0]["template_id"] == "CVE-2021-12345"

    async def test_scan_urls_passes_exclude_tags_to_build_args(self, nuclei_service):
        urls = ["https://example.com"]
        tier2_tags = "dos,headless"
        with patch("app.services.scanning.nuclei_service.SecureToolExecutor") as mock_cls:
            mock_ctx = MagicMock()
            mock_cls.return_value.__enter__.return_value = mock_ctx
            mock_cls.return_value.__exit__.return_value = None
            mock_ctx.create_input_file.return_value = "/tmp/urls.txt"
            mock_ctx.execute.return_value = (0, "", "")
            with patch("app.services.scanning.nuclei_service.store_raw_output"):
                with patch.object(
                    nuclei_service,
                    "_build_nuclei_args",
                    wraps=nuclei_service._build_nuclei_args,
                ) as spy:
                    await nuclei_service.scan_urls(urls, exclude_tags=tier2_tags)
        spy.assert_called_once()
        assert spy.call_args.kwargs.get("exclude_tags") == tier2_tags

    async def test_scan_urls_no_valid_urls_returns_early(self, nuclei_service):
        urls = ["https://localhost", "http://127.0.0.1"]
        result = await nuclei_service.scan_urls(urls)
        assert result["stats"]["urls_scanned"] == 0
        assert result["stats"]["findings_count"] == 0
        assert len(result["errors"]) > 0

    async def test_scan_urls_tool_execution_error(self, nuclei_service):
        urls = ["https://example.com"]
        with patch("app.services.scanning.nuclei_service.SecureToolExecutor") as mock_cls:
            mock_ctx = MagicMock()
            mock_cls.return_value.__enter__.return_value = mock_ctx
            mock_cls.return_value.__exit__.return_value = None
            mock_ctx.create_input_file.return_value = "/tmp/urls.txt"
            mock_ctx.execute.side_effect = ToolExecutionError("Tool failed")
            with patch("app.services.scanning.nuclei_service.store_raw_output"):
                result = await nuclei_service.scan_urls(urls)
        assert result["stats"]["findings_count"] == 0
        assert any("Tool failed" in e for e in result["errors"])

    async def test_scan_urls_exit_code_1_treated_as_ok(self, nuclei_service, sample_nuclei_output):
        urls = ["https://example.com"]
        with patch("app.services.scanning.nuclei_service.SecureToolExecutor") as mock_cls:
            mock_ctx = MagicMock()
            mock_cls.return_value.__enter__.return_value = mock_ctx
            mock_cls.return_value.__exit__.return_value = None
            mock_ctx.create_input_file.return_value = "/tmp/urls.txt"
            mock_ctx.execute.return_value = (1, sample_nuclei_output, "")
            with patch("app.services.scanning.nuclei_service.store_raw_output"):
                result = await nuclei_service.scan_urls(urls)
        assert result["stats"]["findings_count"] == 1

    async def test_scan_asset_attaches_asset_id(self, nuclei_service, sample_nuclei_output):
        with patch("app.services.scanning.nuclei_service.SecureToolExecutor") as mock_cls:
            mock_ctx = MagicMock()
            mock_cls.return_value.__enter__.return_value = mock_ctx
            mock_cls.return_value.__exit__.return_value = None
            mock_ctx.create_input_file.return_value = "/tmp/urls.txt"
            mock_ctx.execute.return_value = (0, sample_nuclei_output, "")
            with patch("app.services.scanning.nuclei_service.store_raw_output"):
                findings = await nuclei_service.scan_asset(asset_id=123, asset_url="https://example.com")
        assert len(findings) == 1
        assert findings[0]["asset_id"] == 123


class TestRiskScoreCalculation:
    def test_empty_findings_returns_zero(self):
        assert calculate_risk_score_from_findings([]) == 0.0

    def test_two_critical_findings(self):
        assert calculate_risk_score_from_findings([{"severity": "critical"}, {"severity": "critical"}]) == 6.0

    def test_mixed_severities(self):
        findings = [
            {"severity": "critical"},
            {"severity": "high"},
            {"severity": "medium"},
            {"severity": "low"},
            {"severity": "info"},
        ]
        assert abs(calculate_risk_score_from_findings(findings) - 6.6) < 1e-9

    def test_score_capped_at_10(self):
        findings = [{"severity": "critical"}] * 10
        assert calculate_risk_score_from_findings(findings) == 10.0

    def test_unknown_severity_contributes_zero(self):
        findings = [
            {"severity": "critical"},
            {"severity": "unknown"},
            {"severity": "high"},
        ]
        assert calculate_risk_score_from_findings(findings) == 5.0
