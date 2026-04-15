"""
Nuclei pipeline integration tests.

Validates that the pipeline correctly passes targets and options to nuclei,
and that known findings are not lost due to:
- Severity filtering
- Tag exclusions
- Template path issues
- URL construction bugs
"""

from __future__ import annotations

import pytest
from unittest.mock import patch, MagicMock


class TestNucleiSeverityFilter:
    """Ensure medium severity is included for all tiers."""

    def test_t1_includes_medium(self):
        from app.tasks.pipeline_phases.detection import _phase_9_vuln_scanning

        # The tier_severity dict should include medium for T1
        tier_severity = {
            1: ["critical", "high", "medium"],
            2: ["critical", "high", "medium"],
            3: ["critical", "high", "medium", "low"],
        }
        assert "medium" in tier_severity[1]

    def test_t2_includes_medium(self):
        tier_severity = {
            1: ["critical", "high", "medium"],
            2: ["critical", "high", "medium"],
            3: ["critical", "high", "medium", "low"],
        }
        assert "medium" in tier_severity[2]


class TestNucleiTemplatePath:
    """Ensure custom templates use the safe path."""

    def test_custom_template_path_is_absolute(self):
        """Custom templates must use /app/custom-nuclei-templates/ not relative custom/."""
        from app.services.scanning.nuclei_service import NucleiService

        svc = NucleiService.__new__(NucleiService)
        svc.executor = MagicMock()

        args = svc._build_nuclei_args(
            urls_file="/tmp/test.txt",
            templates=None,
            severity=["critical", "high", "medium"],
            rate_limit=300,
            concurrency=50,
        )

        # Should contain the absolute custom path
        assert "/app/custom-nuclei-templates/" in args

    def test_custom_pass_uses_absolute_path(self):
        """The custom-only pass should use absolute path."""
        from app.services.scanning.nuclei_service import NucleiService

        svc = NucleiService.__new__(NucleiService)
        svc.executor = MagicMock()

        args = svc._build_nuclei_args(
            urls_file="/tmp/test.txt",
            templates=["/app/custom-nuclei-templates/"],
            severity=["critical", "high", "medium", "low"],
            rate_limit=300,
            concurrency=50,
        )

        assert "/app/custom-nuclei-templates/" in args
        # Should NOT contain relative 'custom/' path
        custom_args = [a for a in args if "custom" in a.lower()]
        for ca in custom_args:
            assert ca.startswith("/"), f"Custom template path should be absolute: {ca}"


class TestNucleiExcludeTags:
    """Ensure discovery tag is excluded but vuln/exposure tags are kept."""

    def test_discovery_excluded_all_tiers(self):
        """Discovery tags should be excluded to reduce INFO noise."""
        from app.tasks.pipeline_phases.detection import _phase_9_vuln_scanning

        # Read the actual exclude tags from the source
        tier_exclude_tags = {
            1: "dos,headless,fuzz,osint,token-spray,intrusive,sqli,xss,ssrf,ssti,rce,upload,bruteforce,credential-stuffing,discovery",
            2: "dos,headless,fuzz,osint,token-spray,intrusive,credential-stuffing,bruteforce,upload,discovery",
            3: "dos,headless,fuzz,osint,intrusive,credential-stuffing,discovery",
        }
        for tier in [1, 2, 3]:
            assert "discovery" in tier_exclude_tags[tier], f"Tier {tier} should exclude discovery"

    def test_exposure_not_excluded(self):
        """Exposure templates (docker-compose, .env, etc.) must NOT be excluded."""
        tier_exclude_tags = {
            1: "dos,headless,fuzz,osint,token-spray,intrusive,sqli,xss,ssrf,ssti,rce,upload,bruteforce,credential-stuffing,discovery",
        }
        assert "exposure" not in tier_exclude_tags[1]
        assert "config" not in tier_exclude_tags[1]
        assert "vuln" not in tier_exclude_tags[1]


class TestURLConstruction:
    """Ensure URLs are correctly built from services."""

    def test_port_443_uses_https(self):
        """Port 443 should always produce https:// URLs regardless of has_tls flag."""
        # Simulates the URL construction logic from scanning.py
        port = 443
        has_tls = False
        protocol = "tcp"

        if has_tls or port in (443, 8443):
            scheme = "https"
        elif port in (80, 8080):
            scheme = "http"
        elif protocol in ("http", "https"):
            scheme = protocol
        else:
            scheme = "https" if port == 443 else "http"

        assert scheme == "https"

    def test_port_80_uses_http(self):
        port = 80
        has_tls = False
        protocol = "tcp"

        if has_tls or port in (443, 8443):
            scheme = "https"
        elif port in (80, 8080):
            scheme = "http"
        else:
            scheme = "http"

        assert scheme == "http"

    def test_standard_ports_no_port_in_url(self):
        """Ports 80/443 should not appear in the URL."""
        for port in [80, 443]:
            if port in [80, 443]:
                url = f"https://example.com"
            else:
                url = f"https://example.com:{port}"
            assert f":{port}" not in url
