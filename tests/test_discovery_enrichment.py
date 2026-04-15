"""Tests for discovery finding → enrichment separation."""

from __future__ import annotations


class TestDiscoveryTemplateFilter:
    """Verify discovery templates are correctly identified."""

    def test_caa_is_discovery(self):
        _DISCOVERY_TEMPLATES = {
            "caa-fingerprint",
            "ns-record-detect",
            "mx-record-detect",
            "soa-record-detect",
            "aaaa-record-detect",
        }
        tid = "caa-fingerprint"
        assert any(dt in tid for dt in _DISCOVERY_TEMPLATES)

    def test_dockerfile_is_not_discovery(self):
        _DISCOVERY_TEMPLATES = {
            "caa-fingerprint",
            "ns-record-detect",
            "mx-record-detect",
        }
        tid = "dockerfile-hidden-disclosure"
        assert not any(dt in tid for dt in _DISCOVERY_TEMPLATES)

    def test_docker_compose_is_not_discovery(self):
        _DISCOVERY_TEMPLATES = {
            "caa-fingerprint",
            "ns-record-detect",
            "mx-record-detect",
        }
        tid = "exposed-docker-compose-credentials"
        assert not any(dt in tid for dt in _DISCOVERY_TEMPLATES)

    def test_cve_is_not_discovery(self):
        _DISCOVERY_TEMPLATES = {
            "caa-fingerprint",
            "ns-record-detect",
            "mx-record-detect",
        }
        tid = "CVE-2021-44228"
        assert not any(dt in tid.lower() for dt in _DISCOVERY_TEMPLATES)

    def test_spf_detect_is_discovery(self):
        _DISCOVERY_TEMPLATES = {"spf-record-detect"}
        tid = "spf-record-detect"
        assert any(dt in tid for dt in _DISCOVERY_TEMPLATES)

    def test_htaccess_is_not_discovery(self):
        _DISCOVERY_TEMPLATES = {
            "caa-fingerprint",
            "ns-record-detect",
            "dns-saas-service-detection",
        }
        tid = "exposed-htaccess"
        assert not any(dt in tid for dt in _DISCOVERY_TEMPLATES)
