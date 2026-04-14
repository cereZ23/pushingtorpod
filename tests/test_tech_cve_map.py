"""Tests for tech-to-CVE mapping service."""

from __future__ import annotations

from app.services.tech_cve_map import get_cves_for_tech, get_cves_for_asset_technologies


class TestGetCvesForTech:
    def test_apache_rce(self):
        cves = get_cves_for_tech("Apache/2.4.49")
        assert any(c["cve"] == "CVE-2021-41773" for c in cves)

    def test_apache_safe_version(self):
        cves = get_cves_for_tech("Apache/2.4.58")
        assert len(cves) == 0

    def test_php_cgi(self):
        cves = get_cves_for_tech("PHP/8.1.2")
        assert any(c["cve"] == "CVE-2024-4577" for c in cves)

    def test_log4j(self):
        cves = get_cves_for_tech("Log4j/2.14.1")
        assert any(c["cve"] == "CVE-2021-44228" for c in cves)

    def test_spring_boot(self):
        cves = get_cves_for_tech("Spring Boot 2.6.6")
        assert any(c["cve"] == "CVE-2022-22965" for c in cves)

    def test_jquery_old(self):
        cves = get_cves_for_tech("jQuery/3.4.1")
        assert any(c["cve"] == "CVE-2020-11022" for c in cves)

    def test_unknown_tech(self):
        assert get_cves_for_tech("UnknownServer/1.0") == []

    def test_empty_string(self):
        assert get_cves_for_tech("") == []

    def test_none(self):
        assert get_cves_for_tech(None) == []


class TestGetCvesForAssetTechnologies:
    def test_dedup_across_techs(self):
        techs = ["Apache/2.4.49", "Apache/2.4.50"]
        cves = get_cves_for_asset_technologies(techs)
        cve_ids = [c["cve"] for c in cves]
        # Should dedup — CVE-2021-41773 appears for both versions
        assert cve_ids.count("CVE-2021-41773") == 1

    def test_multiple_techs(self):
        techs = ["PHP/7.4.3", "Apache/2.4.49"]
        cves = get_cves_for_asset_technologies(techs)
        assert len(cves) >= 2

    def test_includes_matched_tech(self):
        cves = get_cves_for_asset_technologies(["Log4j/2.14.1"])
        assert cves[0]["matched_tech"] == "Log4j/2.14.1"

    def test_empty_list(self):
        assert get_cves_for_asset_technologies([]) == []
