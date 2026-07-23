"""Tests for remediation playbook service."""

from __future__ import annotations

from app.services.remediation_playbook import (
    build_verify_command,
    get_all_playbook_titles,
    get_playbook,
    synthesize_playbook,
)


class TestGetPlaybook:
    def test_docker_compose_matches(self):
        pb = get_playbook(template_id="exposed-docker-compose-credentials")
        assert pb is not None
        assert "docker-compose" in pb["title"].lower()
        assert "steps" in pb
        assert len(pb["steps"]) > 0
        assert "email_template" in pb

    def test_dockerfile_matches(self):
        pb = get_playbook(template_id="exposed-dockerfile", name="Exposed Dockerfile")
        assert pb is not None
        assert "dockerfile" in pb["title"].lower()

    def test_htaccess_matches(self):
        pb = get_playbook(template_id="exposed-htaccess")
        assert pb is not None
        assert "htaccess" in pb["title"].lower()

    def test_env_matches(self):
        pb = get_playbook(template_id="exposed-env-file")
        assert pb is not None
        assert "env" in pb["title"].lower()

    def test_hsts_matches(self):
        pb = get_playbook(template_id="HDR-004", name="Missing HSTS header")
        assert pb is not None
        assert "hsts" in pb["title"].lower()

    def test_login_http_matches(self):
        pb = get_playbook(name="Login page served over unencrypted HTTP")
        assert pb is not None
        assert "https" in pb["title"].lower() or "login" in pb["title"].lower()

    def test_wordpress_plugin_matches(self):
        pb = get_playbook(template_id="wp-ultimate-member-detect")
        assert pb is not None
        assert "wordpress" in pb["title"].lower() or "plugin" in pb["title"].lower()

    def test_cve_magento_matches(self):
        pb = get_playbook(
            template_id="CVE-2020-5777",
            name="Magento Mass Importer Remote Auth Bypass",
        )
        assert pb is not None

    def test_cert_expiring_matches(self):
        pb = get_playbook(template_id="TLS-001", name="Certificate expiring within 30 days")
        assert pb is not None
        assert "tls" in pb["title"].lower() or "cert" in pb["title"].lower()

    def test_security_headers_matches(self):
        pb = get_playbook(template_id="HDR-007", name="Missing Content-Security-Policy header")
        assert pb is not None

    def test_unknown_returns_none(self):
        pb = get_playbook(template_id="random-xyz-template-id")
        assert pb is None

    def test_empty_returns_none(self):
        assert get_playbook() is None


class TestPlaybookStructure:
    def test_all_playbooks_have_required_fields(self):
        titles = get_all_playbook_titles()
        assert len(titles) >= 8
        for t in titles:
            assert "title" in t
            assert "pattern" in t

    def test_playbook_steps_have_title(self):
        pb = get_playbook(template_id="exposed-docker-compose-credentials")
        for step in pb["steps"]:
            assert "title" in step
            assert step["title"]

    def test_playbook_has_verify_command(self):
        pb = get_playbook(template_id="exposed-docker-compose-credentials")
        assert "verify" in pb
        assert pb["verify"]


class TestBuildVerifyCommand:
    """Non-web controls must NOT be verified with an HTTP curl."""

    def test_service_exposure_uses_nc(self):
        cmd = build_verify_command("EXP-011", "host.example.com", {"port": 22})
        assert cmd == "nc -zvw3 host.example.com 22"

    def test_spf_uses_dig_txt(self):
        assert build_verify_command("EML-001", "example.com", {}) == "dig +short TXT example.com"

    def test_dmarc_uses_dig_dmarc(self):
        assert build_verify_command("EML-003", "example.com", {}) == "dig +short TXT _dmarc.example.com"

    def test_starttls_uses_openssl(self):
        cmd = build_verify_command("EML-006", "mail.example.com", {"port": 25})
        assert "openssl s_client -starttls smtp" in cmd
        assert "mail.example.com:25" in cmd

    def test_domain_expiry_uses_whois(self):
        assert build_verify_command("DOM-001", "example.com", {}).startswith("whois example.com")

    def test_tls_uses_openssl_dates(self):
        cmd = build_verify_command("TLS-005", "example.com", {})
        assert "openssl s_client -connect example.com:443" in cmd

    def test_no_curl_for_non_web_controls(self):
        for cid in ("EML-001", "EML-003", "EML-004", "DNS-001", "DOM-001", "ORIGIN-001"):
            cmd = build_verify_command(cid, "example.com", {})
            assert cmd is not None
            assert "curl" not in cmd

    def test_unknown_control_without_port_returns_none(self):
        assert build_verify_command("WHATEVER", "example.com", {}) is None


class TestSynthesizePlaybook:
    def test_surfaces_authored_remediation(self):
        pb = synthesize_playbook(
            control_id="EXP-011",
            name="SSH exposed on port 22",
            host="host.example.com",
            evidence={"port": 22, "remediation": "Restrict SSH to a VPN."},
        )
        assert pb is not None
        assert pb["steps"][0]["description"] == "Restrict SSH to a VPN."
        assert pb["verify"] == "nc -zvw3 host.example.com 22"
        assert pb["synthesized"] is True

    def test_none_when_no_remediation_and_no_verify(self):
        assert synthesize_playbook("WHATEVER", "x", "example.com", {}) is None

    def test_verify_only_still_synthesizes(self):
        pb = synthesize_playbook("EML-003", "No DMARC", "example.com", {})
        assert pb is not None
        assert pb["steps"] == []
        assert pb["verify"] == "dig +short TXT _dmarc.example.com"
