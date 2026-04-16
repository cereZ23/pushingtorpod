"""Tests for remediation playbook service."""

from __future__ import annotations

from app.services.remediation_playbook import get_playbook, get_all_playbook_titles


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
