"""Tests for pure helpers in app/tasks/pipeline_helpers.py.

Tests the scope-matching / parent-domain / IP-detection helpers that
have no DB dependency.
"""

from __future__ import annotations

from types import SimpleNamespace

from app.tasks.pipeline_helpers import (
    _extract_parent_domain,
    _is_hostname_in_scope,
    _is_in_scope,
    _is_ip,
    _scope_matches,
)


class TestIsHostnameInScope:
    def test_exact_match(self):
        assert _is_hostname_in_scope("example.com", {"example.com"}) is True

    def test_subdomain_in_scope(self):
        assert _is_hostname_in_scope("api.example.com", {"example.com"}) is True
        assert _is_hostname_in_scope("x.y.example.com", {"example.com"}) is True

    def test_different_tld_out_of_scope(self):
        assert _is_hostname_in_scope("example.org", {"example.com"}) is False

    def test_partial_match_not_in_scope(self):
        assert _is_hostname_in_scope("notexample.com", {"example.com"}) is False
        assert _is_hostname_in_scope("example.com.evil.net", {"example.com"}) is False

    def test_empty_scope_returns_false(self):
        assert _is_hostname_in_scope("example.com", set()) is False

    def test_case_insensitive(self):
        assert _is_hostname_in_scope("API.Example.COM", {"example.com"}) is True

    def test_trailing_dot_stripped(self):
        assert _is_hostname_in_scope("example.com.", {"example.com"}) is True

    def test_whitespace_stripped(self):
        assert _is_hostname_in_scope("  example.com  ", {"example.com"}) is True


class TestExtractParentDomain:
    def test_subdomain_to_root(self):
        assert _extract_parent_domain("api.example.com") == "example.com"

    def test_deep_subdomain(self):
        assert _extract_parent_domain("a.b.c.example.com") == "example.com"

    def test_root_domain_returns_none(self):
        assert _extract_parent_domain("example.com") is None

    def test_single_label_returns_none(self):
        assert _extract_parent_domain("localhost") is None

    def test_two_part_tld_uk(self):
        assert _extract_parent_domain("www.example.co.uk") == "example.co.uk"

    def test_two_part_tld_au(self):
        assert _extract_parent_domain("api.example.com.au") == "example.com.au"

    def test_co_uk_root_returns_none(self):
        # example.co.uk has exactly 3 labels — treated as root
        assert _extract_parent_domain("example.co.uk") is None

    def test_case_normalized(self):
        assert _extract_parent_domain("API.EXAMPLE.COM") == "example.com"

    def test_trailing_dot_handled(self):
        assert _extract_parent_domain("api.example.com.") == "example.com"


class TestIsIp:
    def test_ipv4(self):
        assert _is_ip("192.168.1.1") is True
        assert _is_ip("8.8.8.8") is True

    def test_ipv6(self):
        assert _is_ip("::1") is True

    def test_hostname_is_not_ip(self):
        assert _is_ip("example.com") is False

    def test_empty_not_ip(self):
        assert _is_ip("") is False

    def test_invalid_string_not_ip(self):
        assert _is_ip("999.999.999.999") is False


class TestScopeMatches:
    def test_domain_exact_match(self):
        scope = SimpleNamespace(match_type="domain", pattern="example.com")
        assert _scope_matches("example.com", scope) is True

    def test_domain_subdomain_match(self):
        scope = SimpleNamespace(match_type="domain", pattern="example.com")
        assert _scope_matches("api.example.com", scope) is True

    def test_domain_no_match(self):
        scope = SimpleNamespace(match_type="domain", pattern="example.com")
        assert _scope_matches("other.com", scope) is False

    def test_regex_match(self):
        scope = SimpleNamespace(match_type="regex", pattern=r"^api-.*\.example\.com$")
        assert _scope_matches("api-v2.example.com", scope) is True
        assert _scope_matches("www.example.com", scope) is False

    def test_ip_exact_match(self):
        scope = SimpleNamespace(match_type="ip", pattern="10.0.0.1")
        assert _scope_matches("10.0.0.1", scope) is True
        assert _scope_matches("10.0.0.2", scope) is False

    def test_cidr_match(self):
        scope = SimpleNamespace(match_type="cidr", pattern="10.0.0.0/8")
        assert _scope_matches("10.1.2.3", scope) is True
        assert _scope_matches("192.168.1.1", scope) is False

    def test_cidr_invalid_pattern(self):
        scope = SimpleNamespace(match_type="cidr", pattern="not-a-network")
        assert _scope_matches("10.0.0.1", scope) is False

    def test_unknown_match_type(self):
        scope = SimpleNamespace(match_type="unknown", pattern="whatever")
        assert _scope_matches("value", scope) is False


class TestIsInScope:
    def test_empty_scopes_all_in_scope(self):
        assert _is_in_scope("anything", []) is True

    def test_include_rule_match(self):
        include = SimpleNamespace(rule_type="include", match_type="domain", pattern="example.com")
        assert _is_in_scope("api.example.com", [include]) is True

    def test_include_rule_no_match(self):
        include = SimpleNamespace(rule_type="include", match_type="domain", pattern="example.com")
        assert _is_in_scope("other.com", [include]) is False

    def test_exclude_takes_precedence(self):
        include = SimpleNamespace(rule_type="include", match_type="domain", pattern="example.com")
        exclude = SimpleNamespace(rule_type="exclude", match_type="domain", pattern="private.example.com")
        assert _is_in_scope("private.example.com", [include, exclude]) is False
        # And other subdomains still in scope
        assert _is_in_scope("public.example.com", [include, exclude]) is True

    def test_only_exclude_rules_default_all_in(self):
        exclude = SimpleNamespace(rule_type="exclude", match_type="domain", pattern="bad.com")
        # With only exclude rules, anything not excluded stays in scope
        assert _is_in_scope("good.com", [exclude]) is True
        assert _is_in_scope("bad.com", [exclude]) is False
