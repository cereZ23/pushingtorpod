"""Sprint 1: the pure nuclei-template endpoint classifier.

host_only = base scan already covers it; endpoint_sensitive = must run on the discovered
endpoint; unknown = fail-closed (never admitted to the endpoint pass without analysis).
"""

from __future__ import annotations

from app.services.endpoint_template_classifier import (
    ENDPOINT_SENSITIVE,
    HOST_ONLY,
    UNKNOWN,
    classify_nuclei_template,
)


def _cat(doc):
    return classify_nuclei_template(doc).category


# --- host_only ---------------------------------------------------------------


def test_dns_template_is_host_only():
    assert _cat({"id": "caa", "info": {"severity": "info"}, "dns": [{"name": "{{FQDN}}"}]}) == HOST_ONLY


def test_network_and_ssl_are_host_only():
    assert _cat({"id": "x", "network": [{"host": ["{{Hostname}}"]}]}) == HOST_ONLY
    assert _cat({"id": "x", "ssl": [{"address": "{{Host}}:{{Port}}"}]}) == HOST_ONLY


def test_baseurl_with_appended_path_is_host_only():
    # brings its own fixed path → the base scan (BaseURL=host) covers the host-root variant
    assert _cat({"id": "grafana", "http": [{"path": ["{{BaseURL}}/login"]}]}) == HOST_ONLY


def test_rooturl_path_is_host_only():
    assert _cat({"id": "x", "http": [{"path": ["{{RootURL}}/api/v1/status"]}]}) == HOST_ONLY


def test_legacy_requests_key_is_supported():
    assert _cat({"id": "x", "requests": [{"path": ["{{BaseURL}}/admin"]}]}) == HOST_ONLY


def test_raw_host_relative_request_line_is_host_only():
    raw = "GET /actuator/env HTTP/1.1\nHost: {{Hostname}}\n"
    assert _cat({"id": "x", "http": [{"raw": [raw]}]}) == HOST_ONLY


# --- endpoint_sensitive ------------------------------------------------------


def test_baseurl_as_is_is_endpoint_sensitive():
    assert _cat({"id": "x", "http": [{"path": ["{{BaseURL}}"]}]}) == ENDPOINT_SENSITIVE
    assert _cat({"id": "x", "http": [{"path": ["{{BaseURL}}/"]}]}) == ENDPOINT_SENSITIVE


def test_baseurl_with_only_query_is_endpoint_sensitive():
    assert _cat({"id": "x", "http": [{"path": ["{{BaseURL}}?q=FUZZ"]}]}) == ENDPOINT_SENSITIVE


def test_fuzzing_block_is_endpoint_sensitive():
    assert _cat({"id": "x", "http": [{"fuzzing": [{"part": "query"}]}]}) == ENDPOINT_SENSITIVE


def test_dast_or_fuzz_tag_is_endpoint_sensitive():
    doc = {"id": "x", "info": {"tags": "dast,cve"}, "http": [{"path": ["{{BaseURL}}/fixed"]}]}
    assert _cat(doc) == ENDPOINT_SENSITIVE  # fuzz tag wins over the appended path


def test_any_base_bare_path_wins_over_appended():
    doc = {"id": "x", "http": [{"path": ["{{BaseURL}}/login", "{{BaseURL}}"]}]}
    assert _cat(doc) == ENDPOINT_SENSITIVE


# --- unknown (fail-closed) ---------------------------------------------------


def test_opaque_protocols_are_unknown():
    assert _cat({"id": "x", "headless": [{"steps": []}]}) == UNKNOWN
    assert _cat({"id": "x", "code": [{"engine": ["python"]}]}) == UNKNOWN
    assert _cat({"id": "x", "javascript": [{"code": "x"}]}) == UNKNOWN


def test_http_mixed_with_opaque_is_unknown():
    assert _cat({"id": "x", "http": [{"path": ["{{BaseURL}}/x"]}], "headless": [{"steps": []}]}) == UNKNOWN


def test_flow_template_is_classified_by_its_http_paths():
    # flow only orchestrates the template's own http requests → classify by the paths, NOT unknown
    doc = {"id": "x", "flow": "http(1) && http(2)", "http": [{"path": ["{{BaseURL}}/login"]}]}
    assert _cat(doc) == HOST_ONLY
    doc2 = {"id": "x", "flow": "http(1)", "http": [{"path": ["{{BaseURL}}"]}]}
    assert _cat(doc2) == ENDPOINT_SENSITIVE


def test_flow_plus_javascript_stays_unknown():
    # a genuinely opaque protocol alongside flow/http is still unknown
    doc = {"id": "x", "flow": "js(1)", "http": [{"path": ["{{BaseURL}}/x"]}], "javascript": [{"code": "1"}]}
    assert _cat(doc) == UNKNOWN


def test_workflows_is_opaque_unknown():
    assert _cat({"id": "x", "workflows": [{"template": "other.yaml"}]}) == UNKNOWN


def test_unknown_variable_in_baseurl_suffix_is_unknown():
    # {{BaseURL}}{{SomePath}} — the appended part depends on an unresolved variable → unknown
    assert _cat({"id": "x", "http": [{"path": ["{{BaseURL}}{{SomePath}}"]}]}) == UNKNOWN
    assert _cat({"id": "x", "http": [{"path": ["{{BaseURL}}/{{dir}}/x"]}]}) == UNKNOWN


def test_variable_only_in_query_is_still_endpoint_sensitive():
    # a variable in the QUERY (not the path) is fine — it still tests the given endpoint as-is
    assert _cat({"id": "x", "http": [{"path": ["{{BaseURL}}?q={{payload}}"]}]}) == ENDPOINT_SENSITIVE


# --- semantic overrides (fix 3) ----------------------------------------------


def test_takeover_family_is_host_only_despite_baseurl_as_is():
    # subdomain-takeover templates hit {{BaseURL}} as-is but are host/domain-level → host_only
    doc = {"id": "azure-takeover", "info": {"tags": "takeover"}, "http": [{"path": ["{{BaseURL}}"]}]}
    assert _cat(doc) == HOST_ONLY


def test_takeover_tag_among_others_still_host_only():
    doc = {"id": "x", "info": {"tags": ["takeover", "cloud"]}, "http": [{"path": ["{{BaseURL}}"]}]}
    assert _cat(doc) == HOST_ONLY


def test_unknown_url_variable_is_unknown():
    assert _cat({"id": "x", "http": [{"path": ["{{Hostname}}/x"]}]}) == UNKNOWN


def test_mixed_known_and_other_is_unknown_fail_closed():
    # one host_only path + one unparseable → fail-closed to unknown, never guess
    doc = {"id": "x", "http": [{"path": ["{{BaseURL}}/login"]}, {"path": ["{{Hostname}}/x"]}]}
    assert _cat(doc) == UNKNOWN


def test_no_request_block_is_unknown():
    assert _cat({"id": "x", "info": {"severity": "info"}}) == UNKNOWN


def test_malformed_request_entry_is_unknown():
    assert _cat({"id": "x", "http": ["not-a-dict"]}) == UNKNOWN


def test_non_mapping_is_unknown():
    assert _cat("not a template") == UNKNOWN
    assert _cat(None) == UNKNOWN


# --- determinism -------------------------------------------------------------


def test_classification_is_deterministic():
    doc = {"id": "x", "http": [{"path": ["{{BaseURL}}/a", "{{RootURL}}/b"]}]}
    results = {classify_nuclei_template(doc).category for _ in range(5)}
    assert results == {HOST_ONLY}
