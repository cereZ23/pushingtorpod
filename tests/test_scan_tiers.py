"""The shared per-tier scan config (single source of truth for detection.py + the report)."""

from __future__ import annotations

from types import SimpleNamespace

from app.services.scan_tiers import (
    TIER_HTTP_STOCK_ROOTS,
    TIER_SEVERITY,
    http_stock_roots,
    nuclei_relevant_flags,
    resolve_endpoint_knobs,
    tier_severity,
)


_KNOB_SETTINGS = SimpleNamespace(
    nuclei_http_endpoint_batch_size=25,
    nuclei_http_endpoint_batch_timeout_seconds=180,
    nuclei_http_endpoint_budget_seconds=600,
    nuclei_http_endpoint_max_per_host=40,
    nuclei_http_endpoint_batch_size_t2=3,
    nuclei_http_endpoint_batch_timeout_seconds_t2=181,
    nuclei_http_endpoint_budget_seconds_t2=900,
    nuclei_http_endpoint_max_per_host_t2=10,
)


def test_resolve_endpoint_knobs_tier2_uses_t2_values():
    assert resolve_endpoint_knobs(_KNOB_SETTINGS, 2) == {
        "batch_size": 3,
        "batch_timeout_seconds": 181,
        "budget_seconds": 900,
        "max_per_host": 10,
    }


def test_resolve_endpoint_knobs_tier1_uses_global_values():
    assert resolve_endpoint_knobs(_KNOB_SETTINGS, 1) == {
        "batch_size": 25,
        "batch_timeout_seconds": 180,
        "budget_seconds": 600,
        "max_per_host": 40,
    }


def test_resolve_endpoint_knobs_other_tiers_fall_back_to_global():
    # Only tier 2 is special; every other tier keeps T1's baseline unchanged.
    assert resolve_endpoint_knobs(_KNOB_SETTINGS, 3) == resolve_endpoint_knobs(_KNOB_SETTINGS, 1)


def test_nuclei_relevant_flags_all_off_by_default():
    # capabilities mirror the REAL CLI flags (not roots): prod passes none of -code/-headless/-dast/
    # -esc, so those are always false regardless of tier/roots.
    assert nuclei_relevant_flags(interactsh_enabled=False) == {
        "code": "false",
        "headless": "false",
        "dast": "false",
        "self_contained": "false",
        "interactsh": "false",
    }


def test_nuclei_relevant_flags_dast_not_inferred_from_roots():
    # selecting a dast/ root must NOT declare dast enabled — nuclei needs -dast, which we don't pass
    assert nuclei_relevant_flags(interactsh_enabled=False)["dast"] == "false"


def test_nuclei_relevant_flags_interactsh_toggle():
    assert nuclei_relevant_flags(interactsh_enabled=True)["interactsh"] == "true"
    assert nuclei_relevant_flags(interactsh_enabled=False)["interactsh"] == "false"


def test_t1_roots_pinned():
    assert http_stock_roots(1) == [
        "http/cves/",
        "http/exposed-panels/",
        "http/takeovers/",
        "http/default-logins/",
        "http/exposures/",
        "http/honeypot/",
        "http/cnvd/",
        "http/technologies/wordpress/",
        "http/technologies/eol/",
        "ssl/",
    ]


def test_t1_severity_pinned():
    assert tier_severity(1) == ["critical", "high", "medium"]
    assert tier_severity(3) == ["critical", "high", "medium", "low"]


def test_returned_lists_are_copies():
    r = http_stock_roots(1)
    r.append("x")
    assert "x" not in http_stock_roots(1)  # mutating the result must not mutate the source
    s = tier_severity(1)
    s.append("info")
    assert "info" not in tier_severity(1)


def test_unknown_tier_defaults():
    assert http_stock_roots(99) == TIER_HTTP_STOCK_ROOTS[2]
    assert tier_severity(99) == TIER_SEVERITY[1]
