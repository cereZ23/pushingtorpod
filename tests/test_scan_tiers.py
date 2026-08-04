"""The shared per-tier scan config (single source of truth for detection.py + the report)."""

from __future__ import annotations

from app.services.scan_tiers import (
    TIER_HTTP_STOCK_ROOTS,
    TIER_SEVERITY,
    http_stock_roots,
    nuclei_relevant_flags,
    tier_severity,
)


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
