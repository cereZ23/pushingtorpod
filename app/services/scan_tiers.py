"""Single source of truth for the per-tier nuclei HTTP-stock template roots and severity.

Both the pipeline (``app/tasks/pipeline_phases/detection.py``) and the Sprint-1 endpoint-classifier
report (``scripts/classify_t1_templates.py``) consume THIS module, so the report's applicable set
can never silently diverge from what the pass actually runs. Exclude-tags live in settings
(``nuclei_exclude_tags_t{1,2,3}``); combine all three (roots + severity + exclude-tags) to reproduce
the exact applicable set.

Rationale for the T1 set (Safe tier): keep the version/path-based CVE detection templates but exclude
the payload-senders via tags; technologies/wordpress+eol are kept for EOL/plugin detection. See
detection.py for the full per-directory reasoning.
"""

from __future__ import annotations

TIER_HTTP_STOCK_ROOTS: dict[int, list[str]] = {
    1: [
        "http/cves/",
        "http/exposed-panels/",
        "http/takeovers/",
        "http/default-logins/",
        "http/exposures/",
        "http/honeypot/",
        "http/cnvd/",
        "http/technologies/wordpress/",  # 239 WP plugin + theme detection
        "http/technologies/eol/",  # End-of-life software detection
        "ssl/",
    ],
    2: [
        "http/cves/",
        "http/exposed-panels/",
        "http/misconfiguration/",
        "http/default-logins/",
        "http/takeovers/",
        "http/exposures/",
        "http/vulnerabilities/",
        "http/iot/",
        "http/cnvd/",
        "http/miscellaneous/",
        "http/honeypot/",
        "http/technologies/",  # All 512 technology detection (WP, Apache, GraphQL, SAP, etc.)
        "cloud/",
        "ssl/",
        "javascript/",
    ],
    3: [
        "http/cves/",
        "http/exposed-panels/",
        "http/misconfiguration/",
        "http/default-logins/",
        "http/takeovers/",
        "http/exposures/",
        "http/vulnerabilities/",
        "http/iot/",
        "http/cnvd/",
        "http/miscellaneous/",
        "http/honeypot/",
        "http/technologies/",
        "cloud/",
        "ssl/",
        "javascript/",
        "dast/",  # Active payload injection — T3 only (requires authorization)
    ],
}

# Tier 3 excludes 'info' — those are mostly tech-detection templates (4000+) that duplicate Phase 6.
# Medium is included in every tier: many real exposure findings (Dockerfile, docker-compose,
# .htaccess, .env) are rated medium; excluding it from T1 caused false negatives on known vulns.
TIER_SEVERITY: dict[int, list[str]] = {
    1: ["critical", "high", "medium"],
    2: ["critical", "high", "medium"],
    3: ["critical", "high", "medium", "low"],
}


def http_stock_roots(tier: int) -> list[str]:
    """Template roots for the HTTP-stock pass at ``tier`` (defaults to tier 2, like the pipeline)."""
    return list(TIER_HTTP_STOCK_ROOTS.get(tier, TIER_HTTP_STOCK_ROOTS[2]))


def tier_severity(tier: int) -> list[str]:
    """Severity whitelist for ``tier`` (defaults to tier 1)."""
    return list(TIER_SEVERITY.get(tier, TIER_SEVERITY[1]))


def resolve_endpoint_knobs(settings, tier: int) -> dict[str, int]:
    """Per-tier http_endpoint knobs (Sprint T2). PURE — reads only the given ``settings``.

    Tier 2 uses the dedicated ``*_t2`` settings; EVERY other tier keeps the global knobs unchanged,
    so T1's validated baseline is untouched. Returns the dict shape ``run_http_endpoint_pass`` expects
    (batch_size / batch_timeout_seconds / budget_seconds / max_per_host).
    """
    if tier == 2:
        return dict(
            batch_size=settings.nuclei_http_endpoint_batch_size_t2,
            batch_timeout_seconds=settings.nuclei_http_endpoint_batch_timeout_seconds_t2,
            budget_seconds=settings.nuclei_http_endpoint_budget_seconds_t2,
            max_per_host=settings.nuclei_http_endpoint_max_per_host_t2,
        )
    return dict(
        batch_size=settings.nuclei_http_endpoint_batch_size,
        batch_timeout_seconds=settings.nuclei_http_endpoint_batch_timeout_seconds,
        budget_seconds=settings.nuclei_http_endpoint_budget_seconds,
        max_per_host=settings.nuclei_http_endpoint_max_per_host,
    )


def nuclei_relevant_flags(*, interactsh_enabled: bool) -> dict[str, str]:
    """The nuclei runtime capabilities a pass ENABLES, mirroring the ACTUAL nuclei CLI flags — NOT
    inferred from template roots (selecting ``dast/`` does NOT enable DAST; nuclei needs ``-dast``).
    Each maps to a real arg: code→-code, headless→-headless, dast→-dast, self_contained→-esc,
    interactsh→a configured ``-iserver`` (i.e. NOT ``-ni``). Recorded in the manifest's
    ``relevant_flags`` so the coverage catalog only counts detectors nuclei actually executes, and
    enabling a capability yields a DIFFERENT policy_hash.

    Prod's ``_build_nuclei_args`` passes NONE of -code/-headless/-dast/-esc → those are ``false``.
    Only interactsh can be on today (iff a server is configured). To enable another capability later,
    thread its boolean to BOTH ``_build_nuclei_args`` (emit the flag) AND here (declare it) together —
    declaring a capability the command doesn't actually pass is the divergence this prevents."""
    return {
        "code": "false",
        "headless": "false",
        "dast": "false",
        "self_contained": "false",
        "interactsh": "true" if interactsh_enabled else "false",
    }
