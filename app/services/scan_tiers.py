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
