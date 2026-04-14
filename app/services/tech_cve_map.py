"""
Technology-to-CVE mapping service.

Maps detected technology stacks (from httpx/fingerprinting) to known CVE
advisories. Uses a curated static map of common technologies and their
critical/high CVEs, supplemented by NVD CPE matching.

Usage:
    from app.services.tech_cve_map import get_cves_for_tech
    cves = get_cves_for_tech("Apache/2.4.49")
"""

from __future__ import annotations

import logging
import re
from typing import Optional

logger = logging.getLogger(__name__)

# Curated map: technology regex -> list of (CVE, severity, affected_versions, description)
# Focus on critical/high CVEs for commonly deployed software.
_TECH_CVE_MAP: list[tuple[re.Pattern, list[dict]]] = [
    # Apache HTTP Server
    (
        re.compile(r"Apache[/ ](2\.4\.(49|50))", re.IGNORECASE),
        [
            {
                "cve": "CVE-2021-41773",
                "severity": "critical",
                "description": "Path traversal and RCE in Apache 2.4.49-2.4.50",
            },
            {
                "cve": "CVE-2021-42013",
                "severity": "critical",
                "description": "Path traversal fix bypass in Apache 2.4.50",
            },
        ],
    ),
    # Nginx
    (
        re.compile(r"nginx/(1\.1[0-7]\.\d+|1\.[0-9]\.\d+)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2021-23017",
                "severity": "high",
                "description": "DNS resolver vulnerability in nginx < 1.21.0",
            },
        ],
    ),
    # jQuery
    (
        re.compile(r"jQuery[/ ](1\.\d+|2\.\d+|3\.[0-4]\.\d+)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2020-11022",
                "severity": "medium",
                "description": "XSS via HTML passed to DOM manipulation methods in jQuery < 3.5.0",
            },
        ],
    ),
    # WordPress
    (
        re.compile(r"WordPress[/ ](\d+\.\d+)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2024-6386",
                "severity": "critical",
                "description": "WordPress WPML plugin RCE via SSTI",
            },
        ],
    ),
    # PHP
    (
        re.compile(r"PHP/(8\.1\.\d+|7\.\d+\.\d+|5\.\d+\.\d+)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2024-4577",
                "severity": "critical",
                "description": "PHP CGI argument injection (Best Fit mapping bypass) in PHP < 8.3.8",
            },
        ],
    ),
    # Microsoft IIS
    (
        re.compile(r"Microsoft-IIS/(7\.\d+|8\.\d+|10\.0)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2021-31166",
                "severity": "critical",
                "description": "HTTP Protocol Stack RCE in IIS (wormable)",
            },
        ],
    ),
    # OpenSSL
    (
        re.compile(r"OpenSSL/(3\.0\.[0-6]|1\.1\.1[a-t]|1\.0\.)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2022-3602",
                "severity": "high",
                "description": "X.509 certificate verification buffer overflow in OpenSSL 3.0.x",
            },
        ],
    ),
    # Tomcat
    (
        re.compile(r"Apache.Tomcat/(9\.[0-3]\d\.\d+|8\.\d+\.\d+|7\.\d+\.\d+)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2024-50379",
                "severity": "critical",
                "description": "Apache Tomcat RCE via partial PUT (TOCTOU race condition)",
            },
        ],
    ),
    # Spring Boot
    (
        re.compile(r"Spring.Boot|spring-boot", re.IGNORECASE),
        [
            {
                "cve": "CVE-2022-22965",
                "severity": "critical",
                "description": "Spring4Shell: RCE via data binding on JDK 9+",
            },
        ],
    ),
    # Log4j (detected via headers/errors)
    (
        re.compile(r"Log4j|log4j/(2\.\d+)", re.IGNORECASE),
        [
            {
                "cve": "CVE-2021-44228",
                "severity": "critical",
                "description": "Log4Shell: RCE via JNDI injection in Log4j 2.x < 2.17.0",
            },
        ],
    ),
]


def get_cves_for_tech(tech_string: str) -> list[dict]:
    """Match a technology string against the curated CVE map.

    Args:
        tech_string: Technology identifier (e.g. "Apache/2.4.49", "PHP/8.1.2")

    Returns:
        List of matching CVE dicts with cve, severity, description.
    """
    if not tech_string:
        return []

    matches = []
    for pattern, cves in _TECH_CVE_MAP:
        if pattern.search(tech_string):
            matches.extend(cves)

    return matches


def get_cves_for_asset_technologies(technologies: list[str]) -> list[dict]:
    """Match multiple technology strings and return unique CVEs.

    Args:
        technologies: List of technology names from httpx/fingerprinting

    Returns:
        Deduplicated list of CVE dicts.
    """
    seen_cves: set[str] = set()
    results: list[dict] = []

    for tech in technologies:
        for cve in get_cves_for_tech(tech):
            if cve["cve"] not in seen_cves:
                seen_cves.add(cve["cve"])
                cve["matched_tech"] = tech
                results.append(cve)

    return results
