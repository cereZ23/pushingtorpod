"""
ISO 27001:2022 Annex A control mapping for EASM findings.

Maps scan findings (by template_id, source, or category) to ISO 27001
Annex A.8 (Technological) controls. Used to show compliance coverage
in customer audit reports and pre-sales demos.

Reference: ISO/IEC 27001:2022 Annex A
"""

from __future__ import annotations

import re
from typing import Optional

# ISO 27001:2022 Annex A.8 controls relevant to EASM
ISO_CONTROLS = {
    "A.8.8": {
        "name": "Management of technical vulnerabilities",
        "description": "Information about technical vulnerabilities shall be obtained, exposure evaluated and mitigated.",
    },
    "A.8.9": {
        "name": "Configuration management",
        "description": "Configurations of hardware, software, services and networks shall be established, documented, implemented, monitored and reviewed.",
    },
    "A.8.12": {
        "name": "Data leakage prevention",
        "description": "Data leakage prevention measures shall be applied to systems, networks and devices that process, store or transmit sensitive information.",
    },
    "A.8.15": {
        "name": "Logging",
        "description": "Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
    },
    "A.8.16": {
        "name": "Monitoring activities",
        "description": "Networks, systems and applications shall be monitored for anomalous behaviour.",
    },
    "A.8.20": {
        "name": "Network security",
        "description": "Networks and network devices shall be secured, managed and controlled to protect information in systems and applications.",
    },
    "A.8.21": {
        "name": "Security of network services",
        "description": "Security mechanisms, service levels and service requirements of network services shall be identified, implemented and monitored.",
    },
    "A.8.22": {
        "name": "Segregation of networks",
        "description": "Groups of information services, users and information systems shall be segregated in the organization's networks.",
    },
    "A.8.23": {
        "name": "Web filtering",
        "description": "Access to external websites shall be managed to reduce exposure to malicious content.",
    },
    "A.8.24": {
        "name": "Use of cryptography",
        "description": "Rules for the effective use of cryptography shall be defined and implemented.",
    },
    "A.8.26": {
        "name": "Application security requirements",
        "description": "Information security requirements shall be identified, specified and approved when developing or acquiring applications.",
    },
    "A.8.28": {
        "name": "Secure coding",
        "description": "Secure coding principles shall be applied to software development.",
    },
    "A.8.29": {
        "name": "Security testing in development and acceptance",
        "description": "Security testing processes shall be defined and implemented in the development life cycle.",
    },
    "A.5.23": {
        "name": "Information security for use of cloud services",
        "description": "Processes for acquisition, use, management and exit from cloud services shall be established.",
    },
    "A.5.37": {
        "name": "Documented operating procedures",
        "description": "Operating procedures for information processing facilities shall be documented and made available.",
    },
}


# Mapping rules: pattern → list of ISO control IDs
# Patterns are evaluated against: template_id, name, category, tags
_MAPPING_RULES: list[tuple[re.Pattern, list[str]]] = [
    # CVE / vulnerability scanning → A.8.8 (technical vulnerabilities)
    (re.compile(r"cve-\d{4}|-rce|-sqli|-xss|-ssrf|vulnerability|exploit", re.IGNORECASE), ["A.8.8", "A.8.29"]),
    # TLS/SSL findings → A.8.24 (cryptography)
    (re.compile(r"tls-|ssl-|cert|cipher|tls_|TLS-", re.IGNORECASE), ["A.8.24"]),
    # HTTP security headers → A.8.9 (configuration management) + A.8.23 (web filtering)
    (re.compile(r"hsts|csp|x-frame|x-content|referrer|HDR-|security.header", re.IGNORECASE), ["A.8.9", "A.8.23"]),
    # Exposed config files (docker, env, htaccess) → A.8.9 + A.8.12 (data leakage)
    (
        re.compile(r"docker|dockerfile|htaccess|exposed|config.exposure|\\.env|backup", re.IGNORECASE),
        ["A.8.9", "A.8.12"],
    ),
    # Email auth (SPF, DKIM, DMARC) → A.8.23 (web filtering — includes email)
    (re.compile(r"spf|dkim|dmarc|EML-", re.IGNORECASE), ["A.8.23"]),
    # DNS security → A.8.20 (network security)
    (re.compile(r"dnssec|DNS-|zone.transfer|dns.security", re.IGNORECASE), ["A.8.20"]),
    # Open ports / exposed services → A.8.20 + A.8.22 (segregation)
    (
        re.compile(r"exposed.service|open.port|exposed.panel|management.interface|EXP-", re.IGNORECASE),
        ["A.8.20", "A.8.22"],
    ),
    # Default credentials → A.8.8 + A.8.26 (application security)
    (re.compile(r"default.login|default.cred|default.password", re.IGNORECASE), ["A.8.8", "A.8.26"]),
    # Subdomain takeover → A.8.9 + A.5.23 (cloud services)
    (re.compile(r"takeover|TKO-|subdomain.takeover", re.IGNORECASE), ["A.8.9", "A.5.23"]),
    # Cloud exposure (S3, GCS, Azure) → A.5.23 + A.8.12
    (re.compile(r"aws|s3|gcs|azure|cloud.bucket|cloud.exposure", re.IGNORECASE), ["A.5.23", "A.8.12"]),
    # Web vulnerabilities (SQLi, XSS, etc.) → A.8.26 + A.8.28
    (re.compile(r"sql.injection|xss|command.injection|lfi|rfi", re.IGNORECASE), ["A.8.26", "A.8.28"]),
    # Logging / monitoring gaps → A.8.15 + A.8.16
    (re.compile(r"logging|audit.log|monitoring", re.IGNORECASE), ["A.8.15", "A.8.16"]),
]


def map_finding_to_controls(
    template_id: Optional[str] = None,
    name: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
) -> list[str]:
    """Map a finding to ISO 27001 Annex A control IDs.

    Args:
        template_id: Nuclei template ID or misconfig control ID
        name: Finding name
        category: Finding category (e.g., "TLS", "Security Headers")
        source: Finding source (nuclei, misconfig, manual)

    Returns:
        Sorted list of unique ISO control IDs (e.g., ["A.8.8", "A.8.24"]).
        Returns ["A.8.8"] as default if no rule matches (all findings map
        to vulnerability management as a minimum).
    """
    haystack = " ".join(filter(None, [template_id, name, category]))
    if not haystack:
        return ["A.8.8"]

    matched: set[str] = set()
    for pattern, controls in _MAPPING_RULES:
        if pattern.search(haystack):
            matched.update(controls)

    if not matched:
        # Default: all findings contribute to vulnerability management
        return ["A.8.8"]

    return sorted(matched)


def get_control_info(control_id: str) -> Optional[dict]:
    """Get control name and description by ID."""
    return ISO_CONTROLS.get(control_id)


def compute_compliance_coverage(findings: list) -> dict:
    """Compute ISO 27001 compliance coverage from findings list.

    Args:
        findings: List of Finding objects (must have template_id, name, source attrs)

    Returns:
        Dict with per-control metrics:
        {
            "A.8.8": {
                "name": "...",
                "findings_count": 42,
                "open": 30,
                "critical_high": 5,
                "status": "findings_present"  # or "clean"
            },
            ...
        }
    """
    coverage: dict[str, dict] = {}

    # Initialize all controls as "clean"
    for cid, info in ISO_CONTROLS.items():
        coverage[cid] = {
            "control_id": cid,
            "name": info["name"],
            "description": info["description"],
            "findings_count": 0,
            "open": 0,
            "critical_high": 0,
            "status": "clean",
        }

    for f in findings:
        tid = getattr(f, "template_id", None)
        name = getattr(f, "name", None)
        source = getattr(f, "source", None)
        controls = map_finding_to_controls(template_id=tid, name=name, source=source)

        severity = str(getattr(f, "severity", "")).lower()
        status = str(getattr(f, "status", "")).lower()

        for cid in controls:
            if cid not in coverage:
                continue
            coverage[cid]["findings_count"] += 1
            if "open" in status:
                coverage[cid]["open"] += 1
            if severity in ("critical", "high"):
                coverage[cid]["critical_high"] += 1
            coverage[cid]["status"] = "findings_present"

    return coverage
