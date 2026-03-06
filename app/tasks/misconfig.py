"""
Misconfiguration Detection Engine - Phase 8

Implements 50 security controls across 10 categories using a decorator-based
control registry. Each control function inspects asset data (services, certificates,
HTTP headers, DNS records) and produces structured findings.

Categories and control IDs:
  - TLS Certificate Intelligence  (TLS-001 to TLS-010)
  - Security Headers              (HDR-001 to HDR-008)
  - Admin Panel Detection         (ADM-001 to ADM-004)
  - Cloud Misconfiguration        (CLD-001 to CLD-004)
  - Subdomain Takeover            (TKO-001 to TKO-003)
  - Email Security                (EML-001 to EML-005)
  - DNS Security                  (DNS-001 to DNS-004)
  - Information Disclosure        (INF-001 to INF-008)
  - Authentication                (AUTH-001 to AUTH-004)
  - Service Exposure              (EXP-001 to EXP-006)
"""

import logging
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from app.celery_app import celery
from app.database import SessionLocal
from app.models.database import (
    Asset,
    Finding,
    FindingSeverity,
    FindingStatus,
    Service,
)
from app.models.enrichment import Certificate
from app.services.dedup import compute_finding_fingerprint
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Control registry
# ---------------------------------------------------------------------------

_CONTROLS: dict[str, dict[str, Any]] = {}


def register(
    control_id: str,
    name: str,
    severity: str,
    confidence: float,
    category: str,
    asset_types: list[str],
) -> Callable:
    """Decorator to register a misconfiguration control.

    Args:
        control_id: Unique control identifier (e.g. "TLS-001").
        name: Human-readable control name.
        severity: Default severity (info, low, medium, high, critical).
        confidence: Default confidence score 0.0 - 1.0.
        category: Category grouping string.
        asset_types: List of applicable AssetType values (e.g. ["domain", "subdomain"]).

    Returns:
        The original check function, unmodified.
    """

    def decorator(func: Callable) -> Callable:
        _CONTROLS[control_id] = {
            "id": control_id,
            "name": name,
            "severity": severity,
            "confidence": confidence,
            "category": category,
            "asset_types": asset_types,
            "check_fn": func,
        }
        return func

    return decorator


def get_registered_controls() -> dict[str, dict[str, Any]]:
    """Return a copy of the control registry for inspection."""
    return dict(_CONTROLS)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

# Ports that are NOT HTTP/HTTPS web services (should not trigger header checks)
_NON_HTTP_PORTS: set[int] = {
    25, 110, 143, 465, 587, 993, 995,  # mail protocols
    21, 22, 53, 123, 389, 636, 3306, 5432,  # FTP, SSH, DNS, NTP, LDAP, DB
}

# Common HTTP/HTTPS ports — run header checks even if http_status is NULL
_HTTP_PORTS: set[int] = {80, 443, 8080, 8443}

# Protocols that indicate non-web services
_NON_HTTP_PROTOCOLS: set[str] = {
    'smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s',
    'ftp', 'ssh', 'dns', 'ldap', 'ldaps', 'mysql', 'postgres',
}


def _is_web_service(service: Service) -> bool:
    """Return True if the service is an HTTP/HTTPS web service.

    Filters out mail (SMTP/IMAP/POP3), database, and other non-web
    protocols that happen to have TLS but should not be checked for
    HTTP security headers.
    """
    if service.port in _NON_HTTP_PORTS:
        return False
    proto = (service.protocol or '').lower()
    if proto in _NON_HTTP_PROTOCOLS:
        return False
    return True


def _get_http_headers(service: Service) -> dict[str, str]:
    """Extract HTTP response headers from a service record.

    Headers are stored as a JSON column on the Service model.  The keys are
    normalised to lower-case so that look-ups are case-insensitive.
    """
    raw = service.http_headers
    if not raw:
        return {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
    if isinstance(raw, dict):
        return {k.lower(): v for k, v in raw.items()}
    return {}


# ---------------------------------------------------------------------------
# HSTS preload list cache (fetched from Chromium source)
# ---------------------------------------------------------------------------

_hsts_preload_cache: set[str] = set()
_hsts_preload_last_fetch: float = 0.0
_HSTS_PRELOAD_TTL = 86400  # refresh once per day


def _load_hsts_preload_list() -> set[str]:
    """Fetch the HSTS preload list from Chromium and cache it.

    Falls back to empty set on failure — preload checking is best-effort.
    """
    global _hsts_preload_cache, _hsts_preload_last_fetch
    now = time.monotonic()
    if _hsts_preload_cache and (now - _hsts_preload_last_fetch) < _HSTS_PRELOAD_TTL:
        return _hsts_preload_cache

    try:
        import urllib.request
        url = "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT"
        import base64
        with urllib.request.urlopen(url, timeout=30) as resp:
            raw = base64.b64decode(resp.read()).decode("utf-8")
        # Parse JSON (strip // comments first)
        lines = [
            line for line in raw.splitlines()
            if not line.strip().startswith("//")
        ]
        data = json.loads("\n".join(lines))
        entries = data.get("entries", [])
        domains = set()
        for entry in entries:
            name = entry.get("name", "")
            if name and entry.get("mode") == "force-https":
                domains.add(name.lower())
                if entry.get("include_subdomains"):
                    # Mark with a prefix so we can match subdomains
                    domains.add(f"*.{name.lower()}")
        _hsts_preload_cache = domains
        _hsts_preload_last_fetch = now
        logger.info("HSTS preload list loaded: %d entries", len(domains))
    except Exception:
        logger.debug("Failed to fetch HSTS preload list, using cached (%d entries)",
                     len(_hsts_preload_cache))
    return _hsts_preload_cache


def _is_hsts_preloaded(hostname: str) -> bool:
    """Check if a hostname is covered by the HSTS preload list."""
    preload = _load_hsts_preload_list()
    if not preload:
        return False
    host = hostname.lower()
    # Direct match
    if host in preload:
        return True
    # Check parent domain wildcard (e.g. *.autistici.org covers sub.autistici.org)
    parts = host.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if f"*.{parent}" in preload:
            return True
    return False


# Common patterns that indicate a default/catch-all vhost response
_DEFAULT_VHOST_PATTERNS: list[str] = [
    "your request could not be identified",
    "default web page",
    "welcome to nginx",
    "apache2 default page",
    "it works!",
    "test page",
    "default server",
    "no site configured",
    "domain not configured",
    "parking page",
    "coming soon",
    "under construction",
]


def _is_default_vhost(service: Service) -> bool:
    """Detect if a service response is from a default/catch-all virtual host.

    These responses don't represent the actual site configuration and
    should not generate security header findings.
    """
    title = (service.http_title or "").lower()
    for pattern in _DEFAULT_VHOST_PATTERNS:
        if pattern in title:
            return True
    # Also check if the response is a generic 404/403 with no meaningful content
    if service.http_status in (502, 503) and not service.http_title:
        return True
    return False


def _get_technologies(service: Service) -> list[str]:
    """Return the technology list for a service as a lowered string list."""
    techs = service.http_technologies or service.technologies
    if not techs:
        return []
    if isinstance(techs, str):
        try:
            techs = json.loads(techs)
        except (json.JSONDecodeError, TypeError):
            return []
    if isinstance(techs, list):
        return [str(t).lower() for t in techs]
    return []


def _severity_enum(value: str) -> FindingSeverity:
    """Map a severity string to the FindingSeverity enum."""
    mapping = {
        "info": FindingSeverity.INFO,
        "low": FindingSeverity.LOW,
        "medium": FindingSeverity.MEDIUM,
        "high": FindingSeverity.HIGH,
        "critical": FindingSeverity.CRITICAL,
    }
    return mapping.get(value.lower(), FindingSeverity.INFO)


# ---------------------------------------------------------------------------
# TLS Certificate Intelligence (TLS-001 .. TLS-010)
# ---------------------------------------------------------------------------

@register(
    control_id="TLS-001",
    name="Certificate expiring within 30 days",
    severity="high",
    confidence=0.95,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect certificates that will expire within 30 days."""
    # ACME providers auto-renew at ~30 days; only alert if renewal seems stuck
    ACME_ISSUERS = (
        "let's encrypt", "letsencrypt", "r3", "r10", "r11", "e5", "e6",
        "zerossl", "buypass", "google trust services",
    )

    findings: list[dict] = []
    for cert in certificates:
        days_left = cert.days_until_expiry
        if days_left is None:
            continue
        if days_left <= 0:
            continue  # handled by TLS-006 (expired cert check)

        issuer_lower = (cert.issuer or "").lower()
        is_acme = any(acme in issuer_lower for acme in ACME_ISSUERS)

        if is_acme:
            # ACME auto-renew: only alert if renewal appears stuck (<7 days)
            if days_left > 7:
                continue
            sev = "critical" if days_left <= 3 else "high"
        else:
            # Manual renewal: alert at 30 days with graduated severity
            if days_left > 30:
                continue
            if days_left <= 7:
                sev = "critical"
            elif days_left <= 14:
                sev = "high"
            else:
                sev = "medium"

        acme_note = " (ACME auto-renewal may have failed)" if is_acme else ""
        findings.append({
            "name": f"TLS certificate expires in {days_left} days{acme_note}",
            "severity": sev,
            "confidence": 0.90 if is_acme else 0.95,
            "evidence": {
                "subject_cn": cert.subject_cn,
                "not_after": str(cert.not_after),
                "days_until_expiry": days_left,
                "issuer": cert.issuer,
                "auto_renew_expected": is_acme,
            },
            "control_id": "TLS-001",
            "finding_key": f"TLS-001:{asset.identifier}:{cert.serial_number}",
            "remediation": (
                "Check that the ACME client (certbot/acme.sh) is running and the "
                "renewal cron/timer is active. Verify DNS and HTTP-01 challenge access."
                if is_acme else
                "Renew the TLS certificate before expiration. Consider using "
                "automated certificate management (e.g. Let's Encrypt with "
                "certbot or ACME protocol) to prevent future lapses."
                ),
            })
    return findings


@register(
    control_id="TLS-002",
    name="Weak TLS version (< TLSv1.2)",
    severity="high",
    confidence=0.90,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect services using TLS versions older than 1.2."""
    weak_versions = {"tlsv1.0", "tlsv1", "tls1.0", "tls1", "sslv3", "sslv2", "tlsv1.1", "tls1.1"}
    findings: list[dict] = []
    for svc in services:
        if not svc.tls_version:
            continue
        version_lower = svc.tls_version.strip().lower().replace(" ", "")
        if version_lower in weak_versions:
            findings.append({
                "name": f"Weak TLS version: {svc.tls_version}",
                "severity": "high",
                "confidence": 0.90,
                "evidence": {
                    "port": svc.port,
                    "tls_version": svc.tls_version,
                    "product": svc.product,
                },
                "control_id": "TLS-002",
                "finding_key": f"TLS-002:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Disable TLSv1.0 and TLSv1.1 on this service and enforce "
                    "a minimum of TLSv1.2. Prefer TLSv1.3 where possible."
                ),
            })
    return findings


@register(
    control_id="TLS-003",
    name="Missing HSTS header on HTTPS service",
    severity="medium",
    confidence=0.85,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_003(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect HTTPS services that do not send Strict-Transport-Security."""
    # Skip if the domain is in the HSTS preload list (browsers enforce HTTPS
    # automatically regardless of the header).
    if _is_hsts_preloaded(asset.identifier):
        return []
    findings: list[dict] = []
    for svc in services:
        if not svc.has_tls or not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        if "strict-transport-security" not in headers:
            findings.append({
                "name": "Missing HSTS header on HTTPS service",
                "severity": "medium",
                "confidence": 0.85,
                "evidence": {
                    "port": svc.port,
                    "url": svc.redirect_url or f"https://{asset.identifier}:{svc.port}",
                },
                "control_id": "TLS-003",
                "finding_key": f"TLS-003:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Add the Strict-Transport-Security header with a max-age of "
                    "at least 31536000 (1 year). Include 'includeSubDomains' if "
                    "all subdomains also support HTTPS."
                ),
            })
    return findings


@register(
    control_id="TLS-004",
    name="Self-signed certificate detected",
    severity="medium",
    confidence=0.95,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_004(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect self-signed certificates."""
    findings: list[dict] = []
    for cert in certificates:
        if cert.is_self_signed:
            findings.append({
                "name": "Self-signed TLS certificate",
                "severity": "medium",
                "confidence": 0.95,
                "evidence": {
                    "subject_cn": cert.subject_cn,
                    "issuer": cert.issuer,
                    "serial_number": cert.serial_number,
                },
                "control_id": "TLS-004",
                "finding_key": f"TLS-004:{asset.identifier}:{cert.serial_number}",
                "remediation": (
                    "Replace the self-signed certificate with one issued by a "
                    "trusted Certificate Authority. Self-signed certificates "
                    "are not trusted by browsers and clients."
                ),
            })
    return findings


@register(
    control_id="TLS-007",
    name="Expired TLS certificate",
    severity="critical",
    confidence=0.99,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_007(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect expired certificates."""
    findings: list[dict] = []
    for cert in certificates:
        if cert.is_expired:
            findings.append({
                "name": "Expired TLS certificate",
                "severity": "critical",
                "confidence": 0.99,
                "evidence": {
                    "subject_cn": cert.subject_cn,
                    "not_after": str(cert.not_after),
                    "days_until_expiry": cert.days_until_expiry,
                    "issuer": cert.issuer,
                },
                "control_id": "TLS-007",
                "finding_key": f"TLS-007:{asset.identifier}:{cert.serial_number}",
                "remediation": (
                    "Immediately renew the expired certificate. An expired "
                    "certificate causes browsers to display security warnings "
                    "and may break automated integrations."
                ),
            })
    return findings


@register(
    control_id="TLS-008",
    name="Certificate CN/SAN mismatch",
    severity="high",
    confidence=0.80,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_008(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect certificates where the CN and SANs do not cover the asset hostname."""
    findings: list[dict] = []
    hostname = asset.identifier.lower()

    for cert in certificates:
        covered = False
        # Check subject CN
        cn = (cert.subject_cn or "").lower()
        if cn == hostname or (cn.startswith("*.") and hostname.endswith(cn[1:])):
            covered = True

        # Check SANs
        if not covered and cert.san_domains:
            san_list = cert.san_domains if isinstance(cert.san_domains, list) else []
            for san in san_list:
                san_lower = str(san).lower()
                if san_lower == hostname:
                    covered = True
                    break
                if san_lower.startswith("*.") and hostname.endswith(san_lower[1:]):
                    covered = True
                    break

        if not covered:
            findings.append({
                "name": f"Certificate does not match hostname {hostname}",
                "severity": "high",
                "confidence": 0.80,
                "evidence": {
                    "hostname": hostname,
                    "subject_cn": cert.subject_cn,
                    "san_domains": cert.san_domains,
                    "serial_number": cert.serial_number,
                },
                "control_id": "TLS-008",
                "finding_key": f"TLS-008:{asset.identifier}:{cert.serial_number}",
                "remediation": (
                    "Reissue the certificate with a Subject Alternative Name "
                    "that covers this hostname, or deploy the correct certificate "
                    "for this service."
                ),
            })
    return findings


@register(
    control_id="TLS-009",
    name="Weak certificate signature algorithm",
    severity="high",
    confidence=0.90,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_009(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect certificates using weak signature algorithms (MD5, SHA-1)."""
    findings: list[dict] = []
    for cert in certificates:
        if cert.has_weak_signature:
            findings.append({
                "name": f"Weak signature algorithm: {cert.signature_algorithm}",
                "severity": "high",
                "confidence": 0.90,
                "evidence": {
                    "subject_cn": cert.subject_cn,
                    "signature_algorithm": cert.signature_algorithm,
                    "serial_number": cert.serial_number,
                },
                "control_id": "TLS-009",
                "finding_key": f"TLS-009:{asset.identifier}:{cert.serial_number}",
                "remediation": (
                    "Reissue the certificate using SHA-256 or stronger. MD5 and "
                    "SHA-1 signatures are considered cryptographically broken."
                ),
            })
    return findings


@register(
    control_id="TLS-005",
    name="Weak key size (< 2048 bits RSA)",
    severity="medium",
    confidence=0.90,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_005(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect certificates with RSA key sizes below 2048 bits."""
    findings: list[dict] = []
    for cert in certificates:
        algo = (cert.public_key_algorithm or "").upper()
        bits = cert.public_key_bits
        if algo == "RSA" and bits is not None and bits < 2048:
            findings.append({
                "name": f"Weak RSA key size: {bits} bits",
                "severity": "medium",
                "confidence": 0.90,
                "evidence": {
                    "subject_cn": cert.subject_cn,
                    "public_key_algorithm": cert.public_key_algorithm,
                    "public_key_bits": bits,
                },
                "control_id": "TLS-005",
                "finding_key": f"TLS-005:{asset.identifier}:{cert.serial_number}",
                "remediation": (
                    "Reissue the certificate with an RSA key of at least 2048 "
                    "bits, or migrate to ECDSA P-256 or higher for better "
                    "performance and equivalent security."
                ),
            })
    return findings


@register(
    control_id="TLS-006",
    name="Wildcard certificate on sensitive service",
    severity="low",
    confidence=0.60,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_006(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Flag wildcard certificates which increase blast radius if compromised."""
    findings: list[dict] = []
    for cert in certificates:
        if cert.is_wildcard:
            findings.append({
                "name": "Wildcard certificate in use",
                "severity": "low",
                "confidence": 0.60,
                "evidence": {
                    "subject_cn": cert.subject_cn,
                    "san_domains": cert.san_domains,
                },
                "control_id": "TLS-006",
                "finding_key": f"TLS-006:{asset.identifier}:{cert.serial_number}",
                "remediation": (
                    "Consider using dedicated certificates per service instead "
                    "of wildcard certificates to limit blast radius if a "
                    "private key is compromised."
                ),
            })
    return findings


@register(
    control_id="TLS-010",
    name="Certificate transparency log missing",
    severity="info",
    confidence=0.50,
    category="TLS Certificate Intelligence",
    asset_types=["domain", "subdomain"],
)
def check_tls_010(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Flag certificates that may not appear in CT logs (heuristic check)."""
    findings: list[dict] = []
    for cert in certificates:
        raw = cert.raw_data or {}
        if isinstance(raw, str):
            try:
                raw = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                raw = {}
        sct_present = raw.get("sct_list") or raw.get("signed_certificate_timestamps")
        if not sct_present and not cert.is_self_signed:
            findings.append({
                "name": "No SCT (Signed Certificate Timestamp) detected",
                "severity": "info",
                "confidence": 0.50,
                "evidence": {
                    "subject_cn": cert.subject_cn,
                    "issuer": cert.issuer,
                },
                "control_id": "TLS-010",
                "finding_key": f"TLS-010:{asset.identifier}:{cert.serial_number}",
                "remediation": (
                    "Ensure the CA embeds Signed Certificate Timestamps (SCTs) "
                    "for Certificate Transparency compliance."
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Security Headers (HDR-001 .. HDR-008)
# ---------------------------------------------------------------------------

@register(
    control_id="HDR-001",
    name="Missing X-Frame-Options header",
    severity="medium",
    confidence=0.85,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect web services missing X-Frame-Options, risking clickjacking."""
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        # Skip plain HTTP — missing headers are moot without TLS
        if not svc.has_tls:
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        if "x-frame-options" not in headers:
            findings.append({
                "name": "Missing X-Frame-Options header",
                "severity": "medium",
                "confidence": 0.85,
                "evidence": {
                    "port": svc.port,
                    "http_status": svc.http_status,
                    "url": svc.redirect_url or f"http://{asset.identifier}:{svc.port}",
                },
                "control_id": "HDR-001",
                "finding_key": f"HDR-001:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Add the X-Frame-Options header set to DENY or SAMEORIGIN "
                    "to prevent clickjacking attacks. Alternatively, use the "
                    "frame-ancestors directive in Content-Security-Policy."
                ),
            })
    return findings


@register(
    control_id="HDR-002",
    name="Missing X-Content-Type-Options header",
    severity="low",
    confidence=0.85,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect web services missing X-Content-Type-Options: nosniff."""
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        # Skip plain HTTP — missing headers are moot without TLS
        if not svc.has_tls:
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        if "x-content-type-options" not in headers:
            findings.append({
                "name": "Missing X-Content-Type-Options header",
                "severity": "low",
                "confidence": 0.85,
                "evidence": {
                    "port": svc.port,
                    "http_status": svc.http_status,
                },
                "control_id": "HDR-002",
                "finding_key": f"HDR-002:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Add 'X-Content-Type-Options: nosniff' to prevent MIME-type "
                    "sniffing attacks."
                ),
            })
    return findings


@register(
    control_id="HDR-003",
    name="Missing Content-Security-Policy header",
    severity="medium",
    confidence=0.80,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_003(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect web services without Content-Security-Policy."""
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        # Skip plain HTTP — missing headers are moot without TLS
        if not svc.has_tls:
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        if "content-security-policy" not in headers:
            findings.append({
                "name": "Missing Content-Security-Policy header",
                "severity": "medium",
                "confidence": 0.80,
                "evidence": {
                    "port": svc.port,
                    "http_status": svc.http_status,
                },
                "control_id": "HDR-003",
                "finding_key": f"HDR-003:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Implement a Content-Security-Policy header to mitigate XSS "
                    "and data injection attacks. Start with a report-only policy "
                    "to identify issues before enforcing."
                ),
            })
    return findings


@register(
    control_id="HDR-004",
    name="Missing Strict-Transport-Security header",
    severity="medium",
    confidence=0.85,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_004(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Header-centric check for missing HSTS (complementary to TLS-003)."""
    if _is_hsts_preloaded(asset.identifier):
        return []
    findings: list[dict] = []
    for svc in services:
        if not svc.has_tls or not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            findings.append({
                "name": "Missing HSTS header (Security Headers check)",
                "severity": "medium",
                "confidence": 0.85,
                "evidence": {"port": svc.port},
                "control_id": "HDR-004",
                "finding_key": f"HDR-004:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Set Strict-Transport-Security with max-age >= 31536000 and "
                    "includeSubDomains where applicable."
                ),
            })
        elif hsts:
            # Check for weak max-age (< 6 months)
            match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if match and int(match.group(1)) < 15768000:
                findings.append({
                    "name": f"HSTS max-age too short ({match.group(1)} seconds)",
                    "severity": "low",
                    "confidence": 0.75,
                    "evidence": {
                        "port": svc.port,
                        "hsts_value": hsts,
                        "max_age_seconds": int(match.group(1)),
                    },
                    "control_id": "HDR-004",
                    "finding_key": f"HDR-004-weak:{asset.identifier}:{svc.port}",
                    "remediation": (
                        "Increase the HSTS max-age to at least 31536000 seconds "
                        "(1 year) for adequate protection."
                    ),
                })
    return findings


@register(
    control_id="HDR-005",
    name="Missing Referrer-Policy header",
    severity="low",
    confidence=0.75,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_005(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect missing Referrer-Policy header."""
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        # Skip plain HTTP — missing headers are moot without TLS
        if not svc.has_tls:
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        if "referrer-policy" not in headers:
            findings.append({
                "name": "Missing Referrer-Policy header",
                "severity": "low",
                "confidence": 0.75,
                "evidence": {"port": svc.port},
                "control_id": "HDR-005",
                "finding_key": f"HDR-005:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Set Referrer-Policy to 'strict-origin-when-cross-origin' or "
                    "'no-referrer' to prevent leaking URL paths to third parties."
                ),
            })
    return findings


@register(
    control_id="HDR-006",
    name="Missing Permissions-Policy header",
    severity="info",
    confidence=0.70,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_006(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect missing Permissions-Policy (formerly Feature-Policy)."""
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        # Skip plain HTTP — missing headers are moot without TLS
        if not svc.has_tls:
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        if "permissions-policy" not in headers and "feature-policy" not in headers:
            findings.append({
                "name": "Missing Permissions-Policy header",
                "severity": "info",
                "confidence": 0.70,
                "evidence": {"port": svc.port},
                "control_id": "HDR-006",
                "finding_key": f"HDR-006:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Add a Permissions-Policy header to restrict browser features "
                    "like geolocation, camera, and microphone access."
                ),
            })
    return findings


@register(
    control_id="HDR-007",
    name="Permissive CORS configuration",
    severity="high",
    confidence=0.85,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_007(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect permissive CORS (Access-Control-Allow-Origin: *)."""
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        headers = _get_http_headers(svc)
        acao = headers.get("access-control-allow-origin", "")
        if acao.strip() == "*":
            # Check if credentials are also allowed (worst case)
            acac = headers.get("access-control-allow-credentials", "").lower()
            sev = "critical" if acac == "true" else "high"
            findings.append({
                "name": "Permissive CORS: Access-Control-Allow-Origin is wildcard",
                "severity": sev,
                "confidence": 0.85,
                "evidence": {
                    "port": svc.port,
                    "access_control_allow_origin": acao,
                    "access_control_allow_credentials": acac or "not set",
                },
                "control_id": "HDR-007",
                "finding_key": f"HDR-007:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Restrict Access-Control-Allow-Origin to specific trusted "
                    "origins instead of using the wildcard '*'. Never combine "
                    "'*' with Access-Control-Allow-Credentials: true."
                ),
            })
    return findings


@register(
    control_id="HDR-008",
    name="X-Powered-By header leaks technology",
    severity="low",
    confidence=0.90,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_008(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect X-Powered-By headers leaking framework or runtime info."""
    findings: list[dict] = []
    for svc in services:
        headers = _get_http_headers(svc)
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            findings.append({
                "name": f"X-Powered-By header reveals: {powered_by}",
                "severity": "low",
                "confidence": 0.90,
                "evidence": {
                    "port": svc.port,
                    "x_powered_by": powered_by,
                },
                "control_id": "HDR-008",
                "finding_key": f"HDR-008:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Remove the X-Powered-By header to reduce information "
                    "available to attackers for technology fingerprinting."
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Admin Panel Detection (ADM-001 .. ADM-004)
# ---------------------------------------------------------------------------

_ADMIN_PATH_PATTERNS = [
    r"/admin", r"/wp-admin", r"/administrator", r"/manager",
    r"/cpanel", r"/phpmyadmin", r"/adminer", r"/webmin",
]

_ADMIN_TITLE_PATTERNS = [
    r"admin\s*(panel|dashboard|console|login)",
    r"phpMyAdmin",
    r"cPanel",
    r"Webmin",
    r"Jenkins",
    r"Grafana",
    r"Kibana",
]


@register(
    control_id="ADM-001",
    name="Admin panel detected via HTTP title",
    severity="medium",
    confidence=0.75,
    category="Admin Panel Detection",
    asset_types=["domain", "subdomain"],
)
def check_adm_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect admin panels based on HTTP response title."""
    findings: list[dict] = []
    for svc in services:
        title = svc.http_title or ""
        for pattern in _ADMIN_TITLE_PATTERNS:
            if re.search(pattern, title, re.IGNORECASE):
                findings.append({
                    "name": f"Admin panel detected: {title[:100]}",
                    "severity": "medium",
                    "confidence": 0.75,
                    "evidence": {
                        "port": svc.port,
                        "http_title": title,
                        "matched_pattern": pattern,
                    },
                    "control_id": "ADM-001",
                    "finding_key": f"ADM-001:{asset.identifier}:{svc.port}",
                    "remediation": (
                        "Restrict access to admin panels using IP allowlists, "
                        "VPN, or zero-trust network access. Never expose admin "
                        "interfaces directly to the internet."
                    ),
                })
                break  # One finding per service
    return findings


@register(
    control_id="ADM-002",
    name="Default admin credentials page detected",
    severity="high",
    confidence=0.65,
    category="Admin Panel Detection",
    asset_types=["domain", "subdomain"],
)
def check_adm_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Flag services whose title suggests a default/setup page."""
    findings: list[dict] = []
    default_patterns = [
        r"setup wizard", r"initial setup", r"installation",
        r"first run", r"default password", r"getting started",
    ]
    for svc in services:
        title = (svc.http_title or "").lower()
        for pattern in default_patterns:
            if re.search(pattern, title, re.IGNORECASE):
                findings.append({
                    "name": f"Default setup/installation page exposed: {svc.http_title[:100]}",
                    "severity": "high",
                    "confidence": 0.65,
                    "evidence": {
                        "port": svc.port,
                        "http_title": svc.http_title,
                    },
                    "control_id": "ADM-002",
                    "finding_key": f"ADM-002:{asset.identifier}:{svc.port}",
                    "remediation": (
                        "Complete the application setup and remove or restrict "
                        "access to setup/installation pages."
                    ),
                })
                break
    return findings


# ---------------------------------------------------------------------------
# Cloud Misconfiguration (CLD-001 .. CLD-004)
# ---------------------------------------------------------------------------

_CLOUD_CNAME_PATTERNS = {
    "s3.amazonaws.com": "AWS S3",
    "cloudfront.net": "AWS CloudFront",
    "azurewebsites.net": "Azure App Service",
    "blob.core.windows.net": "Azure Blob Storage",
    "herokuapp.com": "Heroku",
    "firebaseapp.com": "Firebase",
    "appspot.com": "Google App Engine",
    "storage.googleapis.com": "Google Cloud Storage",
}


@register(
    control_id="CLD-001",
    name="Public cloud storage detected",
    severity="medium",
    confidence=0.70,
    category="Cloud Misconfiguration",
    asset_types=["domain", "subdomain"],
)
def check_cld_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect assets pointing to cloud storage services via CNAME or technology detection."""
    findings: list[dict] = []
    techs = set()
    for svc in services:
        techs.update(_get_technologies(svc))

    storage_indicators = {"amazon s3", "azure blob", "google cloud storage", "minio"}
    detected = storage_indicators & techs

    if detected:
        findings.append({
            "name": f"Public cloud storage detected: {', '.join(detected)}",
            "severity": "medium",
            "confidence": 0.70,
            "evidence": {
                "technologies_detected": list(detected),
                "hostname": asset.identifier,
            },
            "control_id": "CLD-001",
            "finding_key": f"CLD-001:{asset.identifier}",
            "remediation": (
                "Verify that the cloud storage bucket/container has appropriate "
                "access controls. Ensure public listing is disabled and "
                "sensitive data is not publicly accessible."
            ),
        })
    return findings


@register(
    control_id="CLD-002",
    name="CDN or cloud proxy detected without origin protection",
    severity="info",
    confidence=0.60,
    category="Cloud Misconfiguration",
    asset_types=["domain", "subdomain"],
)
def check_cld_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect CDN/proxy usage via headers or technology fingerprints."""
    findings: list[dict] = []
    cdn_indicators = {"cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "sucuri"}
    for svc in services:
        headers = _get_http_headers(svc)
        techs = _get_technologies(svc)
        server = (headers.get("server", "") + " " + (svc.web_server or "")).lower()
        all_signals = set(techs) | {server}
        detected = [cdn for cdn in cdn_indicators if any(cdn in s for s in all_signals)]
        if detected:
            findings.append({
                "name": f"CDN/proxy detected: {', '.join(detected)}",
                "severity": "info",
                "confidence": 0.60,
                "evidence": {
                    "port": svc.port,
                    "cdn_providers": detected,
                    "server_header": headers.get("server", ""),
                },
                "control_id": "CLD-002",
                "finding_key": f"CLD-002:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Ensure the origin server is not directly accessible, "
                    "bypassing the CDN. Use origin authentication headers "
                    "or IP allowlisting."
                ),
            })
            break  # One per asset
    return findings


# ---------------------------------------------------------------------------
# Subdomain Takeover (TKO-001 .. TKO-003)
# ---------------------------------------------------------------------------

_TAKEOVER_FINGERPRINTS = {
    "There isn't a GitHub Pages site here": "GitHub Pages",
    "NoSuchBucket": "AWS S3",
    "No such app": "Heroku",
    "Domain is not configured": "Netlify",
    "The request could not be satisfied": "AWS CloudFront",
    "Repository not found": "Bitbucket",
    "Sorry, this shop is currently unavailable": "Shopify",
    "Do you want to register": "Wordpress.com",
    "Project not found": "Surge.sh",
    "The feed has not been found": "Feedpress",
}


@register(
    control_id="TKO-001",
    name="Potential subdomain takeover (dangling CNAME)",
    severity="critical",
    confidence=0.70,
    category="Subdomain Takeover",
    asset_types=["subdomain"],
)
def check_tko_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect potential subdomain takeover via HTTP response body fingerprints."""
    findings: list[dict] = []

    # Check service response for takeover fingerprints
    for svc in services:
        title = (svc.http_title or "").strip()
        for fingerprint, provider in _TAKEOVER_FINGERPRINTS.items():
            if fingerprint.lower() in title.lower():
                findings.append({
                    "name": f"Potential subdomain takeover ({provider})",
                    "severity": "critical",
                    "confidence": 0.70,
                    "evidence": {
                        "hostname": asset.identifier,
                        "http_title": title,
                        "provider": provider,
                        "fingerprint_matched": fingerprint,
                        "port": svc.port,
                    },
                    "control_id": "TKO-001",
                    "finding_key": f"TKO-001:{asset.identifier}:{provider}",
                    "remediation": (
                        f"Remove the DNS record pointing to {provider} or "
                        f"reclaim the resource on {provider}. Dangling CNAMEs "
                        "can be hijacked by attackers to serve malicious content."
                    ),
                })
                break

    # Also check for NXDOMAIN-like indicators (no services at all with specific status codes)
    if not services:
        # Asset exists but has no services - could indicate a dangling record
        # This is low confidence since the asset might just not have been probed
        findings.append({
            "name": "Subdomain with no resolvable services (possible dangling record)",
            "severity": "medium",
            "confidence": 0.35,
            "evidence": {
                "hostname": asset.identifier,
                "services_count": 0,
            },
            "control_id": "TKO-001",
            "finding_key": f"TKO-001:nxdomain:{asset.identifier}",
            "remediation": (
                "Investigate whether this subdomain's DNS record points to an "
                "unclaimed resource. If unused, remove the DNS record."
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# Email Security (EML-001 .. EML-005)
# ---------------------------------------------------------------------------

@register(
    control_id="EML-001",
    name="Missing SPF record",
    severity="medium",
    confidence=0.60,
    category="Email Security",
    asset_types=["domain"],
)
def check_eml_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect domains without an SPF record.

    Note: This check relies on raw_metadata or DNS enrichment data stored on
    the asset. A full implementation requires querying DNS TXT records which
    is done during the DNS Resolution phase.  Here we inspect cached metadata.
    """
    findings: list[dict] = []
    metadata = _parse_raw_metadata(asset)
    dns_txt = metadata.get("dns_txt", [])

    has_spf = any("v=spf1" in str(txt).lower() for txt in dns_txt)

    if dns_txt and not has_spf:
        findings.append({
            "name": f"Missing SPF record for {asset.identifier}",
            "severity": "medium",
            "confidence": 0.60,
            "evidence": {
                "domain": asset.identifier,
                "txt_records": dns_txt[:5],
            },
            "control_id": "EML-001",
            "finding_key": f"EML-001:{asset.identifier}",
            "remediation": (
                "Add an SPF TXT record (e.g. 'v=spf1 include:_spf.google.com "
                "-all') to prevent email spoofing from this domain."
            ),
        })
    return findings


@register(
    control_id="EML-003",
    name="Missing DMARC record",
    severity="medium",
    confidence=0.60,
    category="Email Security",
    asset_types=["domain"],
)
def check_eml_003(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect domains without a DMARC record."""
    findings: list[dict] = []
    metadata = _parse_raw_metadata(asset)
    dns_txt = metadata.get("dns_txt", [])
    dmarc_txt = metadata.get("dmarc_txt", [])

    all_txt = dns_txt + dmarc_txt
    has_dmarc = any("v=dmarc1" in str(txt).lower() for txt in all_txt)

    if all_txt and not has_dmarc:
        findings.append({
            "name": f"Missing DMARC record for {asset.identifier}",
            "severity": "medium",
            "confidence": 0.60,
            "evidence": {
                "domain": asset.identifier,
            },
            "control_id": "EML-003",
            "finding_key": f"EML-003:{asset.identifier}",
            "remediation": (
                "Add a DMARC TXT record at _dmarc.{domain} (e.g. "
                "'v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com') "
                "to enable email authentication reporting and enforcement."
            ),
        })
    return findings


@register(
    control_id="EML-002",
    name="SPF record with permissive policy (+all)",
    severity="high",
    confidence=0.85,
    category="Email Security",
    asset_types=["domain"],
)
def check_eml_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect SPF records ending with +all (allows any sender)."""
    findings: list[dict] = []
    metadata = _parse_raw_metadata(asset)
    dns_txt = metadata.get("dns_txt", [])

    for txt in dns_txt:
        txt_str = str(txt).lower()
        if "v=spf1" in txt_str and "+all" in txt_str:
            findings.append({
                "name": "SPF record has permissive +all policy",
                "severity": "high",
                "confidence": 0.85,
                "evidence": {
                    "domain": asset.identifier,
                    "spf_record": str(txt),
                },
                "control_id": "EML-002",
                "finding_key": f"EML-002:{asset.identifier}",
                "remediation": (
                    "Change the SPF policy from '+all' to '-all' (hard fail) "
                    "or '~all' (soft fail) to prevent unauthorized email senders."
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# DNS Security (DNS-001 .. DNS-004)
# ---------------------------------------------------------------------------

@register(
    control_id="DNS-001",
    name="Zone transfer possible (AXFR)",
    severity="high",
    confidence=0.50,
    category="DNS Security",
    asset_types=["domain"],
)
def check_dns_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Flag domains where zone transfer metadata has been recorded."""
    findings: list[dict] = []
    metadata = _parse_raw_metadata(asset)
    if metadata.get("axfr_possible"):
        findings.append({
            "name": f"DNS zone transfer (AXFR) possible on {asset.identifier}",
            "severity": "high",
            "confidence": 0.50,
            "evidence": {
                "domain": asset.identifier,
                "nameservers": metadata.get("nameservers", []),
            },
            "control_id": "DNS-001",
            "finding_key": f"DNS-001:{asset.identifier}",
            "remediation": (
                "Restrict AXFR zone transfers to authorized secondary DNS "
                "servers only. Zone transfers expose the full DNS zone contents."
            ),
        })
    return findings


# ---------------------------------------------------------------------------
# Information Disclosure (INF-001 .. INF-008)
# ---------------------------------------------------------------------------

_VERSION_PATTERN = re.compile(
    r"(?:Apache|nginx|IIS|LiteSpeed|OpenResty|Caddy|lighttpd|Tomcat|Jetty)"
    r"[/\s]+([\d]+\.[\d]+[\.\d]*)",
    re.IGNORECASE,
)


@register(
    control_id="INF-001",
    name="Server version banner exposed",
    severity="low",
    confidence=0.90,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect Server headers that reveal software version numbers."""
    findings: list[dict] = []
    for svc in services:
        headers = _get_http_headers(svc)
        server = headers.get("server", "") or (svc.web_server or "")
        if _VERSION_PATTERN.search(server):
            findings.append({
                "name": f"Server version disclosed: {server[:120]}",
                "severity": "low",
                "confidence": 0.90,
                "evidence": {
                    "port": svc.port,
                    "server_header": server,
                },
                "control_id": "INF-001",
                "finding_key": f"INF-001:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Configure the web server to suppress version information "
                    "in the Server header. For nginx: 'server_tokens off;'. "
                    "For Apache: 'ServerTokens Prod'."
                ),
            })
    return findings


@register(
    control_id="INF-003",
    name="Directory listing enabled",
    severity="medium",
    confidence=0.80,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_003(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect directory listing via HTTP response title heuristics."""
    findings: list[dict] = []
    dir_listing_patterns = [
        r"Index of /",
        r"Directory listing for",
        r"Directory Listing",
        r"\[To Parent Directory\]",
    ]
    for svc in services:
        title = svc.http_title or ""
        for pattern in dir_listing_patterns:
            if re.search(pattern, title, re.IGNORECASE):
                findings.append({
                    "name": f"Directory listing enabled: {title[:100]}",
                    "severity": "medium",
                    "confidence": 0.80,
                    "evidence": {
                        "port": svc.port,
                        "http_title": title,
                    },
                    "control_id": "INF-003",
                    "finding_key": f"INF-003:{asset.identifier}:{svc.port}",
                    "remediation": (
                        "Disable directory listing on the web server. For "
                        "Apache: 'Options -Indexes'. For nginx: remove "
                        "'autoindex on' from the configuration."
                    ),
                })
                break
    return findings


@register(
    control_id="INF-005",
    name="Debug mode enabled",
    severity="high",
    confidence=0.75,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_005(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect debug mode indicators from headers and technology fingerprints."""
    findings: list[dict] = []
    debug_headers = ["x-debug-token", "x-debug-token-link", "x-debug"]
    debug_techs = ["django debug toolbar", "werkzeug debugger", "laravel debugbar"]

    for svc in services:
        headers = _get_http_headers(svc)
        techs = _get_technologies(svc)

        # Check debug headers
        debug_found = [h for h in debug_headers if h in headers]

        # Check technology fingerprints
        debug_tech_found = [t for t in debug_techs if t in " ".join(techs)]

        # Check title for common debug page patterns
        title = (svc.http_title or "").lower()
        debug_title = any(
            p in title
            for p in ["werkzeug debugger", "django debug", "debug toolbar", "stack trace"]
        )

        if debug_found or debug_tech_found or debug_title:
            findings.append({
                "name": "Debug mode appears to be enabled",
                "severity": "high",
                "confidence": 0.75,
                "evidence": {
                    "port": svc.port,
                    "debug_headers": debug_found,
                    "debug_technologies": debug_tech_found,
                    "debug_title": debug_title,
                    "http_title": svc.http_title,
                },
                "control_id": "INF-005",
                "finding_key": f"INF-005:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Disable debug mode in production. Debug endpoints expose "
                    "sensitive internals including source code, environment "
                    "variables, and database credentials."
                ),
            })
    return findings


@register(
    control_id="INF-002",
    name="Error page information leakage",
    severity="low",
    confidence=0.65,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect services returning detailed error pages (stack traces in title)."""
    findings: list[dict] = []
    error_patterns = [
        r"500 Internal Server Error",
        r"Application Error",
        r"Traceback \(most recent call",
        r"Fatal error",
        r"Unhandled Exception",
    ]
    for svc in services:
        title = svc.http_title or ""
        for pattern in error_patterns:
            if re.search(pattern, title, re.IGNORECASE):
                findings.append({
                    "name": f"Error page information leakage: {title[:100]}",
                    "severity": "low",
                    "confidence": 0.65,
                    "evidence": {
                        "port": svc.port,
                        "http_title": title,
                        "http_status": svc.http_status,
                    },
                    "control_id": "INF-002",
                    "finding_key": f"INF-002:{asset.identifier}:{svc.port}",
                    "remediation": (
                        "Configure custom error pages that do not expose stack "
                        "traces, internal paths, or software versions."
                    ),
                })
                break
    return findings


@register(
    control_id="INF-004",
    name="Sensitive file or path exposed",
    severity="medium",
    confidence=0.65,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_004(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect sensitive file exposure via crawled endpoint analysis.

    Checks the endpoints table for known sensitive paths like .env, .git,
    backup files, etc.
    """
    findings: list[dict] = []
    sensitive_patterns = [
        (r"\.env$", "Environment file (.env)"),
        (r"\.git/", "Git repository metadata"),
        (r"\.svn/", "SVN repository metadata"),
        (r"\.DS_Store", "macOS directory metadata"),
        (r"web\.config$", "IIS web.config"),
        (r"wp-config\.php", "WordPress configuration"),
        (r"\.htpasswd", "Apache password file"),
        (r"\.htaccess", "Apache configuration"),
        (r"phpinfo\.php", "PHP info page"),
        (r"server-status", "Apache server-status"),
    ]

    # Check crawled endpoints if available
    try:
        from app.models.enrichment import Endpoint
        endpoints = db.query(Endpoint).filter(
            Endpoint.asset_id == asset.id,
            Endpoint.status_code.in_([200, 301, 302, 403]),
        ).all()

        for ep in endpoints:
            path = ep.path or ep.url or ""
            for pattern, desc in sensitive_patterns:
                if re.search(pattern, path, re.IGNORECASE):
                    findings.append({
                        "name": f"Sensitive path exposed: {desc}",
                        "severity": "medium",
                        "confidence": 0.65,
                        "evidence": {
                            "url": ep.url,
                            "path": ep.path,
                            "status_code": ep.status_code,
                            "description": desc,
                        },
                        "control_id": "INF-004",
                        "finding_key": f"INF-004:{asset.identifier}:{path[:100]}",
                        "remediation": (
                            f"Block access to {desc} via web server configuration "
                            "rules. These files may contain sensitive credentials, "
                            "configuration data, or source code."
                        ),
                    })
                    break
    except Exception:
        # Endpoint model might not be available; skip silently
        pass

    return findings


# ---------------------------------------------------------------------------
# Authentication (AUTH-001 .. AUTH-004)
# ---------------------------------------------------------------------------

@register(
    control_id="AUTH-001",
    name="Login page served over HTTP",
    severity="high",
    confidence=0.80,
    category="Authentication",
    asset_types=["domain", "subdomain"],
)
def check_auth_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect login pages served without TLS encryption."""
    findings: list[dict] = []
    login_indicators = ["login", "sign in", "log in", "signin", "authenticate"]
    for svc in services:
        if svc.has_tls:
            continue
        title = (svc.http_title or "").lower()
        if any(indicator in title for indicator in login_indicators):
            findings.append({
                "name": "Login page served over unencrypted HTTP",
                "severity": "high",
                "confidence": 0.80,
                "evidence": {
                    "port": svc.port,
                    "http_title": svc.http_title,
                    "has_tls": False,
                },
                "control_id": "AUTH-001",
                "finding_key": f"AUTH-001:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Enable HTTPS for all pages handling authentication. "
                    "Credentials transmitted over HTTP can be intercepted "
                    "by network attackers."
                ),
            })
    return findings


@register(
    control_id="AUTH-002",
    name="Basic authentication without HTTPS",
    severity="high",
    confidence=0.85,
    category="Authentication",
    asset_types=["domain", "subdomain"],
)
def check_auth_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect HTTP Basic Auth on non-TLS services (credentials sent in cleartext)."""
    findings: list[dict] = []
    for svc in services:
        if svc.has_tls:
            continue
        headers = _get_http_headers(svc)
        www_auth = headers.get("www-authenticate", "").lower()
        if "basic" in www_auth:
            findings.append({
                "name": "HTTP Basic Authentication over unencrypted connection",
                "severity": "high",
                "confidence": 0.85,
                "evidence": {
                    "port": svc.port,
                    "www_authenticate": headers.get("www-authenticate", ""),
                    "http_status": svc.http_status,
                },
                "control_id": "AUTH-002",
                "finding_key": f"AUTH-002:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Enable HTTPS on this service. HTTP Basic Authentication "
                    "sends base64-encoded credentials which are trivially "
                    "decoded by network attackers."
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Service Exposure (EXP-001 .. EXP-006)
# ---------------------------------------------------------------------------

_DATABASE_PORTS = {
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
    9300: "Elasticsearch (transport)",
    5984: "CouchDB",
    7474: "Neo4j",
    8529: "ArangoDB",
    26257: "CockroachDB",
    1433: "MSSQL",
    1521: "Oracle",
}


@register(
    control_id="EXP-002",
    name="Database port exposed to internet",
    severity="critical",
    confidence=0.90,
    category="Service Exposure",
    asset_types=["domain", "subdomain", "ip"],
)
def check_exp_002(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect database services exposed on the internet."""
    findings: list[dict] = []
    for svc in services:
        if svc.port in _DATABASE_PORTS:
            db_name = _DATABASE_PORTS[svc.port]
            # Increase confidence if product name matches
            product_match = svc.product and db_name.lower() in (svc.product or "").lower()
            conf = 0.95 if product_match else 0.90
            findings.append({
                "name": f"{db_name} port {svc.port} exposed",
                "severity": "critical",
                "confidence": conf,
                "evidence": {
                    "port": svc.port,
                    "database": db_name,
                    "product": svc.product,
                    "version": svc.version,
                },
                "control_id": "EXP-002",
                "finding_key": f"EXP-002:{asset.identifier}:{svc.port}",
                "remediation": (
                    f"Restrict access to {db_name} (port {svc.port}) using "
                    "firewall rules or security groups. Database ports should "
                    "never be directly accessible from the internet."
                ),
            })
    return findings


@register(
    control_id="EXP-003",
    name="Unencrypted service protocol (FTP/Telnet)",
    severity="high",
    confidence=0.90,
    category="Service Exposure",
    asset_types=["domain", "subdomain", "ip"],
)
def check_exp_003(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect unencrypted protocols like FTP (21) and Telnet (23).

    FTP/Telnet: HIGH - no encryption at all, credentials in plaintext.
    IMAP/POP3:  MEDIUM - plaintext port open but STARTTLS is typically
                supported; the encrypted ports (993/995) often coexist.
    """
    # (port -> (name, replacement, severity))
    # IMAP 143 and POP3 110 are MEDIUM because they usually offer STARTTLS.
    # FTP 21 and Telnet 23 are HIGH because they have no upgrade mechanism.
    unencrypted_ports: dict[int, tuple[str, str, str]] = {
        21: ("FTP", "SFTP or SCP", "high"),
        23: ("Telnet", "SSH", "high"),
        110: ("POP3", "POP3S (port 995)", "medium"),
        143: ("IMAP", "IMAPS (port 993)", "medium"),
    }

    # For mail ports (110/143), only flag on actual mail-related hosts.
    # In wildcard DNS setups, every subdomain resolves to the same IP
    # where a mail server runs — flagging grafana.example.com:143 is a
    # false positive. Only report on hosts whose name suggests mail service.
    _MAIL_HOST_PATTERNS = {
        "mail", "smtp", "imap", "pop", "pop3", "mx", "webmail",
        "postfix", "dovecot", "exchange", "mta", "relay",
    }
    _MAIL_PORTS = {110, 143}

    def _is_mail_host(hostname: str) -> bool:
        """Return True if hostname looks like a mail server."""
        parts = hostname.lower().split(".")
        return any(
            part in _MAIL_HOST_PATTERNS or part.startswith("mx")
            for part in parts
        )

    # Collect the set of open ports so we can check for encrypted counterparts
    open_ports = {svc.port for svc in services if svc.port}
    encrypted_counterpart = {110: 995, 143: 993}

    findings: list[dict] = []
    for svc in services:
        if svc.port not in unencrypted_ports:
            continue

        # Skip mail ports on non-mail hosts (wildcard DNS false positives)
        if svc.port in _MAIL_PORTS and not _is_mail_host(asset.identifier):
            continue

        proto_name, replacement, severity = unencrypted_ports[svc.port]

        # If the encrypted counterpart (993 for IMAP, 995 for POP3) is also
        # open, skip entirely — the server supports both plaintext+STARTTLS
        # and encrypted ports, which is standard mail server configuration.
        counterpart = encrypted_counterpart.get(svc.port)
        if counterpart and counterpart in open_ports:
            continue

        # Even without the encrypted counterpart, STARTTLS on 143/110 is
        # standard practice.  Downgrade mail ports to INFO.
        if svc.port in _MAIL_PORTS:
            severity = "info"

        findings.append({
            "name": f"Unencrypted {proto_name} service on port {svc.port}",
            "severity": severity,
            "confidence": 0.85 if severity == "high" else 0.60,
            "evidence": {
                "port": svc.port,
                "protocol": proto_name,
                "product": svc.product,
                "encrypted_counterpart_open": bool(
                    counterpart and counterpart in open_ports
                ),
            },
            "control_id": "EXP-003",
            "finding_key": f"EXP-003:{asset.identifier}:{svc.port}",
            "remediation": (
                f"Replace {proto_name} with {replacement} to ensure "
                "credentials and data are encrypted in transit."
            ),
        })
    return findings


@register(
    control_id="EXP-004",
    name="Kubernetes API server exposed",
    severity="critical",
    confidence=0.80,
    category="Service Exposure",
    asset_types=["domain", "subdomain", "ip"],
)
def check_exp_004(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect exposed Kubernetes API servers."""
    k8s_ports = {6443, 8443, 10250}
    k8s_indicators = ["kubernetes", "k8s", "kube-apiserver", "kubelet"]
    findings: list[dict] = []
    for svc in services:
        if svc.port not in k8s_ports:
            continue
        product_lower = (svc.product or "").lower()
        title_lower = (svc.http_title or "").lower()
        techs = _get_technologies(svc)
        all_text = f"{product_lower} {title_lower} {' '.join(techs)}"

        if any(indicator in all_text for indicator in k8s_indicators):
            findings.append({
                "name": f"Kubernetes API server exposed on port {svc.port}",
                "severity": "critical",
                "confidence": 0.80,
                "evidence": {
                    "port": svc.port,
                    "product": svc.product,
                    "http_title": svc.http_title,
                },
                "control_id": "EXP-004",
                "finding_key": f"EXP-004:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Restrict Kubernetes API server access to authorized "
                    "networks only. Use RBAC, network policies, and API "
                    "server flags (--anonymous-auth=false) to secure the cluster."
                ),
            })
    return findings


@register(
    control_id="EXP-005",
    name="RDP service exposed to internet",
    severity="critical",
    confidence=0.90,
    category="Service Exposure",
    asset_types=["domain", "subdomain", "ip"],
)
def check_exp_005(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect exposed Remote Desktop Protocol (RDP) services."""
    findings: list[dict] = []
    for svc in services:
        if svc.port == 3389:
            findings.append({
                "name": "RDP service exposed on port 3389",
                "severity": "critical",
                "confidence": 0.90,
                "evidence": {
                    "port": svc.port,
                    "product": svc.product,
                    "version": svc.version,
                },
                "control_id": "EXP-005",
                "finding_key": f"EXP-005:{asset.identifier}:3389",
                "remediation": (
                    "Disable public RDP access and use a VPN or bastion host "
                    "for remote desktop connections. RDP is a high-value "
                    "target for brute-force and exploitation attacks."
                ),
            })
    return findings


@register(
    control_id="EXP-001",
    name="SSH service exposed on non-standard port",
    severity="info",
    confidence=0.70,
    category="Service Exposure",
    asset_types=["domain", "subdomain", "ip"],
)
def check_exp_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Flag SSH services and note when on non-standard ports."""
    findings: list[dict] = []
    for svc in services:
        is_ssh = svc.port == 22 or (svc.product and "ssh" in (svc.product or "").lower())
        if is_ssh:
            sev = "info" if svc.port == 22 else "low"
            findings.append({
                "name": f"SSH service detected on port {svc.port}",
                "severity": sev,
                "confidence": 0.70,
                "evidence": {
                    "port": svc.port,
                    "product": svc.product,
                    "version": svc.version,
                },
                "control_id": "EXP-001",
                "finding_key": f"EXP-001:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Ensure SSH access is restricted by IP allowlist and uses "
                    "key-based authentication. Disable password authentication."
                ),
            })
    return findings


@register(
    control_id="EXP-006",
    name="Management interface exposed (JMX, SNMP, Docker API)",
    severity="high",
    confidence=0.80,
    category="Service Exposure",
    asset_types=["domain", "subdomain", "ip"],
)
def check_exp_006(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect management interfaces that should not be publicly accessible."""
    mgmt_ports = {
        161: ("SNMP", "high"),
        162: ("SNMP Trap", "high"),
        2375: ("Docker API (unencrypted)", "critical"),
        2376: ("Docker API (TLS)", "high"),
        9090: ("Prometheus", "medium"),
        8080: ("Management Console", "medium"),
        4848: ("GlassFish Admin", "high"),
        9990: ("WildFly Admin", "high"),
        7199: ("JMX (Cassandra)", "high"),
    }
    findings: list[dict] = []
    for svc in services:
        if svc.port in mgmt_ports:
            name, sev = mgmt_ports[svc.port]
            # Only flag 8080/9090 if product confirms management interface
            if svc.port in (8080, 9090):
                product_lower = (svc.product or "").lower()
                title_lower = (svc.http_title or "").lower()
                if not any(
                    kw in f"{product_lower} {title_lower}"
                    for kw in ["prometheus", "grafana", "console", "admin", "management", "tomcat"]
                ):
                    continue
            findings.append({
                "name": f"{name} exposed on port {svc.port}",
                "severity": sev,
                "confidence": 0.80,
                "evidence": {
                    "port": svc.port,
                    "service_name": name,
                    "product": svc.product,
                },
                "control_id": "EXP-006",
                "finding_key": f"EXP-006:{asset.identifier}:{svc.port}",
                "remediation": (
                    f"Restrict access to {name} using firewall rules. "
                    "Management interfaces must not be exposed to the public internet."
                ),
            })
    return findings


# ---------------------------------------------------------------------------
# Stub controls for completeness (remaining IDs in the 50-control set)
# These are registered with the correct metadata but contain simplified logic
# that will be expanded as additional enrichment data becomes available.
# ---------------------------------------------------------------------------

@register(
    control_id="ADM-003",
    name="WordPress admin panel exposed",
    severity="medium",
    confidence=0.75,
    category="Admin Panel Detection",
    asset_types=["domain", "subdomain"],
)
def check_adm_003(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    """Detect WordPress installations via technology fingerprint."""
    findings: list[dict] = []
    for svc in services:
        techs = _get_technologies(svc)
        if "wordpress" in techs:
            findings.append({
                "name": "WordPress detected (wp-admin likely accessible)",
                "severity": "medium",
                "confidence": 0.75,
                "evidence": {"port": svc.port, "technologies": techs},
                "control_id": "ADM-003",
                "finding_key": f"ADM-003:{asset.identifier}:{svc.port}",
                "remediation": "Restrict wp-admin access via IP allowlist or WAF rules.",
            })
    return findings


@register(
    control_id="ADM-004",
    name="phpMyAdmin detected",
    severity="high",
    confidence=0.80,
    category="Admin Panel Detection",
    asset_types=["domain", "subdomain"],
)
def check_adm_004(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    """Detect phpMyAdmin via title or technology fingerprint."""
    findings: list[dict] = []
    for svc in services:
        title = (svc.http_title or "").lower()
        techs = _get_technologies(svc)
        if "phpmyadmin" in title or "phpmyadmin" in techs:
            findings.append({
                "name": "phpMyAdmin detected",
                "severity": "high",
                "confidence": 0.80,
                "evidence": {"port": svc.port, "http_title": svc.http_title},
                "control_id": "ADM-004",
                "finding_key": f"ADM-004:{asset.identifier}:{svc.port}",
                "remediation": (
                    "Remove phpMyAdmin from public-facing servers or restrict "
                    "access via IP allowlists and strong authentication."
                ),
            })
    return findings


@register(
    control_id="CLD-003",
    name="Cloud metadata endpoint potentially accessible",
    severity="high",
    confidence=0.50,
    category="Cloud Misconfiguration",
    asset_types=["domain", "subdomain", "ip"],
)
def check_cld_003(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires SSRF probing or endpoint crawl data
    return []


@register(
    control_id="CLD-004",
    name="Insecure cloud function / Lambda URL",
    severity="medium",
    confidence=0.50,
    category="Cloud Misconfiguration",
    asset_types=["domain", "subdomain"],
)
def check_cld_004(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Detect Lambda/Cloud Function URLs via CNAME or title
    return []


@register(
    control_id="TKO-002",
    name="Subdomain pointing to deprovisioned cloud resource",
    severity="high",
    confidence=0.60,
    category="Subdomain Takeover",
    asset_types=["subdomain"],
)
def check_tko_002(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires CNAME resolution data
    return []


@register(
    control_id="TKO-003",
    name="Subdomain with expired hosted service",
    severity="high",
    confidence=0.55,
    category="Subdomain Takeover",
    asset_types=["subdomain"],
)
def check_tko_003(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires HTTP body fingerprint analysis
    return []


@register(
    control_id="EML-004",
    name="DMARC policy set to none",
    severity="low",
    confidence=0.60,
    category="Email Security",
    asset_types=["domain"],
)
def check_eml_004(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    findings: list[dict] = []
    metadata = _parse_raw_metadata(asset)
    dmarc_records = metadata.get("dmarc_txt", []) + metadata.get("dns_txt", [])
    for txt in dmarc_records:
        txt_str = str(txt).lower()
        if "v=dmarc1" in txt_str and "p=none" in txt_str:
            findings.append({
                "name": "DMARC policy set to none (monitor only)",
                "severity": "low",
                "confidence": 0.60,
                "evidence": {"domain": asset.identifier, "dmarc_record": str(txt)},
                "control_id": "EML-004",
                "finding_key": f"EML-004:{asset.identifier}",
                "remediation": (
                    "Upgrade DMARC policy from p=none to p=quarantine or p=reject "
                    "after verifying legitimate senders are aligned."
                ),
            })
    return findings


@register(
    control_id="EML-005",
    name="Missing DKIM configuration",
    severity="low",
    confidence=0.40,
    category="Email Security",
    asset_types=["domain"],
)
def check_eml_005(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires DKIM selector enumeration via DNS
    return []


@register(
    control_id="DNS-002",
    name="DNSSEC not configured",
    severity="low",
    confidence=0.50,
    category="DNS Security",
    asset_types=["domain"],
)
def check_dns_002(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires DNSSEC validation probing
    return []


@register(
    control_id="DNS-003",
    name="Open DNS resolver detected",
    severity="high",
    confidence=0.60,
    category="DNS Security",
    asset_types=["ip"],
)
def check_dns_003(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    """Flag DNS services on port 53 that could be open resolvers."""
    findings: list[dict] = []
    for svc in services:
        if svc.port == 53:
            findings.append({
                "name": "DNS service on port 53 (potential open resolver)",
                "severity": "high",
                "confidence": 0.60,
                "evidence": {"port": 53, "product": svc.product},
                "control_id": "DNS-003",
                "finding_key": f"DNS-003:{asset.identifier}:53",
                "remediation": (
                    "Verify the DNS server does not respond to recursive queries "
                    "from arbitrary sources. Open resolvers can be abused for "
                    "DNS amplification attacks."
                ),
            })
    return findings


@register(
    control_id="DNS-004",
    name="Wildcard DNS record detected",
    severity="info",
    confidence=0.50,
    category="DNS Security",
    asset_types=["domain"],
)
def check_dns_004(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires wildcard DNS detection during resolution phase
    return []


@register(
    control_id="INF-006",
    name="Source map files exposed",
    severity="medium",
    confidence=0.60,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_006(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires crawl data for .js.map files
    return []


@register(
    control_id="INF-007",
    name="Git repository exposed (.git/HEAD accessible)",
    severity="high",
    confidence=0.70,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_007(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # Covered by INF-004 as part of sensitive path detection
    return []


@register(
    control_id="INF-008",
    name="Backup file detected (.bak, .old, .sql)",
    severity="medium",
    confidence=0.55,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_008(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # Covered by INF-004 as part of sensitive path detection
    return []


@register(
    control_id="AUTH-003",
    name="Default credentials suspected",
    severity="high",
    confidence=0.50,
    category="Authentication",
    asset_types=["domain", "subdomain"],
)
def check_auth_003(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires active probing (out of scope for passive checks)
    return []


@register(
    control_id="AUTH-004",
    name="No rate limiting on login endpoint",
    severity="medium",
    confidence=0.40,
    category="Authentication",
    asset_types=["domain", "subdomain"],
)
def check_auth_004(
    asset: Asset, services: list[Service],
    certificates: list[Certificate], db: Any,
) -> list[dict]:
    # TODO: Requires active probing
    return []


# ---------------------------------------------------------------------------
# Raw metadata helper
# ---------------------------------------------------------------------------

def _parse_raw_metadata(asset: Asset) -> dict:
    """Parse the raw_metadata JSON field from an asset record."""
    raw = asset.raw_metadata
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return {}
    return {}


# ---------------------------------------------------------------------------
# Main Celery task
# ---------------------------------------------------------------------------

@celery.task(
    name="app.tasks.misconfig.run_misconfig_detection",
    bind=True,
    max_retries=3,
    default_retry_delay=60,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
)
def run_misconfig_detection(
    self,
    tenant_id: int,
    scan_run_id: int | None = None,
) -> dict:
    """Run all misconfiguration checks against tenant assets.

    For each active asset the task:
      1. Loads related services and certificates.
      2. Runs applicable controls filtered by asset type.
      3. Skips findings with confidence < 0.3.
      4. Flags findings with confidence 0.3 - 0.7 as needs_review.
      5. Creates or updates Finding records using finding_key dedup.

    Args:
        tenant_id: Tenant whose assets to check.
        scan_run_id: Optional scan run ID for tracking phase results.

    Returns:
        Dictionary with execution statistics.
    """
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    stats: dict[str, Any] = {
        "tenant_id": tenant_id,
        "scan_run_id": scan_run_id,
        "assets_checked": 0,
        "controls_executed": 0,
        "findings_created": 0,
        "findings_updated": 0,
        "findings_skipped_low_confidence": 0,
        "findings_needs_review": 0,
        "errors": 0,
        "controls_by_category": {},
        "status": "success",
    }

    try:
        assets = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.is_active == True,  # noqa: E712
            )
            .all()
        )

        if not assets:
            tenant_logger.warning("No active assets found for misconfig detection")
            stats["status"] = "no_assets"
            return stats

        tenant_logger.info(
            f"Starting misconfiguration detection: {len(assets)} assets, "
            f"{len(_CONTROLS)} controls registered"
        )

        # Mark stale assets: domains/subdomains that no longer resolve DNS
        import socket
        stale_count = 0
        for asset in assets:
            if asset.type and asset.type.value in ("domain", "subdomain"):
                try:
                    socket.getaddrinfo(asset.identifier, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                except socket.gaierror:
                    asset.is_active = False
                    stale_count += 1
                    tenant_logger.info(f"Marking stale asset (no DNS): {asset.identifier}")
        if stale_count:
            db.commit()
            tenant_logger.info(f"Marked {stale_count} stale assets as inactive")
            # Re-query to exclude newly deactivated assets
            assets = [a for a in assets if a.is_active]

        for asset in assets:
            asset_type_value = asset.type.value if asset.type else ""

            services = (
                db.query(Service).filter(Service.asset_id == asset.id).all()
            )
            certificates = (
                db.query(Certificate).filter(Certificate.asset_id == asset.id).all()
            )

            for control_id, control in _CONTROLS.items():
                if asset_type_value not in control["asset_types"]:
                    continue

                try:
                    results = control["check_fn"](asset, services, certificates, db)
                    stats["controls_executed"] += 1

                    category = control["category"]
                    if category not in stats["controls_by_category"]:
                        stats["controls_by_category"][category] = {
                            "executed": 0, "findings": 0
                        }
                    stats["controls_by_category"][category]["executed"] += 1

                    for finding_data in results:
                        confidence = finding_data.get(
                            "confidence", control["confidence"]
                        )

                        if confidence < 0.3:
                            stats["findings_skipped_low_confidence"] += 1
                            continue

                        needs_review = 0.3 <= confidence < 0.7
                        if needs_review:
                            stats["findings_needs_review"] += 1

                        finding_key = finding_data.get(
                            "finding_key",
                            f"{control['id']}:{asset.identifier}",
                        )
                        severity_str = finding_data.get(
                            "severity", control["severity"]
                        )
                        severity_enum = _severity_enum(severity_str)

                        evidence = finding_data.get("evidence", {})
                        evidence["control_id"] = control["id"]
                        evidence["category"] = control["category"]
                        evidence["confidence"] = confidence
                        evidence["remediation"] = finding_data.get("remediation", "")
                        if needs_review:
                            evidence["needs_review"] = True
                        if scan_run_id:
                            evidence["scan_run_id"] = scan_run_id

                        # Compute dedup fingerprint
                        fp = compute_finding_fingerprint(
                            tenant_id=tenant_id,
                            asset_identifier=asset.identifier,
                            template_id=finding_key,
                            source="misconfig",
                        )

                        existing = (
                            db.query(Finding)
                            .filter(Finding.fingerprint == fp)
                            .first()
                        )

                        if existing:
                            existing.last_seen = datetime.now(timezone.utc)
                            existing.evidence = evidence
                            existing.severity = severity_enum
                            existing.occurrence_count = (existing.occurrence_count or 1) + 1
                            if existing.status == FindingStatus.FIXED:
                                existing.status = FindingStatus.OPEN
                            stats["findings_updated"] += 1
                        else:
                            finding = Finding(
                                asset_id=asset.id,
                                source="misconfig",
                                template_id=finding_key,
                                name=finding_data.get("name", control["name"]),
                                severity=severity_enum,
                                evidence=evidence,
                                first_seen=datetime.now(timezone.utc),
                                last_seen=datetime.now(timezone.utc),
                                status=FindingStatus.OPEN,
                                host=asset.identifier,
                                fingerprint=fp,
                                occurrence_count=1,
                            )
                            db.add(finding)
                            stats["findings_created"] += 1

                        stats["controls_by_category"][category]["findings"] += 1

                except Exception as exc:
                    stats["errors"] += 1
                    tenant_logger.warning(
                        f"Control {control_id} failed on asset "
                        f"{asset.identifier}: {exc}",
                        exc_info=True,
                    )

            stats["assets_checked"] += 1

        db.commit()

        # Auto-close stale misconfig findings: any open misconfig finding
        # for this tenant whose last_seen was NOT updated in this scan run
        # is no longer detected — mark it as fixed.
        scan_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        stale_findings = (
            db.query(Finding)
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.source == "misconfig",
                Finding.status == FindingStatus.OPEN,
                Finding.last_seen < scan_cutoff,
            )
            .all()
        )
        auto_closed = 0
        for sf in stale_findings:
            sf.status = FindingStatus.FIXED
            auto_closed += 1
        if auto_closed:
            db.commit()
            tenant_logger.info(
                f"Auto-closed {auto_closed} stale misconfig findings "
                f"not seen in current scan"
            )
        stats["findings_auto_closed"] = auto_closed

        tenant_logger.info(
            f"Misconfiguration detection complete: "
            f"{stats['assets_checked']} assets, "
            f"{stats['controls_executed']} control runs, "
            f"{stats['findings_created']} created, "
            f"{stats['findings_updated']} updated, "
            f"{stats['findings_skipped_low_confidence']} skipped, "
            f"{stats['findings_needs_review']} flagged for review, "
            f"{auto_closed} auto-closed, "
            f"{stats['errors']} errors"
        )

    except Exception as exc:
        tenant_logger.error(
            "Misconfiguration detection failed: %s", exc, exc_info=True
        )
        try:
            db.rollback()
        except Exception:
            pass
        raise self.retry(exc=exc)
    finally:
        db.close()

    return stats
