"""
Misconfiguration Detection Engine - Phase 8

Implements 19 security controls across 7 categories using a decorator-based
control registry. Each control function inspects asset data (services, certificates,
HTTP headers, DNS records) and produces structured findings.

Only controls that provide unique value beyond Nuclei template coverage are
included. Nuclei-duplicate checks (e.g. weak TLS version, self-signed cert,
expired cert, missing common headers, admin panels, cloud misconfig, subdomain
takeover, exposed DB/SSH/RDP/FTP, directory listing, debug mode, etc.) have
been removed to avoid double-counting.

Categories and control IDs:
  - TLS Certificate Intelligence  (TLS-001, TLS-005, TLS-009, TLS-010)
  - Security Headers              (HDR-004, HDR-007, HDR-008, HDR-009, HDR-010)
  - Information Disclosure        (INF-009)
  - Email Security                (EML-001, EML-002, EML-003, EML-006, EML-007)
  - DNS Security                  (DNS-001)
  - Authentication                (AUTH-001, AUTH-002)
  - Service Exposure              (EXP-006)
"""

import json
import logging
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
    25,
    110,
    143,
    465,
    587,
    993,
    995,  # mail protocols
    21,
    22,
    53,
    123,
    389,
    636,
    3306,
    5432,  # FTP, SSH, DNS, NTP, LDAP, DB
}

# Common HTTP/HTTPS ports -- run header checks even if http_status is NULL
_HTTP_PORTS: set[int] = {80, 443, 8080, 8443}

# Protocols that indicate non-web services
_NON_HTTP_PROTOCOLS: set[str] = {
    "smtp",
    "smtps",
    "imap",
    "imaps",
    "pop3",
    "pop3s",
    "ftp",
    "ssh",
    "dns",
    "ldap",
    "ldaps",
    "mysql",
    "postgres",
}


def _is_web_service(service: Service) -> bool:
    """Return True if the service is an HTTP/HTTPS web service.

    Filters out mail (SMTP/IMAP/POP3), database, and other non-web
    protocols that happen to have TLS but should not be checked for
    HTTP security headers.
    """
    if service.port in _NON_HTTP_PORTS:
        return False
    proto = (service.protocol or "").lower()
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

    Falls back to empty set on failure -- preload checking is best-effort.
    """
    global _hsts_preload_cache, _hsts_preload_last_fetch
    now = time.monotonic()
    if _hsts_preload_cache and (now - _hsts_preload_last_fetch) < _HSTS_PRELOAD_TTL:
        return _hsts_preload_cache

    try:
        import base64
        import urllib.request

        url = "https://chromium.googlesource.com/chromium/src/+/main/net/http/transport_security_state_static.json?format=TEXT"

        with urllib.request.urlopen(url, timeout=30) as resp:
            raw = base64.b64decode(resp.read()).decode("utf-8")
        # Parse JSON (strip // comments first)
        lines = [line for line in raw.splitlines() if not line.strip().startswith("//")]
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
    except (OSError, ValueError, json.JSONDecodeError, KeyError) as exc:
        logger.debug("Failed to fetch HSTS preload list, using cached (%d entries): %s", len(_hsts_preload_cache), exc)
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
# TLS Certificate Intelligence (TLS-001, TLS-005, TLS-009, TLS-010)
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
    """Detect certificates that will expire within 30 days.

    Nuclei only flags already-expired certs. This control provides
    proactive pre-expiry alerting with ACME auto-renewal awareness.
    """
    # ACME providers auto-renew at ~30 days; only alert if renewal seems stuck
    ACME_ISSUERS = (
        "let's encrypt",
        "letsencrypt",
        "r3",
        "r10",
        "r11",
        "e5",
        "e6",
        "zerossl",
        "buypass",
        "google trust services",
    )

    findings: list[dict] = []
    for cert in certificates:
        days_left = cert.days_until_expiry
        if days_left is None:
            continue
        if days_left <= 0:
            continue  # expired certs are covered by Nuclei

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
        findings.append(
            {
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
                    if is_acme
                    else "Renew the TLS certificate before expiration. Consider using "
                    "automated certificate management (e.g. Let's Encrypt with "
                    "certbot or ACME protocol) to prevent future lapses."
                ),
            }
        )
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
            findings.append(
                {
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
                }
            )
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
            findings.append(
                {
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
                }
            )
    return findings


@register(
    control_id="TLS-010",
    name="Certificate transparency log missing",
    severity="info",
    confidence=0.20,  # Low confidence — most CAs embed SCT; absence is often a parsing gap
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
            findings.append(
                {
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
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Security Headers (HDR-004, HDR-007, HDR-008, HDR-009, HDR-010)
# ---------------------------------------------------------------------------


@register(
    control_id="HDR-004",
    name="HSTS header missing or weak max-age",
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
    """HSTS max-age validation -- Nuclei only checks presence, this validates the value.

    Dedup: one finding per asset (not per port). If any TLS service on
    the asset has a valid HSTS header, the asset is considered covered.
    """
    if _is_hsts_preloaded(asset.identifier):
        return []

    # Collect HSTS status across all TLS services on this asset
    has_valid_hsts = False
    weakest_max_age = None
    weakest_hsts_value = None
    checked_ports: list[int] = []

    for svc in services:
        if not svc.has_tls or not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        headers = _get_http_headers(svc)
        if not headers:
            continue  # No header data collected — can't assert missing
        checked_ports.append(svc.port)
        hsts = headers.get("strict-transport-security", "")
        if hsts:
            match = re.search(r"max-age=(\d+)", hsts, re.IGNORECASE)
            if match:
                max_age = int(match.group(1))
                if max_age >= 15768000:
                    has_valid_hsts = True
                elif weakest_max_age is None or max_age < weakest_max_age:
                    weakest_max_age = max_age
                    weakest_hsts_value = hsts

    if has_valid_hsts or not checked_ports:
        return []

    findings: list[dict] = []

    if weakest_max_age is not None:
        # At least one service has HSTS but with weak max-age
        findings.append(
            {
                "name": f"HSTS max-age too short ({weakest_max_age}s)",
                "severity": "low",
                "confidence": 0.75,
                "evidence": {
                    "ports": checked_ports,
                    "hsts_value": weakest_hsts_value,
                    "max_age_seconds": weakest_max_age,
                },
                "control_id": "HDR-004",
                "finding_key": f"HDR-004-weak:{asset.identifier}",
                "remediation": "Increase the HSTS max-age to at least 31536000 seconds (1 year).",
            }
        )
    else:
        # No HSTS header on any TLS service
        findings.append(
            {
                "name": "Missing HSTS header (Security Headers check)",
                "severity": "medium",
                "confidence": 0.85,
                "evidence": {"ports": checked_ports},
                "control_id": "HDR-004",
                "finding_key": f"HDR-004:{asset.identifier}",
                "remediation": "Set Strict-Transport-Security with max-age >= 31536000 and includeSubDomains.",
            }
        )
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
    """Detect permissive CORS (Access-Control-Allow-Origin: * with credentials)."""
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
            findings.append(
                {
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
                }
            )
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
            findings.append(
                {
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
                }
            )
    return findings


@register(
    control_id="HDR-009",
    name="CORS origin reflection",
    severity="high",
    confidence=0.90,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_009(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect CORS origin reflection (server echoes arbitrary Origin header).

    More exploitable than wildcard CORS: when combined with
    Access-Control-Allow-Credentials: true, enables cross-origin
    credential theft / account takeover.
    """
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        headers = _get_http_headers(svc)
        acao = headers.get("access-control-allow-origin", "")
        # Check for reflection pattern: origin value contains a domain that
        # is NOT the asset itself (httpx stores the response headers from a
        # standard request, so reflected origins appear when the server echoes
        # the request Origin without validation).
        if acao and acao != "*":
            asset_domain = asset.identifier.lower()
            acao_lower = acao.lower().strip()
            # If the ACAO is set to something other than the asset's own domain
            # and includes credentials, it may be reflecting origins.
            acac = headers.get("access-control-allow-credentials", "").lower()
            if acac == "true" and asset_domain not in acao_lower:
                findings.append(
                    {
                        "name": "CORS origin reflection with credentials",
                        "severity": "high",
                        "confidence": 0.75,
                        "evidence": {
                            "port": svc.port,
                            "access_control_allow_origin": acao,
                            "access_control_allow_credentials": "true",
                        },
                        "control_id": "HDR-009",
                        "finding_key": f"HDR-009:{asset.identifier}:{svc.port}",
                        "remediation": (
                            "Do not reflect the Origin header in Access-Control-Allow-Origin. "
                            "Maintain an explicit allowlist of trusted origins. "
                            "Never combine origin reflection with Allow-Credentials: true."
                        ),
                    }
                )
    return findings


@register(
    control_id="HDR-010",
    name="Insecure cookie attributes",
    severity="medium",
    confidence=0.85,
    category="Security Headers",
    asset_types=["domain", "subdomain"],
)
def check_hdr_010(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect cookies missing Secure, HttpOnly, or SameSite attributes."""
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        headers = _get_http_headers(svc)
        set_cookie = headers.get("set-cookie", "")
        if not set_cookie:
            continue
        cookie_lower = set_cookie.lower()
        missing = []
        if "secure" not in cookie_lower:
            missing.append("Secure")
        if "httponly" not in cookie_lower:
            missing.append("HttpOnly")
        if "samesite" not in cookie_lower:
            missing.append("SameSite")
        if missing:
            findings.append(
                {
                    "name": f"Cookie missing attributes: {', '.join(missing)}",
                    "severity": "medium",
                    "confidence": 0.85,
                    "evidence": {
                        "port": svc.port,
                        "set_cookie_preview": set_cookie[:200],
                        "missing_attributes": missing,
                    },
                    "control_id": "HDR-010",
                    "finding_key": f"HDR-010:{asset.identifier}:{svc.port}",
                    "remediation": (
                        "Set Secure (HTTPS only), HttpOnly (no JS access), and "
                        "SameSite=Lax or Strict on all cookies to prevent session "
                        "hijacking and CSRF attacks."
                    ),
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Information Disclosure (INF-009)
# ---------------------------------------------------------------------------


@register(
    control_id="INF-009",
    name="Dangerous HTTP methods enabled",
    severity="medium",
    confidence=0.80,
    category="Information Disclosure",
    asset_types=["domain", "subdomain"],
)
def check_inf_009(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Detect TRACE, PUT, or DELETE methods enabled via Allow header.

    TRACE enables Cross-Site Tracing (XST) attacks. PUT can allow
    arbitrary file upload. DELETE can allow resource destruction.
    """
    findings: list[dict] = []
    for svc in services:
        if not _is_web_service(svc) or _is_default_vhost(svc):
            continue
        if svc.http_status is None and svc.port not in _HTTP_PORTS:
            continue
        headers = _get_http_headers(svc)
        allow = headers.get("allow", "")
        if not allow:
            continue
        methods = {m.strip().upper() for m in allow.split(",")}
        dangerous = methods & {"TRACE", "PUT", "DELETE"}
        if dangerous:
            sev = "high" if "TRACE" in dangerous else "medium"
            findings.append(
                {
                    "name": f"Dangerous HTTP methods enabled: {', '.join(sorted(dangerous))}",
                    "severity": sev,
                    "confidence": 0.80,
                    "evidence": {
                        "port": svc.port,
                        "allow_header": allow,
                        "dangerous_methods": sorted(dangerous),
                    },
                    "control_id": "INF-009",
                    "finding_key": f"INF-009:{asset.identifier}:{svc.port}",
                    "remediation": (
                        "Disable TRACE method to prevent Cross-Site Tracing (XST). "
                        "Disable PUT and DELETE unless required by the application. "
                        "Configure the web server to only allow GET, HEAD, POST, OPTIONS."
                    ),
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Email Security (EML-001, EML-002, EML-003)
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
        findings.append(
            {
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
            }
        )
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
            findings.append(
                {
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
                }
            )
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
        findings.append(
            {
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
            }
        )
    return findings


@register(
    control_id="EML-006",
    name="SMTP service without STARTTLS",
    severity="medium",
    confidence=0.80,
    category="Email Security",
    asset_types=["domain", "subdomain"],
)
def check_eml_006(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Check SMTP services for STARTTLS support and banner info."""
    import socket

    findings: list[dict] = []
    smtp_ports = {25, 465, 587}
    for svc in services:
        if svc.port not in smtp_ports:
            continue
        try:
            with socket.create_connection((asset.identifier, svc.port), timeout=5) as sock:
                banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
                sock.sendall(b"EHLO easm-scanner\r\n")
                ehlo_resp = sock.recv(4096).decode("utf-8", errors="replace")
                has_starttls = "STARTTLS" in ehlo_resp.upper()

                if svc.port == 25 and not has_starttls:
                    findings.append(
                        {
                            "name": (f"SMTP on port {svc.port} does not support STARTTLS"),
                            "severity": "medium",
                            "confidence": 0.80,
                            "evidence": {
                                "port": svc.port,
                                "banner": banner[:200],
                                "starttls": False,
                            },
                            "control_id": "EML-006",
                            "finding_key": f"EML-006:{asset.identifier}:{svc.port}",
                            "remediation": ("Enable STARTTLS on the SMTP server to encrypt email in transit."),
                        }
                    )
                sock.sendall(b"QUIT\r\n")
        except (socket.timeout, OSError):
            pass  # Port not reachable or connection refused
    return findings


@register(
    control_id="EML-007",
    name="SMTP open relay",
    severity="critical",
    confidence=0.70,
    category="Email Security",
    asset_types=["domain", "subdomain"],
)
def check_eml_007(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Check if SMTP server is an open relay (accepts mail for arbitrary domains)."""
    import smtplib
    import socket

    findings: list[dict] = []
    for svc in services:
        if svc.port not in {25, 587}:
            continue
        try:
            with smtplib.SMTP(asset.identifier, svc.port, timeout=10) as smtp:
                smtp.ehlo("easm-scanner")
                # Try STARTTLS if available
                try:
                    smtp.starttls()
                    smtp.ehlo("easm-scanner")
                except smtplib.SMTPNotSupportedError:
                    pass
                # Test relay: try to send from external to external
                code, msg = smtp.mail("test@easm-scanner.invalid")
                if code == 250:
                    code2, msg2 = smtp.rcpt("test@example.com")
                    if code2 == 250:
                        findings.append(
                            {
                                "name": f"SMTP open relay on port {svc.port}",
                                "severity": "critical",
                                "confidence": 0.70,
                                "evidence": {
                                    "port": svc.port,
                                    "mail_from_response": (f"{code} {msg.decode('utf-8', errors='replace')}"),
                                    "rcpt_to_response": (f"{code2} {msg2.decode('utf-8', errors='replace')}"),
                                },
                                "control_id": "EML-007",
                                "finding_key": (f"EML-007:{asset.identifier}:{svc.port}"),
                                "remediation": (
                                    "Configure the SMTP server to require "
                                    "authentication before relaying mail. An open "
                                    "relay can be abused to send spam and will "
                                    "result in the IP being blacklisted."
                                ),
                            }
                        )
                    smtp.rset()
        except (smtplib.SMTPException, socket.timeout, OSError):
            pass  # Connection failed or SMTP error
    return findings


# ---------------------------------------------------------------------------
# DNS Security (DNS-001)
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
        findings.append(
            {
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
            }
        )
    return findings


# ---------------------------------------------------------------------------
# Authentication (AUTH-001, AUTH-002)
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
        # Skip if TLS is enabled or port is a known HTTPS port
        if svc.has_tls or svc.port in (443, 8443):
            continue
        title = (svc.http_title or "").lower()
        if any(indicator in title for indicator in login_indicators):
            findings.append(
                {
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
                }
            )
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
            findings.append(
                {
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
                }
            )
    return findings


# ---------------------------------------------------------------------------
# Service Exposure (EXP-006)
# ---------------------------------------------------------------------------


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
    """Detect management interfaces that should not be publicly accessible.

    Covers SNMP, JMX, Docker API, Prometheus, and application server admin
    consoles -- services that Nuclei templates do not reliably detect.
    """
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
            findings.append(
                {
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
                }
            )
    return findings


@register(
    control_id="DOM-001",
    name="Domain registration expiring soon",
    severity="high",
    confidence=0.90,
    category="Domain Health",
    asset_types=["domain"],
)
def check_dom_001(
    asset: Asset,
    services: list[Service],
    certificates: list[Certificate],
    db: Any,
) -> list[dict]:
    """Alert when a domain registration expires within 30 days.

    Uses WHOIS expiry date stored in asset.raw_metadata by phase 1c.
    """
    import json as _json
    from datetime import timedelta

    if asset.type.value != "domain":
        return []

    metadata = {}
    if asset.raw_metadata:
        try:
            metadata = _json.loads(asset.raw_metadata) if isinstance(asset.raw_metadata, str) else asset.raw_metadata
        except (ValueError, TypeError):
            pass

    whois_data = metadata.get("whois", metadata.get("network", {}))
    expires_str = whois_data.get("expires") or whois_data.get("expiration_date")
    if not expires_str:
        return []

    from dateutil.parser import parse as _parse_date

    try:
        expires_dt = _parse_date(str(expires_str))
        if expires_dt.tzinfo:
            expires_dt = expires_dt.replace(tzinfo=None)
    except (ValueError, TypeError):
        return []

    now = datetime.now()
    days_left = (expires_dt - now).days

    if days_left > 30:
        return []

    if days_left <= 0:
        sev = "critical"
        name = f"Domain registration EXPIRED ({abs(days_left)} days ago)"
    elif days_left <= 7:
        sev = "critical"
        name = f"Domain expires in {days_left} days"
    else:
        sev = "high"
        name = f"Domain expires in {days_left} days"

    return [
        {
            "name": name,
            "severity": sev,
            "confidence": 0.90,
            "evidence": {
                "expires": str(expires_str),
                "days_left": days_left,
                "registrar": whois_data.get("registrar"),
            },
            "control_id": "DOM-001",
            "finding_key": f"DOM-001:{asset.identifier}",
            "remediation": "Renew domain registration immediately to prevent hijacking.",
        }
    ]


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
            f"Starting misconfiguration detection: {len(assets)} assets, {len(_CONTROLS)} controls registered"
        )

        for asset in assets:
            asset_type_value = asset.type.value if asset.type else ""

            services = db.query(Service).filter(Service.asset_id == asset.id).all()
            certificates = db.query(Certificate).filter(Certificate.asset_id == asset.id).all()

            for control_id, control in _CONTROLS.items():
                if asset_type_value not in control["asset_types"]:
                    continue

                try:
                    results = control["check_fn"](asset, services, certificates, db)
                    stats["controls_executed"] += 1

                    category = control["category"]
                    if category not in stats["controls_by_category"]:
                        stats["controls_by_category"][category] = {"executed": 0, "findings": 0}
                    stats["controls_by_category"][category]["executed"] += 1

                    for finding_data in results:
                        confidence = finding_data.get("confidence", control["confidence"])

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
                        severity_str = finding_data.get("severity", control["severity"])
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

                        existing = db.query(Finding).filter(Finding.fingerprint == fp).first()

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
                        f"Control {control_id} failed on asset {asset.identifier}: {exc}",
                        exc_info=True,
                    )

            stats["assets_checked"] += 1

        db.commit()

        # Auto-close stale misconfig findings: any open misconfig finding
        # for this tenant whose last_seen was NOT updated in this scan run
        # is no longer detected -- mark it as fixed.
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
            tenant_logger.info(f"Auto-closed {auto_closed} stale misconfig findings not seen in current scan")
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
        tenant_logger.error("Misconfiguration detection failed: %s", exc, exc_info=True)
        try:
            db.rollback()
        except Exception:
            logger.debug("db.rollback() failed after misconfig error", exc_info=True)
        raise self.retry(exc=exc)
    finally:
        db.close()

    return stats
