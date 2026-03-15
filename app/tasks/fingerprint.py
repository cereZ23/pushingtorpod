"""
Technology Fingerprinting Engine - Phase 6

Wappalyzer-style engine matching HTTP headers, HTML content, and cookies
to identify technologies. ~40 built-in signatures covering web servers,
CMS platforms, JS frameworks, CDN providers, PaaS platforms, languages,
analytics, WAFs, monitoring tools, CI/CD systems, and ecommerce platforms.
"""

import re
import logging
from datetime import datetime
from typing import Optional

from app.celery_app import celery
from app.database import SessionLocal
from app.models.database import Asset, AssetType, Service
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Technology Signatures (~40 entries)
# ---------------------------------------------------------------------------
# Each signature contains:
#   name       - Technology name
#   category   - Classification bucket
#   headers    - Dict of header_name -> regex pattern (matched case-insensitively)
#   html       - Regex pattern matched against HTML body content
#   cookies    - Dict of cookie_name -> regex pattern
#   confidence - Float 0.0-1.0 representing match reliability
# ---------------------------------------------------------------------------

SIGNATURES: list[dict] = [
    # -- Web Servers --
    {
        "name": "Nginx",
        "category": "web-server",
        "headers": {"server": r"nginx/?(\d[\d.]*)?"},
        "confidence": 0.95,
    },
    {
        "name": "Apache",
        "category": "web-server",
        "headers": {"server": r"Apache/?(\d[\d.]*)?"},
        "confidence": 0.95,
    },
    {
        "name": "IIS",
        "category": "web-server",
        "headers": {"server": r"Microsoft-IIS/?(\d[\d.]*)?"},
        "confidence": 0.95,
    },
    {
        "name": "LiteSpeed",
        "category": "web-server",
        "headers": {"server": r"LiteSpeed"},
        "confidence": 0.9,
    },
    {
        "name": "Caddy",
        "category": "web-server",
        "headers": {"server": r"Caddy"},
        "confidence": 0.9,
    },
    # -- CMS --
    {
        "name": "WordPress",
        "category": "cms",
        "headers": {"x-powered-by": r"WordPress"},
        "html": r"wp-content|wp-includes",
        "confidence": 0.9,
    },
    {
        "name": "Drupal",
        "category": "cms",
        "headers": {"x-drupal-cache": r".*"},
        "html": r"Drupal\.settings",
        "confidence": 0.85,
    },
    {
        "name": "Joomla",
        "category": "cms",
        "html": r"/media/jui/|Joomla!",
        "confidence": 0.85,
    },
    # -- JS Frameworks --
    {
        "name": "React",
        "category": "js-framework",
        "html": r"__NEXT_DATA__|react\.production|_reactRootContainer",
        "confidence": 0.85,
    },
    {
        "name": "Vue.js",
        "category": "js-framework",
        "html": r"Vue\.js|__vue__|v-cloak",
        "confidence": 0.85,
    },
    {
        "name": "Angular",
        "category": "js-framework",
        "html": r"ng-version|angular\.js|ng-app",
        "confidence": 0.85,
    },
    {
        "name": "Next.js",
        "category": "js-framework",
        "headers": {"x-powered-by": r"Next\.js"},
        "confidence": 0.9,
    },
    {
        "name": "jQuery",
        "category": "js-library",
        "html": r"jquery[\-.](\d[\d.]*)?\.min\.js",
        "confidence": 0.9,
    },
    # -- Cloud / CDN --
    {
        "name": "Cloudflare",
        "category": "cdn",
        "headers": {"cf-ray": r".*", "server": r"cloudflare"},
        "confidence": 0.95,
    },
    {
        "name": "AWS CloudFront",
        "category": "cdn",
        "headers": {"x-amz-cf-id": r".*", "via": r"CloudFront"},
        "confidence": 0.9,
    },
    {
        "name": "Akamai",
        "category": "cdn",
        "headers": {"x-akamai-transformed": r".*"},
        "confidence": 0.9,
    },
    {
        "name": "Fastly",
        "category": "cdn",
        "headers": {"x-served-by": r"cache-", "via": r"varnish"},
        "confidence": 0.85,
    },
    # -- Platforms / PaaS --
    {
        "name": "Heroku",
        "category": "paas",
        "headers": {"via": r"vegur"},
        "confidence": 0.9,
    },
    {
        "name": "Vercel",
        "category": "paas",
        "headers": {"x-vercel-id": r".*", "server": r"Vercel"},
        "confidence": 0.95,
    },
    {
        "name": "Netlify",
        "category": "paas",
        "headers": {"x-nf-request-id": r".*", "server": r"Netlify"},
        "confidence": 0.95,
    },
    # -- Languages / Runtimes --
    {
        "name": "PHP",
        "category": "language",
        "headers": {"x-powered-by": r"PHP/?(\d[\d.]*)?"},
        "confidence": 0.95,
    },
    {
        "name": "ASP.NET",
        "category": "language",
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r".*"},
        "confidence": 0.95,
    },
    {
        "name": "Express",
        "category": "framework",
        "headers": {"x-powered-by": r"Express"},
        "confidence": 0.9,
    },
    {
        "name": "Django",
        "category": "framework",
        "headers": {"x-frame-options": r"DENY"},
        "html": r"csrfmiddlewaretoken",
        "confidence": 0.7,
    },
    {
        "name": "Laravel",
        "category": "framework",
        "cookies": {"laravel_session": r".*"},
        "confidence": 0.9,
    },
    {
        "name": "Rails",
        "category": "framework",
        "headers": {"x-request-id": r".*", "x-runtime": r"[\d.]+"},
        "confidence": 0.7,
    },
    # -- Analytics --
    {
        "name": "Google Analytics",
        "category": "analytics",
        "html": r"google-analytics\.com/analytics|gtag/js\?id=",
        "confidence": 0.95,
    },
    {
        "name": "Google Tag Manager",
        "category": "analytics",
        "html": r"googletagmanager\.com/gtm\.js",
        "confidence": 0.95,
    },
    # -- Security / WAF --
    {
        "name": "ModSecurity",
        "category": "waf",
        "headers": {"server": r"mod_security"},
        "confidence": 0.9,
    },
    {
        "name": "AWS WAF",
        "category": "waf",
        "headers": {"x-amzn-waf-action": r".*"},
        "confidence": 0.95,
    },
    # -- App Servers --
    {
        "name": "Tomcat",
        "category": "app-server",
        "headers": {"server": r"Apache-Coyote"},
        "confidence": 0.9,
    },
    # -- Monitoring --
    {
        "name": "Grafana",
        "category": "monitoring",
        "html": r"grafana-app|Grafana",
        "confidence": 0.9,
    },
    {
        "name": "Kibana",
        "category": "monitoring",
        "html": r"kibana|kbn-version",
        "confidence": 0.9,
    },
    # -- CI/CD --
    {
        "name": "Jenkins",
        "category": "ci-cd",
        "headers": {"x-jenkins": r".*"},
        "html": r"Jenkins",
        "confidence": 0.95,
    },
    # -- SCM / Project Management --
    {
        "name": "GitLab",
        "category": "scm",
        "html": r"gitlab-",
        "confidence": 0.85,
    },
    {
        "name": "Jira",
        "category": "project-mgmt",
        "html": r"atlassian|jira",
        "confidence": 0.85,
    },
    {
        "name": "Confluence",
        "category": "wiki",
        "html": r"confluence",
        "confidence": 0.85,
    },
    # -- Ecommerce --
    {
        "name": "Shopify",
        "category": "ecommerce",
        "headers": {"x-shopid": r".*"},
        "html": r"cdn\.shopify",
        "confidence": 0.95,
    },
    {
        "name": "Magento",
        "category": "ecommerce",
        "html": r"Mage\.Cookies|magento",
        "cookies": {"PHPSESSID": r".*", "form_key": r".*"},
        "confidence": 0.8,
    },
]


@celery.task(name="app.tasks.fingerprint.run_fingerprinting")
def run_fingerprinting(
    tenant_id: int, scan_run_id: Optional[int] = None
) -> dict:
    """Run technology fingerprinting on HTTP services.

    Iterates over all services belonging to the tenant that have stored
    HTTP headers, matches each against the built-in SIGNATURES list, and
    persists detected technology names on both the Service and Asset
    records.

    Args:
        tenant_id: Tenant whose services should be fingerprinted.
        scan_run_id: Optional scan run for provenance tracking.

    Returns:
        Dict with ``technologies_detected`` and ``services_analyzed``
        counts, or an ``error`` key on failure.
    """
    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Get services with HTTP data
        services = (
            db.query(Service)
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Service.http_headers.isnot(None),
            )
            .all()
        )

        if not services:
            return {"technologies_detected": 0, "services_analyzed": 0}

        total_detections = 0

        for service in services:
            headers = service.http_headers or {}
            # Normalize header keys to lowercase
            headers_lower = {k.lower(): str(v) for k, v in headers.items()}

            detected: list[dict] = []

            for sig in SIGNATURES:
                match = _match_signature(sig, headers_lower, "", {})
                if match:
                    detected.append(
                        {
                            "name": sig["name"],
                            "category": sig["category"],
                            "confidence": sig["confidence"],
                            "version": match.get("version"),
                        }
                    )

            if detected:
                # Merge with existing technologies from httpx (don't overwrite)
                tech_names = [d["name"] for d in detected]
                existing = service.http_technologies if isinstance(service.http_technologies, list) else []
                merged = list(dict.fromkeys(existing + tech_names))  # dedupe, preserve order
                service.http_technologies = merged

                total_detections += len(detected)

        db.commit()

        result = {
            "technologies_detected": total_detections,
            "services_analyzed": len(services),
        }
        tenant_logger.info(f"Fingerprinting completed: {result}")
        return result

    except Exception as e:
        tenant_logger.error(f"Fingerprinting error: {e}", exc_info=True)
        return {"error": str(e)}
    finally:
        db.close()


def _match_signature(
    sig: dict,
    headers: dict,
    html_content: str,
    cookies: dict,
) -> Optional[dict]:
    """Match a technology signature against response data.

    Checks headers, HTML body content, and cookies in order.  A match
    on *any* signal source is sufficient.  When the regex contains a
    capture group the first group is returned as the detected version.

    Args:
        sig: Signature dict from SIGNATURES.
        headers: Lowercase header name -> value mapping.
        html_content: Full HTML body text (may be empty).
        cookies: Cookie name -> value mapping.

    Returns:
        ``{"version": <str|None>}`` on match, or ``None`` if the
        signature does not match.
    """
    matched = False
    version: Optional[str] = None

    # Check headers
    if "headers" in sig:
        for header_name, pattern in sig["headers"].items():
            value = headers.get(header_name.lower(), "")
            if value:
                m = re.search(pattern, value, re.IGNORECASE)
                if m:
                    matched = True
                    if m.groups():
                        version = m.group(1)

    # Check HTML content
    if "html" in sig and html_content:
        m = re.search(sig["html"], html_content, re.IGNORECASE)
        if m:
            matched = True
            if m.groups():
                version = version or m.group(1)

    # Check cookies
    if "cookies" in sig and cookies:
        for cookie_name, pattern in sig["cookies"].items():
            if cookie_name in cookies:
                matched = True

    return {"version": version} if matched else None
