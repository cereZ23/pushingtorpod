"""
Network Intelligence Service for EASM Platform

Provides WHOIS lookup, reverse DNS, ASN/BGP lookup, GeoIP geolocation,
CDN detection, WAF detection, and cloud provider identification.

Data sources:
- python-whois: WHOIS domain registration data
- socket: Reverse DNS lookups
- MaxMind GeoLite2: GeoIP (City + ASN) via local .mmdb databases
  https://www.maxmind.com/en/geoip-databases

Security:
- GeoIP is a local database lookup (no external API calls, no rate limits)
- Input validation on domains and IPs
- Graceful error handling (enrichment must never crash the pipeline)
- No secrets or credentials stored in enrichment data
"""

import logging
import socket
from datetime import datetime, date
from typing import Optional

from app.config import settings

try:
    import whois as _whois_module
except ImportError:
    _whois_module = None  # type: ignore[assignment]

try:
    import geoip2.database as _geoip2_db
    import geoip2.errors as _geoip2_errors
except ImportError:
    _geoip2_db = None  # type: ignore[assignment]
    _geoip2_errors = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MaxMind GeoLite2 reader singletons (loaded once, reused across lookups)
#
# Each reader uses a (reader, tried) tuple so that a failed load is memoized
# and we don't spam the warning log for every asset lookup when the .mmdb
# files are missing or unreadable.
# ---------------------------------------------------------------------------

_city_reader = None
_city_loaded = False
_asn_reader = None
_asn_loaded = False


def _get_city_reader():
    """Lazy-load GeoLite2-City reader. Memoizes failures to avoid log spam."""
    global _city_reader, _city_loaded
    if _city_loaded:
        return _city_reader
    _city_loaded = True  # memoize regardless of outcome
    if _geoip2_db is None:
        logger.debug("geoip2 package not installed, GeoIP lookups disabled")
        return None
    path = settings.geoip_city_db_path
    if not path:
        logger.debug("GEOIP_CITY_DB_PATH not configured, GeoIP City lookups disabled")
        return None
    try:
        _city_reader = _geoip2_db.Reader(path)
        logger.info("Loaded GeoLite2-City database from %s", path)
        return _city_reader
    except Exception as exc:
        logger.warning(
            "GeoLite2-City database unavailable at %s: %s — city enrichment disabled "
            "(download with scripts/download_geoip.sh)",
            path,
            exc,
        )
        return None


def _get_asn_reader():
    """Lazy-load GeoLite2-ASN reader. Memoizes failures to avoid log spam."""
    global _asn_reader, _asn_loaded
    if _asn_loaded:
        return _asn_reader
    _asn_loaded = True  # memoize regardless of outcome
    if _geoip2_db is None:
        return None
    path = settings.geoip_asn_db_path
    if not path:
        logger.debug("GEOIP_ASN_DB_PATH not configured, GeoIP ASN lookups disabled")
        return None
    try:
        _asn_reader = _geoip2_db.Reader(path)
        logger.info("Loaded GeoLite2-ASN database from %s", path)
        return _asn_reader
    except Exception as exc:
        logger.warning(
            "GeoLite2-ASN database unavailable at %s: %s — ASN enrichment disabled "
            "(download with scripts/download_geoip.sh)",
            path,
            exc,
        )
        return None


# ---------------------------------------------------------------------------
# CDN / WAF / Cloud signatures
# ---------------------------------------------------------------------------

CDN_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": ["cf-ray", "cf-cache-status", "server: cloudflare"],
    "akamai": ["x-akamai-transformed", "akamai-origin-hop"],
    "fastly": ["x-served-by", "x-fastly-request-id"],
    "cloudfront": ["x-amz-cf-id", "x-amz-cf-pop", "server: cloudfront"],
    "incapsula": ["x-iinfo", "x-cdn: incapsula"],
    "sucuri": ["x-sucuri-id", "server: sucuri"],
    "stackpath": ["x-hw", "server: netdna"],
    "azure_cdn": ["x-azure-ref", "x-msedge-ref"],
    "google_cdn": ["x-goog-", "server: gws", "via: 1.1 google"],
}

WAF_SIGNATURES: dict[str, list[str]] = {
    "cloudflare": ["cf-ray", "server: cloudflare"],
    "aws_waf": ["x-amzn-waf-", "awselb"],
    "akamai_kona": ["akamaighost", "x-akamai-session"],
    "imperva": ["x-iinfo", "_imp_apg_r_"],
    "f5_bigip": ["x-cnection", "bigipserver"],
    "barracuda": ["barra_counter_session"],
    "modsecurity": ["mod_security", "noyb"],
    "fortiweb": ["fortiwafsid"],
    "sucuri": ["x-sucuri-id", "sucuri-"],
}

CLOUD_SIGNATURES: dict[str, dict] = {
    "aws": {
        "headers": ["x-amz-", "x-amzn-"],
        "asn_orgs": ["Amazon", "AWS", "AMAZON"],
    },
    "gcp": {
        "headers": ["x-goog-", "server: gws"],
        "asn_orgs": ["Google", "GOOGLE"],
    },
    "azure": {
        "headers": ["x-azure-ref", "x-ms-"],
        "asn_orgs": ["Microsoft", "MICROSOFT"],
    },
    "digitalocean": {
        "headers": [],
        "asn_orgs": ["DigitalOcean", "DIGITALOCEAN"],
    },
    "oracle_cloud": {
        "headers": [],
        "asn_orgs": ["Oracle"],
    },
    "hetzner": {
        "headers": [],
        "asn_orgs": ["Hetzner"],
    },
}


# ---------------------------------------------------------------------------
# Lookup functions
# ---------------------------------------------------------------------------


def _serialize_date(obj: object) -> Optional[str]:
    """Safely serialize date/datetime to ISO string."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, date):
        return obj.isoformat()
    if isinstance(obj, list):
        # python-whois sometimes returns lists of dates
        for item in obj:
            result = _serialize_date(item)
            if result:
                return result
    return None


def whois_lookup(domain: str) -> dict:
    """
    Perform WHOIS lookup for a domain.

    Uses python-whois library. Returns structured registration data.
    Many domains have incomplete WHOIS data due to GDPR privacy, so
    every field may be None.

    Args:
        domain: Domain name (e.g. "example.com")

    Returns:
        Dict with registrar, org, country, creation/expiration dates,
        nameservers, and emails. All values may be None.
    """
    result: dict = {
        "registrar": None,
        "org": None,
        "country": None,
        "created": None,
        "expires": None,
        "nameservers": [],
        "emails": [],
    }

    try:
        if _whois_module is None:
            logger.debug("python-whois not installed, skipping WHOIS for %s", domain)
            return result

        w = _whois_module.whois(domain)

        if w is None:
            return result

        result["registrar"] = w.registrar if hasattr(w, "registrar") else None
        result["org"] = w.org if hasattr(w, "org") else None
        result["country"] = w.country if hasattr(w, "country") else None

        # Dates: python-whois returns datetime or list[datetime]
        result["created"] = _serialize_date(getattr(w, "creation_date", None))
        result["expires"] = _serialize_date(getattr(w, "expiration_date", None))

        # Nameservers: list of strings (lowercase)
        raw_ns = getattr(w, "name_servers", None) or []
        if isinstance(raw_ns, str):
            raw_ns = [raw_ns]
        result["nameservers"] = sorted({ns.lower().rstrip(".") for ns in raw_ns if isinstance(ns, str)})

        # Emails
        raw_emails = getattr(w, "emails", None) or []
        if isinstance(raw_emails, str):
            raw_emails = [raw_emails]
        result["emails"] = sorted({e.lower() for e in raw_emails if isinstance(e, str)})

    except Exception as exc:
        logger.debug("WHOIS lookup failed for %s: %s", domain, exc)

    return result


def reverse_dns(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup for an IP address.

    Uses socket.gethostbyaddr for PTR record resolution.

    Args:
        ip: IPv4 or IPv6 address string

    Returns:
        Hostname string or None if no PTR record exists
    """
    try:
        hostname, _aliases, _addresses = socket.gethostbyaddr(ip)
        # Avoid returning the IP itself as hostname
        if hostname and hostname != ip:
            return hostname
    except (socket.herror, socket.gaierror, OSError) as exc:
        logger.debug("Reverse DNS failed for %s: %s", ip, exc)
    return None


def resolve_domain_ip(domain: str) -> Optional[str]:
    """
    Resolve a domain to its primary IPv4 address.

    Args:
        domain: Domain name

    Returns:
        IPv4 address string or None
    """
    try:
        result = socket.getaddrinfo(domain, None, socket.AF_INET)
        if result:
            return result[0][4][0]
    except (socket.gaierror, OSError) as exc:
        logger.debug("DNS resolution failed for %s: %s", domain, exc)
    return None


def geoip_lookup(ip: str) -> Optional[dict]:
    """
    Perform GeoIP + ASN lookup using MaxMind GeoLite2 local databases.

    No rate limits — pure local .mmdb lookups. Requires:
    - GeoLite2-City.mmdb  (country, region, city, lat/lon)
    - GeoLite2-ASN.mmdb   (ASN number, organization)

    Download free databases from https://www.maxmind.com/en/geoip-databases
    and set GEOIP_CITY_DB_PATH / GEOIP_ASN_DB_PATH in environment.

    Args:
        ip: IPv4 or IPv6 address

    Returns:
        Dict with geo and ASN fields, or None on failure.
        Keys: country, country_code, region, city, lat, lon,
              isp, org, as_name, asn
    """
    result: dict = {}

    # --- City / Geo lookup ---
    city_reader = _get_city_reader()
    if city_reader is not None:
        try:
            resp = city_reader.city(ip)
            result["country"] = resp.country.name
            result["country_code"] = resp.country.iso_code
            result["region"] = resp.subdivisions.most_specific.name if resp.subdivisions else None
            result["city"] = resp.city.name
            result["lat"] = resp.location.latitude
            result["lon"] = resp.location.longitude
        except _geoip2_errors.AddressNotFoundError:
            logger.debug("GeoLite2-City: no record for %s", ip)
        except Exception as exc:
            logger.debug("GeoLite2-City lookup failed for %s: %s", ip, exc)

    # --- ASN lookup ---
    asn_reader = _get_asn_reader()
    if asn_reader is not None:
        try:
            resp = asn_reader.asn(ip)
            result["asn"] = resp.autonomous_system_number
            result["as_name"] = resp.autonomous_system_organization
            # GeoLite2-ASN provides org name as ASN org
            result["org"] = resp.autonomous_system_organization
        except _geoip2_errors.AddressNotFoundError:
            logger.debug("GeoLite2-ASN: no record for %s", ip)
        except Exception as exc:
            logger.debug("GeoLite2-ASN lookup failed for %s: %s", ip, exc)

    if not result:
        return None

    # Fill missing keys with None for consistent downstream access
    for key in ("country", "country_code", "region", "city", "lat", "lon", "isp", "org", "as_name", "asn"):
        result.setdefault(key, None)

    return result


# ---------------------------------------------------------------------------
# Header-based detection
# ---------------------------------------------------------------------------


def _flatten_headers(headers: dict) -> str:
    """
    Flatten a headers dict into a single lowercase string for matching.

    Handles both ``{key: value}`` and ``{key: [values]}`` formats.
    """
    parts: list[str] = []
    for key, value in headers.items():
        key_lower = key.lower()
        if isinstance(value, list):
            for v in value:
                parts.append(f"{key_lower}: {str(v).lower()}")
        else:
            parts.append(f"{key_lower}: {str(value).lower()}")
    return "\n".join(parts)


def detect_cdn(headers: dict) -> Optional[str]:
    """
    Detect CDN provider from HTTP response headers.

    Args:
        headers: Dict of HTTP response headers (key -> value or list)

    Returns:
        CDN provider slug (e.g. "cloudflare") or None
    """
    if not headers:
        return None

    flat = _flatten_headers(headers)

    for cdn_name, signatures in CDN_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in flat:
                return cdn_name

    return None


def detect_waf(headers: dict) -> Optional[str]:
    """
    Detect WAF provider from HTTP response headers.

    Args:
        headers: Dict of HTTP response headers

    Returns:
        WAF provider slug (e.g. "cloudflare") or None
    """
    if not headers:
        return None

    flat = _flatten_headers(headers)

    for waf_name, signatures in WAF_SIGNATURES.items():
        for sig in signatures:
            if sig.lower() in flat:
                return waf_name

    return None


def detect_cloud_provider(
    headers: dict,
    asn_org: Optional[str] = None,
) -> Optional[str]:
    """
    Detect cloud provider from HTTP headers and/or ASN organization.

    Checks headers first (more specific), then falls back to ASN org matching.

    Args:
        headers: Dict of HTTP response headers
        asn_org: ASN organization name from GeoIP/ASN lookup

    Returns:
        Cloud provider slug (e.g. "aws", "gcp") or None
    """
    flat = _flatten_headers(headers) if headers else ""

    for provider, sigs in CLOUD_SIGNATURES.items():
        # Check header signatures
        for header_sig in sigs.get("headers", []):
            if header_sig.lower() in flat:
                return provider

        # Check ASN organization
        if asn_org:
            for org_sig in sigs.get("asn_orgs", []):
                if org_sig.lower() in asn_org.lower():
                    return provider

    return None


# ---------------------------------------------------------------------------
# Batch enrichment helper
# ---------------------------------------------------------------------------


def enrich_asset_network(
    identifier: str,
    asset_type: str,
    ip_address: Optional[str] = None,
    service_headers: Optional[dict] = None,
) -> dict:
    """
    Run full network intelligence enrichment for a single asset.

    Performs WHOIS, rDNS, GeoIP/ASN, CDN, WAF, and cloud detection
    in the correct order. This is the main entry point for the Celery task.

    Args:
        identifier: Asset identifier (domain or IP)
        asset_type: Asset type string ("domain", "subdomain", "ip")
        ip_address: Pre-resolved IP address (avoids re-resolution)
        service_headers: Merged HTTP headers from the asset's services

    Returns:
        Dict with keys: whois, network, cdn, waf, cloud_provider
    """
    result: dict = {
        "whois": {},
        "network": {},
        "cdn": None,
        "waf": None,
        "cloud_provider": None,
    }

    is_domain = asset_type in ("domain", "subdomain")
    is_ip = asset_type == "ip"

    # 1. Resolve IP if needed
    ip = ip_address
    if is_domain and not ip:
        ip = resolve_domain_ip(identifier)
    elif is_ip:
        ip = identifier

    # 2. WHOIS for domains
    if is_domain:
        result["whois"] = whois_lookup(identifier)

    # 3. Network intelligence (rDNS + GeoIP + ASN)
    if ip:
        network_data: dict = {"ip": ip}

        # Reverse DNS
        rdns = reverse_dns(ip)
        if rdns:
            network_data["reverse_dns"] = rdns

        # GeoIP + ASN (MaxMind GeoLite2 local lookup)
        geo = geoip_lookup(ip)
        if geo:
            network_data["asn"] = geo.get("asn")
            network_data["asn_org"] = geo.get("org") or geo.get("as_name")
            network_data["isp"] = geo.get("isp")
            network_data["country"] = geo.get("country")
            network_data["country_code"] = geo.get("country_code")
            network_data["region"] = geo.get("region")
            network_data["city"] = geo.get("city")
            network_data["lat"] = geo.get("lat")
            network_data["lon"] = geo.get("lon")

        result["network"] = network_data

    # 4. CDN / WAF / Cloud detection from headers
    headers = service_headers or {}
    result["cdn"] = detect_cdn(headers)
    result["waf"] = detect_waf(headers)

    # Cloud provider: check headers AND ASN org
    asn_org = result.get("network", {}).get("asn_org")
    result["cloud_provider"] = detect_cloud_provider(headers, asn_org)

    return result


def discover_org_ip_ranges(org_name: str) -> list[dict]:
    """Discover IP ranges owned by an organization via RIPE/BGPView.

    Queries the BGPView API to find ASNs and IP prefixes associated
    with the given organization name. This enables discovery of
    infrastructure that isn't linked to any known domain.

    Args:
        org_name: Organization name from WHOIS (e.g. "Istituti Fisioterapici Ospitalieri")

    Returns:
        List of dicts with keys: prefix, asn, asn_name, description
    """
    import httpx

    if not org_name or len(org_name) < 3:
        return []

    ranges: list[dict] = []

    try:
        with httpx.Client(timeout=15) as client:
            resp = client.get(
                "https://api.bgpview.io/search",
                params={"query_term": org_name},
            )
            if resp.status_code != 200:
                logger.debug("BGPView search failed for '%s': %d", org_name, resp.status_code)
                return []

            data = resp.json().get("data", {})

            # Collect ASNs
            asns = data.get("asns", [])
            asn_numbers = [a["asn"] for a in asns]

            # Collect direct IP prefix results
            for prefix_info in data.get("ipv4_prefixes", []):
                ranges.append(
                    {
                        "prefix": prefix_info.get("prefix"),
                        "asn": prefix_info.get("parent", {}).get("asn"),
                        "asn_name": prefix_info.get("name"),
                        "description": prefix_info.get("description"),
                    }
                )

            # For each ASN, get all announced prefixes
            for asn in asn_numbers:
                try:
                    pfx_resp = client.get(f"https://api.bgpview.io/asn/{asn}/prefixes")
                    if pfx_resp.status_code == 200:
                        pfx_data = pfx_resp.json().get("data", {})
                        for pfx in pfx_data.get("ipv4_prefixes", []):
                            prefix = pfx.get("prefix")
                            if prefix and not any(r["prefix"] == prefix for r in ranges):
                                ranges.append(
                                    {
                                        "prefix": prefix,
                                        "asn": asn,
                                        "asn_name": pfx.get("name"),
                                        "description": pfx.get("description"),
                                    }
                                )
                except Exception:
                    continue

    except Exception as exc:
        logger.warning("Failed to discover IP ranges for org '%s': %s", org_name, exc)

    logger.info("Discovered %d IP range(s) for org '%s'", len(ranges), org_name)
    return ranges
