"""Version -> CVE inference.

We already fingerprint product + version on services (httpx/fingerprintx) and we
already enrich CVEs with EPSS/KEV — but we never turn a fingerprint into CVE
findings; we rely entirely on a nuclei template landing. This closes that gap: for a
recognized product+version, look up known CVEs (NVD, matched by CPE) and emit them as
**presumptive** findings (version-derived, not exploit-confirmed).

Precise by design: only products with a curated CPE mapping and a concrete version are
inferred, so we never fabricate a CVE from an ambiguous banner. The core (product->CPE,
NVD parsing) is pure and unit-tested; the network call is injected.
"""

from __future__ import annotations

import re
from typing import Callable, Optional

# Curated product -> (cpe vendor, cpe product). Keyed by a lowercase substring of the
# fingerprinted product/server string. Only add entries whose CPE we're confident of.
_PRODUCT_CPE: dict[str, tuple[str, str]] = {
    "apache": ("apache", "http_server"),  # "Apache", "Apache httpd"
    "nginx": ("nginx", "nginx"),
    "microsoft-iis": ("microsoft", "internet_information_services"),
    "microsoft-httpapi": ("microsoft", "http.sys"),
    "openssh": ("openbsd", "openssh"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("vsftpd", "vsftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "exim": ("exim", "exim"),
    "postfix": ("postfix", "postfix"),
    "dovecot": ("dovecot", "dovecot"),
    "openssl": ("openssl", "openssl"),
    "php": ("php", "php"),
    "wordpress": ("wordpress", "wordpress"),
    "jenkins": ("jenkins", "jenkins"),
    "tomcat": ("apache", "tomcat"),
    "jetty": ("eclipse", "jetty"),
    "haproxy": ("haproxy", "haproxy"),
}

_VERSION_RE = re.compile(r"\d+(?:\.\d+){1,3}")


def _normalize_product(product: str) -> str:
    return re.sub(r"[/\s].*$", "", (product or "").strip().lower()).replace("_", "-")


def product_to_cpe(product: Optional[str], version: Optional[str]) -> Optional[str]:
    """Build a CPE 2.3 string for a fingerprinted product+version, or None.

    Requires both a curated product mapping and a concrete version (from the version
    field, or extracted from the product string like "Apache/2.4.49").
    """
    if not product:
        return None
    prod_l = product.lower()
    match = None
    for key, cpe in _PRODUCT_CPE.items():
        if key in prod_l:
            match = cpe
            break
    if not match:
        return None

    ver = ""
    if version:
        m = _VERSION_RE.search(version)
        if m:
            ver = m.group(0)
    if not ver:
        m = _VERSION_RE.search(product)
        if m:
            ver = m.group(0)
    if not ver:
        return None

    vendor, prod = match
    return f"cpe:2.3:a:{vendor}:{prod}:{ver}:*:*:*:*:*:*:*"


def parse_nvd_cves(nvd_json: dict, max_n: int = 15) -> list[dict]:
    """Parse an NVD 2.0 /cves response into [{cve_id, cvss, description}], best CVSS first."""
    out: list[dict] = []
    for item in (nvd_json or {}).get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cvss = 0.0
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                try:
                    cvss = float(entries[0]["cvssData"]["baseScore"])
                except (KeyError, IndexError, TypeError, ValueError):
                    cvss = 0.0
                break
        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")[:400]
                break
        out.append({"cve_id": cve_id, "cvss": cvss, "description": desc})
    out.sort(key=lambda c: c["cvss"], reverse=True)
    return out[:max_n]


def infer_cves(
    product: Optional[str],
    version: Optional[str],
    http_get: Optional[Callable[[str], dict]] = None,
    max_n: int = 15,
) -> list[dict]:
    """Return known CVEs for a fingerprinted product+version (empty if unmappable).

    `http_get(cpe) -> nvd_json` is injected so the core is testable without network.
    """
    cpe = product_to_cpe(product, version)
    if not cpe or http_get is None:
        return []
    try:
        data = http_get(cpe)
    except Exception:
        return []
    return parse_nvd_cves(data, max_n=max_n)


def cvss_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    if cvss > 0:
        return "low"
    return "info"
