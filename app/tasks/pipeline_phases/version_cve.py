"""Phase 9e: version -> CVE inference.

For each fingerprinted service (product + version) we look up known CVEs (NVD, by
CPE) and emit them as **presumptive** findings — closing the gap where the scanner
had the fingerprint and the CVE corpus but never turned one into the other, relying
solely on a nuclei template landing. Enriched with EPSS/KEV we already fetch.

Bounded: distinct (product,version) pairs are queried at most once (cached per CPE in
Redis across runs), capped per run, and findings are capped per service. Presumptive
confidence — version-derived, not exploit-confirmed.
"""

from __future__ import annotations

import time

from app.config import settings
from app.core.cache import cache_get_sync, cache_set_sync
from app.services.scanning.cve_inference import infer_cves, product_to_cpe, cvss_to_severity

_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_get(cpe: str) -> dict:
    """Fetch NVD CVEs for a CPE, cached per-CPE in Redis. Rate-limit-friendly."""
    key = f"nvd:cpe:{cpe}"
    cached = cache_get_sync(key)
    if cached is not None:
        return cached
    import requests

    headers = {"User-Agent": "EASM-Scanner/1.0"}
    if settings.nvd_api_key:
        headers["apiKey"] = settings.nvd_api_key
    resp = requests.get(
        _NVD_URL,
        params={"cpeName": cpe, "resultsPerPage": 50},
        headers=headers,
        timeout=30,
    )
    data = resp.json() if resp.status_code == 200 else {"vulnerabilities": []}
    cache_set_sync(key, data, settings.version_cve_cache_ttl)
    return data


def _phase_9e_version_cve(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=1):
    """Phase 9e: turn service fingerprints into presumptive CVE findings."""
    if not settings.version_cve_enabled:
        return {"skipped": "disabled", "findings_created": 0}

    from app.models.database import Asset, AssetType, Service
    from app.repositories.finding_repository import FindingRepository
    from app.services.threat_intel import ThreatIntelService

    # Services (with product+version) on active hostname assets.
    rows = (
        db.query(Service.asset_id, Service.product, Service.version)
        .join(Asset, Asset.id == Service.asset_id)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
            Asset.is_active.is_(True),
            Service.product.isnot(None),
        )
        .all()
    )
    if not rows:
        return {"services_checked": 0, "findings_created": 0}

    host_by_asset = {a.id: a.identifier for a in db.query(Asset.id, Asset.identifier).all()}

    # Resolve distinct (product,version) pairs to CVE lists once (cache warms per CPE).
    pair_cves: dict[tuple, list] = {}
    queried = 0
    for _asset_id, product, version in rows:
        cpe = product_to_cpe(product, version)
        if not cpe:
            continue
        pair = (product, version)
        if pair in pair_cves:
            continue
        if queried >= settings.version_cve_max_pairs:
            continue
        cached = cache_get_sync(f"nvd:cpe:{cpe}")
        if cached is None:
            time.sleep(0 if settings.nvd_api_key else 6)  # NVD anon rate limit
        pair_cves[pair] = infer_cves(product, version, http_get=_nvd_get, max_n=settings.version_cve_max_per_service)
        queried += 1

    # Build presumptive findings per service.
    findings: list[dict] = []
    ti = ThreatIntelService()
    for asset_id, product, version in rows:
        cves = pair_cves.get((product, version))
        if not cves:
            continue
        host = host_by_asset.get(asset_id, "")
        cve_ids = [c["cve_id"] for c in cves]
        epss = ti.get_epss_scores_bulk(cve_ids) if cve_ids else {}
        for c in cves:
            cid = c["cve_id"]
            findings.append(
                {
                    "asset_id": asset_id,
                    "source": "version-cve",
                    "template_id": f"version-cve:{cid}",
                    "name": f"{product} {version or ''} — {cid} (version-based)"[:255],
                    "severity": cvss_to_severity(c["cvss"]),
                    "cvss_score": c["cvss"] or None,
                    "cve_id": cid,
                    "host": host,
                    "matched_at": host,
                    "evidence": {
                        "confidence": "presumptive",
                        "product": product,
                        "version": version,
                        "description": c.get("description", ""),
                        "epss": epss.get(cid, 0.0),
                        "in_kev": ti.is_in_kev(cid),
                        "source": "version-cve-inference",
                    },
                }
            )

    created = 0
    if findings:
        created = (
            FindingRepository(db).bulk_upsert_findings(findings, tenant_id, scan_run_id=scan_run_id).get("created", 0)
        )
    tenant_logger.info(
        "version-CVE: %d services, %d pairs queried, %d presumptive findings",
        len(rows),
        queried,
        len(findings),
    )
    return {"services_checked": len(rows), "pairs_queried": queried, "findings_created": created}
