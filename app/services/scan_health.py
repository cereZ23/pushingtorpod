"""
Tool-invariant scan-health gate.

Complements the canary-based ``scan_validator``. The canary validator asks
"did the pipeline still detect our known-vulnerable URLs?" — great for
regression detection on monitored targets, but it validates nothing on a brand
new target with no canary, and it does not notice when an individual tool
silently produced no output.

This gate asserts *sanity invariants* over what a scan actually produced, so a
silently-failed tool (tlsx returning 0 certs for live HTTPS hosts, naabu finding
0 ports on live hosts, nuclei scanning 0 URLs, a required phase failing) is
turned into a loud DEGRADED verdict on ANY target — not discovered later when a
client asks why the report is empty.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from sqlalchemy import func

from app.database import SessionLocal
from app.models.database import Asset, AssetType, Finding, Service
from app.models.enrichment import Certificate, Endpoint

logger = logging.getLogger(__name__)

PASS = "pass"
WARN = "warn"
FAIL = "fail"
_ORDER = {PASS: 0, WARN: 1, FAIL: 2}


def validate_scan_health(
    tenant_id: int,
    scan_run_id: int,
    pipeline_stats: Optional[Dict] = None,
) -> Dict:
    """Assert tool-invariant sanity over a completed scan.

    Args:
        tenant_id: tenant scope
        scan_run_id: the run being validated (for logging)
        pipeline_stats: the pipeline's aggregate stats dict (phases_failed,
            _fatal, urls_scanned, findings_created) — used for run-level signals

    Returns:
        {'overall': 'pass'|'warn'|'fail', 'checks': [...], 'failures': [...],
         'degraded': bool, 'summary': str}
    """
    pipeline_stats = pipeline_stats or {}
    db = SessionLocal()
    try:
        checks: List[Dict] = []

        def add(name: str, status: str, detail: str) -> None:
            checks.append({"name": name, "status": status, "detail": detail})

        def _count_via_asset(model) -> int:
            return (
                db.query(func.count(model.id))
                .join(Asset, model.asset_id == Asset.id)
                .filter(Asset.tenant_id == tenant_id)
                .scalar()
                or 0
            )

        asset_count = db.query(func.count(Asset.id)).filter(Asset.tenant_id == tenant_id).scalar() or 0
        web_hosts = (
            db.query(func.count(Asset.id))
            .filter(Asset.tenant_id == tenant_id, Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]))
            .scalar()
            or 0
        )
        live_services = (
            db.query(func.count(Service.id))
            .join(Asset, Service.asset_id == Asset.id)
            .filter(Asset.tenant_id == tenant_id, Service.http_status.isnot(None))
            .scalar()
            or 0
        )
        https_services = (
            db.query(func.count(Service.id))
            .join(Asset, Service.asset_id == Asset.id)
            .filter(Asset.tenant_id == tenant_id, (Service.has_tls.is_(True)) | (Service.port.in_([443, 8443])))
            .scalar()
            or 0
        )
        cert_count = _count_via_asset(Certificate)
        endpoint_count = _count_via_asset(Endpoint)
        finding_count = _count_via_asset(Finding)

        phases_failed = int(pipeline_stats.get("phases_failed", 0) or 0)
        fatal = bool(pipeline_stats.get("_fatal", False))
        urls_scanned = pipeline_stats.get("urls_scanned")  # may be None if not aggregated

        # 1. Discovery
        if asset_count == 0:
            add("discovery", FAIL, "No assets discovered — discovery produced nothing.")
        else:
            add("discovery", PASS, f"{asset_count} assets discovered.")

        # 2. Pipeline integrity
        if fatal:
            add("pipeline", FAIL, "A required phase failed fatally.")
        elif phases_failed:
            add("pipeline", WARN, f"{phases_failed} phase(s) failed (non-fatal).")
        else:
            add("pipeline", PASS, "All phases completed.")

        # 3. HTTP probe (httpx)
        if web_hosts > 0 and live_services == 0:
            add("http_probe", FAIL, f"{web_hosts} web hosts but 0 live HTTP services — httpx likely failed (or all down).")
        else:
            add("http_probe", PASS, f"{live_services} live HTTP services.")

        # 4. TLS / certificates (tlsx) — the classic flaky one
        if https_services > 0 and cert_count == 0:
            add("tls_certs", FAIL, f"{https_services} HTTPS services but 0 certificates — tlsx likely failed.")
        else:
            add("tls_certs", PASS, f"{cert_count} certificates captured.")

        # 5. Crawl / endpoints (katana)
        if live_services > 0 and endpoint_count == 0:
            add("crawl", WARN, f"{live_services} live services but 0 endpoints — katana found nothing (check).")
        else:
            add("crawl", PASS, f"{endpoint_count} endpoints discovered.")

        # 6. Vulnerability scan (nuclei) — only assert if the run tracked urls_scanned
        if isinstance(urls_scanned, int):
            if urls_scanned == 0 and live_services > 0:
                add("vuln_scan", FAIL, "nuclei scanned 0 URLs despite live services — template dir or target selection failed.")
            else:
                add("vuln_scan", PASS, f"nuclei scanned {urls_scanned} URLs, {finding_count} findings.")
        # if urls_scanned isn't tracked, we don't guess — no check added

        overall = PASS
        for c in checks:
            if _ORDER[c["status"]] > _ORDER[overall]:
                overall = c["status"]
        failures = [c["name"] for c in checks if c["status"] == FAIL]
        warnings = [c["name"] for c in checks if c["status"] == WARN]

        if overall == FAIL:
            summary = f"SCAN DEGRADED — {len(failures)} check(s) failed: {', '.join(failures)}. Results are unreliable."
        elif overall == WARN:
            summary = f"Scan completed with warnings: {', '.join(warnings)}."
        else:
            summary = "All scan-health invariants passed."

        result = {
            "overall": overall,
            "checks": checks,
            "failures": failures,
            "warnings": warnings,
            "degraded": overall == FAIL,
            "summary": summary,
        }

        log = logger.error if overall == FAIL else (logger.warning if overall == WARN else logger.info)
        log("[scan-health] tenant %s run %s: %s", tenant_id, scan_run_id, summary)
        return result
    finally:
        db.close()
