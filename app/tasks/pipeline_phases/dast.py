"""Phase 9d: Active DAST (nuclei -dast fuzzing on crawled parameterized URLs).

nuclei's fuzzing engine injects payloads into URL parameters (reflected XSS,
error-based SQLi, SSTI, open-redirect, SSRF via OAST). It needs URLs WITH
parameters — those come from katana (phase 6b). Verified live: this finds real
vulns (reflected-XSS on Firing Range).

Intrusive (payload injection) → hard-gated: Tier 3 only, an active
ScanAuthorization, and `dast_enabled`. Off by default.
"""

from __future__ import annotations

import json
from urllib.parse import urlparse, parse_qs

from app.config import settings

# ---- pure helpers (unit-tested) ---------------------------------------------


def dast_skip_reason(scan_tier: int, enabled: bool, authorized: bool) -> str | None:
    """Return why DAST must be skipped, or None if it may run."""
    if not enabled:
        return "dast_disabled"
    if (scan_tier or 0) < 3:
        return "tier_below_3"
    if not authorized:
        return "no_scan_authorization"
    return None


def _url_shape(url: str) -> tuple:
    """(host, id-collapsed path, sorted param names) — collapses /x/1..N & ?id=1..N."""
    p = urlparse(url)
    segs = []
    for seg in (p.path or "").split("/"):
        if seg.isdigit() or (len(seg) >= 16 and seg.isalnum()):
            segs.append("*")
        else:
            segs.append(seg)
    return ((p.hostname or "").lower(), "/".join(segs), tuple(sorted(parse_qs(p.query).keys())))


def select_dast_targets(urls, cap: int) -> list[str]:
    """Keep only URLs with query parameters, dedup by shape, cap the set."""
    seen: set[tuple] = set()
    out: list[str] = []
    for u in urls or []:
        if not u or "?" not in u:
            continue
        shape = _url_shape(u)
        if not shape[2]:  # no query param names
            continue
        if shape in seen:
            continue
        seen.add(shape)
        out.append(u)
        if len(out) >= cap:
            break
    return out


# ---- orchestration ----------------------------------------------------------


def _has_active_scan_authorization(db, tenant_id: int) -> bool:
    from app.models.authorization import ScanAuthorization

    return (
        db.query(ScanAuthorization.id)
        .filter(ScanAuthorization.tenant_id == tenant_id, ScanAuthorization.is_active.is_(True))
        .first()
        is not None
    )


def _phase_9d_dast(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=1):
    """Phase 9d: active DAST fuzzing with nuclei -dast on katana-crawled param URLs."""
    from app.models.database import Asset, AssetType
    from app.models.enrichment import Endpoint
    from app.utils.secure_executor import SecureToolExecutor
    from app.repositories.finding_repository import FindingRepository

    reason = dast_skip_reason(scan_tier, settings.dast_enabled, _has_active_scan_authorization(db, tenant_id))
    if reason:
        tenant_logger.info("DAST phase skipped: %s", reason)
        return {"dast_skipped": reason, "findings_created": 0}

    # Parameterized URLs from the crawl (katana → Endpoint), in-scope active assets.
    active_asset_ids = [
        a.id
        for a in db.query(Asset.id)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active.is_(True),
        )
        .all()
    ]
    if not active_asset_ids:
        return {"dast_skipped": "no_assets", "findings_created": 0}

    host_to_asset: dict[str, int] = {}
    for a in db.query(Asset).filter(Asset.id.in_(active_asset_ids)).all():
        host_to_asset[a.identifier.lower()] = a.id

    endpoint_urls = [
        e.url
        for e in db.query(Endpoint.url).filter(Endpoint.asset_id.in_(active_asset_ids), Endpoint.url.like("%?%")).all()
    ]
    targets = select_dast_targets(endpoint_urls, settings.dast_max_urls)
    if not targets:
        tenant_logger.info("DAST: no parameterized URLs to fuzz")
        return {"dast_targets": 0, "findings_created": 0}

    tenant_logger.info("DAST: fuzzing %d parameterized URLs (nuclei -dast)", len(targets))

    findings: list[dict] = []
    try:
        with SecureToolExecutor(tenant_id) as executor:
            target_file = executor.create_input_file("dast_targets.txt", "\n".join(targets))
            args = [
                "-list",
                target_file,
                "-dast",
                "-t",
                settings.fuzzing_templates_path,
                "-fa",
                settings.dast_aggression,
                "-jsonl",
                "-silent",
                "-rl",
                str(settings.dast_rate_limit),
                "-c",
                str(settings.dast_concurrency),
            ]
            _, stdout, _ = executor.execute("nuclei", args, timeout=settings.dast_timeout)
    except Exception as exc:
        tenant_logger.error("DAST nuclei run failed: %s", exc)
        return {"dast_targets": len(targets), "findings_created": 0, "error": str(exc)[:200]}

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except (ValueError, TypeError):
            continue
        host = (j.get("host") or urlparse(j.get("matched-at", "")).hostname or "").lower()
        asset_id = host_to_asset.get(host)
        if not asset_id:
            continue
        info = j.get("info", {}) or {}
        findings.append(
            {
                "asset_id": asset_id,
                "source": "nuclei-dast",
                "template_id": j.get("template-id", "dast"),
                "name": (info.get("name") or j.get("template-id") or "DAST finding")[:255],
                "severity": (info.get("severity") or "medium").lower(),
                "matched_at": j.get("matched-at"),
                "host": host,
                "matcher_name": j.get("matcher-name"),
                "evidence": {"matched_at": j.get("matched-at"), "type": "dast-fuzzing"},
            }
        )

    created = 0
    if findings:
        res = FindingRepository(db).bulk_upsert_findings(findings, tenant_id)
        created = res.get("created", 0)
    tenant_logger.info("DAST: %d findings from %d targets", len(findings), len(targets))
    return {"dast_targets": len(targets), "findings_created": created, "findings_total": len(findings)}
