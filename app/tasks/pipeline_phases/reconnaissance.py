"""Reconnaissance phase implementations (Phases 6, 6b, 6c, 7).

Phase 6:  Technology Fingerprinting
Phase 6b: Web Crawling (katana)
Phase 6c: Sensitive Path Discovery
Phase 7:  Visual Recon (screenshots)
"""

from __future__ import annotations

import logging

from app.models.risk import Relationship

logger = logging.getLogger(__name__)


def _phase_6_fingerprinting(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 6: Technology fingerprinting."""
    from app.tasks.fingerprint import run_fingerprinting

    result = run_fingerprinting(tenant_id, scan_run_id=scan_run_id)

    if isinstance(result, dict):
        return {
            "technologies_detected": result.get("technologies_detected", 0),
            "services_fingerprinted": result.get("services_analyzed", 0),
        }
    return {"technologies_detected": 0}


def _phase_6b_web_crawling(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 6b: Web crawling with Katana.

    Katana depends on live HTTP services discovered by Phase 4 (HTTPx).
    Only crawls hostnames + standalone IPs (skip IPs already resolved from hostnames).
    """
    from app.tasks.enrichment import run_katana
    from app.models.database import Asset, AssetType

    hostname_assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    covered_ip_ids = {
        r.target_asset_id
        for r in db.query(Relationship.target_asset_id)
        .filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == "resolves_to",
        )
        .all()
    }
    standalone_ips = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type == AssetType.IP,
            Asset.is_active == True,
            ~Asset.id.in_(covered_ip_ids) if covered_ip_ids else True,
        )
        .all()
    )

    assets = hostname_assets + standalone_ips

    if not assets:
        return {"endpoints_discovered": 0}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"Katana: crawling {len(asset_ids)} assets (deduped IPs)")
    result = run_katana(tenant_id, asset_ids)

    return {
        "endpoints_discovered": result.get("endpoints_discovered", 0) if isinstance(result, dict) else 0,
        "endpoints_created": result.get("endpoints_created", 0) if isinstance(result, dict) else 0,
        "urls_crawled": result.get("urls_crawled", 0) if isinstance(result, dict) else 0,
    }


def _phase_6c_sensitive_paths(tenant_id, project_id, scan_run_id, db, tenant_logger, scan_tier=1):
    """Phase 6c: Sensitive path discovery.

    Probes assets with HTTP services for commonly exposed sensitive paths
    (config files, VCS metadata, backups, admin panels, debug endpoints).
    Only scans hostnames + standalone IPs (skip resolved-from-hostname IPs).
    For Tier 1 scans, only the top 50 most impactful paths are checked.

    IP dedup: when multiple hostnames resolve to the same IP, only one
    representative hostname is probed per unique IP.  Findings discovered
    on the representative are replicated to all sibling assets sharing
    that IP, so no exposures are missed in the output.
    """
    from app.tasks.sensitive_paths import run_sensitive_path_scan
    from app.models.database import Asset, AssetType
    from app.services.resource_scaler import get_scan_params
    from app.services.ip_dedup import dedup_by_resolved_ip

    hostname_assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN]),
            Asset.is_active == True,
        )
        .all()
    )

    covered_ip_ids = {
        r.target_asset_id
        for r in db.query(Relationship.target_asset_id)
        .filter(
            Relationship.tenant_id == tenant_id,
            Relationship.rel_type == "resolves_to",
        )
        .all()
    }
    standalone_ips = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type == AssetType.IP,
            Asset.is_active == True,
            ~Asset.id.in_(covered_ip_ids) if covered_ip_ids else True,
        )
        .all()
    )

    assets = hostname_assets + standalone_ips

    if not assets:
        return {"findings_created": 0, "assets_scanned": 0}

    # Deduplicate hostnames resolving to the same IP -- probing the same
    # server 6 times with different Host headers is wasteful and produces
    # identical results for path-based checks.
    assets, ip_dedup_skipped = dedup_by_resolved_ip(assets, tenant_id, db)

    asset_ids = [a.id for a in assets]
    params = get_scan_params(scan_tier=scan_tier)
    tenant_logger.info(
        f"Sensitive path scan: {len(asset_ids)} assets "
        f"({ip_dedup_skipped} same-IP duplicates skipped), "
        f"max_paths={params.sensitive_paths_limit or 'unlimited'}"
    )
    result = run_sensitive_path_scan(
        tenant_id,
        asset_ids,
        db=db,
        scan_run_id=scan_run_id,
        max_paths=params.sensitive_paths_limit,
    )

    return {
        "findings_created": result.get("findings_created", 0) if isinstance(result, dict) else 0,
        "findings_updated": result.get("findings_updated", 0) if isinstance(result, dict) else 0,
        "assets_scanned": result.get("assets_scanned", 0) if isinstance(result, dict) else 0,
        "paths_checked": result.get("paths_checked", 0) if isinstance(result, dict) else 0,
        "ip_dedup_skipped": ip_dedup_skipped,
    }


def _phase_7_visual_recon(tenant_id, project_id, scan_run_id, db, tenant_logger):
    """Phase 7: Visual Recon - capture screenshots of discovered HTTP services.

    Uses Playwright headless Chromium to screenshot all live web services.
    Stores full-size (1920x1080) and thumbnail (320x240) PNGs in MinIO.
    """
    from app.config import settings

    if not getattr(settings, "feature_visual_recon_enabled", True):
        tenant_logger.info("Visual recon disabled in feature flags, skipping Phase 7")
        return {"screenshots_taken": 0, "status": "disabled"}

    from app.tasks.visual_recon import run_visual_recon
    from app.models.database import Asset, AssetType

    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
            Asset.is_active == True,  # noqa: E712
        )
        .all()
    )

    if not assets:
        return {"screenshots_taken": 0, "status": "no_assets"}

    asset_ids = [a.id for a in assets]
    tenant_logger.info(f"Visual recon: {len(asset_ids)} candidate assets")

    result = run_visual_recon(
        tenant_id=tenant_id,
        asset_ids=asset_ids,
    )

    return {
        "screenshots_taken": result.get("screenshots_taken", 0) if isinstance(result, dict) else 0,
        "status": result.get("status", "completed") if isinstance(result, dict) else "completed",
    }
