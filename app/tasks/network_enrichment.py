"""
Network Enrichment Celery Task

Enriches assets with WHOIS, reverse DNS, ASN, GeoIP, CDN, WAF,
and cloud provider data using the NetworkIntel service.

Rate limiting:
- ip-api.com: max 45 requests per minute (handled in network_intel module)
- Batches of 10 assets with 2-second sleep between batches

Storage:
- Enrichment data is merged into asset.raw_metadata under structured keys
  (whois, network, cdn, waf, cloud_provider)
- Existing raw_metadata keys are preserved; enrichment keys are overwritten
"""

import json
import logging
import time
from datetime import datetime, timezone
from typing import Optional

from app.celery_app import celery
from app.models.database import Asset, AssetType, Service
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

# Batch settings
BATCH_SIZE = 10
BATCH_SLEEP_SECONDS = 2.0


def _merge_headers_for_asset(asset_id: int, db) -> dict:
    """
    Collect and merge HTTP response headers from all services of an asset.

    Used for CDN/WAF/cloud detection. Merges headers from every service
    row that has http_headers populated (from HTTPx enrichment).

    Args:
        asset_id: Asset primary key
        db: SQLAlchemy session

    Returns:
        Merged dict of lowercase header keys -> values
    """
    services = (
        db.query(Service)
        .filter(
            Service.asset_id == asset_id,
            Service.http_headers.isnot(None),
        )
        .all()
    )

    merged: dict = {}
    for svc in services:
        headers = svc.http_headers
        if isinstance(headers, str):
            try:
                headers = json.loads(headers)
            except (json.JSONDecodeError, TypeError):
                continue
        if isinstance(headers, dict):
            for k, v in headers.items():
                merged[k.lower()] = v

    return merged


def _parse_raw_metadata(asset: Asset) -> dict:
    """
    Parse the existing raw_metadata JSON field on an asset.

    Returns an empty dict if the field is empty or unparseable.
    """
    if not asset.raw_metadata:
        return {}
    if isinstance(asset.raw_metadata, dict):
        return asset.raw_metadata
    try:
        return json.loads(asset.raw_metadata)
    except (json.JSONDecodeError, TypeError):
        return {}


@celery.task(
    name="app.tasks.network_enrichment.run_network_enrichment",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    soft_time_limit=1800,
    time_limit=1860,
)
def run_network_enrichment(
    self,
    tenant_id: int,
    asset_ids: Optional[list[int]] = None,
) -> dict:
    """
    Enrich assets with WHOIS, rDNS, ASN, GeoIP, CDN, WAF data.

    For each asset:
    1. Resolve IP if domain/subdomain (use existing ip_address or DNS)
    2. WHOIS lookup on domain
    3. Reverse DNS on IP
    4. GeoIP + ASN lookup on IP (ip-api.com)
    5. CDN / WAF detection from service response headers
    6. Cloud provider detection from ASN + headers
    7. Store everything in asset.raw_metadata under structured keys

    Args:
        tenant_id: Tenant ID
        asset_ids: Optional list of specific asset IDs to enrich.
                   If None, enriches all active assets for the tenant.

    Returns:
        Summary dict with counts of enriched/failed assets.
    """
    from app.database import SessionLocal
    from app.services.network_intel import enrich_asset_network

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        # Build query for target assets
        query = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.is_active == True,  # noqa: E712 - SQLAlchemy requires ==
        )

        if asset_ids:
            query = query.filter(Asset.id.in_(asset_ids))

        # Only enrich domains, subdomains, and IPs (not URLs/services)
        query = query.filter(
            Asset.type.in_([
                AssetType.DOMAIN,
                AssetType.SUBDOMAIN,
                AssetType.IP,
            ])
        )

        assets = query.all()

        if not assets:
            tenant_logger.info("No assets eligible for network enrichment")
            return {
                "tenant_id": tenant_id,
                "assets_enriched": 0,
                "assets_failed": 0,
                "status": "no_candidates",
            }

        tenant_logger.info(
            "Starting network enrichment for %d assets", len(assets)
        )

        enriched_count = 0
        failed_count = 0

        # Process in batches to respect ip-api.com rate limits
        for batch_start in range(0, len(assets), BATCH_SIZE):
            batch = assets[batch_start : batch_start + BATCH_SIZE]
            batch_num = batch_start // BATCH_SIZE + 1
            total_batches = (len(assets) + BATCH_SIZE - 1) // BATCH_SIZE

            tenant_logger.info(
                "Processing batch %d/%d (%d assets)",
                batch_num,
                total_batches,
                len(batch),
            )

            for asset in batch:
                try:
                    # Collect existing service headers for this asset
                    headers = _merge_headers_for_asset(asset.id, db)

                    # Run enrichment
                    enrichment = enrich_asset_network(
                        identifier=asset.identifier,
                        asset_type=asset.type.value,
                        ip_address=None,  # let the service resolve it
                        service_headers=headers,
                    )

                    # Merge into raw_metadata (preserve existing keys)
                    metadata = _parse_raw_metadata(asset)
                    metadata["whois"] = enrichment.get("whois", {})
                    metadata["network"] = enrichment.get("network", {})
                    metadata["cdn"] = enrichment.get("cdn")
                    metadata["waf"] = enrichment.get("waf")
                    metadata["cloud_provider"] = enrichment.get("cloud_provider")
                    metadata["network_enriched_at"] = datetime.now(timezone.utc).isoformat()

                    asset.raw_metadata = json.dumps(metadata, default=str)
                    asset.last_enriched_at = datetime.now(timezone.utc)

                    enriched_count += 1

                except Exception as exc:
                    tenant_logger.warning(
                        "Network enrichment failed for asset %s (id=%d): %s",
                        asset.identifier,
                        asset.id,
                        exc,
                    )
                    failed_count += 1

            # Commit after each batch
            try:
                db.commit()
            except Exception as exc:
                tenant_logger.error(
                    "Database commit failed for batch %d: %s",
                    batch_num,
                    exc,
                )
                db.rollback()
                failed_count += len(batch)
                enriched_count -= len(batch)

            # Sleep between batches to respect rate limits
            if batch_start + BATCH_SIZE < len(assets):
                time.sleep(BATCH_SLEEP_SECONDS)

        tenant_logger.info(
            "Network enrichment complete: %d enriched, %d failed",
            enriched_count,
            failed_count,
        )

        return {
            "tenant_id": tenant_id,
            "assets_enriched": enriched_count,
            "assets_failed": failed_count,
            "total_assets": len(assets),
            "status": "completed",
        }

    except Exception as exc:
        tenant_logger.error(
            "Network enrichment task failed: %s", exc, exc_info=True
        )
        return {
            "tenant_id": tenant_id,
            "assets_enriched": 0,
            "assets_failed": 0,
            "error": str(exc),
            "status": "failed",
        }
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Pipeline integration (synchronous, called from app/tasks/pipeline.py)
# ---------------------------------------------------------------------------


def phase_1c_network_enrichment(
    tenant_id: int,
    asset_ids: list[int],
    db,
    tenant_logger,
) -> dict:
    """
    Synchronous network enrichment for pipeline Phase 1c (WHOIS/RDAP Discovery).

    This function is designed to be called directly from the pipeline executor
    (``_phase_1c_whois_discovery`` in pipeline.py) rather than as an async
    Celery task, so the pipeline can track phase progress synchronously.

    It performs the same enrichment as ``run_network_enrichment`` but uses
    the caller-provided database session and logger.

    Args:
        tenant_id: Tenant ID
        asset_ids: List of asset IDs to enrich
        db: SQLAlchemy session (caller manages lifecycle)
        tenant_logger: TenantLoggerAdapter instance

    Returns:
        Dict with assets_discovered (count of newly enriched assets)
        and other summary stats.

    Usage in pipeline.py ``_phase_1c_whois_discovery``:

        from app.tasks.network_enrichment import phase_1c_network_enrichment
        from app.models.database import Asset, AssetType

        assets = db.query(Asset).filter(
            Asset.tenant_id == tenant_id,
            Asset.type.in_([AssetType.DOMAIN, AssetType.SUBDOMAIN, AssetType.IP]),
            Asset.is_active == True,
        ).all()

        if not assets:
            return {'assets_discovered': 0}

        asset_ids = [a.id for a in assets]
        return phase_1c_network_enrichment(tenant_id, asset_ids, db, tenant_logger)
    """
    from app.services.network_intel import enrich_asset_network

    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.id.in_(asset_ids),
            Asset.is_active == True,  # noqa: E712
            Asset.type.in_([
                AssetType.DOMAIN,
                AssetType.SUBDOMAIN,
                AssetType.IP,
            ]),
        )
        .all()
    )

    if not assets:
        tenant_logger.info("Phase 1c: no assets eligible for network enrichment")
        return {"assets_discovered": 0, "assets_enriched": 0, "assets_failed": 0}

    tenant_logger.info(
        "Phase 1c: enriching %d assets with WHOIS/GeoIP/CDN/WAF", len(assets)
    )

    enriched_count = 0
    failed_count = 0

    for batch_start in range(0, len(assets), BATCH_SIZE):
        batch = assets[batch_start : batch_start + BATCH_SIZE]

        for asset in batch:
            try:
                headers = _merge_headers_for_asset(asset.id, db)

                enrichment = enrich_asset_network(
                    identifier=asset.identifier,
                    asset_type=asset.type.value,
                    ip_address=None,
                    service_headers=headers,
                )

                metadata = _parse_raw_metadata(asset)
                metadata["whois"] = enrichment.get("whois", {})
                metadata["network"] = enrichment.get("network", {})
                metadata["cdn"] = enrichment.get("cdn")
                metadata["waf"] = enrichment.get("waf")
                metadata["cloud_provider"] = enrichment.get("cloud_provider")
                metadata["network_enriched_at"] = datetime.now(timezone.utc).isoformat()

                asset.raw_metadata = json.dumps(metadata, default=str)
                asset.last_enriched_at = datetime.now(timezone.utc)
                enriched_count += 1

            except Exception as exc:
                tenant_logger.warning(
                    "Phase 1c enrichment failed for %s: %s",
                    asset.identifier,
                    exc,
                )
                failed_count += 1

        # Commit per batch
        try:
            db.commit()
        except Exception as exc:
            tenant_logger.error("Phase 1c batch commit failed: %s", exc)
            db.rollback()

        # Rate limit pause between batches
        if batch_start + BATCH_SIZE < len(assets):
            time.sleep(BATCH_SLEEP_SECONDS)

    tenant_logger.info(
        "Phase 1c complete: %d enriched, %d failed", enriched_count, failed_count
    )

    return {
        "assets_discovered": 0,  # This phase enriches, it does not discover new assets
        "assets_enriched": enriched_count,
        "assets_failed": failed_count,
    }
