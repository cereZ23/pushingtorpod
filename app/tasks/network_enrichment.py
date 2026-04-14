"""
Network Enrichment Celery Task

Enriches assets with WHOIS, reverse DNS, ASN, GeoIP, CDN, WAF,
and cloud provider data using the NetworkIntel service.

Rate limiting:
- WHOIS lookups may be throttled by registrars
- Batches of 10 assets with 2-second sleep between batches
- GeoIP uses local MaxMind GeoLite2 databases (no rate limits)

Storage:
- Enrichment data is merged into asset.raw_metadata under structured keys
  (whois, network, cdn, waf, cloud_provider)
- Existing raw_metadata keys are preserved; enrichment keys are overwritten
"""

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Optional

from app.celery_app import celery
from app.models.database import Asset, AssetType, Service
from app.utils.logger import TenantLoggerAdapter

logger = logging.getLogger(__name__)

# Batch settings
BATCH_SIZE = 20
BATCH_SLEEP_SECONDS = 0.5
# Max parallel WHOIS/GeoIP lookups (I/O bound)
MAX_WORKERS = 10


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
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
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
    4. GeoIP + ASN lookup on IP (MaxMind GeoLite2)
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
            Asset.type.in_(
                [
                    AssetType.DOMAIN,
                    AssetType.SUBDOMAIN,
                    AssetType.IP,
                ]
            )
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

        tenant_logger.info("Starting network enrichment for %d assets", len(assets))

        enriched_count = 0
        failed_count = 0

        # Process in batches to respect WHOIS rate limits
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

            # Pre-collect headers for batch (DB queries, must be on main thread)
            batch_headers = {}
            for asset in batch:
                batch_headers[asset.id] = _merge_headers_for_asset(asset.id, db)

            # Parallel enrichment (I/O bound: WHOIS, DNS, GeoIP)
            def _enrich_one(asset):
                return asset.id, enrich_asset_network(
                    identifier=asset.identifier,
                    asset_type=asset.type.value,
                    ip_address=None,
                    service_headers=batch_headers.get(asset.id, {}),
                )

            results = {}
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                futures = {pool.submit(_enrich_one, a): a for a in batch}
                for future in as_completed(futures):
                    asset = futures[future]
                    try:
                        asset_id, enrichment = future.result()
                        results[asset_id] = enrichment
                    except Exception as exc:
                        tenant_logger.warning(
                            "Network enrichment failed for asset %s (id=%d): %s",
                            asset.identifier,
                            asset.id,
                            exc,
                        )
                        failed_count += 1

            # Apply results back to ORM objects (main thread)
            for asset in batch:
                if asset.id not in results:
                    continue
                try:
                    enrichment = results[asset.id]
                    metadata = _parse_raw_metadata(asset)
                    metadata["whois"] = enrichment.get("whois", {})
                    # Merge network data: preserve existing GeoIP fields
                    # (lat, lon, country, city, asn, asn_org, etc.) and only
                    # add/update WHOIS-specific fields from this enrichment run.
                    existing_network = metadata.get("network", {})
                    if isinstance(existing_network, dict):
                        existing_network.update(enrichment.get("network", {}))
                        metadata["network"] = existing_network
                    else:
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
                        "Failed to apply enrichment for asset %s (id=%d): %s",
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
        tenant_logger.error("Network enrichment task failed: %s", exc, exc_info=True)
        try:
            db.rollback()
        except Exception:
            logger.debug("db.rollback() failed after network_enrichment error", exc_info=True)
        raise self.retry(exc=exc)
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
            Asset.type.in_(
                [
                    AssetType.DOMAIN,
                    AssetType.SUBDOMAIN,
                    AssetType.IP,
                ]
            ),
        )
        .all()
    )

    if not assets:
        tenant_logger.info("Phase 1c: no assets eligible for network enrichment")
        return {"assets_discovered": 0, "assets_enriched": 0, "assets_failed": 0}

    tenant_logger.info(
        "Phase 1c: enriching %d assets with WHOIS/GeoIP/CDN/WAF (%d workers)",
        len(assets),
        MAX_WORKERS,
    )

    # Pre-collect headers in main thread (DB access is not thread-safe)
    asset_headers: dict[int, dict] = {}
    asset_metadata: dict[int, dict] = {}
    for asset in assets:
        asset_headers[asset.id] = _merge_headers_for_asset(asset.id, db)
        asset_metadata[asset.id] = _parse_raw_metadata(asset)

    def _enrich_one(asset_id: int, identifier: str, asset_type: str) -> tuple[int, dict | None, str | None]:
        """Run enrichment for a single asset (thread-safe, no DB access)."""
        try:
            enrichment = enrich_asset_network(
                identifier=identifier,
                asset_type=asset_type,
                ip_address=None,
                service_headers=asset_headers.get(asset_id, {}),
            )
            return asset_id, enrichment, None
        except Exception as exc:
            return asset_id, None, str(exc)

    enriched_count = 0
    failed_count = 0
    asset_by_id = {a.id: a for a in assets}

    # Process in batches with parallel enrichment within each batch
    for batch_start in range(0, len(assets), BATCH_SIZE):
        batch = assets[batch_start : batch_start + BATCH_SIZE]
        batch_num = batch_start // BATCH_SIZE + 1
        total_batches = (len(assets) + BATCH_SIZE - 1) // BATCH_SIZE

        # Run enrichment in parallel threads
        results: list[tuple[int, dict | None, str | None]] = []
        with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(batch))) as executor:
            futures = {
                executor.submit(_enrich_one, asset.id, asset.identifier, asset.type.value): asset.id for asset in batch
            }
            for future in as_completed(futures):
                results.append(future.result())

        # Apply results in main thread (DB writes)
        for asset_id, enrichment, error in results:
            asset = asset_by_id[asset_id]
            if error:
                tenant_logger.warning(
                    "Phase 1c enrichment failed for %s: %s",
                    asset.identifier,
                    error,
                )
                failed_count += 1
            else:
                metadata = asset_metadata[asset_id]
                metadata["whois"] = enrichment.get("whois", {})
                # Merge network data: preserve existing GeoIP fields
                # (lat, lon, country, city, asn, asn_org, etc.) and only
                # add/update WHOIS-specific fields from this enrichment run.
                existing_network = metadata.get("network", {})
                if isinstance(existing_network, dict):
                    existing_network.update(enrichment.get("network", {}))
                    metadata["network"] = existing_network
                else:
                    metadata["network"] = enrichment.get("network", {})
                metadata["cdn"] = enrichment.get("cdn")
                metadata["waf"] = enrichment.get("waf")
                metadata["cloud_provider"] = enrichment.get("cloud_provider")
                metadata["network_enriched_at"] = datetime.now(timezone.utc).isoformat()

                asset.raw_metadata = json.dumps(metadata, default=str)
                asset.last_enriched_at = datetime.now(timezone.utc)
                enriched_count += 1

        # Commit per batch
        try:
            db.commit()
        except Exception as exc:
            tenant_logger.error("Phase 1c batch %d/%d commit failed: %s", batch_num, total_batches, exc)
            db.rollback()

        tenant_logger.info(
            "Phase 1c batch %d/%d done (%d ok, %d fail)",
            batch_num,
            total_batches,
            enriched_count,
            failed_count,
        )

        # Brief pause between batches for WHOIS rate limits
        if batch_start + BATCH_SIZE < len(assets):
            time.sleep(BATCH_SLEEP_SECONDS)

    tenant_logger.info("Phase 1c complete: %d enriched, %d failed", enriched_count, failed_count)

    return {
        "assets_discovered": 0,  # This phase enriches, it does not discover new assets
        "assets_enriched": enriched_count,
        "assets_failed": failed_count,
    }
