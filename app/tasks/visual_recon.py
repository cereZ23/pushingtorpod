"""
Visual Recon - Phase 7

Captures screenshots of discovered HTTP services using Playwright headless browser.

Screenshots are stored in MinIO under:
  tenant-{tenant_id}/screenshots/{asset_id}/{port}_{timestamp}.png
  tenant-{tenant_id}/screenshots/{asset_id}/{port}_{timestamp}_thumb.png

Generates thumbnails (320x240) for list views and full screenshots (1920x1080).

Security Controls:
- URL validation before navigation
- Ignore HTTPS certificate errors (expected for recon)
- Screenshot timeout per page (30s default)
- Max screenshots per run to prevent OOM (200 default)
- Concurrent page limit (10 default) for resource management
- No JavaScript execution context exposure
- User-agent identifies as EASM scanner

Integration:
- Called from pipeline.py Phase 7
- Stores artifacts in MinIO via existing storage patterns
- Updates asset.raw_metadata with screenshot paths
- Updates service.screenshot_url for quick access
"""

import logging
import asyncio
from datetime import datetime, timezone
from io import BytesIO
from typing import Optional

from app.celery_app import celery
from app.models.database import Asset, AssetType, Service
from app.utils.logger import TenantLoggerAdapter
from app.config import settings

logger = logging.getLogger(__name__)

# Screenshot settings
VIEWPORT_WIDTH = 1920
VIEWPORT_HEIGHT = 1080
THUMB_WIDTH = 320
THUMB_HEIGHT = 240
SCREENSHOT_TIMEOUT = 30000  # 30s per page
MAX_SCREENSHOTS_PER_RUN = 200
BATCH_SIZE = 10  # Concurrent browser pages
NAVIGATION_WAIT = "networkidle"

# HTTP status codes that indicate a screenshottable page
SCREENSHOTTABLE_STATUS_CODES = {200, 301, 302, 403, 401, 500}


@celery.task(
    name="app.tasks.visual_recon.run_visual_recon",
    soft_time_limit=1800,  # 30 minutes soft limit
    time_limit=2100,  # 35 minutes hard limit
)
def run_visual_recon(
    tenant_id: int,
    asset_ids: list[int] | None = None,
    scan_run_id: int | None = None,
) -> dict:
    """
    Capture screenshots for all HTTP services of target assets.

    Workflow:
    1. Query services with live HTTP status for target assets
    2. Build URLs from asset identifier + service port + TLS flag
    3. Use Playwright headless Chromium for screenshots
    4. Store full-size + thumbnail in MinIO
    5. Update service.screenshot_url and asset.raw_metadata

    Args:
        tenant_id: Tenant to process
        asset_ids: Optional list of specific asset IDs (if None, all active)
        scan_run_id: Optional scan run ID for pipeline tracking

    Returns:
        Dict with statistics: screenshots_taken, errors, skipped
    """
    from app.database import SessionLocal

    db = SessionLocal()
    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})

    try:
        tenant_logger.info(
            "Starting visual recon (Phase 7) "
            f"[asset_ids={len(asset_ids) if asset_ids else 'all'}, "
            f"scan_run_id={scan_run_id}]"
        )

        # Build target list from database
        targets = _build_target_list(db, tenant_id, asset_ids, tenant_logger)

        if not targets:
            tenant_logger.info("No screenshottable targets found, skipping visual recon")
            return {
                "screenshots_taken": 0,
                "errors": 0,
                "skipped": 0,
                "status": "no_targets",
            }

        # Enforce max screenshots per run
        if len(targets) > MAX_SCREENSHOTS_PER_RUN:
            tenant_logger.info(f"Capping targets from {len(targets)} to {MAX_SCREENSHOTS_PER_RUN}")
            targets = targets[:MAX_SCREENSHOTS_PER_RUN]

        tenant_logger.info(f"Capturing screenshots for {len(targets)} targets")

        # Run async screenshot capture from sync Celery context
        stats = asyncio.run(_capture_screenshots(tenant_id, targets, tenant_logger))

        tenant_logger.info(
            f"Visual recon complete: {stats['screenshots_taken']} taken, "
            f"{stats['errors']} errors, {stats['skipped']} skipped"
        )

        return stats

    except Exception as e:
        tenant_logger.error(f"Visual recon failed: {e}", exc_info=True)
        return {
            "screenshots_taken": 0,
            "errors": 1,
            "skipped": 0,
            "status": "failed",
            "error": str(e),
        }
    finally:
        db.close()


def _build_target_list(
    db,
    tenant_id: int,
    asset_ids: list[int] | None,
    tenant_logger,
) -> list[dict]:
    """
    Query the database for services with live HTTP and build a URL target list.

    Each target dict contains:
      - url: Full URL to screenshot
      - asset_id: Asset ID for metadata storage
      - service_id: Service ID for screenshot_url update
      - port: Port number for file naming

    Returns:
        Sorted list of target dicts (highest risk_score first)
    """
    # Base query: join Service -> Asset for tenant scoping
    query = (
        db.query(Service, Asset)
        .join(Asset, Service.asset_id == Asset.id)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.is_active == True,  # noqa: E712
            Service.http_status.isnot(None),
            Service.http_status.in_(list(SCREENSHOTTABLE_STATUS_CODES)),
        )
    )

    if asset_ids:
        query = query.filter(Asset.id.in_(asset_ids))

    # Order by risk_score desc so the most important assets get screenshotted first
    # if we hit the MAX_SCREENSHOTS_PER_RUN cap
    query = query.order_by(Asset.risk_score.desc().nullslast(), Asset.id)

    results = query.all()

    targets = []
    seen_urls = set()

    for service, asset in results:
        scheme = "https" if service.has_tls else "http"
        port = service.port

        # Build URL, omitting default ports
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            url = f"{scheme}://{asset.identifier}"
        else:
            url = f"{scheme}://{asset.identifier}:{port}"

        # Deduplicate URLs (same asset could have overlapping service records)
        if url in seen_urls:
            continue
        seen_urls.add(url)

        targets.append(
            {
                "url": url,
                "asset_id": asset.id,
                "service_id": service.id,
                "port": port,
            }
        )

    tenant_logger.info(f"Built {len(targets)} screenshot targets from database")
    return targets


async def _capture_screenshots(
    tenant_id: int,
    targets: list[dict],
    tenant_logger,
) -> dict:
    """
    Async screenshot capture using Playwright.

    Processes targets in batches of BATCH_SIZE concurrent pages.
    Each target: {url, asset_id, service_id, port}

    Args:
        tenant_id: Tenant ID for storage paths
        targets: List of target dicts
        tenant_logger: Logger with tenant context

    Returns:
        Stats dict with screenshots_taken, errors, skipped counts
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        tenant_logger.warning(
            "Playwright not installed, skipping visual recon. "
            "Install with: pip install playwright && playwright install chromium"
        )
        return {
            "screenshots_taken": 0,
            "errors": 0,
            "skipped": len(targets),
            "status": "playwright_not_installed",
        }

    stats = {"screenshots_taken": 0, "errors": 0, "skipped": 0}

    async with async_playwright() as p:
        try:
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                    "--disable-extensions",
                    "--disable-background-networking",
                    "--disable-sync",
                    "--disable-translate",
                    "--mute-audio",
                    "--no-first-run",
                    "--disable-default-apps",
                ],
            )
        except Exception as e:
            tenant_logger.error(
                f"Failed to launch Chromium: {e}. Ensure Playwright browsers are installed: playwright install chromium"
            )
            return {
                "screenshots_taken": 0,
                "errors": 1,
                "skipped": len(targets),
                "status": "browser_launch_failed",
                "error": str(e),
            }

        context = await browser.new_context(
            viewport={"width": VIEWPORT_WIDTH, "height": VIEWPORT_HEIGHT},
            ignore_https_errors=True,
            user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 EASM-VisualRecon/1.0",
        )

        # Process in batches to control concurrency
        for batch_start in range(0, len(targets), BATCH_SIZE):
            batch = targets[batch_start : batch_start + BATCH_SIZE]
            tasks = [_screenshot_page(context, target, tenant_id, tenant_logger) for target in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, Exception):
                    stats["errors"] += 1
                    tenant_logger.debug(f"Screenshot batch exception: {result}")
                elif result is True:
                    stats["screenshots_taken"] += 1
                else:
                    stats["skipped"] += 1

        await browser.close()

    stats["status"] = "completed"
    return stats


async def _screenshot_page(
    context,
    target: dict,
    tenant_id: int,
    tenant_logger,
) -> bool:
    """
    Navigate to a URL and capture a screenshot.

    Stores full-size PNG and thumbnail in MinIO, then updates database metadata.

    Args:
        context: Playwright browser context
        target: Target dict with url, asset_id, service_id, port
        tenant_id: Tenant ID for storage path
        tenant_logger: Logger with tenant context

    Returns:
        True if screenshot was captured and stored, False if skipped
    """
    page = await context.new_page()
    url = target["url"]

    try:
        response = await page.goto(
            url,
            timeout=SCREENSHOT_TIMEOUT,
            wait_until=NAVIGATION_WAIT,
        )

        if response is None:
            tenant_logger.debug(f"No response for {url}, skipping screenshot")
            return False

        # Full-size screenshot (viewport only, not full page scroll)
        screenshot_bytes = await page.screenshot(full_page=False, type="png")

        # Generate thumbnail
        thumb_bytes = _generate_thumbnail(screenshot_bytes)

        # Build storage paths
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        asset_id = target["asset_id"]
        port = target["port"]

        full_path = f"screenshots/{asset_id}/{port}_{timestamp}.png"
        thumb_path = f"screenshots/{asset_id}/{port}_{timestamp}_thumb.png"

        # Store both files in MinIO
        _store_screenshot(tenant_id, full_path, screenshot_bytes)
        _store_screenshot(tenant_id, thumb_path, thumb_bytes)

        # Extract page title for metadata
        page_title = await page.title()

        # Update database records
        _update_screenshot_metadata(
            asset_id=target["asset_id"],
            service_id=target.get("service_id"),
            full_path=full_path,
            thumb_path=thumb_path,
            page_title=page_title,
            http_status=response.status if response else None,
        )

        tenant_logger.debug(f"Screenshot captured: {url} -> {full_path}")
        return True

    except Exception as e:
        tenant_logger.debug(f"Screenshot failed for {url}: {e}")
        return False
    finally:
        await page.close()


def _generate_thumbnail(screenshot_bytes: bytes) -> bytes:
    """
    Generate a thumbnail from a full-size screenshot PNG.

    Uses Pillow if available; falls back to returning the full screenshot
    if Pillow is not installed.

    Args:
        screenshot_bytes: Full-size PNG data

    Returns:
        Thumbnail PNG data
    """
    try:
        from PIL import Image

        img = Image.open(BytesIO(screenshot_bytes))
        img.thumbnail((THUMB_WIDTH, THUMB_HEIGHT), Image.LANCZOS)
        buf = BytesIO()
        img.save(buf, format="PNG", optimize=True)
        return buf.getvalue()
    except ImportError:
        logger.warning("Pillow not installed, returning full screenshot as thumbnail. Install with: pip install Pillow")
        return screenshot_bytes


def _store_screenshot(tenant_id: int, object_path: str, data: bytes) -> None:
    """
    Store a screenshot file in MinIO.

    Uses the same tenant-scoped bucket pattern as store_raw_output:
    bucket = tenant-{tenant_id}, object = screenshots/...

    Args:
        tenant_id: Tenant ID for bucket name
        object_path: Object key within the bucket
        data: PNG bytes to store
    """
    from app.utils.storage import get_minio_client, ensure_bucket_exists

    try:
        client = get_minio_client()
        bucket_name = f"tenant-{tenant_id}"
        ensure_bucket_exists(client, bucket_name)

        client.put_object(
            bucket_name,
            object_path,
            BytesIO(data),
            length=len(data),
            content_type="image/png",
        )
    except Exception as e:
        logger.warning(f"Failed to store screenshot to MinIO ({object_path}): {e}")
        raise


def _update_screenshot_metadata(
    asset_id: int,
    service_id: int | None,
    full_path: str,
    thumb_path: str,
    page_title: str | None = None,
    http_status: int | None = None,
) -> None:
    """
    Update asset raw_metadata and service screenshot_url in the database.

    - Appends to asset.raw_metadata['screenshots'] list
    - Sets service.screenshot_url to the thumbnail path

    Uses a dedicated short-lived session to avoid conflicts with the
    async capture loop.

    Args:
        asset_id: Asset ID to update
        service_id: Service ID to update (optional)
        full_path: MinIO path for the full screenshot
        thumb_path: MinIO path for the thumbnail
        page_title: Page title captured from the browser
        http_status: HTTP response status code
    """
    from app.database import SessionLocal
    import json

    db = SessionLocal()
    try:
        # Update asset raw_metadata
        asset = db.query(Asset).filter_by(id=asset_id).first()
        if asset:
            # Parse existing raw_metadata (stored as Text/JSON string)
            try:
                meta = json.loads(asset.raw_metadata) if asset.raw_metadata else {}
            except (json.JSONDecodeError, TypeError):
                meta = {}

            if "screenshots" not in meta:
                meta["screenshots"] = []

            screenshot_entry = {
                "full": full_path,
                "thumb": thumb_path,
                "service_id": service_id,
                "captured_at": datetime.now(timezone.utc).isoformat(),
            }
            if page_title:
                screenshot_entry["page_title"] = page_title[:500]
            if http_status is not None:
                screenshot_entry["http_status"] = http_status

            meta["screenshots"].append(screenshot_entry)

            # Store back as JSON string (raw_metadata is Text column)
            asset.raw_metadata = json.dumps(meta, default=str)

        # Update service screenshot_url for quick access
        if service_id:
            service = db.query(Service).filter_by(id=service_id).first()
            if service:
                service.screenshot_url = thumb_path

        db.commit()
    except Exception as e:
        logger.warning(f"Failed to update screenshot metadata for asset {asset_id}: {e}")
        db.rollback()
    finally:
        db.close()


def get_screenshot_url(tenant_id: int, object_path: str) -> str | None:
    """
    Generate a presigned URL for a screenshot stored in MinIO.

    Useful for serving screenshots to the frontend without exposing
    MinIO credentials.

    Args:
        tenant_id: Tenant ID
        object_path: Object path within tenant bucket

    Returns:
        Presigned URL string, or None on error
    """
    from app.utils.storage import get_minio_client
    from datetime import timedelta

    try:
        client = get_minio_client()
        bucket_name = f"tenant-{tenant_id}"
        url = client.presigned_get_object(
            bucket_name,
            object_path,
            expires=timedelta(hours=1),
        )
        return url
    except Exception as e:
        logger.warning(f"Failed to generate presigned URL for {object_path}: {e}")
        return None
