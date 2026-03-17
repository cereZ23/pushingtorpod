"""
Assets Router

Handles asset management, discovery, and hierarchy
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func, select
from typing import List, Optional
from datetime import datetime, timezone
import json
import logging

from app.api.dependencies import (
    get_db,
    verify_tenant_access,
    PaginationParams,
    escape_like,
)
from app.api.schemas.asset import (
    AssetResponse,
    AssetCreate,
    AssetUpdate,
    AssetListRequest,
    AssetDetailResponse,
    AssetTreeNode,
    SeedCreate,
    SeedResponse,
    BulkAssetCreate,
)
from app.api.schemas.common import BulkOperationResult
from app.api.schemas.envelope import PaginatedEnvelope, PaginationMeta
from app.models.database import Asset, AssetType, Seed, Service, Finding
from app.models.enrichment import Certificate, Endpoint
from app.repositories.asset_repository import AssetRepository
from app.core.audit import log_data_modification, log_audit_event, AuditEventType

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/assets", tags=["Assets"])


@router.get("", response_model=PaginatedEnvelope[AssetResponse])
def list_assets(
    tenant_id: int,
    asset_type: Optional[str] = Query(None, description="Filter by asset type"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    enrichment_status: Optional[str] = Query(None, description="Filter by enrichment status"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search in identifier"),
    min_risk_score: Optional[float] = Query(None, description="Minimum risk score"),
    max_risk_score: Optional[float] = Query(None, description="Maximum risk score"),
    changed_since: Optional[datetime] = Query(None, description="Changed since timestamp"),
    sort_by: str = Query("last_seen", description="Sort field"),
    sort_order: str = Query("desc", description="Sort order"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    List assets with filtering, search, and pagination

    Supports:
    - Type filtering (domain, subdomain, ip, url)
    - Priority filtering (critical, high, normal, low)
    - Risk score range
    - Search by identifier
    - Changed since timestamp (for delta queries)
    - Sorting and pagination

    Returns:
        Paginated list of assets
    """
    # Build query
    query = db.query(Asset).filter(Asset.tenant_id == tenant_id)

    # Apply filters
    if asset_type:
        try:
            query = query.filter(Asset.type == AssetType(asset_type))
        except ValueError:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid asset type: {asset_type}")

    if priority:
        query = query.filter(Asset.priority == priority)

    if enrichment_status:
        query = query.filter(Asset.enrichment_status == enrichment_status)

    if is_active is not None:
        query = query.filter(Asset.is_active == is_active)

    if search:
        safe_search = escape_like(search)
        query = query.filter(Asset.identifier.ilike(f"%{safe_search}%", escape="\\"))

    if min_risk_score is not None:
        query = query.filter(Asset.risk_score >= min_risk_score)

    if max_risk_score is not None:
        query = query.filter(Asset.risk_score <= max_risk_score)

    if changed_since:
        query = query.filter(or_(Asset.last_seen >= changed_since, Asset.last_enriched_at >= changed_since))

    # Get total count before pagination
    total = query.count()

    # Apply sorting
    ALLOWED_SORT_COLUMNS = {
        "identifier": Asset.identifier,
        "type": Asset.type,
        "first_seen": Asset.first_seen,
        "last_seen": Asset.last_seen,
        "risk_score": Asset.risk_score,
    }
    sort_column = ALLOWED_SORT_COLUMNS.get(sort_by, Asset.last_seen)
    if sort_order.lower() == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = pagination.paginate_query(query)

    # Add correlated subquery counts (single query instead of N+1)
    service_count_sq = (
        select(func.count(Service.id))
        .where(Service.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label("service_count")
    )
    certificate_count_sq = (
        select(func.count(Certificate.id))
        .where(Certificate.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label("certificate_count")
    )
    endpoint_count_sq = (
        select(func.count(Endpoint.id))
        .where(Endpoint.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label("endpoint_count")
    )
    finding_count_sq = (
        select(func.count(Finding.id))
        .where(Finding.asset_id == Asset.id)
        .correlate(Asset)
        .scalar_subquery()
        .label("finding_count")
    )

    # Execute query with counts in a single DB round-trip
    query = query.add_columns(
        service_count_sq,
        certificate_count_sq,
        endpoint_count_sq,
        finding_count_sq,
    )
    results = query.all()

    items = []
    for row in results:
        asset = row[0] if isinstance(row, tuple) else row.Asset if hasattr(row, "Asset") else row
        asset_dict = AssetResponse.model_validate(asset).model_dump()
        asset_dict["service_count"] = row.service_count if hasattr(row, "service_count") else 0
        asset_dict["certificate_count"] = row.certificate_count if hasattr(row, "certificate_count") else 0
        asset_dict["endpoint_count"] = row.endpoint_count if hasattr(row, "endpoint_count") else 0
        asset_dict["finding_count"] = row.finding_count if hasattr(row, "finding_count") else 0
        items.append(asset_dict)

    return PaginatedEnvelope(
        data=items,
        meta=PaginationMeta(
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
            total_pages=(total + pagination.page_size - 1) // pagination.page_size,
        ),
    )


@router.get("/{asset_id}", response_model=AssetDetailResponse)
def get_asset(tenant_id: int, asset_id: int, db: Session = Depends(get_db), membership=Depends(verify_tenant_access)):
    """
    Get asset by ID with comprehensive EASM detail

    Includes:
    - Asset metadata and enrichment status
    - Services with HTTP and TLS details
    - Certificates from TLSx (queried directly)
    - Endpoints from Katana crawler (limited to 100)
    - Findings with fingerprint and occurrence data
    - Events (last 50)
    - DNS/Network intelligence (IPs, rDNS, ASN, cloud provider)
    - Aggregated technology stack
    - Summary statistics with severity breakdown
    - HTTP response info per service

    Raises:
        - 404: Asset not found
        - 403: No access to tenant
    """
    from app.services.asset_detail_service import AssetDetailService

    result = AssetDetailService(db).get_detail(tenant_id, asset_id)
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return result


@router.post("", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_asset(
    tenant_id: int, asset_data: AssetCreate, db: Session = Depends(get_db), membership=Depends(verify_tenant_access)
):
    """
    Create new asset

    Validates asset type and identifier format

    Raises:
        - 400: Invalid asset data or duplicate
        - 403: No write access to tenant
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Write permission required")

    # Check if asset already exists
    existing = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.identifier == asset_data.identifier,
            Asset.type == AssetType(asset_data.type),
        )
        .first()
    )

    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Asset already exists")

    # Create asset
    asset = Asset(
        tenant_id=tenant_id,
        type=AssetType(asset_data.type),
        identifier=asset_data.identifier,
        priority=asset_data.priority or "normal",
    )

    db.add(asset)
    db.commit()
    db.refresh(asset)

    log_data_modification(
        action="create",
        resource="asset",
        resource_id=str(asset.id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={
            "identifier": asset.identifier,
            "type": asset.type.value if hasattr(asset.type, "value") else str(asset.type),
        },
    )

    logger.info(f"Created asset {asset.identifier} for tenant {tenant_id}")

    return AssetResponse.model_validate(asset)


@router.patch("/{asset_id}", response_model=AssetResponse)
def update_asset(
    tenant_id: int,
    asset_id: int,
    updates: AssetUpdate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Update asset

    Allows updating priority and active status

    Raises:
        - 404: Asset not found
        - 403: No write access
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Write permission required")

    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.tenant_id == tenant_id).first()

    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Apply updates
    if updates.priority is not None:
        asset.priority = updates.priority
        asset.priority_updated_at = datetime.now(timezone.utc)
        asset.priority_auto_calculated = False

    if updates.is_active is not None:
        asset.is_active = updates.is_active

    db.commit()
    db.refresh(asset)

    log_data_modification(
        action="update",
        resource="asset",
        resource_id=str(asset_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
    )

    logger.info(f"Updated asset {asset.identifier}")

    return AssetResponse.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    tenant_id: int, asset_id: int, db: Session = Depends(get_db), membership=Depends(verify_tenant_access)
):
    """
    Delete asset (soft delete - mark as inactive)

    Raises:
        - 404: Asset not found
        - 403: No write access
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Write permission required")

    asset = db.query(Asset).filter(Asset.id == asset_id, Asset.tenant_id == tenant_id).first()

    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")

    # Soft delete
    asset.is_active = False
    db.commit()

    log_data_modification(
        action="delete",
        resource="asset",
        resource_id=str(asset_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
    )

    logger.info(f"Deleted asset {asset.identifier}")


@router.get("/tree", response_model=List[AssetTreeNode])
def get_asset_tree(tenant_id: int, db: Session = Depends(get_db), membership=Depends(verify_tenant_access)):
    """
    Get hierarchical asset tree

    Returns:
        Tree structure: domains -> subdomains -> IPs/URLs

    Useful for visualization and navigation
    """
    # Get all domains
    domains = (
        db.query(Asset)
        .filter(Asset.tenant_id == tenant_id, Asset.type == AssetType.DOMAIN, Asset.is_active == True)
        .all()
    )

    tree = []

    for domain in domains:
        domain_node = _build_asset_node(domain, db)

        # Get subdomains
        subdomains = (
            db.query(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.type == AssetType.SUBDOMAIN,
                Asset.identifier.like(f"%.{domain.identifier}"),
                Asset.is_active == True,
            )
            .all()
        )

        domain_node["children"] = [_build_asset_node(subdomain, db) for subdomain in subdomains]

        tree.append(domain_node)

    return tree


@router.post("/bulk", response_model=BulkOperationResult)
def bulk_create_assets(
    tenant_id: int, bulk_data: BulkAssetCreate, db: Session = Depends(get_db), membership=Depends(verify_tenant_access)
):
    """
    Bulk create assets

    Creates multiple assets in one request
    Returns summary of successes and failures

    Raises:
        - 403: No write access
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Write permission required")

    success_count = 0
    failure_count = 0
    errors = []

    for asset_data in bulk_data.assets:
        try:
            # Check if exists
            existing = (
                db.query(Asset)
                .filter(
                    Asset.tenant_id == tenant_id,
                    Asset.identifier == asset_data.identifier,
                    Asset.type == AssetType(asset_data.type),
                )
                .first()
            )

            if existing:
                errors.append(f"Asset '{asset_data.identifier}' already exists")
                failure_count += 1
                continue

            # Create asset
            asset = Asset(
                tenant_id=tenant_id,
                type=AssetType(asset_data.type),
                identifier=asset_data.identifier,
                priority=asset_data.priority or "normal",
            )

            db.add(asset)
            success_count += 1

        except Exception as e:
            errors.append(f"Failed to create '{asset_data.identifier}': {str(e)}")
            failure_count += 1

    db.commit()

    logger.info(f"Bulk created {success_count} assets for tenant {tenant_id}")

    return BulkOperationResult(success_count=success_count, failure_count=failure_count, errors=errors)


# Seeds endpoints
@router.get("/seeds", response_model=List[SeedResponse])
def list_seeds(tenant_id: int, db: Session = Depends(get_db), membership=Depends(verify_tenant_access)):
    """
    List all seeds for tenant

    Seeds are root domains, ASNs, IP ranges used for discovery

    Returns:
        List of seed objects
    """
    seeds = db.query(Seed).filter(Seed.tenant_id == tenant_id).order_by(Seed.created_at.desc()).all()

    return [SeedResponse.model_validate(s) for s in seeds]


@router.post("/seeds", response_model=SeedResponse, status_code=status.HTTP_201_CREATED)
def create_seed(
    tenant_id: int, seed_data: SeedCreate, db: Session = Depends(get_db), membership=Depends(verify_tenant_access)
):
    """
    Create new seed

    Seeds trigger discovery pipeline

    Raises:
        - 403: No write access
        - 400: Invalid seed data
    """
    # Verify write permission
    if not membership.has_permission("write"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Write permission required")

    # Create seed
    seed = Seed(tenant_id=tenant_id, type=seed_data.type, value=seed_data.value, enabled=seed_data.enabled)

    db.add(seed)
    db.commit()
    db.refresh(seed)

    log_data_modification(
        action="create",
        resource="seed",
        resource_id=str(seed.id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={"value": seed_data.value, "type": seed_data.type},
    )

    logger.info(f"Created seed {seed.value} for tenant {tenant_id}")

    return SeedResponse.model_validate(seed)


@router.post("/{asset_id}/rescan", status_code=status.HTTP_202_ACCEPTED)
def rescan_asset(
    tenant_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger re-enrichment scan for a single asset.

    Queues enrichment tasks (HTTPx, Naabu, TLSx) for the asset.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    asset = (
        db.query(Asset)
        .filter(
            Asset.id == asset_id,
            Asset.tenant_id == tenant_id,
        )
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    # Queue enrichment tasks
    task_ids = []
    try:
        from app.tasks.enrichment import run_httpx, run_naabu, run_tlsx
        from app.tasks.cert_harvest import harvest_certificates

        httpx_task = run_httpx.apply_async(kwargs={"tenant_id": tenant_id, "asset_ids": [asset_id]})
        task_ids.append(httpx_task.id)

        naabu_task = run_naabu.apply_async(kwargs={"tenant_id": tenant_id, "asset_ids": [asset_id]})
        task_ids.append(naabu_task.id)

    except Exception as e:
        logger.warning(f"Failed to queue enrichment for asset {asset_id}: {e}")

    # Update enrichment status
    asset.enrichment_status = "pending"
    db.commit()

    log_audit_event(
        event_type=AuditEventType.DATA_UPDATE,
        action=f"Rescan triggered for asset {asset.identifier}",
        result="success",
        user_id=membership.user_id,
        tenant_id=tenant_id,
        resource="asset",
        resource_id=str(asset_id),
    )

    return {
        "status": "queued",
        "asset_id": asset_id,
        "task_ids": task_ids,
    }


@router.get("/{asset_id}/screenshots")
def get_asset_screenshots(
    tenant_id: int,
    asset_id: int,
    include_urls: bool = Query(False, description="Generate presigned MinIO URLs"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get screenshot metadata for an asset.

    Returns the list of screenshots captured during Visual Recon (Phase 7).
    """
    asset = (
        db.query(Asset)
        .filter(
            Asset.id == asset_id,
            Asset.tenant_id == tenant_id,
        )
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    try:
        meta = json.loads(asset.raw_metadata) if asset.raw_metadata else {}
    except (json.JSONDecodeError, TypeError):
        meta = {}

    screenshots = meta.get("screenshots", [])

    if include_urls and screenshots:
        from app.tasks.visual_recon import get_screenshot_url

        for entry in screenshots:
            if entry.get("full"):
                entry["full_url"] = get_screenshot_url(tenant_id, entry["full"])
            if entry.get("thumb"):
                entry["thumb_url"] = get_screenshot_url(tenant_id, entry["thumb"])

    return {
        "asset_id": asset_id,
        "total": len(screenshots),
        "screenshots": screenshots,
    }


@router.post("/{asset_id}/screenshots/capture", status_code=status.HTTP_202_ACCEPTED)
def trigger_asset_screenshot(
    tenant_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger on-demand screenshot capture for a single asset.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    asset = (
        db.query(Asset)
        .filter(
            Asset.id == asset_id,
            Asset.tenant_id == tenant_id,
        )
        .first()
    )

    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found",
        )

    from app.tasks.visual_recon import run_visual_recon

    task = run_visual_recon.apply_async(
        kwargs={
            "tenant_id": tenant_id,
            "asset_ids": [asset_id],
        }
    )

    log_audit_event(
        event_type=AuditEventType.DATA_CREATE,
        action=f"Screenshot capture triggered for asset {asset.identifier}",
        result="success",
        user_id=membership.user_id,
        tenant_id=tenant_id,
        resource="asset",
        resource_id=str(asset_id),
    )

    return {
        "task_id": task.id,
        "status": "queued",
        "asset_id": asset_id,
    }


@router.get("/{asset_id}/screenshots/{screenshot_type}/{filename}")
def proxy_screenshot(
    tenant_id: int,
    asset_id: int,
    screenshot_type: str,
    filename: str,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Proxy screenshot images from MinIO to the frontend.

    Avoids exposing internal MinIO URLs (minio:9000) to the browser.
    """
    from fastapi.responses import StreamingResponse
    from app.utils.storage import get_minio_client

    if screenshot_type not in ("full", "thumb"):
        raise HTTPException(status_code=400, detail="Invalid screenshot type")

    # Verify asset belongs to tenant
    asset = (
        db.query(Asset.id)
        .filter(
            Asset.id == asset_id,
            Asset.tenant_id == tenant_id,
        )
        .first()
    )

    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")

    bucket_name = f"tenant-{tenant_id}"
    object_path = f"screenshots/{asset_id}/{filename}"

    try:
        client = get_minio_client()
        response = client.get_object(bucket_name, object_path)
        data = response.read()
        response.close()
        response.release_conn()

        # Detect content type from filename
        media_type = "image/png"
        if filename.endswith(".jpg") or filename.endswith(".jpeg"):
            media_type = "image/jpeg"

        return StreamingResponse(
            iter([data]),
            media_type=media_type,
            headers={"Cache-Control": "public, max-age=3600"},
        )
    except Exception as exc:
        logger.warning("Screenshot proxy failed: bucket=%s path=%s error=%s", bucket_name, object_path, exc)
        raise HTTPException(status_code=404, detail="Screenshot not found")


def _build_asset_node(asset: Asset, db: Session) -> dict:
    """Build asset tree node with counts"""
    return {
        "id": asset.id,
        "identifier": asset.identifier,
        "type": asset.type.value,
        "risk_score": asset.risk_score,
        "is_active": asset.is_active,
        "service_count": len(asset.services),
        "finding_count": len(asset.findings),
        "children": [],
    }
