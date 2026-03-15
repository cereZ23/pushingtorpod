"""
Exposure Management API router.

Provides endpoints for understanding and tracking the tenant's
exposure posture: summary metrics, detailed asset lists with
exposure details, and change tracking over time.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, case
from sqlalchemy.orm import Session, joinedload
import logging

from app.api.dependencies import get_db, verify_tenant_access, PaginationParams, escape_like
from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
    Service,
    Tenant,
)
from app.api.schemas.exposure import (
    ExposedAssetItem,
    ExposedAssetListResponse,
    ExposureChanges,
    ExposureChangeItem,
    ExposureSummary,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/exposure",
    tags=["Exposure"],
)

# Severity ordering for comparisons (higher index = more severe)
_SEVERITY_ORDER = {
    FindingSeverity.INFO: 0,
    FindingSeverity.LOW: 1,
    FindingSeverity.MEDIUM: 2,
    FindingSeverity.HIGH: 3,
    FindingSeverity.CRITICAL: 4,
}

_SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 0,
}


@router.get("/summary", response_model=ExposureSummary)
def get_exposure_summary(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ExposureSummary:
    """
    Get the overall exposure summary for a tenant.

    Returns:
        - Total exposed assets (assets with at least one open finding)
        - Severity breakdown of exposed assets by highest severity
        - Exposure score (0-100) based on finding severity distribution
        - Top 10 most exposed assets ranked by risk score

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.
    """
    _verify_tenant_exists(db, tenant_id)

    # Total assets (active only)
    total_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
        .scalar()
        or 0
    )

    # Assets with at least one open finding (exposed assets)
    exposed_asset_ids_sq = (
        db.query(Finding.asset_id)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
        )
        .distinct()
        .subquery()
    )

    total_exposed = (
        db.query(func.count(exposed_asset_ids_sq.c.asset_id)).scalar() or 0
    )

    # For each exposed asset, determine highest severity
    # Build a subquery that finds the max severity per asset
    severity_case = case(
        (Finding.severity == FindingSeverity.CRITICAL, 4),
        (Finding.severity == FindingSeverity.HIGH, 3),
        (Finding.severity == FindingSeverity.MEDIUM, 2),
        (Finding.severity == FindingSeverity.LOW, 1),
        else_=0,
    )

    highest_severity_sq = (
        db.query(
            Finding.asset_id,
            func.max(severity_case).label("max_sev"),
        )
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
        )
        .group_by(Finding.asset_id)
        .subquery()
    )

    # Count assets by their highest severity
    severity_breakdown: dict[str, int] = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}

    sev_rows = (
        db.query(
            highest_severity_sq.c.max_sev,
            func.count(highest_severity_sq.c.asset_id),
        )
        .group_by(highest_severity_sq.c.max_sev)
        .all()
    )

    for sev_val, count in sev_rows:
        key = sev_map.get(sev_val, "info")
        severity_breakdown[key] = count

    # Calculate exposure score (0-100)
    # Weighted formula: sum of (severity_weight * count) normalized to 0-100
    raw_score = sum(
        _SEVERITY_WEIGHTS.get(sev, 0) * count
        for sev, count in severity_breakdown.items()
    )
    # Normalize: cap at 100. Use a log-like scale for better distribution.
    if total_assets > 0 and raw_score > 0:
        # Max possible score if all assets had critical findings
        max_possible = total_assets * _SEVERITY_WEIGHTS["critical"]
        exposure_score = min(100.0, (raw_score / max(max_possible, 1)) * 100)
    else:
        exposure_score = 0.0

    # Top 10 most exposed assets by risk score
    finding_count_sq = (
        db.query(
            Finding.asset_id,
            func.count(Finding.id).label("finding_count"),
        )
        .filter(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.asset_id)
        .subquery()
    )

    service_count_sq = (
        db.query(
            Service.asset_id,
            func.count(Service.id).label("service_count"),
        )
        .group_by(Service.asset_id)
        .subquery()
    )

    # Highest severity label per asset
    highest_sev_label = case(
        (highest_severity_sq.c.max_sev == 4, "critical"),
        (highest_severity_sq.c.max_sev == 3, "high"),
        (highest_severity_sq.c.max_sev == 2, "medium"),
        (highest_severity_sq.c.max_sev == 1, "low"),
        else_="info",
    ).label("highest_severity")

    top_exposed = (
        db.query(
            Asset,
            func.coalesce(finding_count_sq.c.finding_count, 0).label("finding_count"),
            func.coalesce(service_count_sq.c.service_count, 0).label("service_count"),
            highest_sev_label,
        )
        .join(highest_severity_sq, Asset.id == highest_severity_sq.c.asset_id)
        .outerjoin(finding_count_sq, Asset.id == finding_count_sq.c.asset_id)
        .outerjoin(service_count_sq, Asset.id == service_count_sq.c.asset_id)
        .filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
        .order_by(Asset.risk_score.desc())
        .limit(10)
        .all()
    )

    most_exposed = [
        ExposedAssetItem(
            id=asset.id,
            identifier=asset.identifier,
            type=asset.type.value,
            risk_score=round(asset.risk_score or 0.0, 2),
            open_findings_count=finding_count,
            highest_severity=highest_sev,
            services_count=service_count,
            last_seen=asset.last_seen,
        )
        for asset, finding_count, service_count, highest_sev in top_exposed
    ]

    return ExposureSummary(
        total_exposed_assets=total_exposed,
        total_assets=total_assets,
        severity_breakdown=severity_breakdown,
        exposure_score=round(exposure_score, 1),
        most_exposed=most_exposed,
    )


@router.get("/assets", response_model=ExposedAssetListResponse)
def list_exposed_assets(
    tenant_id: int,
    asset_type: Optional[str] = Query(
        None, description="Filter by asset type (domain, subdomain, ip, url, service)"
    ),
    min_severity: Optional[str] = Query(
        None, description="Minimum highest severity (info, low, medium, high, critical)"
    ),
    search: Optional[str] = Query(None, description="Search by asset identifier"),
    sort_by: str = Query("risk_score", description="Sort by: risk_score, findings_count"),
    sort_order: str = Query("desc", description="Sort order: asc, desc"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ExposedAssetListResponse:
    """
    List assets with their exposure details.

    Returns paginated list of assets that have at least one open finding,
    along with their exposure metadata: findings count, highest severity,
    services count, and last seen timestamp.

    Args:
        tenant_id: Tenant ID from path.
        asset_type: Optional filter by asset type.
        min_severity: Minimum highest severity to include.
        search: Optional search string for asset identifier.
        sort_by: Sort field (risk_score or findings_count).
        sort_order: Sort direction (asc or desc).
        pagination: Pagination parameters.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        ExposedAssetListResponse with paginated exposed assets.
    """
    _verify_tenant_exists(db, tenant_id)

    # Subquery: open finding count per asset
    finding_count_sq = (
        db.query(
            Finding.asset_id,
            func.count(Finding.id).label("finding_count"),
        )
        .filter(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.asset_id)
        .subquery()
    )

    # Subquery: service count per asset
    service_count_sq = (
        db.query(
            Service.asset_id,
            func.count(Service.id).label("service_count"),
        )
        .group_by(Service.asset_id)
        .subquery()
    )

    # Subquery: highest severity per asset
    severity_case = case(
        (Finding.severity == FindingSeverity.CRITICAL, 4),
        (Finding.severity == FindingSeverity.HIGH, 3),
        (Finding.severity == FindingSeverity.MEDIUM, 2),
        (Finding.severity == FindingSeverity.LOW, 1),
        else_=0,
    )

    highest_severity_sq = (
        db.query(
            Finding.asset_id,
            func.max(severity_case).label("max_sev"),
        )
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
        )
        .group_by(Finding.asset_id)
        .subquery()
    )

    highest_sev_label = case(
        (highest_severity_sq.c.max_sev == 4, "critical"),
        (highest_severity_sq.c.max_sev == 3, "high"),
        (highest_severity_sq.c.max_sev == 2, "medium"),
        (highest_severity_sq.c.max_sev == 1, "low"),
        else_="info",
    ).label("highest_severity")

    # Base query: only assets with open findings
    query = (
        db.query(
            Asset,
            func.coalesce(finding_count_sq.c.finding_count, 0).label("finding_count"),
            func.coalesce(service_count_sq.c.service_count, 0).label("service_count"),
            highest_sev_label,
        )
        .join(highest_severity_sq, Asset.id == highest_severity_sq.c.asset_id)
        .outerjoin(finding_count_sq, Asset.id == finding_count_sq.c.asset_id)
        .outerjoin(service_count_sq, Asset.id == service_count_sq.c.asset_id)
        .filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
    )

    # Apply filters
    if asset_type is not None:
        try:
            query = query.filter(Asset.type == AssetType(asset_type))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid asset type: {asset_type}",
            )

    if min_severity is not None:
        sev_threshold = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }.get(min_severity.lower())
        if sev_threshold is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {min_severity}",
            )
        query = query.filter(highest_severity_sq.c.max_sev >= sev_threshold)

    if search:
        query = query.filter(Asset.identifier.ilike(f"%{escape_like(search)}%", escape="\\"))

    # Count before pagination
    # We need to derive total from a subquery to avoid issues with LIMIT
    count_query = query.with_entities(func.count()).order_by(None)
    total = count_query.scalar() or 0

    # Re-apply entity selection for the data query
    query = (
        db.query(
            Asset,
            func.coalesce(finding_count_sq.c.finding_count, 0).label("finding_count"),
            func.coalesce(service_count_sq.c.service_count, 0).label("service_count"),
            highest_sev_label,
        )
        .join(highest_severity_sq, Asset.id == highest_severity_sq.c.asset_id)
        .outerjoin(finding_count_sq, Asset.id == finding_count_sq.c.asset_id)
        .outerjoin(service_count_sq, Asset.id == service_count_sq.c.asset_id)
        .filter(Asset.tenant_id == tenant_id)
    )

    if asset_type is not None:
        query = query.filter(Asset.type == AssetType(asset_type))
    if min_severity is not None:
        sev_threshold_val = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(
            min_severity.lower(), 0
        )
        query = query.filter(highest_severity_sq.c.max_sev >= sev_threshold_val)
    if search:
        query = query.filter(Asset.identifier.ilike(f"%{escape_like(search)}%", escape="\\"))

    # Apply sorting
    if sort_by == "findings_count":
        sort_col = func.coalesce(finding_count_sq.c.finding_count, 0)
    else:
        sort_col = Asset.risk_score

    if sort_order.lower() == "asc":
        query = query.order_by(sort_col.asc())
    else:
        query = query.order_by(sort_col.desc())

    # Apply pagination
    query = query.offset(pagination.offset).limit(pagination.limit)

    results = query.all()

    items = [
        ExposedAssetItem(
            id=asset.id,
            identifier=asset.identifier,
            type=asset.type.value,
            risk_score=round(asset.risk_score or 0.0, 2),
            open_findings_count=finding_count,
            highest_severity=highest_sev,
            services_count=service_count,
            last_seen=asset.last_seen,
        )
        for asset, finding_count, service_count, highest_sev in results
    ]

    total_pages = (total + pagination.page_size - 1) // pagination.page_size if total > 0 else 0

    return ExposedAssetListResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=total_pages,
    )


@router.get("/changes", response_model=ExposureChanges)
def get_exposure_changes(
    tenant_id: int,
    period: str = Query(
        "24h",
        description="Time period: 24h, 7d, 30d",
        regex="^(24h|7d|30d)$",
    ),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ExposureChanges:
    """
    Get exposure changes within a given time window.

    Returns newly opened and recently resolved findings to help
    security teams track the evolving exposure posture.

    Args:
        tenant_id: Tenant ID from path.
        period: Time window (24h, 7d, 30d).
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        ExposureChanges with new and resolved exposure lists.
    """
    _verify_tenant_exists(db, tenant_id)

    # Calculate cutoff time
    period_map = {
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
        "30d": timedelta(days=30),
    }
    cutoff = datetime.now(timezone.utc) - period_map[period]

    # New exposures: open findings first seen after cutoff
    new_findings = (
        db.query(Finding)
        .join(Asset)
        .options(joinedload(Finding.asset))
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
            Finding.first_seen >= cutoff,
        )
        .order_by(Finding.first_seen.desc())
        .limit(50)
        .all()
    )

    new_exposures = [
        ExposureChangeItem(
            id=f.id,
            asset_id=f.asset_id,
            asset_identifier=f.asset.identifier,
            finding_name=f.name,
            severity=f.severity.value,
            change_type="new",
            detected_at=f.first_seen,
        )
        for f in new_findings
    ]

    # Resolved exposures: findings set to fixed after cutoff
    resolved_findings = (
        db.query(Finding)
        .join(Asset)
        .options(joinedload(Finding.asset))
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.FIXED,
            Finding.last_seen >= cutoff,
        )
        .order_by(Finding.last_seen.desc())
        .limit(50)
        .all()
    )

    resolved_exposures = [
        ExposureChangeItem(
            id=f.id,
            asset_id=f.asset_id,
            asset_identifier=f.asset.identifier,
            finding_name=f.name,
            severity=f.severity.value,
            change_type="resolved",
            detected_at=f.last_seen,
        )
        for f in resolved_findings
    ]

    # Counts (may exceed the returned 50 items)
    new_count = (
        db.query(func.count(Finding.id))
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
            Finding.first_seen >= cutoff,
        )
        .scalar()
        or 0
    )

    resolved_count = (
        db.query(func.count(Finding.id))
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.FIXED,
            Finding.last_seen >= cutoff,
        )
        .scalar()
        or 0
    )

    return ExposureChanges(
        period=period,
        new_exposures=new_exposures,
        resolved_exposures=resolved_exposures,
        new_count=new_count,
        resolved_count=resolved_count,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_tenant_exists(db: Session, tenant_id: int) -> None:
    """
    Raise 404 if the tenant does not exist.

    Args:
        db: Database session.
        tenant_id: Tenant ID to verify.

    Raises:
        HTTPException: 404 when tenant is not found.
    """
    exists = db.query(Tenant.id).filter(Tenant.id == tenant_id).first()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )
