"""
Tenants Router

Handles tenant management, dashboard, and statistics.

High-traffic read endpoints (list, get, dashboard, stats) use the async
dependency chain for true non-blocking I/O.  Mutation endpoints (create,
update) remain sync — lower traffic, simpler code.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session, selectinload
from typing import Dict
import logging

from app.api.dependencies import (
    get_db,
    get_async_db,
    get_current_user,
    get_current_user_async,
    verify_tenant_access,
    verify_tenant_access_async,
    require_admin,
)
from app.api.schemas.tenant import (
    TenantResponse,
    TenantCreate,
    TenantUpdate,
    TenantDashboard,
    TenantStats,
    RecentActivity,
)
from app.core.audit import log_data_modification
from app.models.database import (
    Tenant, Asset, Service, Finding, Event,
    AssetType, FindingSeverity, FindingStatus,
)
from app.models.enrichment import Certificate, Endpoint
from app.models.auth import User, TenantMembership
from app.models.risk import RiskScore
from datetime import datetime, timedelta, timezone

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants", tags=["Tenants"])


# ─── Async read endpoints ────────────────────────────────────────

@router.get("", response_model=list[TenantResponse])
async def list_tenants(
    db: AsyncSession = Depends(get_async_db),
    current_user: User = Depends(get_current_user_async),
):
    """List all tenants accessible to current user."""
    if current_user.is_superuser:
        result = await db.execute(select(Tenant))
        tenants = result.scalars().all()
    else:
        tenants = [
            m.tenant for m in current_user.tenant_memberships
            if m.is_active
        ]

    return [TenantResponse.model_validate(t) for t in tenants]


@router.get("/{tenant_id}", response_model=TenantResponse)
async def get_tenant(
    tenant_id: int,
    db: AsyncSession = Depends(get_async_db),
    membership=Depends(verify_tenant_access_async),
):
    """Get tenant by ID. Requires tenant membership."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    return TenantResponse.model_validate(tenant)


@router.get("/{tenant_id}/dashboard", response_model=TenantDashboard)
async def get_tenant_dashboard(
    tenant_id: int,
    db: AsyncSession = Depends(get_async_db),
    membership=Depends(verify_tenant_access_async),
):
    """Tenant dashboard with statistics, recent activity, and risk distribution."""
    result = await db.execute(select(Tenant).where(Tenant.id == tenant_id))
    tenant = result.scalar_one_or_none()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    stats = await _calculate_tenant_stats_async(db, tenant_id)

    # Recent activity (last 50 events)
    events_result = await db.execute(
        select(Event)
        .join(Asset)
        .options(selectinload(Event.asset))
        .where(Asset.tenant_id == tenant_id)
        .order_by(Event.created_at.desc())
        .limit(50)
    )
    recent_events = events_result.scalars().all()

    recent_activity = [
        RecentActivity(
            id=event.id,
            type=event.kind.value,
            description=_format_event_description(event),
            timestamp=event.created_at,
            metadata={"asset_id": event.asset_id},
        )
        for event in recent_events
    ]

    # Risk distribution (active assets only, thresholds aligned with grade bands).
    # Uses 4 buckets for dashboard UX; 'low' intentionally includes info-level
    # assets (score 0-20) since the distinction isn't actionable for the user.
    risk_buckets = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    assets_result = await db.execute(
        select(Asset.risk_score).where(
            Asset.tenant_id == tenant_id,
            Asset.is_active.is_(True),
        )
    )
    for (score,) in assets_result.all():
        s = score if score is not None else 0
        if s > 80:
            risk_buckets["critical"] += 1
        elif s > 60:
            risk_buckets["high"] += 1
        elif s > 40:
            risk_buckets["medium"] += 1
        else:
            risk_buckets["low"] += 1

    return TenantDashboard(
        tenant=TenantResponse.model_validate(tenant),
        stats=stats,
        recent_activity=recent_activity,
        trending_assets=[],
        risk_distribution=risk_buckets,
    )


@router.get("/{tenant_id}/stats", response_model=TenantStats)
async def get_tenant_stats(
    tenant_id: int,
    db: AsyncSession = Depends(get_async_db),
    membership=Depends(verify_tenant_access_async),
):
    """Detailed tenant statistics for analytics."""
    return await _calculate_tenant_stats_async(db, tenant_id)


# ─── Sync mutation endpoints ─────────────────────────────────────

@router.post("", response_model=TenantResponse)
def create_tenant(
    tenant_data: TenantCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create new tenant (admin only)."""
    existing = db.query(Tenant).filter(Tenant.slug == tenant_data.slug).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Tenant slug already exists",
        )

    tenant = Tenant(
        name=tenant_data.name,
        slug=tenant_data.slug,
        contact_policy=tenant_data.contact_policy,
    )

    db.add(tenant)
    db.commit()
    db.refresh(tenant)

    log_data_modification(
        action="create",
        resource="tenant",
        resource_id=str(tenant.id),
        user_id=admin.id,
        tenant_id=tenant.id,
        details={"name": tenant.name, "slug": tenant.slug},
    )

    return TenantResponse.model_validate(tenant)


@router.patch("/{tenant_id}", response_model=TenantResponse)
async def update_tenant(
    tenant_id: int,
    updates: TenantUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Update tenant. Requires admin permission."""
    await verify_tenant_access(tenant_id, current_user, db, "admin")

    tenant = db.query(Tenant).filter(Tenant.id == tenant_id).first()

    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )

    if updates.name is not None:
        tenant.name = updates.name

    if updates.contact_policy is not None:
        tenant.contact_policy = updates.contact_policy

    db.commit()
    db.refresh(tenant)

    log_data_modification(
        action="update",
        resource="tenant",
        resource_id=str(tenant_id),
        user_id=current_user.id,
        tenant_id=tenant_id,
        details={k: v for k, v in updates.model_dump(exclude_unset=True).items()},
    )

    return TenantResponse.model_validate(tenant)


# ─── Async stats helper ──────────────────────────────────────────

async def _calculate_tenant_stats_async(
    db: AsyncSession, tenant_id: int
) -> TenantStats:
    """Calculate comprehensive tenant statistics using async queries."""

    # Asset count (active only)
    total_assets = (await db.execute(
        select(func.count(Asset.id)).where(
            Asset.tenant_id == tenant_id, Asset.is_active.is_(True)
        )
    )).scalar() or 0

    # Assets by type
    assets_by_type = {}
    for asset_type in AssetType:
        count = (await db.execute(
            select(func.count(Asset.id)).where(
                Asset.tenant_id == tenant_id,
                Asset.is_active.is_(True),
                Asset.type == asset_type,
            )
        )).scalar() or 0
        assets_by_type[asset_type.value] = count

    # Services (active assets only)
    total_services = (await db.execute(
        select(func.count(Service.id))
        .join(Asset)
        .where(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
    )).scalar() or 0

    # Certificates
    total_certificates = (await db.execute(
        select(func.count(Certificate.id))
        .join(Asset)
        .where(Asset.tenant_id == tenant_id)
    )).scalar() or 0

    # Endpoints
    total_endpoints = (await db.execute(
        select(func.count(Endpoint.id))
        .join(Asset)
        .where(Asset.tenant_id == tenant_id)
    )).scalar() or 0

    # Findings total
    total_findings = (await db.execute(
        select(func.count(Finding.id))
        .join(Asset)
        .where(Asset.tenant_id == tenant_id)
    )).scalar() or 0

    # Findings by severity
    findings_by_severity = {}
    for severity in FindingSeverity:
        count = (await db.execute(
            select(func.count(Finding.id))
            .join(Asset)
            .where(Asset.tenant_id == tenant_id, Finding.severity == severity)
        )).scalar() or 0
        findings_by_severity[severity.value] = count

    # Open findings
    open_findings = (await db.execute(
        select(func.count(Finding.id))
        .join(Asset)
        .where(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
        )
    )).scalar() or 0

    # Critical open findings
    critical_findings = (await db.execute(
        select(func.count(Finding.id))
        .join(Asset)
        .where(
            Asset.tenant_id == tenant_id,
            Finding.severity == FindingSeverity.CRITICAL,
            Finding.status == FindingStatus.OPEN,
        )
    )).scalar() or 0

    # High open findings
    high_findings = (await db.execute(
        select(func.count(Finding.id))
        .join(Asset)
        .where(
            Asset.tenant_id == tenant_id,
            Finding.severity == FindingSeverity.HIGH,
            Finding.status == FindingStatus.OPEN,
        )
    )).scalar() or 0

    # Expiring certificates (within 30 days)
    thirty_days = datetime.now(timezone.utc) + timedelta(days=30)
    expiring_certificates = (await db.execute(
        select(func.count(Certificate.id))
        .join(Asset)
        .where(
            Asset.tenant_id == tenant_id,
            Certificate.is_expired == False,
            Certificate.not_after <= thirty_days,
        )
    )).scalar() or 0

    # Organization risk score
    org_score_row = (await db.execute(
        select(RiskScore.score)
        .where(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == 'organization',
        )
        .order_by(RiskScore.scored_at.desc())
        .limit(1)
    )).scalar_one_or_none()

    if org_score_row is not None:
        average_risk_score = round(float(org_score_row), 2)
    else:
        avg_risk = (await db.execute(
            select(func.avg(Asset.risk_score)).where(
                Asset.tenant_id == tenant_id,
                Asset.is_active.is_(True),
            )
        )).scalar() or 0.0
        average_risk_score = round(float(avg_risk), 2)

    return TenantStats(
        total_assets=total_assets,
        assets_by_type=assets_by_type,
        total_services=total_services,
        total_certificates=total_certificates,
        total_endpoints=total_endpoints,
        total_findings=total_findings,
        findings_by_severity=findings_by_severity,
        open_findings=open_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        expiring_certificates=expiring_certificates,
        average_risk_score=average_risk_score,
    )


# ─── Helpers ─────────────────────────────────────────────────────

def _format_event_description(event: Event) -> str:
    """Format event description for display"""
    descriptions = {
        "new_asset": f"New asset discovered: {event.asset.identifier}",
        "open_port": f"New open port detected on {event.asset.identifier}",
        "new_cert": f"New certificate issued for {event.asset.identifier}",
        "new_path": f"New endpoint discovered on {event.asset.identifier}",
        "tech_change": f"Technology change detected on {event.asset.identifier}",
    }

    return descriptions.get(event.kind.value, f"Event on {event.asset.identifier}")
