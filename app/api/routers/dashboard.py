"""
Dashboard API router for KPI metrics and overview data.

Provides aggregated metrics, severity breakdowns, risk score trends,
recent findings, and top risky assets for the tenant dashboard.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, case
from sqlalchemy.orm import Session
import logging

from app.api.dependencies import get_db, verify_tenant_access
from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
    Service,
    Tenant,
)
from app.models.issues import Issue, IssueStatus
from app.models.risk import RiskScore
from app.models.scanning import ScanRun, ScanRunStatus
from app.api.schemas.dashboard import (
    DashboardSummary,
    SeverityBreakdown,
    AssetTypeBreakdown,
    ScoreTrendPoint,
    ScoreTrendItem,
    ScoreTrendResponse,
    RecentFindingItem,
    RiskyAssetItem,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/dashboard",
    tags=["Dashboard"],
)


@router.get("/summary", response_model=DashboardSummary)
def get_dashboard_summary(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> DashboardSummary:
    """
    Main KPI summary for the tenant dashboard.

    Returns high-level counts and the current organizational risk posture
    including total/active assets, findings by status, severity breakdown,
    active scans, asset type distribution, issue count, latest risk score
    and grade, plus 24-hour deltas.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        DashboardSummary with all KPI fields.
    """
    _verify_tenant_exists(db, tenant_id)

    # Asset counts
    total_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.tenant_id == tenant_id)
        .scalar()
        or 0
    )
    active_assets = (
        db.query(func.count(Asset.id))
        .filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
        .scalar()
        or 0
    )

    # Findings by status
    findings_by_status: dict[str, int] = {}
    for finding_status in FindingStatus:
        count = (
            db.query(func.count(Finding.id))
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.status == finding_status,
            )
            .scalar()
            or 0
        )
        findings_by_status[finding_status.value] = count

    total_findings = sum(findings_by_status.values())
    open_findings = findings_by_status.get("open", 0)

    # Severity breakdown (open findings only)
    severity_breakdown: dict[str, int] = {}
    for severity in FindingSeverity:
        count = (
            db.query(func.count(Finding.id))
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.status == FindingStatus.OPEN,
                Finding.severity == severity,
            )
            .scalar()
            or 0
        )
        severity_breakdown[severity.value] = count

    # Asset type breakdown
    asset_type_breakdown: dict[str, int] = {}
    for asset_type in AssetType:
        count = (
            db.query(func.count(Asset.id))
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.type == asset_type,
            )
            .scalar()
            or 0
        )
        asset_type_breakdown[asset_type.value] = count

    # Total open issues
    total_issues = (
        db.query(func.count(Issue.id))
        .filter(
            Issue.tenant_id == tenant_id,
            Issue.status.notin_([IssueStatus.CLOSED, IssueStatus.VERIFIED_FIXED]),
        )
        .scalar()
        or 0
    )

    # Latest organization-level risk score
    latest_risk = (
        db.query(RiskScore)
        .filter(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == "organization",
        )
        .order_by(RiskScore.scored_at.desc())
        .first()
    )
    risk_score = latest_risk.score if latest_risk else 0.0
    risk_grade = latest_risk.grade if latest_risk else "N/A"

    # Active scans (pending or running)
    active_scans = (
        db.query(func.count(ScanRun.id))
        .filter(
            ScanRun.tenant_id == tenant_id,
            ScanRun.status.in_([ScanRunStatus.PENDING, ScanRunStatus.RUNNING]),
        )
        .scalar()
        or 0
    )

    # 24-hour deltas
    cutoff_24h = datetime.now(timezone.utc) - timedelta(hours=24)

    new_assets_24h = (
        db.query(func.count(Asset.id))
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.first_seen >= cutoff_24h,
        )
        .scalar()
        or 0
    )
    new_findings_24h = (
        db.query(func.count(Finding.id))
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.first_seen >= cutoff_24h,
        )
        .scalar()
        or 0
    )

    return DashboardSummary(
        total_assets=total_assets,
        active_assets=active_assets,
        total_findings=total_findings,
        open_findings=open_findings,
        findings_by_status=findings_by_status,
        severity_breakdown=severity_breakdown,
        total_issues=total_issues,
        risk_score=round(risk_score, 2),
        risk_grade=risk_grade,
        active_scans=active_scans,
        asset_type_breakdown=asset_type_breakdown,
        new_assets_24h=new_assets_24h,
        new_findings_24h=new_findings_24h,
    )


@router.get("/severity-breakdown", response_model=SeverityBreakdown)
def get_severity_breakdown(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> SeverityBreakdown:
    """
    Breakdown of open findings by severity level.

    Counts only findings with status 'open' grouped by their severity
    (critical, high, medium, low, info).

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        SeverityBreakdown with counts per severity level.
    """
    _verify_tenant_exists(db, tenant_id)

    counts: dict[str, int] = {}
    for severity in FindingSeverity:
        count = (
            db.query(func.count(Finding.id))
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.status == FindingStatus.OPEN,
                Finding.severity == severity,
            )
            .scalar()
            or 0
        )
        counts[severity.value] = count

    return SeverityBreakdown(
        critical=counts.get("critical", 0),
        high=counts.get("high", 0),
        medium=counts.get("medium", 0),
        low=counts.get("low", 0),
        info=counts.get("info", 0),
    )


@router.get("/asset-types", response_model=AssetTypeBreakdown)
def get_asset_types(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> AssetTypeBreakdown:
    """
    Count of assets grouped by type.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        AssetTypeBreakdown with counts per asset type.
    """
    _verify_tenant_exists(db, tenant_id)

    counts: dict[str, int] = {}
    for asset_type in AssetType:
        count = (
            db.query(func.count(Asset.id))
            .filter(
                Asset.tenant_id == tenant_id,
                Asset.type == asset_type,
            )
            .scalar()
            or 0
        )
        counts[asset_type.value] = count

    return AssetTypeBreakdown(
        domain=counts.get("domain", 0),
        subdomain=counts.get("subdomain", 0),
        ip=counts.get("ip", 0),
        url=counts.get("url", 0),
        service=counts.get("service", 0),
    )


@router.get("/score-trend", response_model=ScoreTrendResponse)
def get_score_trend(
    tenant_id: int,
    limit: int = Query(default=10, ge=1, le=100, description="Number of score snapshots to return"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ScoreTrendResponse:
    """
    Recent organization risk score history.

    Returns the last N organization-level risk score snapshots ordered
    by scored_at descending (most recent first).

    Args:
        tenant_id: Tenant ID from path.
        limit: Number of score snapshots to return (default 10, max 100).
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        ScoreTrendResponse wrapping a list of ScoreTrendItem.
    """
    _verify_tenant_exists(db, tenant_id)

    scores = (
        db.query(RiskScore)
        .filter(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == "organization",
        )
        .order_by(RiskScore.scored_at.desc())
        .limit(limit)
        .all()
    )

    return ScoreTrendResponse(
        scores=[
            ScoreTrendItem(
                score=round(s.score, 2),
                grade=s.grade or "N/A",
                scored_at=s.scored_at,
            )
            for s in scores
        ]
    )


@router.get("/recent-findings", response_model=list[RecentFindingItem])
def get_recent_findings(
    tenant_id: int,
    limit: int = Query(default=10, ge=1, le=50, description="Number of findings to return"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> list[RecentFindingItem]:
    """
    Most recent findings for the tenant.

    Returns the latest findings ordered by first_seen descending,
    including the identifier of the related asset.

    Args:
        tenant_id: Tenant ID from path.
        limit: Maximum number of findings (default 10, max 50).
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        List of RecentFindingItem.
    """
    _verify_tenant_exists(db, tenant_id)

    findings = (
        db.query(Finding)
        .join(Asset)
        .filter(Asset.tenant_id == tenant_id)
        .order_by(Finding.first_seen.desc())
        .limit(limit)
        .all()
    )

    return [
        RecentFindingItem(
            id=f.id,
            name=f.name,
            severity=f.severity.value,
            asset_identifier=f.asset.identifier,
            created_at=f.first_seen,
        )
        for f in findings
    ]


@router.get("/top-risky-assets", response_model=list[RiskyAssetItem])
def get_top_risky_assets(
    tenant_id: int,
    limit: int = Query(default=10, ge=1, le=50, description="Number of assets to return"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> list[RiskyAssetItem]:
    """
    Top assets ranked by risk score descending.

    For each asset the finding count is computed via a correlated
    subquery so the result is returned in a single round-trip.

    Args:
        tenant_id: Tenant ID from path.
        limit: Maximum number of assets (default 10, max 50).
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        List of RiskyAssetItem ordered by risk_score descending.
    """
    _verify_tenant_exists(db, tenant_id)

    # Subquery for open finding count per asset
    finding_count_sq = (
        db.query(
            Finding.asset_id,
            func.count(Finding.id).label("finding_count"),
        )
        .filter(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.asset_id)
        .subquery()
    )

    assets = (
        db.query(
            Asset,
            func.coalesce(finding_count_sq.c.finding_count, 0).label("finding_count"),
        )
        .outerjoin(finding_count_sq, Asset.id == finding_count_sq.c.asset_id)
        .filter(Asset.tenant_id == tenant_id)
        .order_by(Asset.risk_score.desc())
        .limit(limit)
        .all()
    )

    return [
        RiskyAssetItem(
            id=asset.id,
            identifier=asset.identifier,
            type=asset.type.value,
            risk_score=round(asset.risk_score or 0.0, 2),
            finding_count=finding_count,
        )
        for asset, finding_count in assets
    ]


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
