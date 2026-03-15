"""
Remediation analytics API router.

Provides endpoints for tracking remediation progress, resolution
timelines, and SLA compliance metrics across the tenant's security
findings and issues.
"""

from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, case, and_
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, ConfigDict
import logging

from app.api.dependencies import get_db, verify_tenant_access
from app.models.database import (
    Asset,
    Finding,
    FindingSeverity,
    FindingStatus,
    Tenant,
)
from app.models.issues import Issue, IssueStatus

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/remediation",
    tags=["Remediation"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class StatusBreakdown(BaseModel):
    """Finding counts grouped by status."""

    open: int = Field(default=0, description="Open findings")
    suppressed: int = Field(default=0, description="Suppressed findings")
    fixed: int = Field(default=0, description="Fixed findings")

    model_config = ConfigDict(json_schema_extra={"example": {"open": 120, "suppressed": 15, "fixed": 45}})


class IssueStatusBreakdown(BaseModel):
    """Issue counts grouped by lifecycle status."""

    open: int = Field(default=0, description="Open issues")
    triaged: int = Field(default=0, description="Triaged issues")
    in_progress: int = Field(default=0, description="In-progress issues")
    mitigated: int = Field(default=0, description="Mitigated issues")
    verifying: int = Field(default=0, description="Verifying issues")
    verified_fixed: int = Field(default=0, description="Verified fixed issues")
    closed: int = Field(default=0, description="Closed issues")
    false_positive: int = Field(default=0, description="False positive issues")
    accepted_risk: int = Field(default=0, description="Accepted risk issues")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "open": 30,
                "triaged": 10,
                "in_progress": 8,
                "mitigated": 5,
                "verifying": 3,
                "verified_fixed": 20,
                "closed": 15,
                "false_positive": 4,
                "accepted_risk": 2,
            }
        }
    )


class MttrBySeverity(BaseModel):
    """Mean Time to Remediation (MTTR) in hours, grouped by severity."""

    critical: Optional[float] = Field(None, description="MTTR for critical issues (hours)")
    high: Optional[float] = Field(None, description="MTTR for high issues (hours)")
    medium: Optional[float] = Field(None, description="MTTR for medium issues (hours)")
    low: Optional[float] = Field(None, description="MTTR for low issues (hours)")

    model_config = ConfigDict(
        json_schema_extra={"example": {"critical": 12.5, "high": 48.0, "medium": 168.0, "low": 336.0}}
    )


class RemediationStatsResponse(BaseModel):
    """Comprehensive remediation statistics."""

    generated_at: datetime = Field(..., description="Timestamp of generation")
    findings_by_status: StatusBreakdown = Field(..., description="Findings grouped by status")
    issues_by_status: IssueStatusBreakdown = Field(..., description="Issues grouped by lifecycle status")
    total_resolved_issues: int = Field(..., description="Total issues that reached a terminal status")
    mttr: MttrBySeverity = Field(..., description="Mean time to remediation by severity")
    sla_compliance_pct: float = Field(..., description="Percentage of resolved issues that met their SLA deadline")
    overdue_issues: int = Field(..., description="Number of open issues past their SLA due date")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "generated_at": "2026-02-25T12:00:00Z",
                "findings_by_status": {"open": 120, "suppressed": 15, "fixed": 45},
                "issues_by_status": {
                    "open": 30,
                    "triaged": 10,
                    "in_progress": 8,
                    "mitigated": 5,
                    "verifying": 3,
                    "verified_fixed": 20,
                    "closed": 15,
                    "false_positive": 4,
                    "accepted_risk": 2,
                },
                "total_resolved_issues": 35,
                "mttr": {"critical": 12.5, "high": 48.0, "medium": 168.0, "low": 336.0},
                "sla_compliance_pct": 82.5,
                "overdue_issues": 4,
            }
        }
    )


class TimelineBucket(BaseModel):
    """A single bucket in the resolution timeline."""

    period: str = Field(..., description="Period label (e.g. '2026-W08' or '2026-02')")
    resolved: int = Field(..., description="Number of issues resolved in this period")
    opened: int = Field(..., description="Number of issues opened in this period")

    model_config = ConfigDict(json_schema_extra={"example": {"period": "2026-W08", "resolved": 12, "opened": 8}})


class TimelineResponse(BaseModel):
    """Resolution timeline aggregated by week or month."""

    generated_at: datetime = Field(..., description="Timestamp of generation")
    granularity: str = Field(..., description="Aggregation granularity (week or month)")
    buckets: List[TimelineBucket] = Field(..., description="Timeline data points")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "generated_at": "2026-02-25T12:00:00Z",
                "granularity": "week",
                "buckets": [
                    {"period": "2026-W06", "resolved": 5, "opened": 12},
                    {"period": "2026-W07", "resolved": 8, "opened": 6},
                    {"period": "2026-W08", "resolved": 12, "opened": 8},
                ],
            }
        }
    )


class SlaComplianceEntry(BaseModel):
    """SLA compliance breakdown for a single severity level."""

    severity: str = Field(..., description="Severity level")
    total_resolved: int = Field(..., description="Total resolved issues of this severity")
    within_sla: int = Field(..., description="Issues resolved within SLA")
    breached_sla: int = Field(..., description="Issues resolved after SLA deadline")
    compliance_pct: float = Field(..., description="Compliance percentage")
    target_hours: int = Field(..., description="SLA target in hours for this severity")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "critical",
                "total_resolved": 10,
                "within_sla": 8,
                "breached_sla": 2,
                "compliance_pct": 80.0,
                "target_hours": 24,
            }
        }
    )


class SlaComplianceResponse(BaseModel):
    """SLA compliance breakdown by severity."""

    generated_at: datetime = Field(..., description="Timestamp of generation")
    overall_compliance_pct: float = Field(..., description="Overall SLA compliance percentage")
    by_severity: List[SlaComplianceEntry] = Field(..., description="Per-severity breakdown")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "generated_at": "2026-02-25T12:00:00Z",
                "overall_compliance_pct": 82.5,
                "by_severity": [],
            }
        }
    )


# ---------------------------------------------------------------------------
# SLA targets by severity (in hours)
# ---------------------------------------------------------------------------

SLA_TARGETS_HOURS: Dict[str, int] = {
    "critical": 24,
    "high": 168,  # 7 days
    "medium": 720,  # 30 days
    "low": 2160,  # 90 days
}

# Terminal statuses considered "resolved"
RESOLVED_STATUSES = frozenset(
    {
        IssueStatus.VERIFIED_FIXED,
        IssueStatus.CLOSED,
        IssueStatus.FALSE_POSITIVE,
        IssueStatus.ACCEPTED_RISK,
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verify_tenant_exists(db: Session, tenant_id: int) -> None:
    """Raise 404 if the tenant does not exist."""
    exists = db.query(Tenant.id).filter(Tenant.id == tenant_id).first()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )


def _compute_mttr_by_severity(db: Session, tenant_id: int) -> MttrBySeverity:
    """
    Compute Mean Time to Remediation per severity.

    MTTR is calculated as the average elapsed time (in hours) between
    issue creation and resolution for issues that have reached a
    terminal status and have a non-null resolved_at timestamp.
    """
    mttr_values: Dict[str, Optional[float]] = {}
    severity_levels = ["critical", "high", "medium", "low"]

    for sev in severity_levels:
        resolved_issues = (
            db.query(Issue)
            .filter(
                Issue.tenant_id == tenant_id,
                Issue.severity == sev,
                Issue.status.in_(list(RESOLVED_STATUSES)),
                Issue.resolved_at.isnot(None),
            )
            .all()
        )

        if not resolved_issues:
            mttr_values[sev] = None
            continue

        total_hours = sum((issue.resolved_at - issue.created_at).total_seconds() / 3600 for issue in resolved_issues)
        mttr_values[sev] = round(total_hours / len(resolved_issues), 1)

    return MttrBySeverity(
        critical=mttr_values.get("critical"),
        high=mttr_values.get("high"),
        medium=mttr_values.get("medium"),
        low=mttr_values.get("low"),
    )


def _compute_sla_compliance(db: Session, tenant_id: int) -> tuple[float, int]:
    """
    Compute overall SLA compliance percentage and count of overdue issues.

    Returns:
        Tuple of (compliance_pct, overdue_count).
    """
    now = datetime.now(timezone.utc)

    # Resolved issues with SLA
    resolved_with_sla = (
        db.query(Issue)
        .filter(
            Issue.tenant_id == tenant_id,
            Issue.status.in_(list(RESOLVED_STATUSES)),
            Issue.resolved_at.isnot(None),
            Issue.sla_due_at.isnot(None),
        )
        .all()
    )

    within_sla = sum(1 for issue in resolved_with_sla if issue.resolved_at <= issue.sla_due_at)

    compliance_pct = round((within_sla / len(resolved_with_sla)) * 100, 1) if resolved_with_sla else 100.0

    # Overdue open issues
    overdue_count = (
        db.query(func.count(Issue.id))
        .filter(
            Issue.tenant_id == tenant_id,
            Issue.status.notin_(list(RESOLVED_STATUSES)),
            Issue.sla_due_at.isnot(None),
            Issue.sla_due_at < now,
        )
        .scalar()
        or 0
    )

    return compliance_pct, overdue_count


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/stats", response_model=RemediationStatsResponse)
def get_remediation_stats(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> RemediationStatsResponse:
    """
    Get comprehensive remediation statistics.

    Aggregates finding status distribution, issue lifecycle breakdown,
    mean time to remediation (MTTR) per severity, and SLA compliance
    metrics for the tenant.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        RemediationStatsResponse with all metrics.
    """
    _verify_tenant_exists(db, tenant_id)

    # --- Finding counts by status ---
    finding_status_counts: Dict[str, int] = {}
    for fs in FindingStatus:
        count = (
            db.query(func.count(Finding.id))
            .join(Asset)
            .filter(Asset.tenant_id == tenant_id, Finding.status == fs)
            .scalar()
            or 0
        )
        finding_status_counts[fs.value] = count

    findings_by_status = StatusBreakdown(
        open=finding_status_counts.get("open", 0),
        suppressed=finding_status_counts.get("suppressed", 0),
        fixed=finding_status_counts.get("fixed", 0),
    )

    # --- Issue counts by status ---
    issue_status_counts: Dict[str, int] = {}
    for is_status in IssueStatus:
        count = (
            db.query(func.count(Issue.id)).filter(Issue.tenant_id == tenant_id, Issue.status == is_status).scalar() or 0
        )
        issue_status_counts[is_status.value] = count

    issues_by_status = IssueStatusBreakdown(
        open=issue_status_counts.get("open", 0),
        triaged=issue_status_counts.get("triaged", 0),
        in_progress=issue_status_counts.get("in_progress", 0),
        mitigated=issue_status_counts.get("mitigated", 0),
        verifying=issue_status_counts.get("verifying", 0),
        verified_fixed=issue_status_counts.get("verified_fixed", 0),
        closed=issue_status_counts.get("closed", 0),
        false_positive=issue_status_counts.get("false_positive", 0),
        accepted_risk=issue_status_counts.get("accepted_risk", 0),
    )

    # --- Total resolved issues ---
    total_resolved = (
        db.query(func.count(Issue.id))
        .filter(
            Issue.tenant_id == tenant_id,
            Issue.status.in_(list(RESOLVED_STATUSES)),
        )
        .scalar()
        or 0
    )

    # --- MTTR by severity ---
    mttr = _compute_mttr_by_severity(db, tenant_id)

    # --- SLA compliance ---
    sla_compliance_pct, overdue_issues = _compute_sla_compliance(db, tenant_id)

    return RemediationStatsResponse(
        generated_at=datetime.now(timezone.utc),
        findings_by_status=findings_by_status,
        issues_by_status=issues_by_status,
        total_resolved_issues=total_resolved,
        mttr=mttr,
        sla_compliance_pct=sla_compliance_pct,
        overdue_issues=overdue_issues,
    )


@router.get("/timeline", response_model=TimelineResponse)
def get_remediation_timeline(
    tenant_id: int,
    granularity: str = Query(
        default="week",
        description="Aggregation granularity: 'week' or 'month'",
        pattern="^(week|month)$",
    ),
    days: int = Query(default=90, ge=7, le=365, description="Lookback window in days"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> TimelineResponse:
    """
    Get a resolution timeline showing issues opened and resolved over time.

    Buckets are aggregated by week (ISO week number) or month depending
    on the granularity parameter. Useful for visualizing remediation
    velocity and backlog trends.

    Args:
        tenant_id: Tenant ID from path.
        granularity: 'week' or 'month'.
        days: Number of days to look back.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        TimelineResponse with bucketed data.
    """
    _verify_tenant_exists(db, tenant_id)

    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    # Fetch relevant issues in the window
    issues = (
        db.query(Issue)
        .filter(
            Issue.tenant_id == tenant_id,
            Issue.created_at >= cutoff,
        )
        .all()
    )

    # Also fetch issues resolved in the window but created earlier
    resolved_earlier = (
        db.query(Issue)
        .filter(
            Issue.tenant_id == tenant_id,
            Issue.created_at < cutoff,
            Issue.resolved_at >= cutoff,
            Issue.status.in_(list(RESOLVED_STATUSES)),
        )
        .all()
    )

    all_issues = {issue.id: issue for issue in issues}
    for issue in resolved_earlier:
        all_issues.setdefault(issue.id, issue)

    # Build period buckets
    opened_buckets: Dict[str, int] = {}
    resolved_buckets: Dict[str, int] = {}

    def _period_key(dt: datetime) -> str:
        if granularity == "week":
            iso_year, iso_week, _ = dt.isocalendar()
            return f"{iso_year}-W{iso_week:02d}"
        return dt.strftime("%Y-%m")

    for issue in all_issues.values():
        if issue.created_at >= cutoff:
            key = _period_key(issue.created_at)
            opened_buckets[key] = opened_buckets.get(key, 0) + 1

        if issue.resolved_at and issue.resolved_at >= cutoff and issue.status in RESOLVED_STATUSES:
            key = _period_key(issue.resolved_at)
            resolved_buckets[key] = resolved_buckets.get(key, 0) + 1

    # Merge all period keys and sort
    all_keys = sorted(set(opened_buckets.keys()) | set(resolved_buckets.keys()))

    buckets = [
        TimelineBucket(
            period=key,
            resolved=resolved_buckets.get(key, 0),
            opened=opened_buckets.get(key, 0),
        )
        for key in all_keys
    ]

    return TimelineResponse(
        generated_at=datetime.now(timezone.utc),
        granularity=granularity,
        buckets=buckets,
    )


@router.get("/sla-compliance", response_model=SlaComplianceResponse)
def get_sla_compliance(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> SlaComplianceResponse:
    """
    Get SLA compliance breakdown by severity.

    For each severity level, reports how many resolved issues met or
    breached their SLA deadline. SLA targets are:
    - Critical: 24 hours
    - High: 7 days (168 hours)
    - Medium: 30 days (720 hours)
    - Low: 90 days (2160 hours)

    Issues without an sla_due_at value are excluded from the calculation.
    Compliance is computed based on whether resolved_at <= sla_due_at.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        SlaComplianceResponse with per-severity compliance data.
    """
    _verify_tenant_exists(db, tenant_id)

    entries: list[SlaComplianceEntry] = []
    total_resolved_all = 0
    total_within_all = 0

    for sev, target_hours in SLA_TARGETS_HOURS.items():
        resolved_issues = (
            db.query(Issue)
            .filter(
                Issue.tenant_id == tenant_id,
                Issue.severity == sev,
                Issue.status.in_(list(RESOLVED_STATUSES)),
                Issue.resolved_at.isnot(None),
                Issue.sla_due_at.isnot(None),
            )
            .all()
        )

        total_resolved = len(resolved_issues)
        within_sla = sum(1 for issue in resolved_issues if issue.resolved_at <= issue.sla_due_at)
        breached_sla = total_resolved - within_sla

        compliance_pct = round((within_sla / total_resolved) * 100, 1) if total_resolved > 0 else 100.0

        total_resolved_all += total_resolved
        total_within_all += within_sla

        entries.append(
            SlaComplianceEntry(
                severity=sev,
                total_resolved=total_resolved,
                within_sla=within_sla,
                breached_sla=breached_sla,
                compliance_pct=compliance_pct,
                target_hours=target_hours,
            )
        )

    overall_compliance = round((total_within_all / total_resolved_all) * 100, 1) if total_resolved_all > 0 else 100.0

    return SlaComplianceResponse(
        generated_at=datetime.now(timezone.utc),
        overall_compliance_pct=overall_compliance,
        by_severity=entries,
    )
