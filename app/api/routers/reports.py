"""
Report generation API router.

Provides endpoints for generating executive summaries, technical reports,
and data exports (JSON/CSV) of the tenant's attack surface findings.
PDF generation with WeasyPrint can be added as a future enhancement.
"""

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, ConfigDict
import logging

from app.api.dependencies import get_db, verify_tenant_access
from app.models.database import (
    Asset,
    AssetType,
    Finding,
    FindingSeverity,
    FindingStatus,
    Tenant,
)
from app.models.risk import RiskScore

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/reports",
    tags=["Reports"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class TopIssueItem(BaseModel):
    """Single entry in the top issues list."""

    finding_id: int = Field(..., description="Finding ID")
    name: str = Field(..., description="Finding name")
    severity: str = Field(..., description="Severity level")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    template_id: Optional[str] = Field(None, description="Scanner template ID")
    asset_identifier: str = Field(..., description="Affected asset identifier")
    first_seen: datetime = Field(..., description="When the finding was first observed")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "finding_id": 42,
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "cvss_score": 9.8,
                "asset_identifier": "api.example.com",
                "first_seen": "2026-01-10T08:00:00Z",
            }
        }
    )


class ScoreTrendPoint(BaseModel):
    """Single data point in the risk score trend."""

    date: datetime = Field(..., description="Score snapshot timestamp")
    score: float = Field(..., description="Risk score at this point (0-100)")
    grade: str = Field(..., description="Letter grade at this point")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "date": "2026-02-20T08:00:00Z",
                "score": 62.5,
                "grade": "C",
            }
        }
    )


class RecommendationItem(BaseModel):
    """Auto-generated remediation recommendation."""

    priority: int = Field(..., description="Recommendation priority (1 = highest)")
    title: str = Field(..., description="Short recommendation title")
    description: str = Field(..., description="Detailed recommendation")
    affected_count: int = Field(..., description="Number of affected assets or findings")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "priority": 1,
                "title": "Patch critical RCE vulnerabilities",
                "description": "5 assets have critical RCE findings. Apply vendor patches immediately.",
                "affected_count": 5,
            }
        }
    )


class ExecutiveReportResponse(BaseModel):
    """Executive summary report for leadership and compliance audiences."""

    generated_at: datetime = Field(..., description="Report generation timestamp")
    tenant_id: int = Field(..., description="Tenant ID")
    risk_score: float = Field(..., description="Current organization risk score (0-100)")
    risk_grade: str = Field(..., description="Letter grade (A-F)")
    score_trend: List[ScoreTrendPoint] = Field(..., description="Score history over the last 30 days")
    top_issues: List[TopIssueItem] = Field(..., description="Top 10 issues by risk score")
    asset_counts: Dict[str, int] = Field(..., description="Asset count by type")
    finding_counts_by_severity: Dict[str, int] = Field(..., description="Finding count by severity")
    finding_counts_by_status: Dict[str, int] = Field(..., description="Finding count by status")
    total_assets: int = Field(..., description="Total number of assets")
    total_findings: int = Field(..., description="Total number of findings")
    open_findings: int = Field(..., description="Number of open findings")
    recommendations: List[RecommendationItem] = Field(..., description="Auto-generated recommendations")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "generated_at": "2026-02-25T12:00:00Z",
                "tenant_id": 1,
                "risk_score": 62.5,
                "risk_grade": "C",
                "score_trend": [],
                "top_issues": [],
                "asset_counts": {"domain": 10, "subdomain": 200, "ip": 50, "url": 30, "service": 15},
                "finding_counts_by_severity": {"critical": 3, "high": 12, "medium": 45, "low": 80, "info": 20},
                "finding_counts_by_status": {"open": 120, "suppressed": 15, "fixed": 25},
                "total_assets": 305,
                "total_findings": 160,
                "open_findings": 120,
                "recommendations": [],
            }
        }
    )


class TechnicalFindingItem(BaseModel):
    """Detailed finding entry for the technical report."""

    id: int = Field(..., description="Finding ID")
    name: str = Field(..., description="Finding name")
    severity: str = Field(..., description="Severity level")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    template_id: Optional[str] = Field(None, description="Nuclei template ID")
    source: str = Field(..., description="Detection source")
    status: str = Field(..., description="Current status")
    asset_identifier: str = Field(..., description="Affected asset identifier")
    asset_type: str = Field(..., description="Asset type")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Evidence payload")
    first_seen: datetime = Field(..., description="First observed")
    last_seen: datetime = Field(..., description="Last observed")
    remediation: Optional[str] = Field(None, description="Remediation guidance")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 42,
                "name": "Missing HSTS Header",
                "severity": "medium",
                "cvss_score": 5.3,
                "cve_id": None,
                "template_id": "http-missing-security-headers:strict-transport-security",
                "source": "nuclei",
                "status": "open",
                "asset_identifier": "www.example.com",
                "asset_type": "subdomain",
                "evidence": {"matched_at": "header"},
                "first_seen": "2026-02-01T10:00:00Z",
                "last_seen": "2026-02-24T10:00:00Z",
                "remediation": "Add Strict-Transport-Security header with max-age >= 31536000.",
            }
        }
    )


class TechnicalReportResponse(BaseModel):
    """Full technical report with all findings and evidence."""

    generated_at: datetime = Field(..., description="Report generation timestamp")
    tenant_id: int = Field(..., description="Tenant ID")
    total_findings: int = Field(..., description="Total finding count included")
    findings: List[TechnicalFindingItem] = Field(..., description="All findings with details")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "generated_at": "2026-02-25T12:00:00Z",
                "tenant_id": 1,
                "total_findings": 160,
                "findings": [],
            }
        }
    )


# ---------------------------------------------------------------------------
# Severity weights (for sorting top issues)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHT: Dict[str, int] = {
    "critical": 50,
    "high": 30,
    "medium": 15,
    "low": 5,
    "info": 1,
}


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


def _build_recommendations(
    severity_counts: Dict[str, int],
    open_count: int,
) -> List[RecommendationItem]:
    """
    Auto-generate remediation recommendations from finding distribution.

    Recommendations are ordered by priority (critical first).
    """
    recommendations: list[RecommendationItem] = []
    priority = 1

    critical = severity_counts.get("critical", 0)
    high = severity_counts.get("high", 0)
    medium = severity_counts.get("medium", 0)

    if critical > 0:
        recommendations.append(
            RecommendationItem(
                priority=priority,
                title="Remediate critical vulnerabilities immediately",
                description=(
                    f"{critical} critical finding(s) detected. These represent the highest risk "
                    "to the organization and should be patched or mitigated within 24 hours."
                ),
                affected_count=critical,
            )
        )
        priority += 1

    if high > 0:
        recommendations.append(
            RecommendationItem(
                priority=priority,
                title="Address high-severity findings within SLA",
                description=(
                    f"{high} high-severity finding(s) require attention. Schedule remediation "
                    "within the 7-day SLA window to prevent exploitation."
                ),
                affected_count=high,
            )
        )
        priority += 1

    if medium > 0:
        recommendations.append(
            RecommendationItem(
                priority=priority,
                title="Plan remediation of medium-severity issues",
                description=(
                    f"{medium} medium-severity finding(s) should be addressed in the next "
                    "sprint or maintenance cycle to reduce overall risk exposure."
                ),
                affected_count=medium,
            )
        )
        priority += 1

    if open_count > 0:
        recommendations.append(
            RecommendationItem(
                priority=priority,
                title="Review and triage all open findings",
                description=(
                    f"{open_count} finding(s) are currently open. Perform triage to suppress "
                    "false positives, assign ownership, and establish remediation timelines."
                ),
                affected_count=open_count,
            )
        )
        priority += 1

    recommendations.append(
        RecommendationItem(
            priority=priority,
            title="Maintain continuous monitoring",
            description=(
                "Ensure scheduled scans are active and alert policies are configured "
                "for critical and high-severity event types to detect new exposures promptly."
            ),
            affected_count=0,
        )
    )

    return recommendations


# ---------------------------------------------------------------------------
# Remediation guidance mapping (stub -- expand as needed)
# ---------------------------------------------------------------------------

_REMEDIATION_MAP: Dict[str, str] = {
    "http-missing-security-headers": "Add the missing HTTP security header(s) in the web server configuration.",
    "ssl-detect": "Ensure TLS 1.2+ is enforced and weak cipher suites are disabled.",
    "exposed-panels": "Restrict access to administrative panels via IP allowlisting or VPN.",
    "default-login": "Change default credentials and enforce strong password policies.",
}


def _get_remediation(template_id: Optional[str]) -> Optional[str]:
    """Return remediation guidance for a given Nuclei template ID."""
    if not template_id:
        return None
    for prefix, guidance in _REMEDIATION_MAP.items():
        if template_id.startswith(prefix):
            return guidance
    return None


def _parse_evidence(evidence) -> Optional[Dict[str, Any]]:
    """Parse evidence field which may be a dict, a JSON string, or None."""
    if evidence is None:
        return None
    if isinstance(evidence, dict):
        return evidence
    if isinstance(evidence, str):
        try:
            parsed = json.loads(evidence)
            return parsed if isinstance(parsed, dict) else None
        except (json.JSONDecodeError, TypeError):
            return None
    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/executive", response_model=ExecutiveReportResponse)
def generate_executive_report(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ExecutiveReportResponse:
    """
    Generate an executive summary report.

    Intended for leadership, compliance, and non-technical stakeholders.
    Aggregates the current risk posture into a concise overview with
    score trends, top issues, and auto-generated recommendations.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        ExecutiveReportResponse with full summary data.
    """
    _verify_tenant_exists(db, tenant_id)

    # --- Risk score and grade ---
    latest_risk = (
        db.query(RiskScore)
        .filter(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == "organization",
        )
        .order_by(RiskScore.scored_at.desc())
        .first()
    )
    risk_score = round(latest_risk.score, 2) if latest_risk else 0.0
    risk_grade = latest_risk.grade if latest_risk else "N/A"

    # --- Score trend (last 30 days) ---
    cutoff_30d = datetime.now(timezone.utc) - timedelta(days=30)
    score_rows = (
        db.query(RiskScore)
        .filter(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == "organization",
            RiskScore.scored_at >= cutoff_30d,
        )
        .order_by(RiskScore.scored_at.asc())
        .all()
    )
    score_trend = [
        ScoreTrendPoint(
            date=row.scored_at,
            score=round(row.score, 2),
            grade=row.grade or "N/A",
        )
        for row in score_rows
    ]

    # --- Asset counts by type ---
    asset_counts: Dict[str, int] = {}
    for asset_type in AssetType:
        count = (
            db.query(func.count(Asset.id)).filter(Asset.tenant_id == tenant_id, Asset.type == asset_type).scalar() or 0
        )
        asset_counts[asset_type.value] = count
    total_assets = sum(asset_counts.values())

    # --- Finding counts by severity ---
    finding_counts_severity: Dict[str, int] = {}
    for severity in FindingSeverity:
        count = (
            db.query(func.count(Finding.id))
            .join(Asset)
            .filter(Asset.tenant_id == tenant_id, Finding.severity == severity)
            .scalar()
            or 0
        )
        finding_counts_severity[severity.value] = count

    # --- Finding counts by status ---
    finding_counts_status: Dict[str, int] = {}
    for finding_status in FindingStatus:
        count = (
            db.query(func.count(Finding.id))
            .join(Asset)
            .filter(Asset.tenant_id == tenant_id, Finding.status == finding_status)
            .scalar()
            or 0
        )
        finding_counts_status[finding_status.value] = count

    total_findings = sum(finding_counts_status.values())
    open_findings = finding_counts_status.get("open", 0)

    # --- Top 10 issues by computed risk weight ---
    top_findings_query = (
        db.query(Finding, Asset.identifier)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
        )
        .order_by(Finding.severity.desc(), Finding.cvss_score.desc().nullslast())
        .limit(200)
        .all()
    )

    # Sort in Python using severity weights + CVSS, dedup by name+asset
    scored_issues = []
    seen_keys: set[str] = set()
    for finding, asset_identifier in top_findings_query:
        dedup_key = f"{finding.name}|{asset_identifier}"
        if dedup_key in seen_keys:
            continue
        seen_keys.add(dedup_key)
        weight = SEVERITY_WEIGHT.get(finding.severity.value, 0)
        cvss = finding.cvss_score or 0.0
        scored_issues.append((weight + cvss, finding, asset_identifier))

    scored_issues.sort(key=lambda x: x[0], reverse=True)

    top_issues = [
        TopIssueItem(
            finding_id=finding.id,
            name=finding.name,
            severity=finding.severity.value,
            cvss_score=finding.cvss_score,
            cve_id=finding.cve_id,
            template_id=finding.template_id,
            asset_identifier=asset_identifier,
            first_seen=finding.first_seen,
        )
        for _, finding, asset_identifier in scored_issues[:10]
    ]

    # --- Recommendations ---
    open_severity_counts = {}
    for severity in FindingSeverity:
        count = (
            db.query(func.count(Finding.id))
            .join(Asset)
            .filter(
                Asset.tenant_id == tenant_id,
                Finding.severity == severity,
                Finding.status == FindingStatus.OPEN,
            )
            .scalar()
            or 0
        )
        open_severity_counts[severity.value] = count

    recommendations = _build_recommendations(open_severity_counts, open_findings)

    return ExecutiveReportResponse(
        generated_at=datetime.now(timezone.utc),
        tenant_id=tenant_id,
        risk_score=risk_score,
        risk_grade=risk_grade,
        score_trend=score_trend,
        top_issues=top_issues,
        asset_counts=asset_counts,
        finding_counts_by_severity=finding_counts_severity,
        finding_counts_by_status=finding_counts_status,
        total_assets=total_assets,
        total_findings=total_findings,
        open_findings=open_findings,
        recommendations=recommendations,
    )


@router.get("/technical", response_model=TechnicalReportResponse)
def generate_technical_report(
    tenant_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    finding_status: Optional[str] = Query(None, alias="status", description="Filter by status"),
    limit: int = Query(default=500, ge=1, le=5000, description="Maximum findings to include"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> TechnicalReportResponse:
    """
    Generate a full technical report with all findings and evidence.

    Intended for security engineers and penetration testers.
    Includes evidence payloads, remediation guidance, and affected asset
    details for every finding matching the optional filters.

    Args:
        tenant_id: Tenant ID from path.
        severity: Optional severity filter.
        finding_status: Optional status filter.
        limit: Maximum number of findings to include.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        TechnicalReportResponse with finding details.
    """
    _verify_tenant_exists(db, tenant_id)

    query = db.query(Finding, Asset.identifier, Asset.type).join(Asset).filter(Asset.tenant_id == tenant_id)

    if severity:
        try:
            query = query.filter(Finding.severity == FindingSeverity(severity))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}",
            )

    if finding_status:
        try:
            query = query.filter(Finding.status == FindingStatus(finding_status))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {finding_status}",
            )

    query = query.order_by(
        Finding.severity.desc(),
        Finding.cvss_score.desc().nullslast(),
        Finding.last_seen.desc(),
    )

    results = query.limit(limit).all()

    findings = [
        TechnicalFindingItem(
            id=finding.id,
            name=finding.name,
            severity=finding.severity.value,
            cvss_score=finding.cvss_score,
            cve_id=finding.cve_id,
            template_id=finding.template_id,
            source=finding.source,
            status=finding.status.value,
            asset_identifier=asset_identifier,
            asset_type=asset_type.value if asset_type else "unknown",
            evidence=_parse_evidence(finding.evidence),
            first_seen=finding.first_seen,
            last_seen=finding.last_seen,
            remediation=_get_remediation(finding.template_id),
        )
        for finding, asset_identifier, asset_type in results
    ]

    return TechnicalReportResponse(
        generated_at=datetime.now(timezone.utc),
        tenant_id=tenant_id,
        total_findings=len(findings),
        findings=findings,
    )


@router.get("/export/pdf")
def export_report_pdf(
    tenant_id: int,
    report_type: str = Query(
        default="executive", regex="^(executive|technical|soc2|iso27001)$", description="Report type"
    ),
    severity: Optional[str] = Query(None, description="Filter by severity (technical only)"),
    finding_status: Optional[str] = Query(None, alias="status", description="Filter by status (technical only)"),
    limit: int = Query(default=500, ge=1, le=5000, description="Max findings (technical only)"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> StreamingResponse:
    """
    Export a professional PDF report.

    Supported report types:

    - ``executive`` – High-level risk summary for leadership.
    - ``technical`` – Detailed findings with evidence for engineers.
    - ``soc2`` – SOC 2 Trust Service Criteria compliance assessment.
    - ``iso27001`` – ISO 27001 Annex A control assessment.

    Returns a streaming PDF response with charts, tables, severity badges,
    and branded layout suitable for stakeholder distribution.

    Args:
        tenant_id: Tenant ID from path.
        report_type: ``executive``, ``technical``, ``soc2``, or ``iso27001``.
        severity: Optional severity filter for technical reports.
        finding_status: Optional status filter for technical reports.
        limit: Max findings to include in technical reports.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        StreamingResponse with application/pdf content type.
    """
    _verify_tenant_exists(db, tenant_id)

    from app.services.report_generator import ReportGenerator

    generator = ReportGenerator(db, tenant_id)
    try:
        pdf_bytes = generator.generate_pdf(
            report_type=report_type,
            severity=severity,
            finding_status=finding_status,
            limit=limit,
        )
    except Exception as exc:
        logger.exception("PDF generation failed for tenant %s", tenant_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PDF generation failed: {exc}",
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"easm_{report_type}_tenant_{tenant_id}_{timestamp}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/docx")
def export_report_docx(
    tenant_id: int,
    report_type: str = Query(
        default="executive", regex="^(executive|technical|soc2|iso27001)$", description="Report type"
    ),
    severity: Optional[str] = Query(None, description="Filter by severity (technical only)"),
    finding_status: Optional[str] = Query(None, alias="status", description="Filter by status (technical only)"),
    limit: int = Query(default=500, ge=1, le=5000, description="Max findings (technical only)"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> StreamingResponse:
    """
    Export a professional DOCX report.

    Supported report types: ``executive``, ``technical``, ``soc2``, ``iso27001``.

    Returns a streaming DOCX response with charts, tables, and
    structured sections suitable for editing or sharing.

    Args:
        tenant_id: Tenant ID from path.
        report_type: ``executive``, ``technical``, ``soc2``, or ``iso27001``.
        severity: Optional severity filter for technical reports.
        finding_status: Optional status filter for technical reports.
        limit: Max findings to include in technical reports.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        StreamingResponse with DOCX content type.
    """
    _verify_tenant_exists(db, tenant_id)

    from app.services.report_generator import ReportGenerator

    generator = ReportGenerator(db, tenant_id)
    try:
        docx_bytes = generator.generate_docx(
            report_type=report_type,
            severity=severity,
            finding_status=finding_status,
            limit=limit,
        )
    except Exception as exc:
        logger.exception("DOCX generation failed for tenant %s", tenant_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"DOCX generation failed: {exc}",
        )

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"easm_{report_type}_tenant_{tenant_id}_{timestamp}.docx"

    return StreamingResponse(
        io.BytesIO(docx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/json")
def export_findings_json(
    tenant_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    finding_status: Optional[str] = Query(None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> StreamingResponse:
    """
    Export all findings as a downloadable JSON file.

    Returns a streaming JSON response with Content-Disposition set for
    file download. The export includes every finding for the tenant
    (optionally filtered by severity and status).

    Args:
        tenant_id: Tenant ID from path.
        severity: Optional severity filter.
        finding_status: Optional status filter.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        StreamingResponse with application/json content type.
    """
    _verify_tenant_exists(db, tenant_id)

    query = db.query(Finding, Asset.identifier, Asset.type).join(Asset).filter(Asset.tenant_id == tenant_id)

    if severity:
        try:
            query = query.filter(Finding.severity == FindingSeverity(severity))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}",
            )

    if finding_status:
        try:
            query = query.filter(Finding.status == FindingStatus(finding_status))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {finding_status}",
            )

    results = query.order_by(Finding.last_seen.desc()).all()

    import json

    export_data = {
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "tenant_id": tenant_id,
        "total": len(results),
        "findings": [
            {
                "id": finding.id,
                "name": finding.name,
                "severity": finding.severity.value,
                "cvss_score": finding.cvss_score,
                "cve_id": finding.cve_id,
                "template_id": finding.template_id,
                "source": finding.source,
                "status": finding.status.value,
                "asset_identifier": asset_identifier,
                "asset_type": asset_type.value if asset_type else None,
                "evidence": _parse_evidence(finding.evidence),
                "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
                "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            }
            for finding, asset_identifier, asset_type in results
        ],
    }

    json_bytes = json.dumps(export_data, indent=2, default=str).encode("utf-8")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"findings_tenant_{tenant_id}_{timestamp}.json"

    return StreamingResponse(
        io.BytesIO(json_bytes),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/csv")
def export_findings_csv(
    tenant_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    finding_status: Optional[str] = Query(None, alias="status", description="Filter by status"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> StreamingResponse:
    """
    Export all findings as a downloadable CSV file.

    Returns a streaming CSV response with Content-Disposition set for
    file download. Suitable for import into spreadsheets, SIEM tools,
    or external reporting systems.

    Args:
        tenant_id: Tenant ID from path.
        severity: Optional severity filter.
        finding_status: Optional status filter.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        StreamingResponse with text/csv content type.
    """
    _verify_tenant_exists(db, tenant_id)

    query = db.query(Finding, Asset.identifier, Asset.type).join(Asset).filter(Asset.tenant_id == tenant_id)

    if severity:
        try:
            query = query.filter(Finding.severity == FindingSeverity(severity))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid severity: {severity}",
            )

    if finding_status:
        try:
            query = query.filter(Finding.status == FindingStatus(finding_status))
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid status: {finding_status}",
            )

    results = query.order_by(Finding.last_seen.desc()).all()

    csv_headers = [
        "id",
        "name",
        "severity",
        "cvss_score",
        "cve_id",
        "template_id",
        "source",
        "status",
        "asset_identifier",
        "asset_type",
        "first_seen",
        "last_seen",
    ]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(csv_headers)

    for finding, asset_identifier, asset_type in results:
        writer.writerow(
            [
                finding.id,
                finding.name,
                finding.severity.value,
                finding.cvss_score or "",
                finding.cve_id or "",
                finding.template_id or "",
                finding.source,
                finding.status.value,
                asset_identifier,
                asset_type.value if asset_type else "",
                finding.first_seen.isoformat() if finding.first_seen else "",
                finding.last_seen.isoformat() if finding.last_seen else "",
            ]
        )

    csv_bytes = output.getvalue().encode("utf-8")
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"findings_tenant_{tenant_id}_{timestamp}.csv"

    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/assets-csv")
def export_assets_csv(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> StreamingResponse:
    """
    Export all assets as a downloadable CSV file.

    Returns a streaming CSV response with Content-Disposition set for
    file download. Suitable for import into spreadsheets, CMDBs,
    or external asset management systems.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        StreamingResponse with text/csv content type.
    """
    _verify_tenant_exists(db, tenant_id)

    results = db.query(Asset).filter(Asset.tenant_id == tenant_id).order_by(Asset.last_seen.desc()).all()

    csv_headers = [
        "id",
        "identifier",
        "type",
        "priority",
        "risk_score",
        "first_seen",
        "last_seen",
        "is_active",
        "enrichment_status",
    ]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(csv_headers)

    for asset in results:
        writer.writerow(
            [
                asset.id,
                asset.identifier,
                asset.type.value if asset.type else "",
                asset.priority or "",
                asset.risk_score or "",
                asset.first_seen.isoformat() if asset.first_seen else "",
                asset.last_seen.isoformat() if asset.last_seen else "",
                asset.is_active,
                asset.enrichment_status or "",
            ]
        )

    csv_bytes = output.getvalue().encode("utf-8")

    return StreamingResponse(
        io.BytesIO(csv_bytes),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="assets_export.csv"'},
    )
