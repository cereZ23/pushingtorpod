"""
Risk Summary & Trend API Router

Provides endpoints for:
    - Executive risk summary (widget data for dashboards)
    - EPSS trend chart data (per-tenant CVE exploitation probability over time)
    - Attack surface grouping (findings grouped by surface area)
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, case, literal
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, verify_tenant_access
from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus
from app.models.enrichment import Certificate, Service
from app.models.risk import RiskScore

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/risk",
    tags=["Risk Intelligence"],
)


@router.get("/summary")
def get_risk_summary(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Executive risk summary widget.

    Returns a single-screen overview of the tenant's security posture:
    risk grade, finding breakdown, top risks, and key metrics.
    """
    # Latest org risk score
    latest_score = (
        db.query(RiskScore)
        .filter(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == "organization",
        )
        .order_by(RiskScore.scored_at.desc())
        .first()
    )

    # Finding severity breakdown (open only)
    severity_counts = dict(
        db.query(Finding.severity, func.count(Finding.id))
        .join(Asset)
        .filter(Asset.tenant_id == tenant_id, Finding.status == FindingStatus.OPEN)
        .group_by(Finding.severity)
        .all()
    )

    # Asset counts by type
    asset_counts = dict(
        db.query(Asset.type, func.count(Asset.id))
        .filter(Asset.tenant_id == tenant_id, Asset.is_active == True)
        .group_by(Asset.type)
        .all()
    )

    # Top 5 riskiest assets
    top_assets = (
        db.query(Asset.id, Asset.identifier, Asset.type, Asset.risk_score)
        .filter(Asset.tenant_id == tenant_id, Asset.is_active == True, Asset.risk_score > 0)
        .order_by(Asset.risk_score.desc())
        .limit(5)
        .all()
    )

    # Expiring certificates (30 days)
    now_naive = datetime.utcnow()
    thirty_days = now_naive + timedelta(days=30)
    expiring_certs = (
        db.query(func.count(Certificate.id))
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Certificate.is_expired == False,
            Certificate.not_after <= thirty_days,
        )
        .scalar()
        or 0
    )

    return {
        "risk_score": latest_score.score if latest_score else None,
        "risk_grade": latest_score.grade if latest_score else None,
        "risk_delta": latest_score.delta if latest_score else None,
        "findings": {
            "critical": severity_counts.get(FindingSeverity.CRITICAL, 0),
            "high": severity_counts.get(FindingSeverity.HIGH, 0),
            "medium": severity_counts.get(FindingSeverity.MEDIUM, 0),
            "low": severity_counts.get(FindingSeverity.LOW, 0),
            "info": severity_counts.get(FindingSeverity.INFO, 0),
        },
        "assets": {
            "domains": asset_counts.get(AssetType.DOMAIN, 0),
            "subdomains": asset_counts.get(AssetType.SUBDOMAIN, 0),
            "ips": asset_counts.get(AssetType.IP, 0),
            "total": sum(asset_counts.values()),
        },
        "top_risks": [
            {
                "id": a.id,
                "identifier": a.identifier,
                "type": a.type.value if hasattr(a.type, "value") else str(a.type),
                "risk_score": a.risk_score,
            }
            for a in top_assets
        ],
        "expiring_certificates": expiring_certs,
        "components": latest_score.components if latest_score else None,
    }


@router.get("/trend")
def get_risk_trend(
    tenant_id: int,
    days: int = Query(30, ge=7, le=365),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Risk score trend over time.

    Returns daily risk score snapshots for charting. Used by the
    dashboard risk trend widget.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)

    scores = (
        db.query(RiskScore.score, RiskScore.grade, RiskScore.delta, RiskScore.scored_at)
        .filter(
            RiskScore.tenant_id == tenant_id,
            RiskScore.scope_type == "organization",
            RiskScore.scored_at >= cutoff,
        )
        .order_by(RiskScore.scored_at.asc())
        .all()
    )

    return {
        "days": days,
        "data_points": len(scores),
        "trend": [
            {
                "date": s.scored_at.isoformat() if s.scored_at else None,
                "score": s.score,
                "grade": s.grade,
                "delta": s.delta,
            }
            for s in scores
        ],
    }


@router.get("/attack-surface")
def get_attack_surface_groups(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Group findings by attack surface area.

    Returns findings clustered by: exposed services, web applications,
    TLS/certificates, DNS, and email — giving a structural view of
    where risk concentrates.
    """
    open_findings = (
        db.query(Finding).join(Asset).filter(Asset.tenant_id == tenant_id, Finding.status == FindingStatus.OPEN).all()
    )

    groups = {
        "web_vulnerabilities": [],
        "exposed_services": [],
        "tls_certificates": [],
        "dns_email": [],
        "misconfigurations": [],
        "information_disclosure": [],
    }

    for f in open_findings:
        tid = (f.template_id or "").lower()
        name_lower = (f.name or "").lower()

        if any(k in tid for k in ("cve", "vuln", "rce", "sqli", "xss", "ssrf")):
            groups["web_vulnerabilities"].append(f.id)
        elif any(k in tid for k in ("exposed", "panel", "login", "default")):
            groups["exposed_services"].append(f.id)
        elif any(k in tid for k in ("ssl", "tls", "cert", "TLS", "HDR-004")):
            groups["tls_certificates"].append(f.id)
        elif any(k in tid for k in ("dns", "spf", "dkim", "dmarc", "eml", "EML")):
            groups["dns_email"].append(f.id)
        elif any(k in name_lower for k in ("missing", "weak", "misconfigur")):
            groups["misconfigurations"].append(f.id)
        else:
            groups["information_disclosure"].append(f.id)

    return {
        "total_findings": len(open_findings),
        "groups": {name: {"count": len(ids), "finding_ids": ids[:20]} for name, ids in groups.items()},
    }
