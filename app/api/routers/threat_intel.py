"""
Threat Intelligence API Router

Provides endpoints for EPSS/KEV threat intelligence management:
    - Manual refresh of threat intel data (admin)
    - Cache status monitoring (admin)
    - Per-tenant finding enrichment triggers
    - Per-finding threat intel lookup
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_db,
    require_admin,
    verify_tenant_access,
)
from app.api.schemas.threat_intel import (
    FindingThreatIntelResponse,
    TenantEnrichmentResponse,
    ThreatIntelRefreshResponse,
    ThreatIntelStatusResponse,
    build_risk_boost_description,
    classify_epss_severity,
)
from app.models.database import Asset, Finding

logger = logging.getLogger(__name__)

# Admin router for platform-wide threat intel management
admin_router = APIRouter(
    prefix="/api/v1/admin/threat-intel",
    tags=["Threat Intelligence (Admin)"],
)

# Tenant-scoped router for per-finding lookups and enrichment
tenant_router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/threat-intel",
    tags=["Threat Intelligence"],
)


# --------------------------------------------------------------------------
# Admin Endpoints
# --------------------------------------------------------------------------


@admin_router.post("/refresh", response_model=ThreatIntelRefreshResponse)
def trigger_threat_intel_refresh(
    admin=Depends(require_admin),
):
    """Manually trigger a full KEV + EPSS refresh.

    Queues a Celery task that:
    1. Downloads the latest CISA KEV catalog
    2. Fetches EPSS scores for all CVEs found in the findings table
    3. Caches everything in Redis with 24h TTL

    Requires admin privileges.

    Returns:
        Task ID for tracking the refresh progress.
    """
    from app.tasks.threat_intel_sync import refresh_threat_intel

    task = refresh_threat_intel.delay()

    logger.info("Threat intel refresh triggered manually by admin")

    return ThreatIntelRefreshResponse(
        task_id=task.id,
        status="queued",
        message="Threat intelligence refresh queued",
    )


@admin_router.get("/status", response_model=ThreatIntelStatusResponse)
def get_threat_intel_status(
    admin=Depends(require_admin),
):
    """Get current threat intelligence cache status.

    Returns metadata about the last KEV/EPSS refresh including:
    - Last refresh timestamp
    - Number of CVEs in KEV catalog
    - Whether the Redis cache is populated
    - Whether the EPSS cache is reachable

    Requires admin privileges.
    """
    from app.services.threat_intel import ThreatIntelService

    service = ThreatIntelService()
    status_data = service.get_status()

    return ThreatIntelStatusResponse(**status_data)


# --------------------------------------------------------------------------
# Tenant-Scoped Endpoints
# --------------------------------------------------------------------------


@tenant_router.post("/enrich", response_model=TenantEnrichmentResponse)
def trigger_tenant_enrichment(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Trigger threat intel enrichment for all findings in this tenant.

    Queues a Celery task that enriches each open finding with:
    - EPSS probability score
    - CISA KEV catalog membership
    - KEV details (vendor, product, required action, due date)

    The enrichment data is stored in the finding's evidence JSON field
    under the "threat_intel" key. After enrichment completes, a risk
    score recalculation is automatically triggered.

    Args:
        tenant_id: Tenant whose findings should be enriched.

    Returns:
        Task ID for tracking enrichment progress.
    """
    from app.tasks.threat_intel_sync import enrich_findings_threat_intel

    task = enrich_findings_threat_intel.delay(tenant_id)

    logger.info("Threat intel enrichment triggered for tenant %d", tenant_id)

    return TenantEnrichmentResponse(
        task_id=task.id,
        status="queued",
        message=f"Threat intel enrichment queued for tenant {tenant_id}",
    )


@tenant_router.get(
    "/findings/{finding_id}",
    response_model=FindingThreatIntelResponse,
)
def get_finding_threat_intel(
    tenant_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Get EPSS and KEV data for a specific finding.

    Performs a real-time lookup (checking Redis cache first, then external
    APIs on cache miss) for the finding's CVE. Unlike the bulk enrichment
    task, this endpoint returns fresh data immediately.

    Args:
        tenant_id: Tenant ID for access control.
        finding_id: Finding to look up.

    Returns:
        EPSS score, KEV status, and risk impact description.

    Raises:
        404: Finding not found or does not belong to tenant.
        400: Finding has no associated CVE ID.
    """
    from app.api.schemas.threat_intel import KEVDetailResponse
    from app.services.threat_intel import ThreatIntelService

    # Verify finding belongs to tenant
    finding = (
        db.query(Finding)
        .join(Asset)
        .filter(Finding.id == finding_id, Asset.tenant_id == tenant_id)
        .first()
    )

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    if not finding.cve_id:
        return FindingThreatIntelResponse(
            finding_id=finding_id,
            cve_id=None,
            epss_score=0.0,
            epss_severity="low",
            is_kev=False,
            kev_details=None,
            risk_boost_description="No CVE associated with this finding.",
        )

    service = ThreatIntelService()
    cve_id = finding.cve_id.upper().strip()

    # Look up EPSS score
    epss_score = service.get_epss_score(cve_id)

    # Check KEV
    is_kev = service.is_in_kev(cve_id)
    kev_details = None
    if is_kev:
        raw_details = service.get_kev_details(cve_id)
        if raw_details:
            kev_details = KEVDetailResponse(**raw_details)

    epss_severity = classify_epss_severity(epss_score)
    risk_description = build_risk_boost_description(epss_score, is_kev)

    return FindingThreatIntelResponse(
        finding_id=finding_id,
        cve_id=cve_id,
        epss_score=epss_score,
        epss_severity=epss_severity,
        is_kev=is_kev,
        kev_details=kev_details,
        risk_boost_description=risk_description,
    )
