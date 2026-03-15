"""
DNSTwist Router

Domain permutation / typosquatting detection endpoints.
Allows triggering on-demand scans and querying the resulting findings.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from typing import Optional
import logging

from app.api.dependencies import get_db, verify_tenant_access, PaginationParams, escape_like
from app.api.schemas.common import TaskResponse, PaginatedResponse
from app.api.schemas.dnstwist import DnstwistScanRequest, DnstwistFindingResponse
from app.models.database import Asset, Finding, FindingSeverity, FindingStatus
from app.tasks.dnstwist_scan import run_dnstwist

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/dnstwist",
    tags=["DNSTwist"],
)


@router.post("/scan", response_model=TaskResponse)
def trigger_dnstwist_scan(
    tenant_id: int,
    body: Optional[DnstwistScanRequest] = None,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger a DNSTwist typosquatting scan for the tenant.

    When ``domain_list`` is provided in the request body, only those domains
    are scanned.  Otherwise every active root-domain asset belonging to the
    tenant is scanned.

    The scan runs asynchronously as a Celery task; the response contains the
    task ID that can be used to poll for completion.

    Args:
        tenant_id: Tenant ID
        body: Optional request body with explicit domain list

    Returns:
        TaskResponse with Celery task ID

    Example:
        POST /api/v1/tenants/2/dnstwist/scan
        {
            "domain_list": ["example.com"]
        }
    """
    domain_list = body.domain_list if body else None

    logger.info(f"Triggering DNSTwist scan for tenant {tenant_id} (domains: {domain_list or 'all'})")

    task = run_dnstwist.delay(
        tenant_id=tenant_id,
        domain_list=domain_list,
    )

    return TaskResponse(
        task_id=task.id,
        status="queued",
        message=f"DNSTwist scan queued for tenant {tenant_id}",
    )


@router.get("/findings", response_model=PaginatedResponse[DnstwistFindingResponse])
def list_dnstwist_findings(
    tenant_id: int,
    severity: Optional[str] = Query(None, description="Filter by severity (medium, high)"),
    finding_status: Optional[str] = Query(
        None, alias="status", description="Filter by status (open, suppressed, fixed)"
    ),
    search: Optional[str] = Query(None, description="Search in finding name / permutation domain"),
    sort_by: str = Query("last_seen", description="Sort field"),
    sort_order: str = Query("desc", regex="^(asc|desc)$", description="Sort order"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    List typosquatting findings produced by DNSTwist.

    Results are scoped to the given tenant and limited to findings whose
    ``source`` equals ``dnstwist``.

    Args:
        tenant_id: Tenant ID
        severity: Optional severity filter
        finding_status: Optional status filter
        search: Optional text search across finding name
        sort_by: Column to sort by (default ``last_seen``)
        sort_order: ``asc`` or ``desc`` (default ``desc``)

    Returns:
        Paginated list of ``DnstwistFindingResponse`` items
    """
    query = (
        db.query(Finding, Asset.identifier.label("asset_identifier"))
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.source == "dnstwist",
        )
    )

    # -- Optional filters ------------------------------------------------
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

    if search:
        query = query.filter(Finding.name.ilike(f"%{escape_like(search)}%", escape="\\"))

    # -- Sorting ---------------------------------------------------------
    sort_column = getattr(Finding, sort_by, Finding.last_seen)
    if sort_order == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # -- Pagination ------------------------------------------------------
    total = query.count()
    results = pagination.paginate_query(query).all()

    items = []
    for finding, asset_identifier in results:
        item = DnstwistFindingResponse(
            id=finding.id,
            asset_id=finding.asset_id,
            template_id=finding.template_id,
            name=finding.name,
            severity=finding.severity.value if finding.severity else "medium",
            evidence=finding.evidence,
            first_seen=finding.first_seen.isoformat() if finding.first_seen else "",
            last_seen=finding.last_seen.isoformat() if finding.last_seen else "",
            status=finding.status.value if finding.status else "open",
            asset_identifier=asset_identifier,
        )
        items.append(item)

    return PaginatedResponse(
        items=items,
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=(total + pagination.page_size - 1) // pagination.page_size,
    )
