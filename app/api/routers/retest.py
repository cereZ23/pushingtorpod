"""
Retest API router.

Provides endpoints for retesting findings by dispatching targeted
Nuclei scans against specific assets and templates. Supports single
finding retests and bulk operations with a configurable limit.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session, joinedload
from pydantic import BaseModel, Field, ConfigDict
from typing import Optional
from datetime import datetime
import logging

from app.api.dependencies import (
    get_db,
    verify_tenant_access,
)
from app.api.schemas.common import TaskResponse, SuccessResponse
from app.models.database import Asset, Finding, FindingStatus
from app.models.scanning import ScanRun, ScanRunStatus

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}",
    tags=["Retest"],
)

# Maximum number of findings in a single bulk retest request
BULK_RETEST_LIMIT = 100


# ---------------------------------------------------------------------------
# Pydantic schemas (inline for this router)
# ---------------------------------------------------------------------------


class BulkRetestRequest(BaseModel):
    """Schema for bulk retest request."""

    finding_ids: list[int] = Field(
        ...,
        min_length=1,
        max_length=BULK_RETEST_LIMIT,
        description=f"List of finding IDs to retest (max {BULK_RETEST_LIMIT})",
    )


class RetestStatusResponse(BaseModel):
    """Schema for retest status of a finding."""

    finding_id: int
    finding_name: str
    retest_scan_run_id: int | None = None
    retest_result: str | None = None
    retest_count: int = 0
    current_status: str
    scan_run_status: str | None = None

    model_config = ConfigDict(from_attributes=True)


class BulkRetestResponse(BaseModel):
    """Schema for bulk retest result."""

    queued: int = Field(..., description="Number of retests successfully queued")
    skipped: int = Field(0, description="Number of findings skipped")
    errors: list[str] = Field(default_factory=list, description="Error messages for skipped findings")
    tasks: list[dict] = Field(default_factory=list, description="Queued task details")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_finding_for_tenant(
    db: Session,
    tenant_id: int,
    finding_id: int,
) -> Finding:
    """Fetch a finding scoped to the given tenant, or raise 404."""
    finding = (
        db.query(Finding)
        .join(Asset)
        .options(joinedload(Finding.asset))
        .filter(
            Finding.id == finding_id,
            Asset.tenant_id == tenant_id,
        )
        .first()
    )
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found",
        )
    return finding


def _create_retest_scan_run(
    db: Session,
    finding: Finding,
    tenant_id: int,
) -> ScanRun:
    """
    Create a ScanRun record for a retest and dispatch the Nuclei task.

    The scan run is linked to the finding's asset project (if available)
    and uses 'retest' as the trigger source.
    """
    # Determine project_id from the asset's existing scan runs or use a
    # fallback approach: find the most recent project for this tenant.
    project_id = _resolve_project_id(db, finding, tenant_id)

    scan_run = ScanRun(
        project_id=project_id,
        profile_id=None,
        tenant_id=tenant_id,
        status=ScanRunStatus.PENDING,
        triggered_by="retest",
        stats={
            "retest_finding_id": finding.id,
            "template_id": finding.template_id,
            "asset_identifier": finding.asset.identifier if finding.asset else None,
        },
    )
    db.add(scan_run)
    db.flush()  # Get the scan_run.id before commit

    # Update finding retest tracking columns (added via migration 006)
    # Using setattr to remain safe if columns are not yet present on the ORM
    _safe_set(finding, "retest_scan_run_id", scan_run.id)
    _safe_set(finding, "retest_count", (_safe_get(finding, "retest_count") or 0) + 1)
    _safe_set(finding, "retest_result", "pending")

    db.commit()
    db.refresh(scan_run)
    db.refresh(finding)

    # Dispatch targeted Nuclei scan as a Celery task
    celery_task_id = _dispatch_nuclei_retest(
        scan_run_id=scan_run.id,
        tenant_id=tenant_id,
        asset_id=finding.asset_id,
        template_id=finding.template_id,
    )

    if celery_task_id:
        scan_run.celery_task_id = celery_task_id
        db.commit()

    return scan_run


def _resolve_project_id(db: Session, finding: Finding, tenant_id: int) -> int:
    """Resolve a project ID for the retest scan run."""
    from app.models.scanning import Project

    # Try to find a project for this tenant
    project = (
        db.query(Project)
        .filter(
            Project.tenant_id == tenant_id,
        )
        .order_by(Project.updated_at.desc())
        .first()
    )

    if project:
        return project.id

    # Auto-create a retest project if none exists
    project = Project(
        tenant_id=tenant_id,
        name="Retests",
        description="Auto-created project for retest scan runs",
    )
    db.add(project)
    db.flush()
    return project.id


def _dispatch_nuclei_retest(
    scan_run_id: int,
    tenant_id: int,
    asset_id: int,
    template_id: str | None,
) -> str | None:
    """Dispatch a targeted Nuclei retest via Celery."""
    try:
        from app.tasks.scanning import run_retest

        task = run_retest.delay(
            scan_run_id=scan_run_id,
            tenant_id=tenant_id,
            asset_id=asset_id,
            template_id=template_id,
        )
        logger.info(
            f"Dispatched retest (task={task.id}, scan_run={scan_run_id}, "
            f"asset={asset_id}, template={template_id})"
        )
        return task.id
    except Exception as exc:
        logger.error(f"Failed to dispatch retest task for scan_run {scan_run_id}: {exc}")
        return None


def _safe_get(obj: object, attr: str, default=None):
    """Safely get an attribute that may not exist on the ORM model."""
    return getattr(obj, attr, default)


def _safe_set(obj: object, attr: str, value) -> None:
    """Safely set an attribute that may not exist on the ORM model."""
    if hasattr(obj, attr):
        setattr(obj, attr, value)


# ===========================================================================
# ENDPOINTS
# ===========================================================================


@router.post("/findings/{finding_id}/retest", response_model=TaskResponse)
def trigger_retest(
    tenant_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger a retest for a single finding.

    Creates a new ScanRun with triggered_by='retest' and dispatches a
    targeted Nuclei scan on the finding's asset using the original
    template_id. The finding's retest tracking fields are updated.

    Args:
        tenant_id: Tenant ID (path)
        finding_id: Finding ID to retest (path)

    Returns:
        TaskResponse with scan_run_id and Celery task_id

    Raises:
        404: Finding not found
        403: Insufficient permissions
        400: Finding is already being retested
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    finding = _get_finding_for_tenant(db, tenant_id, finding_id)

    # Check if a retest is already pending for this finding
    existing_retest_id = _safe_get(finding, "retest_scan_run_id")
    if existing_retest_id:
        existing_run = (
            db.query(ScanRun)
            .filter(
                ScanRun.id == existing_retest_id,
            )
            .first()
        )
        if existing_run and existing_run.status in (ScanRunStatus.PENDING, ScanRunStatus.RUNNING):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(f"Finding {finding_id} already has a pending retest (scan_run_id={existing_retest_id})"),
            )

    scan_run = _create_retest_scan_run(db, finding, tenant_id)

    logger.info(f"Triggered retest for finding {finding_id} (scan_run={scan_run.id}, tenant={tenant_id})")

    return TaskResponse(
        task_id=scan_run.celery_task_id or "pending",
        status="queued",
        message=f"Retest queued for finding '{finding.name}'",
        data={
            "scan_run_id": scan_run.id,
            "finding_id": finding_id,
            "template_id": finding.template_id,
            "asset_identifier": finding.asset.identifier if finding.asset else None,
        },
    )


@router.get("/findings/{finding_id}/retest-status", response_model=RetestStatusResponse)
def get_retest_status(
    tenant_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get the retest status for a finding.

    Returns the current retest tracking information including the
    linked scan run status, retest count, and result.

    Args:
        tenant_id: Tenant ID (path)
        finding_id: Finding ID (path)

    Returns:
        RetestStatusResponse with current retest state

    Raises:
        404: Finding not found
    """
    finding = _get_finding_for_tenant(db, tenant_id, finding_id)

    retest_scan_run_id = _safe_get(finding, "retest_scan_run_id")
    retest_result = _safe_get(finding, "retest_result")
    retest_count = _safe_get(finding, "retest_count") or 0

    # Resolve scan run status if a retest has been triggered
    scan_run_status = None
    if retest_scan_run_id:
        scan_run = db.query(ScanRun).filter(ScanRun.id == retest_scan_run_id).first()
        if scan_run:
            scan_run_status = scan_run.status.value if hasattr(scan_run.status, "value") else str(scan_run.status)

    return RetestStatusResponse(
        finding_id=finding.id,
        finding_name=finding.name,
        retest_scan_run_id=retest_scan_run_id,
        retest_result=retest_result,
        retest_count=retest_count,
        current_status=finding.status.value if hasattr(finding.status, "value") else str(finding.status),
        scan_run_status=scan_run_status,
    )


@router.post("/findings/bulk/retest", response_model=BulkRetestResponse)
def bulk_retest(
    tenant_id: int,
    payload: BulkRetestRequest,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger retests for multiple findings at once.

    Processes each finding independently: findings that are not found,
    inaccessible, or already being retested are skipped with an error
    message in the response.

    Args:
        tenant_id: Tenant ID (path)
        payload: List of finding IDs to retest (max 100)

    Returns:
        BulkRetestResponse with queued count, skipped count, and per-finding details

    Raises:
        403: Insufficient permissions
        422: Validation error (empty list or exceeds limit)
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    queued = 0
    skipped = 0
    errors: list[str] = []
    tasks: list[dict] = []

    for finding_id in payload.finding_ids:
        # Fetch finding with tenant isolation
        finding = (
            db.query(Finding)
            .join(Asset)
            .options(joinedload(Finding.asset))
            .filter(
                Finding.id == finding_id,
                Asset.tenant_id == tenant_id,
            )
            .first()
        )

        if not finding:
            skipped += 1
            errors.append(f"Finding {finding_id} not found")
            continue

        # Skip if already being retested
        existing_retest_id = _safe_get(finding, "retest_scan_run_id")
        if existing_retest_id:
            existing_run = (
                db.query(ScanRun)
                .filter(
                    ScanRun.id == existing_retest_id,
                )
                .first()
            )
            if existing_run and existing_run.status in (ScanRunStatus.PENDING, ScanRunStatus.RUNNING):
                skipped += 1
                errors.append(f"Finding {finding_id} already has a pending retest (scan_run_id={existing_retest_id})")
                continue

        try:
            scan_run = _create_retest_scan_run(db, finding, tenant_id)
            queued += 1
            tasks.append(
                {
                    "finding_id": finding_id,
                    "scan_run_id": scan_run.id,
                    "task_id": scan_run.celery_task_id or "pending",
                }
            )
        except Exception as exc:
            skipped += 1
            errors.append(f"Failed to queue retest for finding {finding_id}: {str(exc)}")
            logger.error(f"Bulk retest error for finding {finding_id}: {exc}", exc_info=True)

    logger.info(
        f"Bulk retest completed for tenant {tenant_id}: "
        f"{queued} queued, {skipped} skipped out of {len(payload.finding_ids)} requested"
    )

    return BulkRetestResponse(
        queued=queued,
        skipped=skipped,
        errors=errors,
        tasks=tasks,
    )
