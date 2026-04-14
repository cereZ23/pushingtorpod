"""
Scanning Router

Manual scanning endpoints for Nuclei vulnerability scanning
"""

from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from typing import Optional, List
import logging

from app.api.dependencies import get_db, verify_tenant_access
from app.api.schemas.common import TaskResponse
from app.models.scanning import ScanRun
from app.tasks.scanning import run_nuclei_scan

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/scan", tags=["Scanning"])


@router.post("/nuclei", response_model=TaskResponse)
def trigger_nuclei_scan(
    tenant_id: int,
    asset_ids: Optional[List[int]] = Body(None, description="Specific asset IDs to scan (optional)"),
    severity_levels: List[str] = Body(["critical", "high", "medium"], description="Severity levels to scan"),
    template_paths: Optional[List[str]] = Body(None, description="Specific template paths (optional)"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Manually trigger a Nuclei vulnerability scan

    Args:
        tenant_id: Tenant ID
        asset_ids: Optional list of specific asset IDs to scan. If not provided, scans all active assets.
        severity_levels: Severity levels to include (critical, high, medium, low, info)
        template_paths: Optional specific Nuclei template paths to use

    Returns:
        TaskResponse with Celery task ID

    Example:
        POST /api/v1/tenants/2/scan/nuclei
        {
            "severity_levels": ["critical", "high"],
            "asset_ids": [1, 2, 3]
        }
    """
    logger.info(f"Triggering Nuclei scan for tenant {tenant_id} (asset_ids: {asset_ids}, severity: {severity_levels})")

    # Trigger async Nuclei scan task (note: task uses 'severity' parameter, not 'severity_levels')
    task = run_nuclei_scan.delay(
        tenant_id=tenant_id,
        asset_ids=asset_ids,
        severity=severity_levels,  # Map severity_levels -> severity
        templates=template_paths,  # Map template_paths -> templates
    )

    return TaskResponse(task_id=task.id, status="queued", message=f"Nuclei scan queued for tenant {tenant_id}")


@router.post("/nuclei/update-templates", response_model=TaskResponse)
def update_nuclei_templates(tenant_id: int, membership=Depends(verify_tenant_access)):
    """
    Update Nuclei templates to latest version

    This will pull the latest templates from the Nuclei templates repository.
    Templates are shared across all tenants.

    Returns:
        TaskResponse with task status
    """
    from app.tasks.scanning import update_nuclei_templates as update_task

    logger.info(f"Triggering Nuclei template update (requested by tenant {tenant_id})")

    task = update_task.delay()

    return TaskResponse(task_id=task.id, status="queued", message="Nuclei template update queued")


@router.post("/runs/{scan_run_id}/phases/{phase_id}/rerun", response_model=TaskResponse)
def rerun_phase(
    tenant_id: int,
    scan_run_id: int,
    phase_id: str,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Re-run a single pipeline phase on an existing scan run.

    Useful for debugging or retrying a failed phase without re-running
    the full 15+ minute pipeline.
    """
    from app.tasks.pipeline import run_single_phase

    scan_run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if not scan_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found")

    if scan_run.tenant_id != tenant_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan run not found")

    task = run_single_phase.delay(scan_run_id, phase_id)

    return TaskResponse(
        task_id=task.id,
        status="queued",
        message=f"Phase {phase_id} rerun queued for scan {scan_run_id}",
        data={"scan_run_id": scan_run_id, "phase_id": phase_id},
    )
