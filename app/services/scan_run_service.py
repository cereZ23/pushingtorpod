"""Scan run lifecycle service.

Manages scan run operations: trigger, cancel, and progress retrieval.
Extracted from ``app.api.routers.projects``.
"""

from __future__ import annotations

import logging

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.scanning import (
    PhaseResult,
    Project,
    ScanProfile,
    ScanRun,
    ScanRunStatus,
)

logger = logging.getLogger(__name__)


def _serialize_scan_run(scan_run: ScanRun) -> dict:
    """Convert a ScanRun ORM instance to a response-friendly dict."""
    return {
        "id": scan_run.id,
        "project_id": scan_run.project_id,
        "profile_id": scan_run.profile_id,
        "tenant_id": scan_run.tenant_id,
        "status": scan_run.status.value if hasattr(scan_run.status, "value") else str(scan_run.status),
        "triggered_by": scan_run.triggered_by,
        "started_at": scan_run.started_at,
        "completed_at": scan_run.completed_at,
        "stats": scan_run.stats,
        "error_message": scan_run.error_message,
        "celery_task_id": scan_run.celery_task_id,
        "created_at": scan_run.created_at,
        "duration_seconds": scan_run.duration_seconds,
    }


def _serialize_phase_result(phase: PhaseResult) -> dict:
    """Convert a PhaseResult ORM instance to a response-friendly dict."""
    return {
        "id": phase.id,
        "scan_run_id": phase.scan_run_id,
        "phase": phase.phase,
        "status": phase.status.value if hasattr(phase.status, "value") else str(phase.status),
        "started_at": phase.started_at,
        "completed_at": phase.completed_at,
        "stats": phase.stats,
        "error_message": phase.error_message,
        "duration_seconds": phase.duration_seconds,
    }


class ScanRunService:
    """Manages scan run lifecycle operations."""

    def __init__(self, db: Session):
        self.db = db

    def trigger_scan(
        self,
        tenant_id: int,
        project: Project,
        profile_id: int | None,
        scan_tier: int,
        triggered_by: str,
    ) -> tuple[ScanRun, str]:
        """Create a scan run and dispatch the pipeline to Celery.

        Args:
            tenant_id: Tenant ID.
            project: Project ORM instance (already validated).
            profile_id: Optional scan profile ID.
            scan_tier: Scan tier (1-3) used when profile_id is None.
            triggered_by: Who triggered the scan (e.g. "manual").

        Returns:
            Tuple of (ScanRun instance, Celery task ID).

        Raises:
            HTTPException: 400 if profile_id is invalid.
        """
        # Validate profile if provided, otherwise auto-create from scan_tier
        if profile_id is not None:
            profile = (
                self.db.query(ScanProfile)
                .filter(
                    ScanProfile.id == profile_id,
                    ScanProfile.project_id == project.id,
                )
                .first()
            )
            if not profile:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Scan profile {profile_id} not found for this project",
                )
        else:
            # Auto-create or find a default profile for the requested tier
            tier = scan_tier
            tier_names = {1: "Safe", 2: "Moderate", 3: "Aggressive"}
            tier_ports = {1: "top-100", 2: "top-1000", 3: "full"}
            tier_rates = {1: 10, 2: 50, 3: 100}
            tier_timeouts = {1: 60, 2: 120, 3: 240}
            default_name = f"Default {tier_names.get(tier, 'Safe')} (Tier {tier})"

            profile = (
                self.db.query(ScanProfile)
                .filter(
                    ScanProfile.project_id == project.id,
                    ScanProfile.name == default_name,
                )
                .first()
            )

            if not profile:
                profile = ScanProfile(
                    project_id=project.id,
                    name=default_name,
                    scan_tier=tier,
                    port_scan_mode=tier_ports.get(tier, "top-100"),
                    max_rate_pps=tier_rates.get(tier, 10),
                    timeout_minutes=tier_timeouts.get(tier, 120),
                )
                self.db.add(profile)
                self.db.flush()

            profile_id = profile.id

        # Create scan run
        scan_run = ScanRun(
            project_id=project.id,
            profile_id=profile_id,
            tenant_id=tenant_id,
            status=ScanRunStatus.PENDING,
            triggered_by=triggered_by,
        )
        self.db.add(scan_run)
        self.db.commit()
        self.db.refresh(scan_run)

        # Dispatch to Celery
        from app.tasks.pipeline import run_scan_pipeline

        task = run_scan_pipeline.delay(scan_run.id)

        # Store celery task id
        scan_run.celery_task_id = task.id
        self.db.commit()

        return scan_run, task.id

    def cancel_scan_run(
        self,
        tenant_id: int,
        project_id: int,
        run_id: int,
    ) -> None:
        """Cancel a running or pending scan.

        Args:
            tenant_id: Tenant ID.
            project_id: Project ID.
            run_id: Scan run ID.

        Raises:
            HTTPException: 404 if not found, 400 if not cancellable.
        """
        scan_run = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.id == run_id,
                ScanRun.project_id == project_id,
                ScanRun.tenant_id == tenant_id,
            )
            .first()
        )
        if not scan_run:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan run not found",
            )

        if scan_run.status not in (ScanRunStatus.PENDING, ScanRunStatus.RUNNING):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel scan in status '{scan_run.status.value}'",
            )

        from app.tasks.pipeline import cancel_scan

        cancel_scan.delay(scan_run.id)

    def cancel_scan_run_by_tenant(
        self,
        tenant_id: int,
        run_id: int,
    ) -> None:
        """Cancel a scan run by its ID scoped to tenant (no project_id).

        Args:
            tenant_id: Tenant ID.
            run_id: Scan run ID.

        Raises:
            HTTPException: 404 if not found, 400 if not cancellable.
        """
        scan_run = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.id == run_id,
                ScanRun.tenant_id == tenant_id,
            )
            .first()
        )
        if not scan_run:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan run not found",
            )

        if scan_run.status not in (ScanRunStatus.PENDING, ScanRunStatus.RUNNING):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot cancel scan in status '{scan_run.status.value}'",
            )

        from app.tasks.pipeline import cancel_scan

        cancel_scan.delay(scan_run.id)

    def get_scan_progress(
        self,
        tenant_id: int,
        project_id: int,
        run_id: int,
    ) -> dict:
        """Get real-time progress for a scan run.

        Returns the scan run status plus all per-phase results.

        Args:
            tenant_id: Tenant ID.
            project_id: Project ID.
            run_id: Scan run ID.

        Returns:
            Dict with ``scan_run`` and ``phases`` keys.

        Raises:
            HTTPException: 404 if scan run not found.
        """
        scan_run = (
            self.db.query(ScanRun)
            .filter(
                ScanRun.id == run_id,
                ScanRun.project_id == project_id,
                ScanRun.tenant_id == tenant_id,
            )
            .first()
        )
        if not scan_run:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan run not found",
            )

        phases = (
            self.db.query(PhaseResult)
            .filter(
                PhaseResult.scan_run_id == run_id,
            )
            .order_by(PhaseResult.phase.asc())
            .all()
        )

        return {
            "scan_run": _serialize_scan_run(scan_run),
            "phases": [_serialize_phase_result(p) for p in phases],
        }
