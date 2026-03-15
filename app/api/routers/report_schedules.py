"""
Scheduled report delivery API router.

Provides CRUD operations for report schedules that define automated
PDF/DOCX report generation and email delivery on configurable cadences.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, verify_tenant_access
from app.core.audit import log_data_modification
from app.api.schemas.report_schedule import (
    ReportScheduleCreate,
    ReportScheduleResponse,
    ReportScheduleUpdate,
)
from app.models.database import Tenant
from app.models.report_schedule import ReportSchedule

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/report-schedules",
    tags=["Report Schedules"],
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


def _schedule_to_response(schedule: ReportSchedule) -> ReportScheduleResponse:
    """Convert a ReportSchedule ORM instance to the response schema.

    The ``recipients`` column is stored as a JSON string in the database
    but exposed as ``list[str]`` in the API.
    """
    try:
        recipients = json.loads(schedule.recipients)
    except (json.JSONDecodeError, TypeError):
        recipients = []

    return ReportScheduleResponse(
        id=schedule.id,
        tenant_id=schedule.tenant_id,
        name=schedule.name,
        report_type=schedule.report_type,
        format=schedule.format,
        schedule=schedule.schedule,
        recipients=recipients,
        is_active=schedule.is_active,
        last_sent_at=schedule.last_sent_at,
        created_at=schedule.created_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=List[ReportScheduleResponse])
def list_report_schedules(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> List[ReportScheduleResponse]:
    """
    List all report schedules for a tenant.

    Returns both active and inactive schedules.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership (read permission).

    Returns:
        List of report schedule objects.
    """
    _verify_tenant_exists(db, tenant_id)

    schedules = (
        db.query(ReportSchedule)
        .filter(ReportSchedule.tenant_id == tenant_id)
        .order_by(ReportSchedule.created_at.desc())
        .all()
    )

    return [_schedule_to_response(s) for s in schedules]


@router.post(
    "/",
    response_model=ReportScheduleResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_report_schedule(
    tenant_id: int,
    body: ReportScheduleCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ReportScheduleResponse:
    """
    Create a new report schedule.

    Requires write permission on the tenant.

    Args:
        tenant_id: Tenant ID from path.
        body: Schedule creation payload.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        The newly created report schedule.
    """
    _verify_tenant_exists(db, tenant_id)

    schedule = ReportSchedule(
        tenant_id=tenant_id,
        name=body.name,
        report_type=body.report_type,
        format=body.format,
        schedule=body.schedule,
        recipients=json.dumps([str(r) for r in body.recipients]),
        is_active=True,
    )
    db.add(schedule)
    db.commit()
    db.refresh(schedule)

    log_data_modification(
        action="create",
        resource="report_schedule",
        resource_id=str(schedule.id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={"report_type": body.report_type, "format": body.format, "schedule": body.schedule},
    )

    return _schedule_to_response(schedule)


@router.patch("/{schedule_id}", response_model=ReportScheduleResponse)
def update_report_schedule(
    tenant_id: int,
    schedule_id: int,
    body: ReportScheduleUpdate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ReportScheduleResponse:
    """
    Partially update an existing report schedule.

    Only the fields provided in the request body are updated.

    Args:
        tenant_id: Tenant ID from path.
        schedule_id: Schedule ID from path.
        body: Partial update payload.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        The updated report schedule.
    """
    _verify_tenant_exists(db, tenant_id)

    schedule = (
        db.query(ReportSchedule)
        .filter(
            ReportSchedule.id == schedule_id,
            ReportSchedule.tenant_id == tenant_id,
        )
        .first()
    )

    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report schedule not found",
        )

    update_data = body.model_dump(exclude_unset=True)

    if "name" in update_data and update_data["name"] is not None:
        schedule.name = update_data["name"]

    if "schedule" in update_data and update_data["schedule"] is not None:
        schedule.schedule = update_data["schedule"]

    if "recipients" in update_data and update_data["recipients"] is not None:
        schedule.recipients = json.dumps([str(r) for r in update_data["recipients"]])

    if "is_active" in update_data and update_data["is_active"] is not None:
        schedule.is_active = update_data["is_active"]

    schedule.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(schedule)

    log_data_modification(
        action="update",
        resource="report_schedule",
        resource_id=str(schedule_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={k: str(v) for k, v in update_data.items()},
    )

    return _schedule_to_response(schedule)


@router.delete("/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
def delete_report_schedule(
    tenant_id: int,
    schedule_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> None:
    """
    Soft-delete a report schedule by setting is_active=False.

    Args:
        tenant_id: Tenant ID from path.
        schedule_id: Schedule ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        204 No Content on success.
    """
    _verify_tenant_exists(db, tenant_id)

    schedule = (
        db.query(ReportSchedule)
        .filter(
            ReportSchedule.id == schedule_id,
            ReportSchedule.tenant_id == tenant_id,
        )
        .first()
    )

    if not schedule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report schedule not found",
        )

    schedule.is_active = False
    schedule.updated_at = datetime.now(timezone.utc)
    db.commit()

    log_data_modification(
        action="delete",
        resource="report_schedule",
        resource_id=str(schedule_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
    )

    logger.info(
        "Soft-deleted report schedule %d for tenant %d",
        schedule_id,
        tenant_id,
    )
