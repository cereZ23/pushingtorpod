"""
Audit log API router.

Provides admin-only access to tenant audit logs for compliance and forensics.
"""

import logging
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_tenant_permission
from app.core.audit import AuditLog

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/audit-logs",
    tags=["Audit"],
)


@router.get("")
async def list_audit_logs(
    tenant_id: int,
    _membership=Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    user_id: Optional[int] = Query(None, description="Filter by user ID"),
    start_date: Optional[datetime] = Query(None, description="Start date filter"),
    end_date: Optional[datetime] = Query(None, description="End date filter"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Results per page"),
):
    """List audit logs for a tenant (admin only)."""
    query = db.query(AuditLog).filter(AuditLog.tenant_id == tenant_id)

    if event_type:
        query = query.filter(AuditLog.event_type == event_type)
    if severity:
        query = query.filter(AuditLog.severity == severity)
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)

    total = query.count()
    logs = (
        query.order_by(AuditLog.timestamp.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "data": [
            {
                "id": log.id,
                "timestamp": log.timestamp.isoformat() if log.timestamp else None,
                "event_type": log.event_type,
                "user_id": log.user_id,
                "action": log.action,
                "resource": log.resource,
                "resource_id": log.resource_id,
                "result": log.result,
                "severity": log.severity,
                "ip_address": log.ip_address,
                "endpoint": log.endpoint,
                "method": log.method,
                "error_message": log.error_message,
            }
            for log in logs
        ],
        "meta": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": max(1, (total + page_size - 1) // page_size),
        },
    }
