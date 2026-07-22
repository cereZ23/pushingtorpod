"""Admin API for the scan kill-switch (blast-radius emergency stop)."""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_admin
from app.core.tenant_context import allow_cross_tenant
from app.services import kill_switch

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/admin/kill-switch", tags=["Admin"])


def _scope(tenant_id: Optional[int]) -> str:
    return f"tenant:{tenant_id}" if tenant_id is not None else "global"


def _revoke_running_scans(db: Session, tenant_id: Optional[int]) -> int:
    """Revoke the Celery tasks of currently-running scans (best effort)."""
    from app.celery_app import celery
    from app.models.scanning import ScanRun, ScanRunStatus

    revoked = 0
    try:
        with allow_cross_tenant():
            q = db.query(ScanRun).filter(ScanRun.status == ScanRunStatus.RUNNING)
            if tenant_id is not None:
                q = q.filter(ScanRun.tenant_id == tenant_id)
            runs = q.all()
        for run in runs:
            if run.celery_task_id:
                celery.control.revoke(run.celery_task_id, terminate=True)
                revoked += 1
    except Exception as exc:  # pragma: no cover - best effort
        logger.warning("kill-switch: failed to revoke running scans: %s", exc)
    return revoked


@router.get("/status")
def kill_switch_status(
    tenant_id: Optional[int] = Query(None, description="Check a tenant's switch instead of global"),
    _=Depends(require_admin),
) -> dict:
    active, reason = kill_switch.is_active(tenant_id)
    return {"active": active, "reason": reason, "scope": _scope(tenant_id)}


@router.post("/activate")
def kill_switch_activate(
    reason: str = Query("manual", description="Why the kill switch is being engaged"),
    tenant_id: Optional[int] = Query(None, description="Scope to a single tenant (default: global)"),
    db: Session = Depends(get_db),
    _=Depends(require_admin),
) -> dict:
    kill_switch.activate(reason, tenant_id)
    revoked = _revoke_running_scans(db, tenant_id)
    return {"active": True, "scope": _scope(tenant_id), "reason": reason, "scans_revoked": revoked}


@router.post("/deactivate")
def kill_switch_deactivate(
    tenant_id: Optional[int] = Query(None, description="Scope to a single tenant (default: global)"),
    _=Depends(require_admin),
) -> dict:
    kill_switch.deactivate(tenant_id)
    return {"active": False, "scope": _scope(tenant_id)}
