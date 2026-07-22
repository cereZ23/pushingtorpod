"""Scan-authorization management API.

CRUD for the ScanAuthorization records that gate active scanning (see
app.services.scope_authorization). Creating these is the prerequisite for
flipping scope enforcement from audit to enforce.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, verify_tenant_access
from app.api.schemas.authorization import ScanAuthorizationCreate, ScanAuthorizationResponse
from app.core.audit import log_data_modification
from app.models.authorization import ScanAuthorization
from app.models.database import Tenant

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/scan-authorizations",
    tags=["Scan Authorizations"],
)


def _verify_tenant_exists(db: Session, tenant_id: int) -> None:
    if not db.query(Tenant.id).filter(Tenant.id == tenant_id).first():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Tenant not found")


@router.get("", response_model=list[ScanAuthorizationResponse])
def list_scan_authorizations(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> list[ScanAuthorization]:
    """List scan authorizations for a tenant (active and inactive)."""
    _verify_tenant_exists(db, tenant_id)
    return (
        db.query(ScanAuthorization)
        .filter(ScanAuthorization.tenant_id == tenant_id)
        .order_by(ScanAuthorization.created_at.desc())
        .all()
    )


@router.post("", response_model=ScanAuthorizationResponse, status_code=status.HTTP_201_CREATED)
def create_scan_authorization(
    tenant_id: int,
    body: ScanAuthorizationCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> ScanAuthorization:
    """Create a scan authorization (requires tenant write access)."""
    _verify_tenant_exists(db, tenant_id)

    auth = ScanAuthorization(
        tenant_id=tenant_id,
        name=body.name,
        scope_entries=[e.model_dump() for e in body.scope_entries],
        authorized_by=body.authorized_by,
        authorization_ref=body.authorization_ref,
        authorized_at=datetime.now(timezone.utc),
        valid_from=body.valid_from or datetime.now(timezone.utc),
        valid_until=body.valid_until,
        is_active=True,
    )
    db.add(auth)
    db.commit()
    db.refresh(auth)

    log_data_modification(
        action="create",
        resource="scan_authorization",
        resource_id=str(auth.id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={"name": body.name, "scope_count": len(body.scope_entries)},
    )
    return auth


@router.delete("/{auth_id}")
def revoke_scan_authorization(
    tenant_id: int,
    auth_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> dict:
    """Revoke (deactivate) a scan authorization."""
    _verify_tenant_exists(db, tenant_id)
    auth = (
        db.query(ScanAuthorization)
        .filter(ScanAuthorization.id == auth_id, ScanAuthorization.tenant_id == tenant_id)
        .first()
    )
    if not auth:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authorization not found")

    auth.is_active = False
    db.commit()

    log_data_modification(
        action="revoke",
        resource="scan_authorization",
        resource_id=str(auth_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
    )
    return {"id": auth_id, "revoked": True}
