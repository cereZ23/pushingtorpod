"""
Tenant-scoped User Management Router

Manages users and invitations within a specific tenant.
All endpoints require admin permission on the tenant.
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, require_tenant_permission
from app.core.audit import log_audit_event, log_data_modification, AuditEventType
from app.api.schemas.user import (
    InvitationCreate,
    InvitationResponse,
    TenantUserCreate,
    TenantUserResponse,
    TenantUserUpdate,
)
from app.models.auth import TenantMembership, User, UserInvitation

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/users",
    tags=["User Management"],
)

INVITATION_EXPIRY_DAYS = 7


# --- Users ---


@router.get("", response_model=list[TenantUserResponse])
def list_tenant_users(
    tenant_id: int,
    membership: TenantMembership = Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
):
    """List all users in a tenant with their roles"""
    memberships = (
        db.query(TenantMembership)
        .filter(TenantMembership.tenant_id == tenant_id)
        .all()
    )

    results = []
    for m in memberships:
        user = m.user
        results.append(
            TenantUserResponse(
                id=user.id,
                email=user.email,
                username=user.username,
                full_name=user.full_name,
                role=m.role,
                is_active=user.is_active,
                membership_active=m.is_active,
                last_login=user.last_login,
                created_at=user.created_at,
            )
        )

    return results


@router.post("", response_model=TenantUserResponse, status_code=status.HTTP_201_CREATED)
def create_tenant_user(
    tenant_id: int,
    payload: TenantUserCreate,
    membership: TenantMembership = Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
):
    """Create a new user and add them to this tenant"""
    # Check email uniqueness
    if db.query(User).filter(User.email == payload.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered",
        )

    # Check username uniqueness
    if db.query(User).filter(User.username == payload.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken",
        )

    user = User(
        email=payload.email,
        username=payload.username,
        hashed_password=User.hash_password(payload.password),
        full_name=payload.full_name,
    )
    db.add(user)
    db.flush()

    tm = TenantMembership(
        user_id=user.id,
        tenant_id=tenant_id,
        role=payload.role,
    )
    db.add(tm)
    db.commit()

    logger.info("Created user %s in tenant %d with role %s", user.email, tenant_id, payload.role)

    log_data_modification(
        action="create",
        resource="user",
        resource_id=str(user.id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={"email": user.email, "role": payload.role},
    )

    return TenantUserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=tm.role,
        is_active=user.is_active,
        membership_active=tm.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
    )


@router.patch("/{user_id}", response_model=TenantUserResponse)
def update_tenant_user(
    tenant_id: int,
    user_id: int,
    payload: TenantUserUpdate,
    membership: TenantMembership = Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
):
    """Update a user's role or deactivate their membership"""
    tm = (
        db.query(TenantMembership)
        .filter(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.user_id == user_id,
        )
        .first()
    )

    if not tm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in this tenant",
        )

    # Cannot demote/deactivate an owner
    if tm.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify the tenant owner",
        )

    if payload.role is not None:
        tm.role = payload.role

    if payload.is_active is not None:
        tm.is_active = payload.is_active

    db.commit()

    user = tm.user
    logger.info("Updated user %s in tenant %d: role=%s, active=%s", user.email, tenant_id, tm.role, tm.is_active)

    log_data_modification(
        action="update",
        resource="user",
        resource_id=str(user_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
        details={"role": tm.role, "is_active": tm.is_active},
    )

    return TenantUserResponse(
        id=user.id,
        email=user.email,
        username=user.username,
        full_name=user.full_name,
        role=tm.role,
        is_active=user.is_active,
        membership_active=tm.is_active,
        last_login=user.last_login,
        created_at=user.created_at,
    )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_tenant_user(
    tenant_id: int,
    user_id: int,
    membership: TenantMembership = Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
):
    """Remove a user's membership from this tenant (soft-delete)"""
    tm = (
        db.query(TenantMembership)
        .filter(
            TenantMembership.tenant_id == tenant_id,
            TenantMembership.user_id == user_id,
        )
        .first()
    )

    if not tm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found in this tenant",
        )

    if tm.role == "owner":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot remove the tenant owner",
        )

    tm.is_active = False
    db.commit()

    logger.info("Deactivated membership for user %d in tenant %d", user_id, tenant_id)

    log_data_modification(
        action="delete",
        resource="user",
        resource_id=str(user_id),
        user_id=membership.user_id,
        tenant_id=tenant_id,
    )


# --- Invitations ---


invitations_router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/invitations",
    tags=["User Management"],
)


@invitations_router.get("", response_model=list[InvitationResponse])
def list_invitations(
    tenant_id: int,
    membership: TenantMembership = Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
):
    """List pending invitations for this tenant"""
    invitations = (
        db.query(UserInvitation)
        .filter(
            UserInvitation.tenant_id == tenant_id,
            UserInvitation.accepted_at.is_(None),
        )
        .order_by(UserInvitation.created_at.desc())
        .all()
    )

    results = []
    for inv in invitations:
        inviter = db.query(User).filter(User.id == inv.invited_by).first()
        results.append(
            InvitationResponse(
                id=inv.id,
                email=inv.email,
                tenant_id=inv.tenant_id,
                role=inv.role,
                invited_by=inv.invited_by,
                inviter_name=inviter.full_name or inviter.email if inviter else None,
                accepted_at=inv.accepted_at,
                expires_at=inv.expires_at,
                created_at=inv.created_at,
            )
        )

    return results


@invitations_router.post("", response_model=InvitationResponse, status_code=status.HTTP_201_CREATED)
def create_invitation(
    tenant_id: int,
    payload: InvitationCreate,
    membership: TenantMembership = Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
):
    """Invite a user to join this tenant by email"""
    # Check for existing pending invitation
    existing = (
        db.query(UserInvitation)
        .filter(
            UserInvitation.tenant_id == tenant_id,
            UserInvitation.email == payload.email,
            UserInvitation.accepted_at.is_(None),
        )
        .first()
    )

    if existing and not existing.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An active invitation already exists for this email",
        )

    # Check if user already has membership
    existing_user = db.query(User).filter(User.email == payload.email).first()
    if existing_user:
        existing_membership = (
            db.query(TenantMembership)
            .filter(
                TenantMembership.tenant_id == tenant_id,
                TenantMembership.user_id == existing_user.id,
                TenantMembership.is_active.is_(True),
            )
            .first()
        )
        if existing_membership:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User is already a member of this tenant",
            )

    invitation = UserInvitation(
        email=payload.email,
        tenant_id=tenant_id,
        role=payload.role,
        token=secrets.token_urlsafe(32),
        invited_by=membership.user_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=INVITATION_EXPIRY_DAYS),
    )
    db.add(invitation)
    db.commit()
    db.refresh(invitation)

    # Send invitation email (best-effort)
    try:
        from app.services.email_service import send_invitation_email

        inviter = db.query(User).filter(User.id == membership.user_id).first()
        tenant = invitation.tenant
        send_invitation_email(
            email=payload.email,
            token=invitation.token,
            tenant_name=tenant.name if tenant else "EASM Platform",
            inviter_name=inviter.full_name or inviter.email if inviter else "Admin",
        )
    except Exception:
        logger.exception("Failed to send invitation email to %s", payload.email)

    inviter = db.query(User).filter(User.id == invitation.invited_by).first()

    logger.info("Created invitation for %s to tenant %d", payload.email, tenant_id)

    log_audit_event(
        event_type=AuditEventType.USER_CREATE,
        action=f"Invitation sent to {payload.email}",
        result="success",
        user_id=membership.user_id,
        tenant_id=tenant_id,
        resource="invitation",
        resource_id=str(invitation.id),
        details={"email": payload.email, "role": payload.role},
    )

    return InvitationResponse(
        id=invitation.id,
        email=invitation.email,
        tenant_id=invitation.tenant_id,
        role=invitation.role,
        invited_by=invitation.invited_by,
        inviter_name=inviter.full_name or inviter.email if inviter else None,
        accepted_at=invitation.accepted_at,
        expires_at=invitation.expires_at,
        created_at=invitation.created_at,
    )


@invitations_router.delete("/{invitation_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_invitation(
    tenant_id: int,
    invitation_id: int,
    membership: TenantMembership = Depends(require_tenant_permission("admin")),
    db: Session = Depends(get_db),
):
    """Revoke a pending invitation"""
    invitation = (
        db.query(UserInvitation)
        .filter(
            UserInvitation.id == invitation_id,
            UserInvitation.tenant_id == tenant_id,
        )
        .first()
    )

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Invitation not found",
        )

    db.delete(invitation)
    db.commit()

    logger.info("Revoked invitation %d for tenant %d", invitation_id, tenant_id)

    log_audit_event(
        event_type=AuditEventType.USER_DELETE,
        action=f"Invitation revoked: {invitation.email}",
        result="success",
        user_id=membership.user_id,
        tenant_id=tenant_id,
        resource="invitation",
        resource_id=str(invitation_id),
    )
