"""
SAML2 SSO authentication router.

Endpoints:
  GET  /api/v1/auth/saml/login    - SP-initiated login (redirect to IdP)
  POST /api/v1/auth/saml/acs      - Assertion Consumer Service callback
  GET  /api/v1/auth/saml/metadata - SP metadata XML for IdP registration
"""

from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.api.dependencies import get_db
from app.config import settings
from app.models.auth import TenantMembership, User
from app.security.jwt_auth import jwt_manager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth/saml", tags=["SAML SSO"])


def _require_saml_enabled() -> None:
    """Raise 404 if SAML SSO is not enabled."""
    if not settings.saml_enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="SAML SSO is not enabled",
        )


@router.get("/login")
def saml_login(request: Request):
    """
    Initiate SP-initiated SAML login.

    Builds an AuthnRequest and redirects the user to the IdP SSO URL.
    """
    _require_saml_enabled()

    from app.services.saml import get_saml_auth, prepare_saml_request

    req_data = prepare_saml_request(request)
    auth = get_saml_auth(request, req_data)
    redirect_url = auth.login()

    logger.info("SAML AuthnRequest initiated, redirecting to IdP")
    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/acs")
async def saml_acs(request: Request, db: Session = Depends(get_db)):
    """
    SAML Assertion Consumer Service.

    Receives the IdP SAML Response via HTTP-POST, validates it,
    provisions/updates the user, and redirects to the frontend with JWT tokens.
    """
    _require_saml_enabled()

    from app.services.saml import get_saml_auth, prepare_saml_request_with_post

    req_data = await prepare_saml_request_with_post(request)
    auth = get_saml_auth(request, req_data)
    auth.process_response()

    errors = auth.get_errors()
    if errors:
        reason = auth.get_last_error_reason() or ", ".join(errors)
        logger.error(f"SAML response validation failed: {reason}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SAML authentication failed",
        )

    if not auth.is_authenticated():
        logger.warning("SAML response processed but user is not authenticated")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SAML authentication failed",
        )

    # Extract user attributes from SAML assertion
    name_id = auth.get_nameid()
    attributes = auth.get_attributes()

    email = (
        _first(attributes.get("email"))
        or _first(attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"))
        or name_id
    )
    full_name = _first(attributes.get("displayName")) or _first(
        attributes.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
    )

    if not email:
        logger.error("SAML assertion missing email attribute and NameID")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SAML assertion does not contain an email",
        )

    logger.info(f"SAML authentication successful for {email}")

    # Find or create user
    user = db.query(User).filter(User.email == email).first()

    if user is None:
        if not settings.saml_auto_provision:
            logger.warning(f"SAML user {email} not found and auto-provision disabled")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User not provisioned. Contact your administrator.",
            )

        # Auto-provision user
        username = email.split("@")[0]
        # Ensure unique username
        base_username = username
        counter = 1
        while db.query(User).filter(User.username == username).first():
            username = f"{base_username}{counter}"
            counter += 1

        user = User(
            email=email,
            username=username,
            hashed_password=None,
            full_name=full_name,
            is_active=True,
            is_superuser=False,
            sso_provider="saml",
            sso_subject_id=name_id,
        )
        db.add(user)
        db.flush()

        # Create tenant membership
        membership = TenantMembership(
            user_id=user.id,
            tenant_id=settings.saml_default_tenant_id,
            role=settings.saml_default_role,
            is_active=True,
        )
        db.add(membership)
        logger.info(f"SAML auto-provisioned user {email} (tenant {settings.saml_default_tenant_id})")
    else:
        # Update SSO fields if not set
        if not user.sso_provider:
            user.sso_provider = "saml"
            user.sso_subject_id = name_id
        if full_name and not user.full_name:
            user.full_name = full_name

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive",
        )

    # Update last login
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    # Determine tenant and roles
    tenant_id = settings.saml_default_tenant_id
    tenant_role = settings.saml_default_role
    if user.tenant_memberships:
        tenant_id = user.tenant_memberships[0].tenant_id
        tenant_role = user.tenant_memberships[0].role

    roles = [tenant_role]
    if user.is_superuser:
        roles.append("admin")

    # Issue JWT tokens
    access_token = jwt_manager.create_access_token(
        subject=str(user.id),
        tenant_id=tenant_id,
        roles=roles,
    )
    refresh_token = jwt_manager.create_refresh_token(
        subject=str(user.id),
        tenant_id=tenant_id,
    )

    # Redirect to frontend with tokens in URL fragment (not query string)
    # Fragment is not sent to the server on subsequent requests
    fragment = urlencode(
        {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.jwt_access_token_expire_minutes * 60,
        }
    )
    redirect_url = f"{settings.saml_frontend_url}/auth/sso-callback#{fragment}"

    logger.info(f"SAML login complete for {email}, redirecting to frontend")
    return RedirectResponse(url=redirect_url, status_code=302)


@router.get("/metadata")
def saml_metadata(request: Request):
    """
    Return SP SAML metadata XML for IdP registration.
    """
    _require_saml_enabled()

    from app.services.saml import get_saml_auth, prepare_saml_request

    req_data = prepare_saml_request(request)
    auth = get_saml_auth(request, req_data)
    metadata = auth.get_settings().get_sp_metadata()
    errors = auth.get_settings().validate_sp_metadata(metadata)

    if errors:
        logger.error(f"SP metadata validation errors: {errors}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="SP metadata generation failed",
        )

    return Response(content=metadata, media_type="application/xml")


def _first(values: list | None) -> str | None:
    """Return first element of a list or None."""
    if values and len(values) > 0:
        return values[0]
    return None
