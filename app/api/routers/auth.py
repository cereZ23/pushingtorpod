"""
Authentication Router

Handles user authentication, token management, and user operations
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from datetime import datetime, timedelta, timezone
import hashlib
import logging

from app.api.dependencies import get_db, get_current_user, get_current_user_async, get_current_user_payload, require_admin
from app.api.schemas.auth import (
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RefreshTokenResponse,
    UserResponse,
    UserCreate,
    UserUpdate,
    ChangePasswordRequest,
    ForgotPasswordRequest,
    ResetPasswordRequest,
    InviteAcceptRequest,
    MfaSetupResponse,
    MfaVerifyRequest,
    MfaLoginRequest,
    MfaDisableRequest,
)
from app.models.auth import User, TenantMembership, UserInvitation
from app.security.jwt_auth import jwt_manager
from app.config import settings
from app.core.audit import (
    log_audit_event,
    log_authentication_attempt,
    log_data_modification,
    AuditEventType,
)
from app.utils.crypto import encrypt_mfa_secret, decrypt_mfa_secret

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])

from app.rate_limiter import limiter


def _get_client_ip(request: Request) -> str:
    """Extract client IP from request, respecting X-Forwarded-For."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _build_tokens_and_response(user: "User", db: Session) -> dict:
    """Build JWT tokens and LoginResponse data for an authenticated user.

    Raises HTTPException 403 if the user has no active tenant membership.
    """
    # Resolve tenant from memberships — never fall back to a hardcoded ID
    active_memberships = [m for m in user.tenant_memberships if m.is_active]
    if not active_memberships:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No active tenant membership. Contact your administrator.",
        )

    tenant_id = active_memberships[0].tenant_id
    tenant_role = active_memberships[0].role

    roles = [tenant_role]
    if user.is_superuser:
        roles.append("admin")

    access_token = jwt_manager.create_access_token(
        subject=str(user.id),
        tenant_id=tenant_id,
        roles=roles,
    )
    refresh_token = jwt_manager.create_refresh_token(
        subject=str(user.id),
        tenant_id=tenant_id,
    )

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    tenant_roles = {m.tenant_id: m.role for m in user.tenant_memberships if m.is_active}

    user_response = UserResponse.model_validate(user)
    user_response.tenant_roles = tenant_roles

    return LoginResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
        expires_in=settings.jwt_access_token_expire_minutes * 60,
        user=user_response,
    )


@router.post("/login", response_model=LoginResponse)
@limiter.limit("5/minute")
def login(
    request: Request,
    credentials: LoginRequest,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return JWT tokens

    Returns:
        - Access token (30 minutes)
        - Refresh token (7 days)
        - User information

    Raises:
        - 401: Invalid credentials
        - 403: Account inactive
    """
    client_ip = _get_client_ip(request)
    user_agent = request.headers.get("user-agent")

    # Find user by email
    user = db.query(User).filter(User.email == credentials.email).first()

    if not user:
        log_authentication_attempt(
            success=False, username=credentials.email,
            ip_address=client_ip, user_agent=user_agent,
            error_message="Non-existent email",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # SSO-only users cannot use password login
    if not user.hashed_password and user.sso_provider:
        log_authentication_attempt(
            success=False, username=credentials.email,
            ip_address=client_ip, user_agent=user_agent,
            error_message="SSO-only account attempted password login",
            user_id=user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This account uses SSO. Please sign in with your identity provider."
        )

    # Verify password
    if not user.hashed_password or not user.verify_password(credentials.password):
        log_authentication_attempt(
            success=False, username=credentials.email,
            ip_address=client_ip, user_agent=user_agent,
            error_message="Invalid password",
            user_id=user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )

    # Check if user is active
    if not user.is_active:
        log_authentication_attempt(
            success=False, username=credentials.email,
            ip_address=client_ip, user_agent=user_agent,
            error_message="Inactive account",
            user_id=user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive"
        )

    # Check if MFA is enabled - return challenge instead of tokens
    if user.mfa_enabled and user.mfa_secret:
        import secrets as _secrets

        mfa_token = _secrets.token_urlsafe(32)
        # Store MFA token in Redis with 5 min expiry
        try:
            import redis
            r = redis.from_url(settings.redis_url, socket_connect_timeout=2)
            r.setex(f"mfa_token:{mfa_token}", 300, str(user.id))
            r.close()
        except Exception:
            logger.exception("Failed to store MFA token in Redis")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="MFA service unavailable"
            )

        logger.info(f"MFA challenge issued for user {user.email}")
        return {"mfa_required": True, "mfa_token": mfa_token}

    # Build tokens — raises 403 if no active tenant membership
    response = _build_tokens_and_response(user, db)

    first_tenant = next(iter(response.user.tenant_roles), None) if response.user.tenant_roles else None
    log_authentication_attempt(
        success=True, username=user.email,
        ip_address=client_ip, user_agent=user_agent,
        user_id=user.id,
        tenant_id=first_tenant,
    )

    return response


@router.post("/refresh", response_model=RefreshTokenResponse)
@limiter.limit("10/minute")
def refresh_token(
    request: Request,
    payload: RefreshTokenRequest,
):
    """
    Refresh access token using refresh token

    Returns new access and refresh tokens (token rotation)

    Raises:
        - 401: Invalid or expired refresh token
    """
    try:
        result = jwt_manager.refresh_access_token(payload.refresh_token)

        logger.info("Token refreshed successfully")

        return RefreshTokenResponse(
            access_token=result['access_token'],
            refresh_token=result['refresh_token'],
            token_type=result['token_type'],
            expires_in=settings.jwt_access_token_expire_minutes * 60
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Token refresh error: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Failed to refresh token"
        )


@router.post("/logout")
def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    payload: Dict[str, Any] = Depends(get_current_user_payload),
):
    """
    Logout user (revoke current access token)

    Note: Client should also discard tokens locally

    Returns:
        - Success message
    """
    jti = payload.get("jti")
    token_type = payload.get("type", "access")

    token_revoked = False
    if jti:
        try:
            jwt_manager.revoke_token(jti, token_type)
            token_revoked = True
            logger.info(f"User {current_user.email} logged out, token {jti} revoked")
        except Exception as e:
            logger.error(f"Failed to revoke token on logout: {e}")
    else:
        logger.warning(f"User {current_user.email} logged out but token had no JTI")

    log_audit_event(
        event_type=AuditEventType.AUTH_LOGOUT,
        action=f"User logout: {current_user.email}",
        result="success",
        user_id=current_user.id,
        ip_address=_get_client_ip(request),
        resource="user",
        resource_id=str(current_user.id),
    )

    return {
        "success": True,
        "message": "Logged out successfully",
        "token_revoked": token_revoked,
    }


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user_async),
):
    """
    Get current user information

    Returns user profile based on JWT token with tenant roles.
    Uses async DB session — tenant_memberships are eagerly loaded.

    Raises:
        - 401: Invalid or expired token
    """
    tenant_roles = {}
    for m in current_user.tenant_memberships:
        if m.is_active:
            tenant_roles[m.tenant_id] = m.role

    response = UserResponse.model_validate(current_user)
    response.tenant_roles = tenant_roles
    return response


@router.patch("/me", response_model=UserResponse)
def update_current_user(
    updates: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update current user profile

    Allows users to update their own information

    Raises:
        - 401: Invalid or expired token
        - 400: Invalid update data
    """
    # Apply updates
    if updates.email is not None:
        # Check if email is already in use
        existing = db.query(User).filter(
            User.email == updates.email,
            User.id != current_user.id
        ).first()

        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already in use"
            )

        current_user.email = updates.email

    if updates.full_name is not None:
        current_user.full_name = updates.full_name

    if updates.is_active is not None:
        # Users can't deactivate themselves
        if not updates.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot deactivate your own account"
            )

    db.commit()
    db.refresh(current_user)

    logger.info(f"User {current_user.email} updated their profile")

    return UserResponse.model_validate(current_user)


@router.post("/change-password")
def change_password(
    http_request: Request,
    request: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change user password

    Requires current password for verification

    Raises:
        - 401: Invalid current password
        - 400: Invalid new password
    """
    client_ip = _get_client_ip(http_request)

    # Verify current password
    if not current_user.verify_password(request.current_password):
        log_audit_event(
            event_type=AuditEventType.AUTH_PASSWORD_CHANGE,
            action=f"Password change failed: {current_user.email}",
            result="failure",
            user_id=current_user.id,
            ip_address=client_ip,
            severity="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password is incorrect"
        )

    # Update password
    current_user.hashed_password = User.hash_password(request.new_password)
    db.commit()

    log_audit_event(
        event_type=AuditEventType.AUTH_PASSWORD_CHANGE,
        action=f"Password changed: {current_user.email}",
        result="success",
        user_id=current_user.id,
        ip_address=client_ip,
        resource="user",
        resource_id=str(current_user.id),
    )

    return {
        "success": True,
        "message": "Password changed successfully"
    }


@router.post("/forgot-password")
@limiter.limit("3/minute")
def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    Request password reset email.

    Always returns 200 to prevent email enumeration.
    """
    import secrets

    user = db.query(User).filter(User.email == payload.email).first()

    if user and user.hashed_password:
        token = secrets.token_urlsafe(32)
        # Store SHA-256 hash of token — never store plaintext reset tokens
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        user.password_reset_token = token_hash
        user.password_reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
        db.commit()

        try:
            from app.services.email_service import send_password_reset_email
            send_password_reset_email(user.email, token)  # send plaintext to user
        except Exception:
            logger.exception("Failed to send password reset email to %s", payload.email)
            # Clear the token so the user can retry
            user.password_reset_token = None
            user.password_reset_expires = None
            db.commit()

    log_audit_event(
        event_type=AuditEventType.AUTH_PASSWORD_RESET,
        action=f"Password reset requested: {payload.email}",
        result="success",
        ip_address=_get_client_ip(request),
        resource="user",
        severity="info",
    )

    return {"message": "If the email exists, a reset link has been sent."}


@router.post("/reset-password")
@limiter.limit("5/minute")
def reset_password(
    request: Request,
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
):
    """
    Reset password using a valid token.

    Raises:
        - 400: Invalid or expired token
    """
    # Hash the incoming token to compare against stored hash
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    user = db.query(User).filter(
        User.password_reset_token == token_hash,
    ).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    if not user.password_reset_expires or user.password_reset_expires.replace(
        tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    user.hashed_password = User.hash_password(payload.new_password)
    user.password_reset_token = None
    user.password_reset_expires = None
    db.commit()

    log_audit_event(
        event_type=AuditEventType.AUTH_PASSWORD_RESET,
        action=f"Password reset completed: {user.email}",
        result="success",
        user_id=user.id,
        ip_address=_get_client_ip(request),
        resource="user",
        resource_id=str(user.id),
    )

    return {"message": "Password has been reset successfully."}


@router.post("/accept-invite", response_model=UserResponse)
@limiter.limit("5/minute")
def accept_invite(
    request: Request,
    payload: InviteAcceptRequest,
    db: Session = Depends(get_db),
):
    """
    Accept a tenant invitation, creating the user if needed.

    Raises:
        - 400: Invalid, expired, or already-accepted invitation
    """
    token_hash = hashlib.sha256(payload.token.encode()).hexdigest()
    invitation = db.query(UserInvitation).filter(
        UserInvitation.token == token_hash,
    ).first()

    if not invitation:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid invitation token",
        )

    if invitation.is_accepted:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation has already been accepted",
        )

    if invitation.is_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invitation has expired",
        )

    # Find or create user
    user = db.query(User).filter(User.email == invitation.email).first()

    if not user:
        # Check username uniqueness
        if db.query(User).filter(User.username == payload.username).first():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Username already taken",
            )

        user = User(
            email=invitation.email,
            username=payload.username,
            hashed_password=User.hash_password(payload.password),
            full_name=payload.full_name,
        )
        db.add(user)
        db.flush()

    # Create or reactivate membership
    existing_membership = db.query(TenantMembership).filter(
        TenantMembership.user_id == user.id,
        TenantMembership.tenant_id == invitation.tenant_id,
    ).first()

    if existing_membership:
        existing_membership.is_active = True
        existing_membership.role = invitation.role
    else:
        membership = TenantMembership(
            user_id=user.id,
            tenant_id=invitation.tenant_id,
            role=invitation.role,
        )
        db.add(membership)

    invitation.accepted_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    log_audit_event(
        event_type=AuditEventType.USER_CREATE,
        action=f"Invitation accepted: {user.email} joined tenant {invitation.tenant_id} as {invitation.role}",
        result="success",
        user_id=user.id,
        tenant_id=invitation.tenant_id,
        ip_address=_get_client_ip(request),
        resource="user",
        resource_id=str(user.id),
    )

    tenant_roles = {}
    for m in user.tenant_memberships:
        if m.is_active:
            tenant_roles[m.tenant_id] = m.role

    response = UserResponse.model_validate(user)
    response.tenant_roles = tenant_roles
    return response


# MFA endpoints
@router.post("/mfa/setup", response_model=MfaSetupResponse)
def mfa_setup(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Generate MFA secret and provisioning URI for TOTP setup.

    Returns secret, provisioning URI, and QR code image.
    """
    import pyotp
    import base64
    import io

    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    secret = pyotp.random_base32()
    current_user.mfa_secret = encrypt_mfa_secret(secret)
    db.commit()

    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=current_user.email,
        issuer_name="EASM Platform",
    )

    # Generate QR code
    qr_base64 = None
    try:
        import qrcode

        qr = qrcode.make(provisioning_uri)
        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")
        qr_base64 = base64.b64encode(buffer.getvalue()).decode()
    except ImportError:
        logger.warning("qrcode package not available for MFA QR generation")

    return MfaSetupResponse(
        secret=secret,
        provisioning_uri=provisioning_uri,
        qr_code_base64=qr_base64,
    )


@router.post("/mfa/verify-setup")
def mfa_verify_setup(
    payload: MfaVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Verify TOTP code and enable MFA."""
    import pyotp

    if not current_user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Run MFA setup first",
        )

    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is already enabled",
        )

    totp = pyotp.TOTP(decrypt_mfa_secret(current_user.mfa_secret))
    if not totp.verify(payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code",
        )

    current_user.mfa_enabled = True
    db.commit()

    log_audit_event(
        event_type=AuditEventType.CONFIG_CHANGE,
        action=f"MFA enabled: {current_user.email}",
        result="success",
        user_id=current_user.id,
        resource="user",
        resource_id=str(current_user.id),
    )
    return {"message": "MFA enabled successfully"}


@router.post("/mfa/disable")
def mfa_disable(
    payload: MfaDisableRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Disable MFA (requires password confirmation)."""
    if not current_user.mfa_enabled:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA is not enabled",
        )

    if not current_user.verify_password(payload.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password",
        )

    current_user.mfa_secret = None
    current_user.mfa_enabled = False
    db.commit()

    log_audit_event(
        event_type=AuditEventType.CONFIG_CHANGE,
        action=f"MFA disabled: {current_user.email}",
        result="success",
        user_id=current_user.id,
        resource="user",
        resource_id=str(current_user.id),
    )
    return {"message": "MFA disabled successfully"}


@router.post("/mfa/verify", response_model=LoginResponse)
@limiter.limit("5/minute")
def mfa_verify(
    request: Request,
    payload: MfaLoginRequest,
    db: Session = Depends(get_db),
):
    """
    Second step of MFA login: exchange MFA token + TOTP code for JWT tokens.
    """
    import pyotp
    import redis as _redis

    # Look up MFA token in Redis
    try:
        r = _redis.from_url(settings.redis_url, socket_connect_timeout=2)
        user_id_bytes = r.get(f"mfa_token:{payload.mfa_token}")
        if user_id_bytes:
            r.delete(f"mfa_token:{payload.mfa_token}")
        r.close()
    except Exception:
        logger.exception("Failed to validate MFA token from Redis")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="MFA service unavailable",
        )

    if not user_id_bytes:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired MFA token",
        )

    user_id = int(user_id_bytes.decode())
    user = db.query(User).filter(User.id == user_id).first()

    if not user or not user.mfa_secret:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid MFA session",
        )

    # Verify TOTP code — decrypt secret from DB
    totp = pyotp.TOTP(decrypt_mfa_secret(user.mfa_secret))
    if not totp.verify(payload.code):
        log_authentication_attempt(
            success=False, username=user.email,
            ip_address=_get_client_ip(request),
            error_message="Invalid MFA code",
            user_id=user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid verification code",
        )

    # Build tokens — raises 403 if no active tenant membership
    response = _build_tokens_and_response(user, db)

    log_authentication_attempt(
        success=True, username=user.email,
        ip_address=_get_client_ip(request),
        user_id=user.id,
    )

    return response


# Admin endpoints
@router.post("/users", response_model=UserResponse)
def create_user(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    Create new user (admin only)

    Raises:
        - 403: Not admin
        - 400: Email or username already exists
    """
    # Check if email exists
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )

    # Check if username exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already taken"
        )

    # Create user
    user = User(
        email=user_data.email,
        username=user_data.username,
        hashed_password=User.hash_password(user_data.password),
        full_name=user_data.full_name,
        is_superuser=user_data.is_superuser
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    log_audit_event(
        event_type=AuditEventType.USER_CREATE,
        action=f"Admin created user: {user.email}",
        result="success",
        user_id=admin.id,
        resource="user",
        resource_id=str(user.id),
        details={"created_email": user.email, "is_superuser": user.is_superuser},
    )

    return UserResponse.model_validate(user)


@router.get("/users", response_model=list[UserResponse])
def list_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    List all users (admin only)

    Raises:
        - 403: Not admin
    """
    users = db.query(User).offset(skip).limit(limit).all()

    return [UserResponse.model_validate(u) for u in users]


@router.get("/users/{user_id}", response_model=UserResponse)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """
    Get user by ID (admin only)

    Raises:
        - 403: Not admin
        - 404: User not found
    """
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return UserResponse.model_validate(user)
