"""
Authentication Schemas

Pydantic models for authentication and authorization
"""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, Field, EmailStr, ConfigDict, field_validator
from datetime import datetime

from app.utils.security import validate_password_strength


class LoginRequest(BaseModel):
    """Login request"""

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123"
            }
        }
    )


class LoginResponse(BaseModel):
    """Login response with tokens"""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")
    user: "UserResponse" = Field(..., description="User information")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800,
                "user": {
                    "id": 1,
                    "email": "user@example.com",
                    "username": "user",
                    "full_name": "John Doe"
                }
            }
        }
    )


class RefreshTokenRequest(BaseModel):
    """Refresh token request"""

    refresh_token: str = Field(..., description="JWT refresh token")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            }
        }
    )


class RefreshTokenResponse(BaseModel):
    """Refresh token response"""

    access_token: str = Field(..., description="New JWT access token")
    refresh_token: str = Field(..., description="New JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration time in seconds")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
                "expires_in": 1800
            }
        }
    )


class TokenPayload(BaseModel):
    """JWT token payload"""

    sub: str = Field(..., description="Subject (user ID)")
    tenant_id: int = Field(..., description="Tenant ID")
    roles: List[str] = Field(..., description="User roles")
    exp: datetime = Field(..., description="Expiration time")
    iat: datetime = Field(..., description="Issued at time")
    type: str = Field(..., description="Token type (access/refresh)")


class UserResponse(BaseModel):
    """User response"""

    id: int = Field(..., description="User ID")
    email: EmailStr = Field(..., description="Email address")
    username: str = Field(..., description="Username")
    full_name: Optional[str] = Field(None, description="Full name")
    is_active: bool = Field(..., description="Active status")
    is_superuser: bool = Field(..., description="Superuser status")
    mfa_enabled: bool = Field(default=False, description="MFA enabled")
    tenant_roles: dict[int, str] = Field(default_factory=dict, description="Role per tenant")
    created_at: datetime = Field(..., description="Account creation date")
    last_login: Optional[datetime] = Field(None, description="Last login date")

    model_config = ConfigDict(from_attributes=True)


class UserCreate(BaseModel):
    """Create user request"""

    email: EmailStr = Field(..., description="Email address")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=8, description="Password")
    full_name: Optional[str] = Field(None, description="Full name")
    is_superuser: bool = Field(default=False, description="Superuser status")

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "newuser@example.com",
                "username": "newuser",
                "password": "SecurePassword123",
                "full_name": "John Doe",
                "is_superuser": False
            }
        }
    )


class UserUpdate(BaseModel):
    """Update user request"""

    email: Optional[EmailStr] = Field(None, description="Email address")
    full_name: Optional[str] = Field(None, description="Full name")
    is_active: Optional[bool] = Field(None, description="Active status")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "email": "updated@example.com",
                "full_name": "John Updated Doe",
                "is_active": True
            }
        }
    )


class ChangePasswordRequest(BaseModel):
    """Change password request"""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=8, description="New password")

    @field_validator("new_password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "current_password": "OldPassword123",
                "new_password": "NewSecurePassword456"
            }
        }
    )


class ForgotPasswordRequest(BaseModel):
    """Request password reset"""

    email: EmailStr = Field(..., description="Email address")


class ResetPasswordRequest(BaseModel):
    """Reset password with token"""

    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=8, description="New password")

    @field_validator("new_password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v


class InviteAcceptRequest(BaseModel):
    """Accept an invitation"""

    token: str = Field(..., description="Invitation token")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    password: str = Field(..., min_length=8, description="Password")
    full_name: Optional[str] = Field(None, description="Full name")

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str) -> str:
        is_valid, error = validate_password_strength(v)
        if not is_valid:
            raise ValueError(error)
        return v


class MfaSetupResponse(BaseModel):
    """MFA setup response with provisioning URI"""

    secret: str = Field(..., description="TOTP secret")
    provisioning_uri: str = Field(..., description="URI for QR code")
    qr_code_base64: Optional[str] = Field(None, description="Base64-encoded QR code image")


class MfaVerifyRequest(BaseModel):
    """Verify MFA code"""

    code: str = Field(..., min_length=6, max_length=6, description="TOTP code")


class MfaLoginRequest(BaseModel):
    """Second step of MFA login"""

    mfa_token: str = Field(..., description="Temporary MFA token from first login step")
    code: str = Field(..., min_length=6, max_length=6, description="TOTP code")


class MfaDisableRequest(BaseModel):
    """Disable MFA"""

    password: str = Field(..., description="Current password for confirmation")


# Rebuild models to resolve forward references
LoginResponse.model_rebuild()
RefreshTokenResponse.model_rebuild()
