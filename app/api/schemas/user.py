"""
User Management Schemas

Pydantic models for tenant-scoped user management and invitations.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field, EmailStr, ConfigDict
from datetime import datetime


class TenantUserResponse(BaseModel):
    """User within a tenant context"""

    id: int
    email: EmailStr
    username: str
    full_name: Optional[str] = None
    role: str = Field(..., description="Role in this tenant")
    is_active: bool
    membership_active: bool = Field(..., description="Whether membership is active")
    last_login: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TenantUserCreate(BaseModel):
    """Create a user and add to tenant"""

    email: EmailStr
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    full_name: Optional[str] = None
    role: str = Field(default="analyst", pattern="^(viewer|analyst|admin)$")


class TenantUserUpdate(BaseModel):
    """Update a user's role or status within a tenant"""

    role: Optional[str] = Field(None, pattern="^(viewer|analyst|admin)$")
    is_active: Optional[bool] = None


class InvitationCreate(BaseModel):
    """Create an invitation"""

    email: EmailStr
    role: str = Field(default="analyst", pattern="^(viewer|analyst|admin)$")


class InvitationResponse(BaseModel):
    """Invitation details"""

    id: int
    email: EmailStr
    tenant_id: int
    role: str
    invited_by: int
    inviter_name: Optional[str] = None
    accepted_at: Optional[datetime] = None
    expires_at: datetime
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
