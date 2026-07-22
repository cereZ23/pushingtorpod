"""Schemas for scan-authorization management."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ScopeEntry(BaseModel):
    type: str = Field(..., description="Scope entry type: 'domain', 'ip', or 'cidr'")
    value: str = Field(..., min_length=1, max_length=253, description="Domain, IP, or CIDR")

    @field_validator("type")
    @classmethod
    def _valid_type(cls, v: str) -> str:
        if v not in ("domain", "ip", "cidr"):
            raise ValueError("type must be one of: domain, ip, cidr")
        return v


class ScanAuthorizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    scope_entries: List[ScopeEntry] = Field(..., min_length=1, description="At least one authorized scope entry")
    authorized_by: Optional[str] = Field(None, max_length=255)
    authorization_ref: Optional[str] = Field(None, max_length=500, description="Signed doc / ticket / engagement ref")
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None


class ScanAuthorizationResponse(BaseModel):
    id: int
    tenant_id: int
    name: str
    scope_entries: List[ScopeEntry]
    authorized_by: Optional[str] = None
    authorization_ref: Optional[str] = None
    authorized_at: Optional[datetime] = None
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime] = None
    is_active: bool
    created_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)
