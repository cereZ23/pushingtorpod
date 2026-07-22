"""Schemas for scan-authorization management."""

from __future__ import annotations

from datetime import datetime
from typing import List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field


class ScopeEntry(BaseModel):
    type: Literal["domain", "ip", "cidr"] = Field(..., description="Scope entry type")
    value: str = Field(..., min_length=1, max_length=253, description="Domain, IP, or CIDR")


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
