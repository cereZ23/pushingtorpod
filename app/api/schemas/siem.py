"""
SIEM Export Schemas

Pydantic models for SIEM integration (Splunk HEC, CEF/Azure Sentinel).
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SIEMExportRequest(BaseModel):
    """Request body for exporting findings in a SIEM-compatible format."""

    format: str = Field(
        ...,
        pattern="^(splunk_hec|cef)$",
        description="Export format: splunk_hec or cef",
    )
    since: Optional[datetime] = Field(
        None,
        description="Export findings since this timestamp (ISO 8601)",
    )
    severity_min: Optional[str] = Field(
        None,
        pattern="^(info|low|medium|high|critical)$",
        description="Minimum severity threshold for exported findings",
    )


class SIEMExportResponse(BaseModel):
    """Response containing SIEM-formatted events."""

    format: str = Field(..., description="Format used for the export")
    event_count: int = Field(..., description="Number of events returned")
    events: list[dict] = Field(
        default_factory=list,
        description="List of SIEM-formatted events",
    )


class SIEMPushRequest(BaseModel):
    """Request body for pushing findings directly to a SIEM endpoint."""

    format: str = Field(
        ...,
        pattern="^(splunk_hec|cef)$",
        description="Export format: splunk_hec or cef",
    )
    since: Optional[datetime] = Field(
        None,
        description="Export findings since this timestamp (ISO 8601)",
    )
    severity_min: Optional[str] = Field(
        None,
        pattern="^(info|low|medium|high|critical)$",
        description="Minimum severity threshold for exported findings",
    )
    endpoint_url: str = Field(
        ...,
        description="SIEM collector endpoint URL (e.g. https://splunk:8088/services/collector)",
    )
    auth_token: str = Field(
        ...,
        description="Authentication token for the SIEM endpoint",
    )


class SIEMPushResponse(BaseModel):
    """Response from a SIEM push operation."""

    format: str = Field(..., description="Format used for the push")
    event_count: int = Field(..., description="Number of events pushed")
    success: bool = Field(..., description="Whether the push succeeded")
    detail: Optional[str] = Field(None, description="Additional detail or error message")
