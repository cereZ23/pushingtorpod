"""
Ticket integration Pydantic schemas.

Request/response models for the ticketing API endpoints.
"""

from __future__ import annotations

from typing import Optional, Any
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


# ------------------------------------------------------------------
# Ticketing Config schemas
# ------------------------------------------------------------------

class TicketingConfigCreate(BaseModel):
    """Request body to create/update a ticketing integration config."""

    provider: str = Field(
        ...,
        description="Ticketing provider: 'jira' or 'servicenow'",
        pattern="^(jira|servicenow)$",
    )
    config: dict = Field(
        ...,
        description=(
            "Provider-specific configuration. "
            "Jira: {url, email, api_token, project_key, issue_type}. "
            "ServiceNow: {instance, username, password, table}."
        ),
    )
    auto_create_on_triage: bool = Field(
        default=False,
        description="Automatically create a ticket when a finding is triaged.",
    )
    sync_status_back: bool = Field(
        default=True,
        description="Sync ticket status changes back to EASM findings.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "provider": "jira",
                "config": {
                    "url": "https://company.atlassian.net",
                    "email": "security@company.com",
                    "api_token": "ATATT3xFf...",
                    "project_key": "EASM",
                    "issue_type": "Bug",
                },
                "auto_create_on_triage": False,
                "sync_status_back": True,
            }
        }
    )


class TicketingConfigResponse(BaseModel):
    """Response body for ticketing integration config (credentials masked)."""

    id: int = Field(..., description="Config ID")
    tenant_id: int = Field(..., description="Tenant ID")
    provider: str = Field(..., description="Provider type")
    config_masked: dict = Field(..., description="Config with sensitive fields masked")
    is_active: bool = Field(..., description="Whether the config is active")
    auto_create_on_triage: bool = Field(...)
    sync_status_back: bool = Field(...)
    created_at: datetime = Field(...)
    updated_at: Optional[datetime] = Field(None)

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "tenant_id": 1,
                "provider": "jira",
                "config_masked": {
                    "url": "https://company.atlassian.net",
                    "email": "security@company.com",
                    "api_token": "AT**...Ff",
                    "project_key": "EASM",
                    "issue_type": "Bug",
                },
                "is_active": True,
                "auto_create_on_triage": False,
                "sync_status_back": True,
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T10:00:00Z",
            }
        },
    )


class TicketingTestResult(BaseModel):
    """Result of a ticketing connection test."""

    success: bool = Field(..., description="Whether the connection test passed")
    message: str = Field(..., description="Human-readable result message")
    provider: str = Field(..., description="Provider that was tested")


# ------------------------------------------------------------------
# Ticket schemas
# ------------------------------------------------------------------

class TicketCreateRequest(BaseModel):
    """Request body to create a ticket for a finding."""

    provider: Optional[str] = Field(
        None,
        description="Override provider (defaults to tenant's active config).",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"provider": "jira"}
        }
    )


class TicketResponse(BaseModel):
    """Response body for a ticket record."""

    id: int = Field(..., description="Internal ticket ID")
    tenant_id: int = Field(...)
    finding_id: int = Field(...)
    provider: str = Field(...)
    external_id: str = Field(..., description="External ticket key/number")
    external_url: Optional[str] = Field(None, description="Link to the external ticket")
    external_status: Optional[str] = Field(None, description="Current status in external system")
    sync_status: str = Field(..., description="Sync state: synced, pending, error, conflict")
    sync_error: Optional[str] = Field(None, description="Last sync error if any")
    last_synced_at: Optional[datetime] = Field(None)
    created_at: datetime = Field(...)
    updated_at: Optional[datetime] = Field(None)

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 42,
                "tenant_id": 1,
                "finding_id": 99,
                "provider": "jira",
                "external_id": "EASM-123",
                "external_url": "https://company.atlassian.net/browse/EASM-123",
                "external_status": "To Do",
                "sync_status": "synced",
                "sync_error": None,
                "last_synced_at": "2024-01-15T12:00:00Z",
                "created_at": "2024-01-15T10:00:00Z",
                "updated_at": "2024-01-15T12:00:00Z",
            }
        },
    )


class TicketSyncResponse(BaseModel):
    """Response body for a sync operation."""

    status: str = Field(..., description="Overall sync status")
    synced: int = Field(default=0, description="Number of tickets synced")
    errors: int = Field(default=0, description="Number of sync errors")
    skipped: int = Field(default=0, description="Number skipped")
    message: Optional[str] = Field(None, description="Additional info")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "status": "completed",
                "synced": 12,
                "errors": 1,
                "skipped": 0,
                "message": None,
            }
        }
    )


class TicketSingleSyncResponse(BaseModel):
    """Response for a single ticket sync operation."""

    status: str = Field(..., description="Sync result: synced, partial, error")
    inbound: bool = Field(..., description="Whether inbound sync succeeded")
    outbound: bool = Field(..., description="Whether outbound sync succeeded")
    external_status: Optional[str] = Field(None)
    sync_status: str = Field(...)
