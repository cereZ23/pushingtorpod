"""
Pydantic v2 schemas for the scheduled report delivery API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, ConfigDict, EmailStr, Field


class ReportScheduleCreate(BaseModel):
    """Request body for creating a new report schedule."""

    name: str = Field(..., min_length=1, max_length=255, description="Schedule name")
    report_type: str = Field(
        ...,
        pattern=r"^(executive|technical|soc2|iso27001)$",
        description="Report type: executive, technical, soc2, or iso27001",
    )
    format: str = Field(
        ...,
        pattern=r"^(pdf|docx)$",
        description="Output format: pdf or docx",
    )
    schedule: str = Field(
        ...,
        pattern=r"^(daily|weekly|monthly)$",
        description="Delivery cadence: daily, weekly, or monthly",
    )
    recipients: list[EmailStr] = Field(
        ...,
        min_length=1,
        description="Email addresses to deliver the report to",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Weekly Executive Report",
                "report_type": "executive",
                "format": "pdf",
                "schedule": "weekly",
                "recipients": ["ciso@example.com", "security-team@example.com"],
            }
        }
    )


class ReportScheduleUpdate(BaseModel):
    """Request body for partially updating a report schedule."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    schedule: Optional[str] = Field(None, pattern=r"^(daily|weekly|monthly)$")
    recipients: Optional[list[EmailStr]] = Field(None, min_length=1)
    is_active: Optional[bool] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "schedule": "monthly",
                "is_active": False,
            }
        }
    )


class ReportScheduleResponse(BaseModel):
    """Response model for a single report schedule."""

    id: int = Field(..., description="Schedule ID")
    tenant_id: int = Field(..., description="Tenant ID")
    name: str = Field(..., description="Schedule name")
    report_type: str = Field(..., description="Report type")
    format: str = Field(..., description="Output format")
    schedule: str = Field(..., description="Delivery cadence")
    recipients: list[str] = Field(..., description="Recipient email addresses")
    is_active: bool = Field(..., description="Whether the schedule is active")
    last_sent_at: Optional[datetime] = Field(None, description="Last delivery timestamp")
    created_at: datetime = Field(..., description="Creation timestamp")

    model_config = ConfigDict(from_attributes=True)
