"""
Exposure Management Schemas

Pydantic models for the exposure management API endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ExposedAssetItem(BaseModel):
    """An asset with its exposure details."""

    id: int = Field(..., description="Asset ID")
    identifier: str = Field(..., description="Asset identifier (domain, IP, URL, etc.)")
    type: str = Field(..., description="Asset type")
    risk_score: float = Field(..., description="Current risk score (0-100)")
    open_findings_count: int = Field(..., description="Number of open findings")
    highest_severity: Optional[str] = Field(None, description="Highest severity among open findings")
    services_count: int = Field(..., description="Number of exposed services")
    last_seen: Optional[datetime] = Field(None, description="Last time this asset was observed")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 42,
                "identifier": "api.example.com",
                "type": "subdomain",
                "risk_score": 75.0,
                "open_findings_count": 4,
                "highest_severity": "critical",
                "services_count": 3,
                "last_seen": "2026-02-25T10:00:00Z",
            }
        }
    )


class ExposureSummary(BaseModel):
    """Summary of the tenant's exposure posture."""

    total_exposed_assets: int = Field(..., description="Total assets with at least one open finding")
    total_assets: int = Field(..., description="Total assets for the tenant")
    severity_breakdown: Dict[str, int] = Field(..., description="Number of exposed assets by highest severity")
    exposure_score: float = Field(..., description="Overall exposure score (0-100)")
    most_exposed: list[ExposedAssetItem] = Field(..., description="Top 10 most exposed assets by risk score")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_exposed_assets": 35,
                "total_assets": 250,
                "severity_breakdown": {
                    "critical": 2,
                    "high": 8,
                    "medium": 15,
                    "low": 10,
                },
                "exposure_score": 62.5,
                "most_exposed": [],
            }
        }
    )


class ExposedAssetListResponse(BaseModel):
    """Paginated list of exposed assets."""

    items: list[ExposedAssetItem] = Field(..., description="List of exposed assets")
    total: int = Field(..., description="Total number of matching assets")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of items per page")
    total_pages: int = Field(..., description="Total number of pages")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "items": [],
                "total": 35,
                "page": 1,
                "page_size": 50,
                "total_pages": 1,
            }
        }
    )


class ExposureChangeItem(BaseModel):
    """A single exposure change event."""

    id: int = Field(..., description="Finding ID")
    asset_id: int = Field(..., description="Related asset ID")
    asset_identifier: str = Field(..., description="Related asset identifier")
    finding_name: str = Field(..., description="Finding name / title")
    severity: str = Field(..., description="Severity level")
    change_type: str = Field(..., description="Type of change: new, resolved, or severity_changed")
    detected_at: datetime = Field(..., description="When the change was detected")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 101,
                "asset_id": 42,
                "asset_identifier": "api.example.com",
                "finding_name": "Exposed Admin Panel",
                "severity": "critical",
                "change_type": "new",
                "detected_at": "2026-02-25T08:30:00Z",
            }
        }
    )


class ExposureChanges(BaseModel):
    """Exposure changes within a given time window."""

    period: str = Field(..., description="Time period label (24h, 7d, 30d)")
    new_exposures: list[ExposureChangeItem] = Field(..., description="Newly opened findings")
    resolved_exposures: list[ExposureChangeItem] = Field(..., description="Recently resolved (fixed) findings")
    new_count: int = Field(..., description="Count of new exposures")
    resolved_count: int = Field(..., description="Count of resolved exposures")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "period": "24h",
                "new_exposures": [],
                "resolved_exposures": [],
                "new_count": 3,
                "resolved_count": 1,
            }
        }
    )
