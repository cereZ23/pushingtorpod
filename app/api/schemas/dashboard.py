"""
Dashboard Schemas

Pydantic models for dashboard KPI endpoints.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class DashboardSummary(BaseModel):
    """Main KPI summary returned by GET /summary."""

    total_assets: int = Field(..., description="Total number of assets for the tenant")
    active_assets: int = Field(..., description="Number of currently active assets")
    total_findings: int = Field(..., description="Total findings across all statuses")
    open_findings: int = Field(..., description="Findings currently in open status")
    findings_by_status: Dict[str, int] = Field(
        ..., description="Finding counts keyed by status (open, suppressed, fixed)"
    )
    severity_breakdown: Dict[str, int] = Field(
        ..., description="Open finding counts keyed by severity (critical, high, medium, low, info)"
    )
    total_issues: int = Field(..., description="Number of non-closed issues")
    risk_score: float = Field(..., description="Latest organization-level risk score (0-100)")
    risk_grade: str = Field(..., description="Letter grade derived from risk score")
    active_scans: int = Field(..., description="Number of currently running or pending scan runs")
    asset_type_breakdown: Dict[str, int] = Field(
        ..., description="Asset counts keyed by type (domain, subdomain, ip, url, service)"
    )
    new_assets_24h: int = Field(..., description="Assets first seen in the last 24 hours")
    new_findings_24h: int = Field(..., description="Findings first seen in the last 24 hours")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "total_assets": 1250,
                "active_assets": 1180,
                "total_findings": 235,
                "open_findings": 180,
                "findings_by_status": {"open": 180, "suppressed": 30, "fixed": 25},
                "severity_breakdown": {"critical": 2, "high": 8, "medium": 12, "low": 8, "info": 0},
                "total_issues": 42,
                "risk_score": 62.5,
                "risk_grade": "C",
                "active_scans": 1,
                "asset_type_breakdown": {"domain": 5, "subdomain": 80, "ip": 20, "url": 10, "service": 5},
                "new_assets_24h": 15,
                "new_findings_24h": 3,
            }
        }
    )


class SeverityBreakdown(BaseModel):
    """Open findings grouped by severity level."""

    critical: int = Field(default=0, description="Critical severity open findings")
    high: int = Field(default=0, description="High severity open findings")
    medium: int = Field(default=0, description="Medium severity open findings")
    low: int = Field(default=0, description="Low severity open findings")
    info: int = Field(default=0, description="Informational open findings")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "critical": 5,
                "high": 25,
                "medium": 80,
                "low": 55,
                "info": 15,
            }
        }
    )


class AssetTypeBreakdown(BaseModel):
    """Asset counts grouped by type."""

    domain: int = Field(default=0, description="Number of root domains")
    subdomain: int = Field(default=0, description="Number of subdomains")
    ip: int = Field(default=0, description="Number of IP addresses")
    url: int = Field(default=0, description="Number of URLs")
    service: int = Field(default=0, description="Number of services")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "domain": 50,
                "subdomain": 800,
                "ip": 300,
                "url": 75,
                "service": 25,
            }
        }
    )


class ScoreTrendPoint(BaseModel):
    """Single data point in the risk score history."""

    date: datetime = Field(..., description="Timestamp of the score snapshot")
    score: float = Field(..., description="Risk score at this point (0-100)")
    grade: str = Field(..., description="Letter grade at this point")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "date": "2026-02-20T08:00:00Z",
                "score": 58.3,
                "grade": "C",
            }
        }
    )


class RecentFindingItem(BaseModel):
    """Compact finding representation for the recent-findings list."""

    id: int = Field(..., description="Finding ID")
    name: str = Field(..., description="Finding name / title")
    severity: str = Field(..., description="Severity level")
    asset_identifier: str = Field(..., description="Identifier of the related asset")
    created_at: datetime = Field(..., description="Timestamp the finding was first seen")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 142,
                "name": "Missing HSTS Header",
                "severity": "medium",
                "asset_identifier": "api.example.com",
                "created_at": "2026-02-24T14:30:00Z",
            }
        }
    )


class RiskyAssetItem(BaseModel):
    """Asset entry for the top-risky-assets list."""

    id: int = Field(..., description="Asset ID")
    identifier: str = Field(..., description="Asset identifier (domain, IP, URL, etc.)")
    type: str = Field(..., description="Asset type")
    risk_score: float = Field(..., description="Current risk score (0-100)")
    finding_count: int = Field(..., description="Number of open findings for this asset")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 87,
                "identifier": "admin.example.com",
                "type": "subdomain",
                "risk_score": 92.0,
                "finding_count": 7,
            }
        }
    )


class ScoreTrendItem(BaseModel):
    """Single entry in the score trend response."""

    score: float = Field(..., description="Risk score at this snapshot (0-100)")
    grade: str = Field(..., description="Letter grade at this snapshot")
    scored_at: datetime = Field(..., description="Timestamp when the score was recorded")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "score": 65.5,
                "grade": "C",
                "scored_at": "2026-02-25T12:00:00Z",
            }
        }
    )


class ScoreTrendResponse(BaseModel):
    """Wrapper for the score trend endpoint."""

    scores: list[ScoreTrendItem] = Field(
        ..., description="Recent organization risk scores ordered by scored_at descending"
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "scores": [
                    {"score": 65.5, "grade": "C", "scored_at": "2026-02-25T12:00:00"},
                    {"score": 70.2, "grade": "D", "scored_at": "2026-02-24T12:00:00"},
                ]
            }
        }
    )


class HeatmapCell(BaseModel):
    """Single cell in the risk heatmap matrix."""

    severity: str = Field(..., description="Finding severity level")
    asset_type: str = Field(..., description="Asset type")
    count: int = Field(..., description="Number of open findings for this severity/asset_type combination")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "severity": "critical",
                "asset_type": "subdomain",
                "count": 3,
            }
        }
    )


class RiskHeatmapResponse(BaseModel):
    """Risk heatmap: open findings grouped by severity and asset type."""

    cells: list[HeatmapCell] = Field(..., description="Heatmap cells with finding counts per severity/asset_type pair")
    severities: list[str] = Field(..., description="Ordered list of severity levels (rows)")
    asset_types: list[str] = Field(..., description="Ordered list of asset types (columns)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cells": [
                    {"severity": "critical", "asset_type": "subdomain", "count": 3},
                    {"severity": "high", "asset_type": "domain", "count": 7},
                    {"severity": "medium", "asset_type": "ip", "count": 12},
                ],
                "severities": ["critical", "high", "medium", "low", "info"],
                "asset_types": ["domain", "subdomain", "ip", "url", "service"],
            }
        }
    )
