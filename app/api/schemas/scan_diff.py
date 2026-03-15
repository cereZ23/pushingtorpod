from __future__ import annotations

"""
Scan Diff Schemas

Pydantic response models for scan-to-scan comparison endpoint.
"""

from pydantic import BaseModel, Field
from datetime import datetime


class ScanRunSummary(BaseModel):
    id: int
    status: str
    completed_at: datetime | None = None


class DiffSummary(BaseModel):
    new_assets: int = 0
    removed_assets: int = 0
    new_services: int = 0
    removed_services: int = 0
    new_findings: int = 0
    resolved_findings: int = 0


class DiffAssetItem(BaseModel):
    identifier: str
    type: str


class DiffServiceItem(BaseModel):
    asset_identifier: str
    port: int
    protocol: str


class DiffFindingItem(BaseModel):
    id: int | None = None
    name: str | None = None
    severity: str | None = None
    asset_identifier: str | None = None



class DiffAssets(BaseModel):
    added: list[DiffAssetItem] = Field(default_factory=list)
    removed: list[DiffAssetItem] = Field(default_factory=list)


class DiffServices(BaseModel):
    added: list[DiffServiceItem] = Field(default_factory=list)
    removed: list[DiffServiceItem] = Field(default_factory=list)


class DiffFindings(BaseModel):
    added: list[DiffFindingItem] = Field(default_factory=list)
    resolved: list[DiffFindingItem] = Field(default_factory=list)


class ScanCompareResponse(BaseModel):
    base_run: ScanRunSummary
    compare_run: ScanRunSummary
    is_suspicious: bool = False
    summary: DiffSummary
    assets: DiffAssets = Field(default_factory=DiffAssets)
    services: DiffServices = Field(default_factory=DiffServices)
    findings: DiffFindings = Field(default_factory=DiffFindings)
