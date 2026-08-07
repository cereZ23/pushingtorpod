"""Typed response contract for the UI-3 operational dashboard aggregate (U3-1).

Closed + OpenAPI-visible + ``extra="forbid"`` so the frontend can generate types, and no accidental
or sensitive field can slip into the payload. All values are integers/floats + UTC ISO strings.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ScansBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int  # = completed + completed_with_limitations + failed (cancelled tracked separately)
    completed: int
    completed_with_limitations: int
    failed: int
    cancelled: int


class EndpointsBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    selected: int  # = verified + not_verifiable + failed + skipped
    verified: int
    not_verifiable: int
    failed: int
    skipped: int
    coverage_percent: Optional[float]  # null when selected == 0 (never 100)


class FindingsBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    auto_closed: int  # distinct findings auto-closed in the window
    reopened: int  # distinct findings reopened in the window
    awaiting_confirmation: int  # current open findings mid-streak (below the close threshold)


class TierBlock(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scans: ScansBlock
    endpoints: EndpointsBlock
    findings: FindingsBlock


class DashboardOperationalSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_version: int
    period_days: int
    window_from: str = Field(alias="from")  # UTC ISO
    window_to: str = Field(alias="to")  # UTC ISO
    scans: ScansBlock
    endpoints: EndpointsBlock
    findings: FindingsBlock
    by_tier: dict[str, TierBlock]  # always keys "1" and "2"
