"""Typed response schema for the UI-1 operational_summary (PR 1b).

A CLOSED, OpenAPI-visible contract so the frontend can generate types, enums are validated on the way
out, and any accidental extra/sensitive key is rejected (``extra="forbid"``). The Literals below MUST
stay in sync with the service constants — ``tests/test_scan_summary_schema.py`` asserts that.
"""

from __future__ import annotations

from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict

# Endpoint verification operational state (None only for a legacy clean run).
EndpointState = Literal[
    "disabled",
    "no_targets",
    "complete",
    "limited",
    "incomplete",
    "failed",
]

# Closed set of limitation reason codes (the full VALID_LIMITATIONS vocabulary).
EndpointLimitation = Literal[
    "configuration_error",
    "execution_error",
    "writer_error",
    "catalog_drift",
    "parser_incomplete",
    "timeout",
    "output_truncated",
    "insufficient_budget",
    "unresponsive_origins",
    "unknown",
    "feature_disabled",
    "no_targets",
    "data_inconsistent",
]

ScanOutcome = Literal[
    "pending",
    "running",
    "completed",
    "completed_with_limitations",
    "failed",
    "cancelled",
    "unknown",
]


class EndpointVerificationSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    available: bool
    enabled: bool
    state: Optional[EndpointState]
    limitation: Optional[EndpointLimitation]
    limitations: list[EndpointLimitation]
    selected: int
    covered: int
    not_verifiable: int
    failed: int
    skipped: int
    unstarted: int
    coverage_percent: Optional[int]
    data_inconsistent: bool


class AutoCloseSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    detected: int
    eligible_miss: int
    would_close: int
    closed: int
    reopened: int


class OperationalSummaryResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int
    outcome: ScanOutcome
    tier: Optional[int]
    trigger_type: Optional[str]
    trigger_label: Optional[str]
    endpoint_verification: EndpointVerificationSummaryResponse
    auto_close: AutoCloseSummaryResponse
