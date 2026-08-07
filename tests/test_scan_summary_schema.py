"""The typed operational_summary response contract (UI-1 PR 1b, blocker 3): closed enums stay in sync
with the service vocabulary, extra keys are forbidden, and invalid enum values are rejected.
"""

from __future__ import annotations

import typing

import pytest
from pydantic import ValidationError

from app.api.schemas.scan_summary import (
    EndpointLimitation,
    EndpointState,
    EndpointVerificationSummaryResponse,
    OperationalSummaryResponse,
    ScanOutcome,
)
from app.services.endpoint_verification import VALID_LIMITATIONS, VALID_STATES
from app.services.operational_summary import VALID_OUTCOMES, build_operational_summary


def _literal_values(lit):
    return set(typing.get_args(lit))


def test_endpoint_state_literal_matches_service():
    assert _literal_values(EndpointState) == set(VALID_STATES)


def test_endpoint_limitation_literal_matches_service():
    assert _literal_values(EndpointLimitation) == set(VALID_LIMITATIONS)


def test_scan_outcome_literal_matches_service():
    assert _literal_values(ScanOutcome) == set(VALID_OUTCOMES)


def _valid_ev():
    return {
        "available": True,
        "enabled": True,
        "state": "limited",
        "limitation": "unresponsive_origins",
        "limitations": ["unresponsive_origins"],
        "selected": 3,
        "covered": 2,
        "not_verifiable": 1,
        "failed": 0,
        "skipped": 0,
        "unstarted": 0,
        "coverage_percent": 67,
        "data_inconsistent": False,
    }


def test_extra_field_is_rejected():
    payload = _valid_ev()
    payload["policy_hash"] = "abc"  # a sensitive extra key must NOT validate
    with pytest.raises(ValidationError):
        EndpointVerificationSummaryResponse(**payload)


def test_invalid_enum_is_rejected():
    payload = _valid_ev()
    payload["limitation"] = "not_a_reason"
    with pytest.raises(ValidationError):
        EndpointVerificationSummaryResponse(**payload)


def test_builder_output_validates_against_the_response_model():
    # the builder's real output round-trips through the closed typed model (no extra/missing keys).
    summary = build_operational_summary(
        scan_status="completed",
        scan_tier=1,
        trigger_type="manual",
        trigger_label=None,
        snapshot={
            "schema_version": 1,
            "enabled": True,
            "state": "limited",
            "limitation": "unresponsive_origins",
            "limitations": ["unresponsive_origins"],
            "selected": 3,
            "covered": 2,
            "partial": 1,
            "failed": 0,
            "skipped": 0,
        },
        ledger_counts={"covered": 2, "partial": 1},
        lifecycle_counts={},
    )
    model = OperationalSummaryResponse(**summary)
    assert model.outcome == "completed_with_limitations"
    assert model.endpoint_verification.state == "limited"
