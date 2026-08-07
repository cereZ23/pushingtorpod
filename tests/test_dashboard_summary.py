"""Pure builder for the UI-3 operational dashboard aggregate (U3-1): day clamping, scan-outcome
buckets (reusing operational_summary), block invariants, tier schema. No DB.
"""

from __future__ import annotations

from datetime import datetime, timezone

from app.services.dashboard_summary import (
    build_dashboard_summary,
    build_endpoints_block,
    build_scans_block,
    clamp_days,
    scan_outcome_bucket,
)

NOW = datetime(2026, 8, 7, 12, 0, 0, tzinfo=timezone.utc)


def _snap(state):
    return {
        "schema_version": 1,
        "enabled": True,
        "state": state,
        "limitation": None,
        "limitations": [],
        "selected": 1,
        "covered": 1,
        "partial": 0,
        "failed": 0,
        "skipped": 0,
    }


# --- clamp ---


def test_clamp_days():
    assert clamp_days(30) == 30
    assert clamp_days(0) == 1
    assert clamp_days(-5) == 1
    assert clamp_days(9999) == 365
    assert clamp_days("x") == 30
    assert clamp_days(True) == 30  # bool rejected → default


# --- scan outcome buckets ---


def test_scan_outcome_failed_stays_failed():
    # even a clean snapshot cannot rescue a failed scan
    assert scan_outcome_bucket("failed", _snap("complete")) == "failed"


def test_scan_outcome_cancelled():
    assert scan_outcome_bucket("cancelled", None) == "cancelled"


def test_scan_outcome_pending_running_excluded():
    assert scan_outcome_bucket("pending", None) is None
    assert scan_outcome_bucket("running", None) is None


def test_scan_outcome_completed_states():
    assert scan_outcome_bucket("completed", _snap("complete")) == "completed"
    assert scan_outcome_bucket("completed", _snap("no_targets")) == "completed"
    assert scan_outcome_bucket("completed", _snap("disabled")) == "completed"
    assert scan_outcome_bucket("completed", _snap("limited")) == "completed_with_limitations"
    assert scan_outcome_bucket("completed", _snap("incomplete")) == "completed_with_limitations"
    assert scan_outcome_bucket("completed", _snap("failed")) == "completed_with_limitations"


def test_scan_outcome_legacy_or_malformed_never_invents_limitation():
    assert scan_outcome_bucket("completed", None) == "completed"  # legacy
    assert scan_outcome_bucket("completed", {}) == "completed"  # malformed
    assert scan_outcome_bucket("completed", {"schema_version": 999, "state": "complete"}) == "completed"
    assert scan_outcome_bucket("completed", {"state": "garbage", "schema_version": 1}) == "completed"


# --- blocks ---


def test_scans_block_total_excludes_cancelled():
    b = build_scans_block(["completed", "completed_with_limitations", "failed", "cancelled", None])
    assert b == {"total": 3, "completed": 1, "completed_with_limitations": 1, "failed": 1, "cancelled": 1}
    assert b["total"] == b["completed"] + b["completed_with_limitations"] + b["failed"]


def test_endpoints_block_reconciles_and_percent():
    b = build_endpoints_block({"covered": 96, "partial": 4})
    assert (b["selected"], b["verified"], b["not_verifiable"]) == (100, 96, 4)
    assert b["selected"] == b["verified"] + b["not_verifiable"] + b["failed"] + b["skipped"]
    assert b["coverage_percent"] == 96.0


def test_endpoints_block_empty_percent_null():
    b = build_endpoints_block({})
    assert b["selected"] == 0
    assert b["coverage_percent"] is None  # never 100 for an empty set


# --- full assembly + invariants ---


def _build(**kw):
    base = dict(
        now=NOW,
        days=30,
        scans_total_outcomes=["completed", "completed_with_limitations", "failed"],
        endpoints_total_ledger={"covered": 96, "partial": 4},
        findings_total={"auto_closed": 2, "reopened": 1, "awaiting_confirmation": 3},
        per_tier={
            1: {"outcomes": ["completed"], "ledger": {"covered": 50}, "findings": {"auto_closed": 1}},
            2: {"outcomes": ["failed"], "ledger": {"covered": 46, "partial": 4}, "findings": {"reopened": 1}},
        },
    )
    base.update(kw)
    return build_dashboard_summary(**base)


def test_full_summary_shape_and_window():
    s = _build()
    assert s["schema_version"] == 1
    assert s["period_days"] == 30
    assert s["to"] == "2026-08-07T12:00:00Z"
    assert s["from"] == "2026-07-08T12:00:00Z"
    assert set(s["by_tier"].keys()) == {"1", "2"}
    # tier blocks share the totals' schema
    for t in ("1", "2"):
        assert set(s["by_tier"][t].keys()) == {"scans", "endpoints", "findings"}
        assert set(s["by_tier"][t]["scans"].keys()) == set(s["scans"].keys())
        assert set(s["by_tier"][t]["endpoints"].keys()) == set(s["endpoints"].keys())
        assert set(s["by_tier"][t]["findings"].keys()) == set(s["findings"].keys())


def test_full_summary_invariants():
    s = _build()
    sc = s["scans"]
    assert sc["total"] == sc["completed"] + sc["completed_with_limitations"] + sc["failed"]
    ep = s["endpoints"]
    assert ep["selected"] == ep["verified"] + ep["not_verifiable"] + ep["failed"] + ep["skipped"]
    assert ep["coverage_percent"] == 96.0


def test_empty_period_is_all_zero():
    s = _build(scans_total_outcomes=[], endpoints_total_ledger={}, findings_total={}, per_tier={})
    assert s["scans"]["total"] == 0
    assert s["endpoints"]["coverage_percent"] is None
    assert s["findings"] == {"auto_closed": 0, "reopened": 0, "awaiting_confirmation": 0}
    # tiers still present with zeros
    assert s["by_tier"]["1"]["scans"]["total"] == 0
    assert s["by_tier"]["2"]["endpoints"]["coverage_percent"] is None


def test_clamp_applied_in_full_build():
    s = _build(days=9999)
    assert s["period_days"] == 365


def test_no_sensitive_data():
    import json
    import re

    s = _build()
    blob = json.dumps(s)
    assert "://" not in blob
    assert not re.search(r"[a-f0-9]{32,}", blob)
    for bad in ("policy_hash", "shape_hash", "url", "hostname", "name"):
        assert bad not in blob
