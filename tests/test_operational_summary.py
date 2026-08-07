"""Pure builder for the customer-facing operational_summary (UI-1 PR 1b): outcome mapping, count
reconciliation against the authoritative ledger, conservative handling of legacy + inconsistent data.
No DB.
"""

from __future__ import annotations

from app.services.operational_summary import (
    OUTCOME_CANCELLED,
    OUTCOME_COMPLETED,
    OUTCOME_COMPLETED_WITH_LIMITATIONS,
    OUTCOME_FAILED,
    OUTCOME_PENDING,
    OUTCOME_RUNNING,
    OUTCOME_UNKNOWN,
    build_operational_summary,
)


def _snap(state, limitation=None, limitations=None, selected=100, covered=100, partial=0, failed=0, skipped=0):
    return {
        "schema_version": 1,
        "enabled": True,
        "state": state,
        "limitation": limitation,
        "limitations": limitations if limitations is not None else ([] if limitation is None else [limitation]),
        "selected": selected,
        "covered": covered,
        "partial": partial,
        "failed": failed,
        "skipped": skipped,
    }


def _ledger(covered=100, partial=0, failed=0, skipped=0, unstarted=0):
    return {"covered": covered, "partial": partial, "failed": failed, "skipped": skipped, "unstarted": unstarted}


def _build(scan_status="completed", snapshot=None, ledger=None, lifecycle=None, tier=1):
    return build_operational_summary(
        scan_status=scan_status,
        scan_tier=tier,
        trigger_type="manual",
        trigger_label=None,
        snapshot=snapshot,
        ledger_counts=ledger if ledger is not None else {},
        lifecycle_counts=lifecycle or {},
    )


# --- outcome mapping (invariant table) ---


def test_outcome_pending_running_cancelled_failed():
    assert _build(scan_status="pending")["outcome"] == OUTCOME_PENDING
    assert _build(scan_status="running")["outcome"] == OUTCOME_RUNNING
    assert _build(scan_status="cancelled")["outcome"] == OUTCOME_CANCELLED
    assert _build(scan_status="failed")["outcome"] == OUTCOME_FAILED


def test_failed_scan_is_failed_regardless_of_endpoint_state():
    # even a clean endpoint pass cannot rescue a failed scan
    s = _build(scan_status="failed", snapshot=_snap("complete"), ledger=_ledger())
    assert s["outcome"] == OUTCOME_FAILED


def test_completed_all_covered_is_completed():
    s = _build(snapshot=_snap("complete"), ledger=_ledger(covered=100))
    assert s["outcome"] == OUTCOME_COMPLETED
    ev = s["endpoint_verification"]
    assert ev["state"] == "complete"
    assert ev["coverage_percent"] == 100
    assert ev["data_inconsistent"] is False


def test_completed_limited_is_cwl():
    s = _build(
        snapshot=_snap("limited", "unresponsive_origins", selected=100, covered=96, partial=4),
        ledger=_ledger(covered=96, partial=4),
    )
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS
    ev = s["endpoint_verification"]
    assert ev["state"] == "limited"
    assert ev["limitation"] == "unresponsive_origins"
    assert ev["not_verifiable"] == 4
    assert ev["coverage_percent"] == 96


def test_completed_incomplete_is_cwl():
    s = _build(
        snapshot=_snap("incomplete", "insufficient_budget", selected=100, covered=60, skipped=40),
        ledger=_ledger(covered=60, skipped=40),
    )
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS
    assert s["endpoint_verification"]["limitation"] == "insufficient_budget"


def test_completed_endpoint_failed_is_cwl():
    s = _build(
        snapshot=_snap("failed", "execution_error", selected=10, covered=0, failed=10),
        ledger=_ledger(covered=0, failed=10),
    )
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS
    assert s["endpoint_verification"]["state"] == "failed"


def test_feature_disabled_is_not_a_limitation():
    s = _build(snapshot=_snap("disabled", selected=0, covered=0), ledger={})
    assert s["outcome"] == OUTCOME_COMPLETED
    ev = s["endpoint_verification"]
    assert ev["state"] == "disabled"
    assert ev["enabled"] is True  # snapshot.enabled passthrough (disabled state may still be enabled=False in real)
    assert ev["coverage_percent"] is None  # selected 0 → None, never 100


def test_no_targets_is_completed_with_null_percent():
    s = _build(snapshot=_snap("no_targets", selected=0, covered=0), ledger={})
    assert s["outcome"] == OUTCOME_COMPLETED
    assert s["endpoint_verification"]["state"] == "no_targets"
    assert s["endpoint_verification"]["coverage_percent"] is None


# --- legacy + inconsistency (negative space) ---


def test_legacy_run_without_snapshot_clean_ledger():
    # no snapshot + empty/all-covered ledger → clean completed
    s = _build(scan_status="completed", snapshot=None, ledger={})
    assert s["outcome"] == OUTCOME_COMPLETED
    ev = s["endpoint_verification"]
    assert ev["available"] is False
    assert ev["state"] is None
    assert ev["limitation"] is None
    assert ev["data_inconsistent"] is False
    assert ev["coverage_percent"] is None


def test_legacy_run_only_covered_is_completed():
    s = _build(scan_status="completed", snapshot=None, ledger=_ledger(covered=5))
    assert s["outcome"] == OUTCOME_COMPLETED
    assert s["endpoint_verification"]["state"] is None


def test_legacy_run_with_partial_ledger_is_incomplete_unknown():
    # ledger proves some endpoints were NOT fully verified, but no historical reason → unknown, CWL.
    s = _build(scan_status="completed", snapshot=None, ledger=_ledger(covered=8, partial=2))
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS
    ev = s["endpoint_verification"]
    assert ev["available"] is False
    assert ev["state"] == "incomplete"
    assert ev["limitation"] == "unknown"
    assert ev["limitation"] != "unresponsive_origins"  # never guessed
    assert ev["data_inconsistent"] is False


def test_legacy_run_with_failed_ledger_is_incomplete_unknown():
    s = _build(scan_status="completed", snapshot=None, ledger=_ledger(covered=0, failed=3))
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS
    assert s["endpoint_verification"]["state"] == "incomplete"
    assert s["endpoint_verification"]["limitation"] == "unknown"


def test_legacy_run_with_unstarted_ledger_is_incomplete_unknown():
    s = _build(scan_status="completed", snapshot=None, ledger=_ledger(covered=1, unstarted=4))
    assert s["endpoint_verification"]["state"] == "incomplete"
    assert s["endpoint_verification"]["limitation"] == "unknown"
    assert s["endpoint_verification"]["unstarted"] == 4


# --- malformed snapshots (fail-closed) ---


def test_empty_snapshot_dict_is_data_inconsistent():
    s = _build(snapshot={}, ledger=_ledger(covered=3))
    ev = s["endpoint_verification"]
    assert ev["available"] is False  # a malformed dict is NOT available
    assert ev["data_inconsistent"] is True
    assert ev["state"] == "incomplete"
    assert ev["limitation"] == "data_inconsistent"
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS


def test_unknown_schema_version_is_data_inconsistent():
    s = _build(snapshot={"schema_version": 999, "state": "complete"}, ledger=_ledger())
    assert s["endpoint_verification"]["data_inconsistent"] is True
    assert s["endpoint_verification"]["available"] is False


def test_unknown_state_is_data_inconsistent():
    snap = _snap("complete")
    snap["state"] = "garbage"
    s = _build(snapshot=snap, ledger=_ledger())
    assert s["endpoint_verification"]["data_inconsistent"] is True
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS


def test_unknown_limitation_is_data_inconsistent():
    snap = _snap("limited", "unresponsive_origins")
    snap["limitation"] = "not_a_reason"
    s = _build(snapshot=snap, ledger=_ledger(covered=100))
    assert s["endpoint_verification"]["data_inconsistent"] is True


def test_limitations_not_a_list_is_data_inconsistent():
    snap = _snap("complete")
    snap["limitations"] = "unresponsive_origins"  # not a list
    s = _build(snapshot=snap, ledger=_ledger())
    assert s["endpoint_verification"]["data_inconsistent"] is True


def test_limitations_with_non_enum_is_data_inconsistent():
    snap = _snap("complete")
    snap["limitations"] = ["not-an-enum"]
    s = _build(snapshot=snap, ledger=_ledger())
    assert s["endpoint_verification"]["data_inconsistent"] is True


# --- unknown scan status ---


def test_unrecognized_scan_status_is_unknown_not_completed():
    s = _build(scan_status="weird_status", snapshot=_snap("complete"), ledger=_ledger())
    assert s["outcome"] == OUTCOME_UNKNOWN


def test_unstarted_is_exposed_and_reconciles():
    s = _build(snapshot=None, ledger=_ledger(covered=6, unstarted=4))
    ev = s["endpoint_verification"]
    assert ev["unstarted"] == 4
    assert ev["selected"] == ev["covered"] + ev["not_verifiable"] + ev["failed"] + ev["skipped"] + ev["unstarted"]


def test_snapshot_ledger_count_mismatch_is_data_inconsistent():
    # snapshot claims all covered, but the ledger disagrees → data_inconsistent + conservative CWL
    s = _build(snapshot=_snap("complete", selected=100, covered=100), ledger=_ledger(covered=50, partial=50))
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS
    ev = s["endpoint_verification"]
    assert ev["data_inconsistent"] is True
    assert ev["state"] != "complete"  # never report complete under inconsistency
    assert ev["limitation"] == "data_inconsistent"
    # displayed counts come from the LEDGER (authoritative), not the snapshot
    assert ev["covered"] == 50
    assert ev["not_verifiable"] == 50


def test_snapshot_self_marked_data_inconsistent_is_propagated():
    snap = _snap("incomplete", "data_inconsistent", limitations=["data_inconsistent"], selected=5, covered=5)
    s = _build(snapshot=snap, ledger=_ledger(covered=5))
    ev = s["endpoint_verification"]
    assert ev["data_inconsistent"] is True
    assert s["outcome"] == OUTCOME_COMPLETED_WITH_LIMITATIONS


def test_negative_and_bool_ledger_counts_are_treated_as_zero():
    s = _build(snapshot=None, ledger={"covered": True, "partial": -3, "failed": 2, "skipped": 0})
    ev = s["endpoint_verification"]
    assert ev["covered"] == 0  # bool rejected
    assert ev["not_verifiable"] == 0  # negative rejected
    assert ev["failed"] == 2
    assert ev["selected"] == 2  # only the valid count contributes


def test_coverage_percent_rounds():
    s = _build(snapshot=None, ledger=_ledger(covered=2, partial=1))  # 2/3
    assert s["endpoint_verification"]["coverage_percent"] == 67


def test_auto_close_counts_mapped():
    s = _build(
        snapshot=_snap("complete"),
        ledger=_ledger(),
        lifecycle={"detected": 5, "eligible_miss": 3, "would_close": 2, "auto_closed": 1, "reopened": 4},
    )
    ac = s["auto_close"]
    assert ac == {"detected": 5, "eligible_miss": 3, "would_close": 2, "closed": 1, "reopened": 4}


def test_summary_carries_trigger_and_tier():
    s = build_operational_summary(
        scan_status="completed",
        scan_tier=2,
        trigger_type="scheduled",
        trigger_label="nightly",
        snapshot=_snap("complete"),
        ledger_counts=_ledger(),
        lifecycle_counts={},
    )
    assert s["tier"] == 2
    assert s["trigger_type"] == "scheduled"
    assert s["trigger_label"] == "nightly"
    assert s["schema_version"] == 1


def test_no_sensitive_data_in_summary():
    import json

    snap = _snap("limited", "unresponsive_origins", selected=100, covered=96, partial=4)
    s = _build(snapshot=snap, ledger=_ledger(covered=96, partial=4))
    blob = json.dumps(s)
    assert "://" not in blob
    import re

    assert not re.search(r"[a-f0-9]{32,}", blob)
    for bad in ("policy_hash", "shape_hash", "url", "hostname", "command", "error"):
        assert bad not in blob
