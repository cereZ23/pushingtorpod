"""Wiring: EVERY http_endpoint return path emits a JSON-serializable, enum-free, sensitive-free
endpoint_verification snapshot (UI-1 PR 1a).
"""

from __future__ import annotations

import json
import re
from types import SimpleNamespace

from app.models.coverage import CoverageStatus
from app.services.scanning.http_endpoint_orchestrator import (
    _endpoint_error_stats,
    _feature_disabled_stats,
    _resolve_batch_limitation,
    _rollup_stats,
    _skipped,
)

_SENSITIVE_KEYS = {"policy_hash", "catalog_digest", "url", "error", "target", "hostname", "command"}


def _assert_clean_snapshot(ev: dict):
    # JSON-serializable (no Python enums / objects)
    blob = json.dumps(ev)
    # no coverage-status enum leaked
    assert "CoverageStatus" not in blob
    # no URL / long hash / sensitive keys
    assert "://" not in blob
    assert not re.search(r"[a-f0-9]{32,}", blob)
    assert not (_SENSITIVE_KEYS & set(ev.keys()))
    # every value is a JSON primitive / list of enum strings
    for v in ev.values():
        assert v is None or isinstance(v, (bool, int, str, list))


def test_feature_disabled_path_has_snapshot():
    ev = _feature_disabled_stats()["endpoint_verification"]
    assert ev["state"] == "disabled" and ev["enabled"] is False
    _assert_clean_snapshot(ev)


def test_no_targets_path_has_snapshot():
    ev = _skipped("no_targets", stats={"selected_count": 0}).stats["endpoint_verification"]
    assert ev["state"] == "no_targets" and ev["enabled"] is True
    _assert_clean_snapshot(ev)


def test_skipped_feature_disabled_path_has_snapshot():
    ev = _skipped("feature_disabled").stats["endpoint_verification"]
    assert ev["state"] == "disabled"
    _assert_clean_snapshot(ev)


def test_wiring_error_path_has_snapshot():
    ev = _endpoint_error_stats("SomeRunnerError")["endpoint_verification"]
    assert ev["state"] == "failed" and ev["limitation"] == "execution_error"
    _assert_clean_snapshot(ev)


def _fake_batch(status, *, targets=2, opcomplete=True, limitation_reason=None, **ev_kw):
    evidence = SimpleNamespace(
        launched=True,
        exit_code=0,
        timed_out=False,
        budget_expired=False,
        truncated=False,
        drift=False,
        parse_incomplete=False,
        unresponsive_targets=0,
    )
    for k, v in ev_kw.items():
        setattr(evidence, k, v)
    return SimpleNamespace(
        status=status,
        batch=SimpleNamespace(targets=list(range(targets))),
        evidence=evidence,
        operationally_complete=opcomplete,
        findings_created=0,
        findings_updated=0,
        limitation_reason=limitation_reason,
    )


def _base_stats(selected):
    return {"selected_count": selected, "candidate_count": 100, "out_of_scope": 5, "template_count": 40}


def test_rollup_complete_path_snapshot():
    batches = [_fake_batch(CoverageStatus.COVERED, targets=30), _fake_batch(CoverageStatus.COVERED, targets=30)]
    stats = _rollup_stats(_base_stats(60), batches, None, "completed", None, None)
    ev = stats["endpoint_verification"]
    assert ev["state"] == "complete"
    assert ev["limitation"] is None
    assert (ev["selected"], ev["covered"], ev["partial"], ev["failed"], ev["skipped"]) == (60, 60, 0, 0, 0)
    _assert_clean_snapshot(ev)


def test_rollup_limited_unresponsive_snapshot():
    batches = [
        _fake_batch(CoverageStatus.COVERED, targets=57),
        _fake_batch(CoverageStatus.PARTIAL, targets=3, unresponsive_targets=3),
    ]
    stats = _rollup_stats(_base_stats(60), batches, None, "partial", None, None)
    ev = stats["endpoint_verification"]
    assert ev["state"] == "limited"
    assert ev["limitation"] == "unresponsive_origins"
    assert ev["execution_complete"] is True
    assert (ev["covered"], ev["partial"]) == (57, 3)
    _assert_clean_snapshot(ev)


def test_rollup_incomplete_timeout_snapshot():
    batches = [
        _fake_batch(CoverageStatus.COVERED, targets=50),
        _fake_batch(CoverageStatus.PARTIAL, targets=10, opcomplete=False, timed_out=True),
    ]
    stats = _rollup_stats(_base_stats(60), batches, None, "partial", None, None)
    ev = stats["endpoint_verification"]
    assert ev["state"] == "incomplete"
    assert ev["limitation"] == "timeout"
    _assert_clean_snapshot(ev)


def test_rollup_budget_skipped_tail_snapshot():
    # Blocker 1: a budget-out tail is a SKIPPED batch whose _skipped_evidence carries budget_expired.
    # It must surface as insufficient_budget (not lost), state incomplete, skipped>0.
    from app.services.scanning.http_endpoint_orchestrator import _skipped_evidence

    ran = _fake_batch(CoverageStatus.COVERED, targets=50)
    skipped = SimpleNamespace(
        status=CoverageStatus.SKIPPED,
        batch=SimpleNamespace(targets=list(range(10))),
        evidence=_skipped_evidence(),
        operationally_complete=False,
        findings_created=0,
        findings_updated=0,
        limitation_reason=None,
    )
    stats = _rollup_stats(_base_stats(60), [ran, skipped], None, "partial", None, None)
    ev = stats["endpoint_verification"]
    assert ev["state"] == "incomplete"
    assert ev["limitation"] == "insufficient_budget"
    assert ev["skipped"] == 10
    _assert_clean_snapshot(ev)


def test_rollup_writer_error_from_batch_limitation_reason():
    # Blocker 2: writer/attribution/cleanup are out-of-evidence — they reach the snapshot ONLY via the
    # batch's resolved limitation_reason. A clean-evidence PARTIAL batch tagged writer_error must win.
    batches = [
        _fake_batch(CoverageStatus.COVERED, targets=57),
        _fake_batch(CoverageStatus.PARTIAL, targets=3, opcomplete=False, limitation_reason="writer_error"),
    ]
    stats = _rollup_stats(_base_stats(60), batches, None, "partial", None, None)
    ev = stats["endpoint_verification"]
    assert ev["limitation"] == "writer_error"
    assert ev["state"] == "incomplete"
    _assert_clean_snapshot(ev)


def _clean_ev():
    # a runner that executed cleanly (the #155 shape: successful runner, failure AFTER execution)
    return SimpleNamespace(
        launched=True,
        exit_code=0,
        timed_out=False,
        budget_expired=False,
        truncated=False,
        drift=False,
        parse_incomplete=False,
        unresponsive_targets=0,
    )


def test_resolve_batch_limitation_writer_failure_after_clean_run():
    # THE #155 regression: runner succeeds, but the finding writer fails. writer_ok is an out-of-
    # evidence signal — it must still reach the reason. (Reasonless before the fix.)
    assert (
        _resolve_batch_limitation(writer_ok=False, attribution_ok=True, cleanup_failed=False, evidence=_clean_ev())
        == "writer_error"
    )


def test_resolve_batch_limitation_cleanup_failure_is_execution_error():
    assert (
        _resolve_batch_limitation(writer_ok=True, attribution_ok=True, cleanup_failed=True, evidence=_clean_ev())
        == "execution_error"
    )


def test_resolve_batch_limitation_attribution_failure_is_parser_incomplete():
    assert (
        _resolve_batch_limitation(writer_ok=True, attribution_ok=False, cleanup_failed=False, evidence=_clean_ev())
        == "parser_incomplete"
    )


def test_resolve_batch_limitation_writer_outranks_evidence_timeout():
    ev = _clean_ev()
    ev.timed_out = True
    assert (
        _resolve_batch_limitation(writer_ok=False, attribution_ok=True, cleanup_failed=False, evidence=ev)
        == "writer_error"
    )


def test_resolve_batch_limitation_clean_batch_is_none():
    assert (
        _resolve_batch_limitation(writer_ok=True, attribution_ok=True, cleanup_failed=False, evidence=_clean_ev())
        is None
    )


def test_rollup_batch_limitation_reason_takes_precedence_over_evidence():
    # writer_error (batch-level) outranks a timeout in the same batch's evidence.
    batches = [
        _fake_batch(CoverageStatus.COVERED, targets=57),
        _fake_batch(
            CoverageStatus.PARTIAL,
            targets=3,
            opcomplete=False,
            timed_out=True,
            limitation_reason="writer_error",
        ),
    ]
    stats = _rollup_stats(_base_stats(60), batches, None, "partial", None, None)
    assert stats["endpoint_verification"]["limitation"] == "writer_error"
