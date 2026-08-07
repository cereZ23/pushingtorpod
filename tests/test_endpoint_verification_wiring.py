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


def _fake_batch(status, *, targets=2, opcomplete=True, **ev_kw):
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
