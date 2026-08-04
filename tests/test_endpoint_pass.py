"""http_endpoint pass — pure orchestration core (Sprint 3, step 3a).

Batching determinism, the conservative per-batch verdict mapping, pass-status aggregation, and the
budget/deadline arithmetic. No Nuclei, no DB.
"""

from __future__ import annotations

import os
from collections import namedtuple
from datetime import datetime, timedelta, timezone

import pytest

from app.models.coverage import CoverageStatus
from app.services.endpoint_selection import SelectedEndpoint
from app.services.scanning.endpoint_pass import (
    PASS_COMPLETED,
    PASS_FAILED,
    PASS_PARTIAL,
    PASS_SKIPPED,
    TemplateStagingError,
    aggregate_pass_status,
    batch_verdict,
    compute_effective_deadline,
    plan_batches,
    remaining_budget_seconds,
    stage_selected_templates,
)

PH = "p" * 64


def _sel(i, *, asset_id=10, prio=0):
    h = f"{i:064x}"
    return SelectedEndpoint(
        url=f"https://app.curci.it/{i}",
        host="app.curci.it",
        asset_id=asset_id,
        endpoint_type=None,
        priority=prio,
        shape_hash=h,
    )


# --- batching -------------------------------------------------------------------------------------


def test_plan_batches_splits_by_size_in_order():
    sel = [_sel(i) for i in range(5)]
    batches = plan_batches(sel, batch_size=2, policy_hash=PH)
    assert [len(b.targets) for b in batches] == [2, 2, 1]
    assert [b.index for b in batches] == [0, 1, 2]
    assert all(b.policy_hash == PH for b in batches)


def test_plan_batches_is_order_independent():
    sel = [_sel(i) for i in range(6)]
    a = plan_batches(sel, batch_size=3, policy_hash=PH)
    b = plan_batches(list(reversed(sel)), batch_size=3, policy_hash=PH)
    assert [[t.shape_hash for t in x.targets] for x in a] == [[t.shape_hash for t in x.targets] for x in b]


def test_batch_entries_are_asset_and_shape_only():
    b = plan_batches([_sel(1, asset_id=7)], batch_size=10, policy_hash=PH)[0]
    assert b.entries() == [(7, f"{1:064x}")]


def test_batch_repr_has_no_url():
    b = plan_batches([_sel(1)], batch_size=10, policy_hash=PH)[0]
    assert "app.curci.it/1" not in repr(b)
    assert "https://" not in repr(b)


def test_plan_batches_rejects_nonpositive_size():
    with pytest.raises(ValueError):
        plan_batches([_sel(1)], batch_size=0, policy_hash=PH)


# --- verdict --------------------------------------------------------------------------------------


def test_clean_batch_is_covered():
    assert batch_verdict() == CoverageStatus.COVERED


@pytest.mark.parametrize(
    "kw",
    [
        {"timed_out": True},
        {"budget_expired": True},
        {"truncated": True},
        {"drift": True},
        {"unresponsive": True},
        {"parse_incomplete": True},
    ],
)
def test_uncertain_signals_are_partial(kw):
    assert batch_verdict(**kw) == CoverageStatus.PARTIAL


@pytest.mark.parametrize("kw", [{"process_error": True}, {"exit_error": True}])
def test_structural_signals_are_failed(kw):
    assert batch_verdict(**kw) == CoverageStatus.FAILED


def test_failed_wins_over_partial():
    # a structural failure dominates even if uncertainty signals are also set
    assert batch_verdict(exit_error=True, timed_out=True) == CoverageStatus.FAILED


# --- pass status aggregation ----------------------------------------------------------------------


def test_flag_off_is_skipped():
    assert aggregate_pass_status([], flag_enabled=False, selected_count=100) == (PASS_SKIPPED, "feature_disabled")


def test_no_targets_is_skipped():
    assert aggregate_pass_status([], flag_enabled=True, selected_count=0) == (PASS_SKIPPED, "no_targets")


def test_all_covered_is_completed():
    st, reason = aggregate_pass_status(
        [CoverageStatus.COVERED, CoverageStatus.COVERED], flag_enabled=True, selected_count=50
    )
    assert st == PASS_COMPLETED and reason is None


def test_any_partial_is_partial():
    st, _ = aggregate_pass_status(
        [CoverageStatus.COVERED, CoverageStatus.PARTIAL], flag_enabled=True, selected_count=50
    )
    assert st == PASS_PARTIAL


def test_structural_error_no_covered_is_failed():
    st, reason = aggregate_pass_status(
        [CoverageStatus.FAILED], flag_enabled=True, selected_count=50, structural_error=True
    )
    assert st == PASS_FAILED and reason == "structural_error"


def test_structural_error_but_some_covered_is_partial():
    st, _ = aggregate_pass_status(
        [CoverageStatus.COVERED, CoverageStatus.FAILED], flag_enabled=True, selected_count=50, structural_error=True
    )
    assert st == PASS_PARTIAL  # a completed batch is not thrown away


# --- budget / deadline ----------------------------------------------------------------------------

_T0 = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)


def test_effective_deadline_is_the_earlier_bound():
    # own budget (start+120s) is earlier than the phase deadline (start+600s)
    phase_deadline = _T0 + timedelta(seconds=600)
    eff = compute_effective_deadline(phase_9_deadline=phase_deadline, started_at=_T0, endpoint_budget_seconds=120)
    assert eff == _T0 + timedelta(seconds=120)


def test_effective_deadline_capped_by_phase():
    # phase deadline (start+60s) is earlier than the endpoint budget (start+600s)
    phase_deadline = _T0 + timedelta(seconds=60)
    eff = compute_effective_deadline(phase_9_deadline=phase_deadline, started_at=_T0, endpoint_budget_seconds=600)
    assert eff == phase_deadline


def test_remaining_budget_never_negative():
    past = _T0 - timedelta(seconds=5)
    assert remaining_budget_seconds(now=_T0, effective_deadline=past) == 0.0
    assert remaining_budget_seconds(now=_T0, effective_deadline=_T0 + timedelta(seconds=30)) == 30.0


# --- staging --------------------------------------------------------------------------------------

_File = namedtuple("_File", "relative_path content")
_Snap = namedtuple("_Snap", "files")


def _snap(files):
    return _Snap(files=[_File(rel, data) for rel, data in files])


def test_stage_writes_snapshot_bytes(tmp_path):
    snap = _snap([("http/cves/a.yaml", b"id: a\n"), ("http/exposures/b.yaml", b"id: b\n"), ("skip.yaml", b"x")])
    written = stage_selected_templates(snap, ["http/cves/a.yaml", "http/exposures/b.yaml"], str(tmp_path))
    assert len(written) == 2
    for p in written:
        assert p.startswith(str(tmp_path.resolve()) + os.sep)
    assert (tmp_path / "http/cves/a.yaml").read_bytes() == b"id: a\n"
    # the non-selected template is NOT materialised
    assert not (tmp_path / "skip.yaml").exists()


def test_stage_rejects_path_absent_from_snapshot(tmp_path):
    snap = _snap([("http/cves/a.yaml", b"id: a\n")])
    with pytest.raises(TemplateStagingError):
        stage_selected_templates(snap, ["http/cves/ghost.yaml"], str(tmp_path))


@pytest.mark.parametrize("bad", ["../evil.yaml", "/etc/passwd", "a/../../evil.yaml", ""])
def test_stage_rejects_traversal(tmp_path, bad):
    snap = _snap([(bad, b"x")])  # even if the snapshot 'contains' it, the path is refused
    with pytest.raises(TemplateStagingError):
        stage_selected_templates(snap, [bad], str(tmp_path))
