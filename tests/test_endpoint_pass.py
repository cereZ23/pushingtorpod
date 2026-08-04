"""http_endpoint pass — pure orchestration core (Sprint 3, step 3a).

Batching determinism, the conservative per-batch verdict mapping, pass-status aggregation, and the
budget/deadline arithmetic. No Nuclei, no DB.
"""

from __future__ import annotations

import os
from collections import namedtuple
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

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
    validate_endpoint_pass_config,
)

PH = "p" * 64


def _sel(i, *, asset_id=10, prio=0, url=None, host="app.curci.it"):
    h = f"{i:064x}"
    return SelectedEndpoint(
        url=url or f"https://app.curci.it/{i}",
        host=host,
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


# --- host-homogeneous batching (an unresponsive host contaminates only its own endpoints) ---------


def test_plan_batches_never_mixes_assets_in_one_batch():
    # Two hosts interleaved in the input; no batch may contain more than one asset_id.
    sel = [_sel(i, asset_id=(i % 2 + 1)) for i in range(8)]  # assets 1 and 2, 4 endpoints each
    batches = plan_batches(sel, batch_size=5, policy_hash=PH)
    for b in batches:
        assert len({t.asset_id for t in b.targets}) == 1, "a batch spans more than one host"


def test_plan_batches_respects_cap_per_host():
    # 7 endpoints on one host, cap 5 → that host chunks into [5, 2]; a second host stays separate.
    sel = [_sel(i, asset_id=1) for i in range(7)] + [_sel(100, asset_id=2)]
    batches = plan_batches(sel, batch_size=5, policy_hash=PH)
    assert all(len(b.targets) <= 5 for b in batches)
    per_asset = {}
    for b in batches:
        per_asset.setdefault(b.targets[0].asset_id, []).append(len(b.targets))
    assert per_asset[1] == [5, 2]
    assert per_asset[2] == [1]


def test_plan_batches_is_deterministic_across_asset_order():
    sel = [_sel(i, asset_id=(i % 3 + 1)) for i in range(9)]
    a = plan_batches(sel, batch_size=2, policy_hash=PH)
    b = plan_batches(list(reversed(sel)), batch_size=2, policy_hash=PH)
    shape = lambda bs: [[(t.asset_id, t.shape_hash) for t in x.targets] for x in bs]  # noqa: E731
    assert shape(a) == shape(b)


def test_unresponsive_host_does_not_contaminate_other_assets():
    # Model the prod cause: one host (asset 2) is unresponsive; assert its endpoints never share a
    # batch with a healthy host, so PARTIAL on asset 2 cannot force asset 1/3 endpoints to PARTIAL.
    sel = [_sel(i, asset_id=1) for i in range(3)]
    sel += [_sel(50 + i, asset_id=2) for i in range(3)]  # the "dead" host
    sel += [_sel(90 + i, asset_id=3) for i in range(3)]
    batches = plan_batches(sel, batch_size=5, policy_hash=PH)
    dead_batches = [b for b in batches if any(t.asset_id == 2 for t in b.targets)]
    assert dead_batches, "expected at least one batch for the unresponsive host"
    for b in dead_batches:
        assert all(t.asset_id == 2 for t in b.targets), "dead host shares a batch with a healthy host"


def test_plan_batches_coverage_is_per_endpoint():
    # Every selected endpoint appears exactly once across all batches, one coverage row each.
    sel = [_sel(i, asset_id=(i % 2 + 1)) for i in range(8)]
    batches = plan_batches(sel, batch_size=3, policy_hash=PH)
    entries = [e for b in batches for e in b.entries()]
    assert len(entries) == len(sel)
    assert sorted(entries) == sorted((t.asset_id, t.shape_hash) for t in sel)


# --- priority survives batching (budget truncation must run the highest-value surface first) ------


def test_high_priority_asset_precedes_lower_id_asset_with_worse_priority():
    # asset 5 carries a priority-0 endpoint; asset 1 only a priority-2 one. Under a budget cut the
    # high-value asset MUST batch first, despite its higher asset_id (priority beats id).
    sel = [_sel(1, asset_id=1, prio=2), _sel(2, asset_id=5, prio=0)]
    batches = plan_batches(sel, batch_size=5, policy_hash=PH)
    assert [b.targets[0].asset_id for b in batches] == [5, 1]


def test_plan_batches_orders_endpoints_within_origin_by_priority():
    # Same origin; the priority-0 endpoint comes first inside the batch, then 1, then 2.
    sel = [_sel(3, asset_id=1, prio=2), _sel(1, asset_id=1, prio=0), _sel(2, asset_id=1, prio=1)]
    batch = plan_batches(sel, batch_size=5, policy_hash=PH)[0]
    assert [t.priority for t in batch.targets] == [0, 1, 2]


# --- origin (host:port) is the real boundary, not just asset_id -----------------------------------


def test_plan_batches_splits_origins_within_one_asset():
    # One asset_id, two origins (https:443 and http:80). They must NOT share a batch, so a dead
    # host:port origin cannot contaminate the other origin's endpoints of the SAME asset.
    sel = [
        _sel(1, asset_id=9, url="https://app.curci.it/a"),
        _sel(2, asset_id=9, url="http://app.curci.it/b"),
    ]
    batches = plan_batches(sel, batch_size=5, policy_hash=PH)
    assert len(batches) == 2
    schemes = {frozenset(urlparse(t.url).scheme for t in b.targets) for b in batches}
    assert schemes == {frozenset({"https"}), frozenset({"http"})}
    for b in batches:
        assert len({urlparse(t.url).scheme for t in b.targets}) == 1


def test_plan_batches_splits_alternate_ports_within_one_asset():
    # Same asset + scheme + host but different ports are distinct origins → distinct batches.
    sel = [
        _sel(1, asset_id=9, url="https://app.curci.it/a"),  # :443
        _sel(2, asset_id=9, url="https://app.curci.it:8443/b"),  # :8443
    ]
    batches = plan_batches(sel, batch_size=5, policy_hash=PH)
    assert len(batches) == 2
    for b in batches:
        assert len({urlparse(t.url).port or (443 if urlparse(t.url).scheme == "https" else 80) for t in b.targets}) == 1


# --- verdict --------------------------------------------------------------------------------------


# A fully-proven clean run — the ONLY shape that yields COVERED.
_PROVEN = dict(launched=True, exit_code=0, output_complete=True, catalog_verified=True, targets_completed=True)


def test_covered_requires_positive_proof():
    assert batch_verdict(**_PROVEN) == CoverageStatus.COVERED


def test_no_args_raises():
    # positive-proof kwargs are required → a caller that forgets everything cannot get COVERED
    with pytest.raises(TypeError):
        batch_verdict()


def test_unlaunched_is_caller_error():
    with pytest.raises(ValueError):
        batch_verdict(**{**_PROVEN, "launched": False})


@pytest.mark.parametrize(
    "kw",
    [
        {"timed_out": True},
        {"budget_expired": True},
        {"truncated": True},
        {"drift": True},
        {"unresponsive": True},
        {"parse_incomplete": True},
        {"output_complete": False},  # missing positive proof → not COVERED
        {"catalog_verified": False},
        {"targets_completed": False},
    ],
)
def test_uncertain_or_unproven_is_partial(kw):
    assert batch_verdict(**{**_PROVEN, **kw}) == CoverageStatus.PARTIAL


@pytest.mark.parametrize("exit_code", [None, 1, 2, -1])
def test_invalid_exit_code_is_failed(exit_code):
    assert batch_verdict(**{**_PROVEN, "exit_code": exit_code}) == CoverageStatus.FAILED


def test_timeout_wins_over_bad_exit_code():
    # a timed-out batch is killed → non-zero/None exit, but the contract is timeout → PARTIAL, so the
    # incompleteness must win over the exit code (else every timeout would wrongly read as FAILED).
    assert batch_verdict(**{**_PROVEN, "exit_code": 1, "timed_out": True}) == CoverageStatus.PARTIAL
    assert batch_verdict(**{**_PROVEN, "exit_code": None, "truncated": True}) == CoverageStatus.PARTIAL


def test_bad_exit_without_uncertainty_is_failed():
    # a non-zero exit NOT attributable to timeout/truncation is a structural failure
    assert batch_verdict(**{**_PROVEN, "exit_code": 1}) == CoverageStatus.FAILED


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


def test_all_batches_skipped_for_budget_is_insufficient_phase_budget():
    # targets were selected but NOT ONE batch launched (budget already spent) → not a generic PARTIAL
    st, reason = aggregate_pass_status(
        [CoverageStatus.SKIPPED, CoverageStatus.SKIPPED], flag_enabled=True, selected_count=50
    )
    assert st == PASS_SKIPPED and reason == "insufficient_phase_budget"


def test_empty_statuses_with_selected_is_insufficient_phase_budget():
    # selected>0 but NO batch status recorded (nothing launched) → SKIPPED, not PARTIAL
    st, reason = aggregate_pass_status([], flag_enabled=True, selected_count=50)
    assert st == PASS_SKIPPED and reason == "insufficient_phase_budget"


def test_some_covered_then_skipped_is_partial():
    st, _ = aggregate_pass_status(
        [CoverageStatus.COVERED, CoverageStatus.SKIPPED], flag_enabled=True, selected_count=50
    )
    assert st == PASS_PARTIAL  # ran out of budget partway → not COMPLETED


# --- config validation ----------------------------------------------------------------------------


def test_valid_config_passes():
    validate_endpoint_pass_config(batch_size=25, batch_timeout_seconds=180, budget_seconds=600, max_per_host=40)


@pytest.mark.parametrize(
    "kw",
    [
        {"batch_size": 0},
        {"batch_timeout_seconds": 0},
        {"budget_seconds": -1},
        {"max_per_host": 0},
        {"batch_size": True},  # bool is an int subclass — must NOT slip through as a count
        {"max_per_host": False},
    ],
)
def test_invalid_config_rejected(kw):
    base = dict(batch_size=25, batch_timeout_seconds=180, budget_seconds=600, max_per_host=40)
    with pytest.raises(ValueError):
        validate_endpoint_pass_config(**{**base, **kw})


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


def test_effective_deadline_rejects_naive_datetime():
    naive = datetime(2026, 8, 4, 12, 0, 0)  # no tzinfo
    with pytest.raises(ValueError):
        compute_effective_deadline(phase_9_deadline=_T0, started_at=naive, endpoint_budget_seconds=120)
    with pytest.raises(ValueError):
        compute_effective_deadline(phase_9_deadline=naive, started_at=_T0, endpoint_budget_seconds=120)


def test_effective_deadline_rejects_nonpositive_budget():
    with pytest.raises(ValueError):
        compute_effective_deadline(
            phase_9_deadline=_T0 + timedelta(seconds=600), started_at=_T0, endpoint_budget_seconds=0
        )


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
