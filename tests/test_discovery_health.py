"""Discovery-health guard — pure verdict logic (fail-safe by design)."""

from __future__ import annotations

from app.services.discovery_health import (
    ReasonCode,
    compute_discovery_health,
    discovery_scope_hash,
)


def _h(**kw):
    base = dict(
        discovery_phase_status="COMPLETED",
        baseline_available=True,
        previous_count=20,
        observed_count=20,
    )
    base.update(kw)
    return compute_discovery_health(**base)


# --- explicit failure precedes the heuristic ---------------------------------


def test_discovery_failed_is_unhealthy_even_with_no_drop():
    h = _h(discovery_phase_status="FAILED", observed_count=20)  # no drop, but FAILED wins
    assert h.healthy is False and h.degraded is True
    assert h.reason_code == ReasonCode.DISCOVERY_FAILED.value
    assert h.comparison_performed is False  # didn't need the heuristic


def test_discovery_partial_is_unhealthy():
    h = _h(discovery_phase_status="PARTIAL")
    assert h.healthy is False
    assert h.reason_code == ReasonCode.DISCOVERY_PARTIAL.value


# --- baseline handling -------------------------------------------------------


def test_no_baseline_is_not_suspicious():
    h = compute_discovery_health(
        discovery_phase_status="COMPLETED", baseline_available=False, previous_count=None, observed_count=0
    )
    assert h.healthy is True and h.degraded is False
    assert h.reason_code == ReasonCode.NO_COMPARABLE_BASELINE.value
    assert h.comparison_performed is False


def test_empty_output_vs_nonempty_baseline_is_unhealthy():
    h = _h(observed_count=0, previous_count=15)
    assert h.healthy is False
    assert h.reason_code == ReasonCode.EMPTY_OUTPUT.value
    assert h.missing_ratio == 1.0 and h.missing_count == 15


def test_large_drop_is_unhealthy_with_counts():
    h = _h(previous_count=20, observed_count=8)  # 12/20 = 0.6 > 0.5
    assert h.healthy is False
    assert h.reason_code == ReasonCode.ASSET_DROP_THRESHOLD.value
    assert h.previous_count == 20 and h.observed_count == 8
    assert h.missing_count == 12 and h.missing_ratio == 0.6


def test_moderate_drop_is_healthy_but_counts_persisted():
    h = _h(previous_count=20, observed_count=12)  # 8/20 = 0.4 <= 0.5
    assert h.healthy is True
    assert h.reason_code == ReasonCode.OK.value
    assert h.missing_count == 8 and h.missing_ratio == 0.4


def test_small_dataset_50pct_passes_mvp_but_records_counts():
    # 1 of 2 missing = 0.5, NOT > 0.5 → healthy in the MVP, but counts are there
    # so a later policy can combine ratio + absolute.
    h = _h(previous_count=2, observed_count=1)
    assert h.healthy is True
    assert h.missing_count == 1 and h.missing_ratio == 0.5


def test_growth_is_healthy_no_negative_missing():
    h = _h(previous_count=10, observed_count=25)
    assert h.healthy is True
    assert h.missing_count == 0 and h.missing_ratio == 0.0


def test_result_always_carries_raw_counts():
    for h in (_h(), _h(discovery_phase_status="FAILED"), _h(observed_count=8, previous_count=20)):
        assert h.previous_count is not None or h.reason_code == ReasonCode.NO_COMPARABLE_BASELINE.value
        assert isinstance(h.observed_count, int)
        assert "reason_code" in h.to_dict()


# --- fail-closed on non-terminal / missing discovery (#2) --------------------


def test_unknown_discovery_status_is_unhealthy():
    for bad in ("UNKNOWN", "PENDING", "RUNNING", "", None):
        h = _h(discovery_phase_status=bad)
        assert h.healthy is False and h.degraded is True
        assert h.reason_code == ReasonCode.DISCOVERY_INCOMPLETE.value
        assert h.auto_close_allowed is False


# --- auto_close_allowed is stricter than healthy (#6) ------------------------


def test_no_baseline_is_healthy_but_not_authorized_to_close():
    h = compute_discovery_health(
        discovery_phase_status="COMPLETED", baseline_available=False, previous_count=None, observed_count=5
    )
    assert h.healthy is True  # not suspicious
    assert h.auto_close_allowed is False  # ...but NOT allowed to close


def test_zero_observed_baseline_never_authorizes_close():
    # A prior run that observed 0 assets (e.g. a broken first run) is NOT a usable
    # baseline — it must never authorize closing everything on the next run.
    h = compute_discovery_health(
        discovery_phase_status="COMPLETED", baseline_available=True, previous_count=0, observed_count=0
    )
    assert h.reason_code == ReasonCode.NO_COMPARABLE_BASELINE.value
    assert h.auto_close_allowed is False


def test_skipped_required_discovery_is_incomplete():
    h = _h(discovery_phase_status="SKIPPED")
    assert h.healthy is False
    assert h.reason_code == ReasonCode.DISCOVERY_INCOMPLETE.value
    assert h.auto_close_allowed is False


def test_healthy_with_baseline_is_authorized_to_close():
    h = _h(previous_count=20, observed_count=20)
    assert h.healthy is True and h.comparison_performed is True
    assert h.auto_close_allowed is True


def test_unhealthy_is_never_authorized_to_close():
    for h in (
        _h(discovery_phase_status="FAILED"),
        _h(discovery_phase_status="PARTIAL"),
        _h(observed_count=0, previous_count=20),
        _h(previous_count=20, observed_count=2),
    ):
        assert h.auto_close_allowed is False


# --- scope hash --------------------------------------------------------------


def test_scope_hash_is_stable_and_order_independent():
    a = discovery_scope_hash(["b.com", "a.com"], ["include:x", "exclude:y"])
    b = discovery_scope_hash(["a.com", "b.com"], ["exclude:y", "include:x"])
    assert a == b


def test_scope_hash_changes_with_seeds():
    assert discovery_scope_hash(["a.com"], []) != discovery_scope_hash(["a.com", "b.com"], [])
