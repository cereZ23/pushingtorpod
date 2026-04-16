"""Tests for adaptive throttle service (app/services/adaptive_throttle.py).

Pure-unit tests (no DB or external deps) covering:
- ThrottleState 429/timeout tracking and rate reduction
- Recovery after clean phases
- Rate/delay computation with multiplier
- Global registry: get_throttle / cleanup_throttle
"""

from __future__ import annotations

import pytest

from app.services import adaptive_throttle
from app.services.adaptive_throttle import (
    ThrottleState,
    cleanup_throttle,
    get_throttle,
)


@pytest.fixture(autouse=True)
def _reset_registry():
    """Ensure the global registry is empty before each test."""
    adaptive_throttle._active_throttles.clear()
    yield
    adaptive_throttle._active_throttles.clear()


class TestThrottleStateBasics:
    def test_initial_state_not_throttled(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        assert state.is_throttled is False
        assert state.rate_multiplier == 1.0
        assert state.total_429s == 0

    def test_get_rate_returns_base_when_not_throttled(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        assert state.get_rate(200) == 200
        assert state.get_rate(1000) == 1000

    def test_get_delay_returns_base_when_not_throttled(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        assert state.get_delay(0.5) == 0.5
        assert state.get_delay() == 0.0


class TestReport429:
    def test_single_429_below_threshold_no_throttle(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        state.report_429("host1")
        # Threshold is 3 — below that, multiplier stays at 1.0
        assert state.total_429s == 1
        assert state.is_throttled is False
        assert state.rate_multiplier == 1.0

    def test_three_429s_triggers_throttle(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        for _ in range(3):
            state.report_429("host1")
        assert state.total_429s == 3
        assert state.is_throttled is True
        # _BACKOFF_FACTOR is 0.5 → multiplier halved
        assert state.rate_multiplier == 0.5

    def test_per_host_count_tracking(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        state.report_429("host1")
        state.report_429("host1")
        state.report_429("host2")
        summary = state.summary()
        assert summary["hosts_429"] == {"host1": 2, "host2": 1}
        assert summary["total_429s"] == 3

    def test_unknown_host_default(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        state.report_429()
        summary = state.summary()
        assert "unknown" in summary["hosts_429"]

    def test_multiplier_floor_after_many_429s(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        # Trigger enough 429s to exceed the 0.5 multiplier floor condition
        # (guard: _rate_multiplier > _BACKOFF_FACTOR (0.5) — so only one backoff)
        for _ in range(20):
            state.report_429("h")
        # After backoff multiplier is 0.5, the guard stops further reduction
        assert state.rate_multiplier == 0.5


class TestReportTimeout:
    def test_timeout_accumulates(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        state.report_timeout("a")
        state.report_timeout("a")
        state.report_timeout("b")
        summary = state.summary()
        assert summary["total_timeouts"] == 3


class TestReportPhaseClean:
    def test_clean_phase_no_effect_when_not_throttled(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        state.report_phase_clean()
        state.report_phase_clean()
        assert state.rate_multiplier == 1.0

    def test_recovery_after_two_clean_phases(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        # Trigger throttle
        for _ in range(3):
            state.report_429("h")
        assert state.rate_multiplier == 0.5

        # _RECOVERY_PHASES is 2
        state.report_phase_clean()
        assert state.rate_multiplier == 0.5  # First clean phase: no recovery yet
        state.report_phase_clean()
        # Recovery: 0.5 / 0.5 = 1.0, capped at 1.0
        assert state.rate_multiplier == 1.0

    def test_429_resets_clean_counter(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        for _ in range(3):
            state.report_429("h")
        state.report_phase_clean()
        # Another 429 resets the clean counter
        state.report_429("h")
        state.report_phase_clean()
        # Only one clean phase — no recovery yet
        assert state.rate_multiplier == 0.5


class TestGetRateWithThrottle:
    def test_rate_halved_when_throttled(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        for _ in range(3):
            state.report_429("h")
        # multiplier=0.5 → 200 * 0.5 = 100
        assert state.get_rate(200) == 100

    def test_rate_respects_min_floor(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        for _ in range(3):
            state.report_429("h")
        # base_rate=10, multiplier=0.5 → 5, clamped to _MIN_RATE=10
        assert state.get_rate(10) == 10
        # base_rate=1 → clamped to 10
        assert state.get_rate(1) == 10

    def test_delay_increases_when_throttled(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        for _ in range(3):
            state.report_429("h")
        delay = state.get_delay(0.0)
        # multiplier=0.5 → added=(1/0.5 - 1)*0.5 = 0.5
        assert delay == pytest.approx(0.5)

    def test_delay_preserves_base_delay(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        for _ in range(3):
            state.report_429("h")
        assert state.get_delay(1.0) == pytest.approx(1.5)


class TestSummary:
    def test_summary_rounds_multiplier(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        for _ in range(3):
            state.report_429("h")
        summary = state.summary()
        assert summary["rate_multiplier"] == 0.5
        assert summary["is_throttled"] is True
        assert summary["total_429s"] == 3

    def test_summary_not_throttled(self):
        state = ThrottleState(tenant_id=1, scan_run_id=1)
        summary = state.summary()
        assert summary == {
            "total_429s": 0,
            "total_timeouts": 0,
            "rate_multiplier": 1.0,
            "is_throttled": False,
            "hosts_429": {},
        }


class TestRegistry:
    def test_get_throttle_creates_once(self):
        t1 = get_throttle(1, 42)
        t2 = get_throttle(1, 42)
        assert t1 is t2

    def test_get_throttle_different_scans(self):
        t1 = get_throttle(1, 42)
        t2 = get_throttle(1, 43)
        assert t1 is not t2

    def test_get_throttle_different_tenants(self):
        t1 = get_throttle(1, 42)
        t2 = get_throttle(2, 42)
        assert t1 is not t2

    def test_cleanup_returns_summary(self):
        t = get_throttle(1, 42)
        for _ in range(3):
            t.report_429("x")
        summary = cleanup_throttle(1, 42)
        assert summary is not None
        assert summary["total_429s"] == 3
        assert summary["is_throttled"] is True

    def test_cleanup_removes_from_registry(self):
        get_throttle(1, 42)
        assert (1, 42) in adaptive_throttle._active_throttles
        cleanup_throttle(1, 42)
        assert (1, 42) not in adaptive_throttle._active_throttles

    def test_cleanup_missing_returns_none(self):
        assert cleanup_throttle(99, 99) is None
