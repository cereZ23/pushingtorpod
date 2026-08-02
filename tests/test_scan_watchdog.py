"""Stale-scan watchdog — pure decision logic."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.tasks.scan_watchdog import (
    _TIER_PHASE_BUDGET,
    _as_aware,
    _should_reap,
    _stale_threshold_seconds,
    reap_stale_scans,
)


NOW = datetime(2026, 8, 2, 12, 0, 0, tzinfo=timezone.utc)


def test_threshold_exceeds_tier_budget():
    # Must always be strictly greater than the phase budget so a legit long scan survives.
    for tier, budget in _TIER_PHASE_BUDGET.items():
        assert _stale_threshold_seconds(tier, 1800) == budget + 1800
        assert _stale_threshold_seconds(tier, 1800) > budget
    # unknown tier falls back to the T2 budget
    assert _stale_threshold_seconds(99, 100) == 3600 + 100


def test_as_aware_treats_naive_as_utc():
    naive = datetime(2026, 8, 2, 10, 0, 0)
    assert _as_aware(naive).tzinfo is not None
    assert _as_aware(None) is None


def test_should_reap_stale_scan():
    # T2 threshold = 3600 + 1800 = 5400s. Idle 2h → reap.
    last = NOW - timedelta(hours=2)
    assert _should_reap(NOW, last, tier=2, grace=1800) is True


def test_should_not_reap_long_but_within_budget():
    # A legitimately long T2 nuclei phase (~54 min idle) must NOT be reaped.
    last = NOW - timedelta(minutes=54)
    assert _should_reap(NOW, last, tier=2, grace=1800) is False


def test_should_not_reap_fresh_scan():
    last = NOW - timedelta(minutes=2)
    assert _should_reap(NOW, last, tier=1, grace=1800) is False


def test_should_not_reap_when_no_activity():
    assert _should_reap(NOW, None, tier=2, grace=1800) is False


def test_t3_gets_a_much_longer_leash():
    # A 2h-idle T3 scan is still within its 3h budget → not reaped.
    last = NOW - timedelta(hours=2)
    assert _should_reap(NOW, last, tier=3, grace=1800) is False
    # ...but 4h idle exceeds 3h + grace → reaped.
    assert _should_reap(NOW, NOW - timedelta(hours=4), tier=3, grace=1800) is True


def test_reaper_respects_disable_flag(monkeypatch):
    from app.config import settings

    monkeypatch.setattr(settings, "stale_scan_reaper_enabled", False, raising=False)
    assert reap_stale_scans() == {"disabled": True}
