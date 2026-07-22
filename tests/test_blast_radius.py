"""Tests for the blast-radius controls: kill-switch + circuit breaker."""

from unittest.mock import MagicMock, patch

from app.config import settings
from app.services import circuit_breaker as cb
from app.services import kill_switch


def _fake_redis():
    store: dict = {}
    r = MagicMock()
    r.set.side_effect = lambda k, v: store.__setitem__(k, v)
    r.get.side_effect = lambda k: store.get(k)
    r.delete.side_effect = lambda k: store.pop(k, None)
    r.incr.side_effect = lambda k: store.__setitem__(k, store.get(k, 0) + 1) or store[k]
    r.expire.side_effect = lambda k, t: None
    return r, store


class TestKillSwitch:
    def test_activate_status_deactivate(self):
        r, _ = _fake_redis()
        with patch("app.services.kill_switch._get_sync_redis", return_value=r):
            assert kill_switch.is_active()[0] is False
            kill_switch.activate("incident")
            active, reason = kill_switch.is_active()
            assert active is True and reason == "incident"
            kill_switch.deactivate()
            assert kill_switch.is_active()[0] is False

    def test_tenant_scoped_and_global(self):
        r, _ = _fake_redis()
        with patch("app.services.kill_switch._get_sync_redis", return_value=r):
            kill_switch.activate("t", tenant_id=7)
            assert kill_switch.is_active(tenant_id=7)[0] is True
            assert kill_switch.is_active(tenant_id=8)[0] is False  # other tenant unaffected
            assert kill_switch.is_active()[0] is False  # global not set
            # global switch trips every tenant
            kill_switch.activate("all")
            assert kill_switch.is_active(tenant_id=8)[0] is True

    def test_fail_open_on_redis_error(self):
        r = MagicMock()
        r.get.side_effect = RuntimeError("redis down")
        with patch("app.services.kill_switch._get_sync_redis", return_value=r):
            assert kill_switch.is_active()[0] is False  # never freezes scans on a blip


class TestCircuitBreaker:
    def test_opens_after_threshold_and_resets(self):
        r, _ = _fake_redis()
        with (
            patch("app.services.circuit_breaker._get_sync_redis", return_value=r),
            patch.object(settings, "circuit_breaker_threshold", 3),
        ):
            host = "target.example.com"
            assert cb.is_open(host) is False
            cb.record_failure(host)
            cb.record_failure(host)
            assert cb.is_open(host) is False  # 2 < 3
            cb.record_failure(host)
            assert cb.is_open(host) is True  # 3 >= 3
            cb.record_success(host)
            assert cb.is_open(host) is False  # reset on success

    def test_fail_open_on_redis_error(self):
        r = MagicMock()
        r.get.side_effect = RuntimeError("redis down")
        with patch("app.services.circuit_breaker._get_sync_redis", return_value=r):
            assert cb.is_open("x") is False  # never blocks probing on a blip
