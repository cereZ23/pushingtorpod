"""Tests for scope-authorization matching + enforcement."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from app.config import settings
from app.models.authorization import ScanAuthorization
from app.services.scope_authorization import (
    ScopeViolationError,
    _active_authorizations,
    _as_aware_utc,
    assert_targets_authorized,
    target_in_scope,
)

DOMAIN = [{"type": "domain", "value": "example.com"}]
CIDR = [{"type": "cidr", "value": "203.0.113.0/24"}]
IP = [{"type": "ip", "value": "203.0.113.5"}]


class TestTargetInScope:
    def test_domain_and_subdomains(self):
        assert target_in_scope("example.com", DOMAIN) is True
        assert target_in_scope("www.example.com", DOMAIN) is True
        assert target_in_scope("a.b.example.com", DOMAIN) is True

    def test_domain_suffix_confusion_blocked(self):
        assert target_in_scope("evil.com", DOMAIN) is False
        assert target_in_scope("notexample.com", DOMAIN) is False
        assert target_in_scope("example.com.evil.com", DOMAIN) is False

    def test_cidr_match(self):
        assert target_in_scope("203.0.113.5", CIDR) is True
        assert target_in_scope("203.0.114.5", CIDR) is False

    def test_ip_exact(self):
        assert target_in_scope("203.0.113.5", IP) is True
        assert target_in_scope("203.0.113.6", IP) is False

    def test_type_mismatch(self):
        assert target_in_scope("203.0.113.5", DOMAIN) is False  # IP vs domain entry
        assert target_in_scope("example.com", CIDR) is False  # domain vs cidr entry

    def test_empty(self):
        assert target_in_scope("example.com", []) is False
        assert target_in_scope("", DOMAIN) is False


def _auth(scope):
    return ScanAuthorization(
        tenant_id=1, name="eng", scope_entries=scope, valid_from=None, valid_until=None, is_active=True
    )


def _mock_db(auths):
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = auths
    return db


class TestAssertTargetsAuthorized:
    def test_audit_returns_out_of_scope_no_raise(self):
        db = _mock_db([_auth(DOMAIN)])
        with patch.object(settings, "scope_enforcement_mode", "audit"):
            out = assert_targets_authorized(db, 1, ["www.example.com", "evil.com"])
        assert out == ["evil.com"]  # in-scope one passes, out-of-scope flagged

    def test_enforce_raises_on_out_of_scope(self):
        db = _mock_db([_auth(DOMAIN)])
        with patch.object(settings, "scope_enforcement_mode", "enforce"):
            with pytest.raises(ScopeViolationError):
                assert_targets_authorized(db, 1, ["evil.com"])

    def test_enforce_passes_when_all_in_scope(self):
        db = _mock_db([_auth(DOMAIN)])
        with patch.object(settings, "scope_enforcement_mode", "enforce"):
            out = assert_targets_authorized(db, 1, ["example.com", "api.example.com"])
        assert out == []

    def test_off_disables_check(self):
        db = _mock_db([])
        with patch.object(settings, "scope_enforcement_mode", "off"):
            out = assert_targets_authorized(db, 1, ["anything.com"])
        assert out == []


def _auth_window(valid_from, valid_until):
    return ScanAuthorization(
        tenant_id=1, name="eng", scope_entries=DOMAIN, valid_from=valid_from, valid_until=valid_until, is_active=True
    )


class TestActiveAuthorizationsNaiveAware:
    """valid_from/valid_until are Column(DateTime) → postgres returns NAIVE datetimes. Comparing
    them to an aware now() used to raise 'can't compare offset-naive and offset-aware datetimes',
    which silently killed the Katana endpoint loader. _active_authorizations must tolerate both."""

    def test_as_aware_utc(self):
        naive = datetime(2026, 1, 1, 12, 0, 0)
        assert _as_aware_utc(naive) == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        aware = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        assert _as_aware_utc(aware) == aware
        assert _as_aware_utc(None) is None

    def test_naive_window_does_not_raise_and_is_live(self):
        now_aware = datetime.now(timezone.utc)
        naive_now = now_aware.replace(tzinfo=None)
        auth = _auth_window(naive_now - timedelta(days=1), naive_now + timedelta(days=1))
        live = _active_authorizations(_mock_db([auth]), 1, now_aware)  # aware now vs naive window
        assert live == [auth]

    def test_naive_expired_is_excluded(self):
        now_aware = datetime.now(timezone.utc)
        naive_past = now_aware.replace(tzinfo=None) - timedelta(days=2)
        auth = _auth_window(naive_past - timedelta(days=1), naive_past)  # valid_until in the past
        assert _active_authorizations(_mock_db([auth]), 1, now_aware) == []

    def test_naive_not_yet_valid_is_excluded(self):
        now_aware = datetime.now(timezone.utc)
        naive_future = now_aware.replace(tzinfo=None) + timedelta(days=2)
        auth = _auth_window(naive_future, None)  # valid_from in the future
        assert _active_authorizations(_mock_db([auth]), 1, now_aware) == []

    def test_naive_now_argument_also_tolerated(self):
        # some callers may pass a naive now; it must still work against naive windows
        naive_now = datetime.now()
        auth = _auth_window(naive_now - timedelta(days=1), naive_now + timedelta(days=1))
        assert _active_authorizations(_mock_db([auth]), 1, naive_now) == [auth]
