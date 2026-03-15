"""
Account Lockout Tests

Tests for Redis-backed account lockout after failed login attempts,
and per-user MFA verification rate limiting.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app.api.routers.auth import (
    LOGIN_LOCKOUT_MAX_FAILURES,
    LOGIN_LOCKOUT_DURATION_SECONDS,
    MFA_LOCKOUT_MAX_FAILURES,
    MFA_LOCKOUT_DURATION_SECONDS,
    _check_account_lockout,
    _record_login_failure,
    _clear_login_failures,
    _check_mfa_lockout,
    _record_mfa_failure,
    _clear_mfa_failures,
)


class TestAccountLockoutConstants:
    """Verify lockout thresholds are configured correctly."""

    def test_login_lockout_threshold(self):
        assert LOGIN_LOCKOUT_MAX_FAILURES == 5

    def test_login_lockout_duration(self):
        assert LOGIN_LOCKOUT_DURATION_SECONDS == 15 * 60

    def test_mfa_lockout_threshold(self):
        assert MFA_LOCKOUT_MAX_FAILURES == 5

    def test_mfa_lockout_duration(self):
        assert MFA_LOCKOUT_DURATION_SECONDS == 15 * 60


class TestCheckAccountLockout:
    """Tests for _check_account_lockout."""

    @patch("app.api.routers.auth._get_redis")
    def test_no_failures_allows_login(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = None
        mock_get_redis.return_value = mock_r

        # Should not raise
        _check_account_lockout("user@example.com")
        mock_r.get.assert_called_once_with("login:failures:user@example.com")
        mock_r.close.assert_called_once()

    @patch("app.api.routers.auth._get_redis")
    def test_below_threshold_allows_login(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = b"3"
        mock_get_redis.return_value = mock_r

        # Should not raise
        _check_account_lockout("user@example.com")
        mock_r.close.assert_called_once()

    @patch("app.api.routers.auth._get_redis")
    def test_at_threshold_blocks_login(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = b"5"
        mock_r.ttl.return_value = 600  # 10 minutes remaining
        mock_get_redis.return_value = mock_r

        with pytest.raises(HTTPException) as exc_info:
            _check_account_lockout("user@example.com")
        assert exc_info.value.status_code == 429
        assert "Account temporarily locked" in exc_info.value.detail
        assert "10 minutes" in exc_info.value.detail

    @patch("app.api.routers.auth._get_redis")
    def test_above_threshold_blocks_login(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = b"8"
        mock_r.ttl.return_value = 120  # 2 minutes remaining
        mock_get_redis.return_value = mock_r

        with pytest.raises(HTTPException) as exc_info:
            _check_account_lockout("user@example.com")
        assert exc_info.value.status_code == 429
        assert "2 minutes" in exc_info.value.detail

    @patch("app.api.routers.auth._get_redis")
    def test_ttl_expired_shows_fallback_minutes(self, mock_get_redis):
        """When TTL is -1 or -2 (no expiry / key missing), show default lockout duration."""
        mock_r = MagicMock()
        mock_r.get.return_value = b"5"
        mock_r.ttl.return_value = -1
        mock_get_redis.return_value = mock_r

        with pytest.raises(HTTPException) as exc_info:
            _check_account_lockout("user@example.com")
        assert exc_info.value.status_code == 429
        assert "15 minutes" in exc_info.value.detail

    @patch("app.api.routers.auth._get_redis")
    def test_redis_failure_does_not_block(self, mock_get_redis):
        """If Redis is unavailable, fail open (allow login attempt)."""
        mock_get_redis.side_effect = ConnectionError("Redis down")

        # Should not raise -- fail open
        _check_account_lockout("user@example.com")


class TestRecordLoginFailure:
    """Tests for _record_login_failure."""

    @patch("app.api.routers.auth._get_redis")
    def test_first_failure_sets_ttl(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.incr.return_value = 1
        mock_get_redis.return_value = mock_r

        _record_login_failure("user@example.com")

        mock_r.incr.assert_called_once_with("login:failures:user@example.com")
        mock_r.expire.assert_called_once_with(
            "login:failures:user@example.com", LOGIN_LOCKOUT_DURATION_SECONDS
        )
        mock_r.close.assert_called_once()

    @patch("app.api.routers.auth._get_redis")
    def test_threshold_failure_sets_ttl(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.incr.return_value = 5
        mock_get_redis.return_value = mock_r

        _record_login_failure("user@example.com")

        mock_r.expire.assert_called_once_with(
            "login:failures:user@example.com", LOGIN_LOCKOUT_DURATION_SECONDS
        )

    @patch("app.api.routers.auth._get_redis")
    def test_mid_range_failure_no_expire(self, mock_get_redis):
        """Failures 2-4 should not reset the TTL."""
        mock_r = MagicMock()
        mock_r.incr.return_value = 3
        mock_get_redis.return_value = mock_r

        _record_login_failure("user@example.com")

        mock_r.expire.assert_not_called()
        mock_r.close.assert_called_once()

    @patch("app.api.routers.auth._get_redis")
    def test_redis_failure_is_silent(self, mock_get_redis):
        mock_get_redis.side_effect = ConnectionError("Redis down")

        # Should not raise
        _record_login_failure("user@example.com")


class TestClearLoginFailures:
    """Tests for _clear_login_failures."""

    @patch("app.api.routers.auth._get_redis")
    def test_deletes_key(self, mock_get_redis):
        mock_r = MagicMock()
        mock_get_redis.return_value = mock_r

        _clear_login_failures("user@example.com")

        mock_r.delete.assert_called_once_with("login:failures:user@example.com")
        mock_r.close.assert_called_once()

    @patch("app.api.routers.auth._get_redis")
    def test_redis_failure_is_silent(self, mock_get_redis):
        mock_get_redis.side_effect = ConnectionError("Redis down")

        # Should not raise
        _clear_login_failures("user@example.com")


class TestMfaLockout:
    """Tests for MFA per-user lockout functions."""

    @patch("app.api.routers.auth._get_redis")
    def test_check_no_failures_allows(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = None
        mock_get_redis.return_value = mock_r

        _check_mfa_lockout(42)
        mock_r.get.assert_called_once_with("mfa:failures:42")

    @patch("app.api.routers.auth._get_redis")
    def test_check_at_threshold_blocks(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.get.return_value = b"5"
        mock_r.ttl.return_value = 300
        mock_get_redis.return_value = mock_r

        with pytest.raises(HTTPException) as exc_info:
            _check_mfa_lockout(42)
        assert exc_info.value.status_code == 429
        assert "Too many failed MFA attempts" in exc_info.value.detail

    @patch("app.api.routers.auth._get_redis")
    def test_record_increments_counter(self, mock_get_redis):
        mock_r = MagicMock()
        mock_r.incr.return_value = 1
        mock_get_redis.return_value = mock_r

        _record_mfa_failure(42)

        mock_r.incr.assert_called_once_with("mfa:failures:42")
        mock_r.expire.assert_called_once_with("mfa:failures:42", MFA_LOCKOUT_DURATION_SECONDS)

    @patch("app.api.routers.auth._get_redis")
    def test_clear_deletes_key(self, mock_get_redis):
        mock_r = MagicMock()
        mock_get_redis.return_value = mock_r

        _clear_mfa_failures(42)

        mock_r.delete.assert_called_once_with("mfa:failures:42")

    @patch("app.api.routers.auth._get_redis")
    def test_redis_failure_fails_open(self, mock_get_redis):
        mock_get_redis.side_effect = ConnectionError("Redis down")

        # All three operations should fail open
        _check_mfa_lockout(42)
        _record_mfa_failure(42)
        _clear_mfa_failures(42)
