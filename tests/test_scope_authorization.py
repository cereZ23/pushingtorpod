"""Tests for scope-authorization matching + enforcement."""

from unittest.mock import MagicMock, patch

import pytest

from app.config import settings
from app.models.authorization import ScanAuthorization
from app.services.scope_authorization import (
    ScopeViolationError,
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
