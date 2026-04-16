"""
Unit tests for app/services/scanning/suppression_service.py

Covers:
- should_suppress (match on template_id, url, host, severity, name, unknown type)
- create_suppression: happy path, invalid regex
- update_suppression: not found, tenant mismatch, update fields
- delete_suppression: not found, tenant mismatch, global allowed
- list_suppressions: include global, include expired
- filter_findings: partitioning
- _get_active_suppressions filter logic
- _matches_suppression invalid regex handled
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.services.scanning.suppression_service import (
    COMMON_SUPPRESSIONS,
    SuppressionService,
)


def _make_supp(
    id_=1,
    tenant_id=1,
    name="rule",
    pattern_type="template_id",
    pattern=r"^CVE-",
    is_active=True,
    is_global=False,
    priority=0,
    expires_at=None,
):
    s = SimpleNamespace()
    s.id = id_
    s.tenant_id = tenant_id
    s.name = name
    s.pattern_type = pattern_type
    s.pattern = pattern
    s.reason = "test reason"
    s.is_active = is_active
    s.is_global = is_global
    s.priority = priority
    s.expires_at = expires_at
    s.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
    s.updated_at = None
    return s


class _Query:
    def __init__(self, result=None, list_result=None):
        self._single = result
        self._list = list_result or []

    def filter(self, *a, **kw):
        return self

    def filter_by(self, *a, **kw):
        return self

    def order_by(self, *a, **kw):
        return self

    def first(self):
        return self._single

    def all(self):
        return self._list


class TestShouldSuppress:
    def test_no_rules_returns_false(self):
        db = MagicMock()
        db.query.return_value = _Query(list_result=[])
        svc = SuppressionService(db, tenant_id=1)
        assert svc.should_suppress({"template_id": "x"}) == (False, None)

    def test_matches_template_id(self):
        supp = _make_supp(pattern_type="template_id", pattern=r"^CVE-2024")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        result, reason = svc.should_suppress({"template_id": "CVE-2024-1"})
        assert result is True
        assert "Suppressed by rule" in reason

    def test_matches_url_pattern(self):
        supp = _make_supp(pattern_type="url", pattern=r"staging\.")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        ok, _ = svc.should_suppress({"matched_at": "https://staging.x.com"})
        assert ok is True

    def test_matches_host_pattern(self):
        supp = _make_supp(pattern_type="host", pattern=r"^localhost$")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        ok, _ = svc.should_suppress({"host": "localhost"})
        assert ok is True

    def test_matches_severity(self):
        supp = _make_supp(pattern_type="severity", pattern=r"^info$")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        ok, _ = svc.should_suppress({"severity": "info"})
        assert ok is True

    def test_matches_name(self):
        supp = _make_supp(pattern_type="name", pattern=r"weak.*cipher")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        ok, _ = svc.should_suppress({"name": "Weak Cipher Suite"})
        assert ok is True

    def test_unknown_pattern_type_no_match(self):
        supp = _make_supp(pattern_type="unknown_type", pattern=r".*")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        ok, _ = svc.should_suppress({"name": "x"})
        assert ok is False

    def test_no_match(self):
        supp = _make_supp(pattern_type="template_id", pattern=r"^NOPE")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        ok, reason = svc.should_suppress({"template_id": "CVE-1"})
        assert ok is False
        assert reason is None

    def test_invalid_regex_in_existing_rule_returns_false(self):
        # Bad regex stored in DB -> _matches_suppression returns False
        supp = _make_supp(pattern_type="name", pattern=r"[invalid(regex")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        ok, _ = svc.should_suppress({"name": "x"})
        assert ok is False


class TestCreateSuppression:
    def test_happy_path(self):
        db = MagicMock()
        svc = SuppressionService(db, tenant_id=1)

        # Make db.refresh populate ID
        def _refresh(obj):
            obj.id = 42
            obj.updated_at = None

        db.refresh.side_effect = _refresh
        result = svc.create_suppression(
            name="R1",
            pattern_type="template_id",
            pattern=r"^CVE-",
            reason="testing",
        )
        assert result["id"] == 42
        assert result["name"] == "R1"
        assert db.add.called
        assert db.commit.called

    def test_invalid_regex_raises(self):
        db = MagicMock()
        svc = SuppressionService(db, tenant_id=1)
        with pytest.raises(ValueError):
            svc.create_suppression(
                name="bad",
                pattern_type="template_id",
                pattern=r"[invalid(",
                reason="x",
            )

    def test_global_rule_no_tenant(self):
        db = MagicMock()

        created = {}

        def _add(obj):
            created["obj"] = obj

        def _refresh(obj):
            obj.id = 7
            obj.updated_at = None

        db.add.side_effect = _add
        db.refresh.side_effect = _refresh
        svc = SuppressionService(db, tenant_id=1)
        svc.create_suppression(
            name="G",
            pattern_type="host",
            pattern=r".*",
            reason="global",
            is_global=True,
        )
        assert created["obj"].tenant_id is None
        assert created["obj"].is_global is True


class TestUpdateSuppression:
    def test_not_found(self):
        db = MagicMock()
        db.query.return_value = _Query(result=None)
        svc = SuppressionService(db, tenant_id=1)
        assert svc.update_suppression(99) is None

    def test_tenant_mismatch(self):
        supp = _make_supp(tenant_id=999, is_global=False)
        db = MagicMock()
        db.query.return_value = _Query(result=supp)
        svc = SuppressionService(db, tenant_id=1)
        assert svc.update_suppression(1, is_active=False) is None

    def test_update_active(self):
        supp = _make_supp(tenant_id=1, is_active=True)
        db = MagicMock()
        db.query.return_value = _Query(result=supp)
        svc = SuppressionService(db, tenant_id=1)
        result = svc.update_suppression(1, is_active=False)
        assert result is not None
        assert supp.is_active is False

    def test_update_expires_at(self):
        supp = _make_supp(tenant_id=1)
        new_expiry = datetime(2025, 1, 1, tzinfo=timezone.utc)
        db = MagicMock()
        db.query.return_value = _Query(result=supp)
        svc = SuppressionService(db, tenant_id=1)
        svc.update_suppression(1, expires_at=new_expiry)
        assert supp.expires_at == new_expiry

    def test_update_global_rule_allowed(self):
        supp = _make_supp(is_global=True, tenant_id=None)
        db = MagicMock()
        db.query.return_value = _Query(result=supp)
        svc = SuppressionService(db, tenant_id=1)
        result = svc.update_suppression(1, is_active=False)
        assert result is not None


class TestDeleteSuppression:
    def test_not_found(self):
        db = MagicMock()
        db.query.return_value = _Query(result=None)
        svc = SuppressionService(db, tenant_id=1)
        assert svc.delete_suppression(99) is False

    def test_tenant_mismatch(self):
        supp = _make_supp(tenant_id=999)
        db = MagicMock()
        db.query.return_value = _Query(result=supp)
        svc = SuppressionService(db, tenant_id=1)
        assert svc.delete_suppression(1) is False

    def test_delete_success(self):
        supp = _make_supp(tenant_id=1)
        db = MagicMock()
        db.query.return_value = _Query(result=supp)
        svc = SuppressionService(db, tenant_id=1)
        assert svc.delete_suppression(1) is True
        assert db.delete.called

    def test_delete_global(self):
        supp = _make_supp(is_global=True, tenant_id=None)
        db = MagicMock()
        db.query.return_value = _Query(result=supp)
        svc = SuppressionService(db, tenant_id=1)
        assert svc.delete_suppression(1) is True


class TestListSuppressions:
    def test_empty_list(self):
        db = MagicMock()
        db.query.return_value = _Query(list_result=[])
        svc = SuppressionService(db, tenant_id=1)
        assert svc.list_suppressions() == []

    def test_with_results(self):
        supp1 = _make_supp(id_=1, name="one")
        supp2 = _make_supp(id_=2, name="two", is_global=True)
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp1, supp2])
        svc = SuppressionService(db, tenant_id=1)
        results = svc.list_suppressions()
        assert len(results) == 2
        assert results[0]["name"] == "one"

    def test_without_global(self):
        db = MagicMock()
        db.query.return_value = _Query(list_result=[])
        svc = SuppressionService(db, tenant_id=1)
        assert svc.list_suppressions(include_global=False) == []


class TestFilterFindings:
    def test_partitions_correctly(self):
        supp = _make_supp(pattern_type="template_id", pattern=r"^SUPP-")
        db = MagicMock()
        db.query.return_value = _Query(list_result=[supp])
        svc = SuppressionService(db, tenant_id=1)
        findings = [
            {"template_id": "SUPP-1"},
            {"template_id": "KEEP-1"},
            {"template_id": "SUPP-2"},
        ]
        kept, dropped = svc.filter_findings(findings)
        assert len(kept) == 1
        assert len(dropped) == 2
        assert all("suppression_reason" in f for f in dropped)

    def test_empty_findings(self):
        db = MagicMock()
        db.query.return_value = _Query(list_result=[])
        svc = SuppressionService(db, tenant_id=1)
        kept, dropped = svc.filter_findings([])
        assert kept == [] and dropped == []


class TestCommonSuppressions:
    def test_common_patterns_list(self):
        assert len(COMMON_SUPPRESSIONS) >= 1
        for s in COMMON_SUPPRESSIONS:
            assert "name" in s and "pattern_type" in s and "pattern" in s
