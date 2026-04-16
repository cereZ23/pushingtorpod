"""
Unit tests for app/repositories/finding_repository.py

Covers pure logic paths that do not require a real DB:
- get_by_id: found/not found
- get_findings: filter construction (severity/status normalization), no DB errors raised
- bulk_upsert_findings: empty input, missing fields, invalid severity, asset not found
- update_finding_status: not found, invalid status, append notes with bad JSON
- count_by_asset / delete_by_asset basic paths
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.models.database import FindingSeverity, FindingStatus
from app.repositories.finding_repository import FindingRepository


class _ChainQuery:
    """Chainable query returning configurable results for .first()/.all()/.count()."""

    def __init__(self, *, first_val=None, all_val=None, count_val=0):
        self._first = first_val
        self._all = all_val or []
        self._count = count_val

    def filter(self, *a, **kw):
        return self

    def filter_by(self, *a, **kw):
        return self

    def order_by(self, *a, **kw):
        return self

    def limit(self, *a, **kw):
        return self

    def offset(self, *a, **kw):
        return self

    def join(self, *a, **kw):
        return self

    def first(self):
        return self._first

    def all(self):
        return self._all

    def count(self):
        return self._count

    def group_by(self, *a, **kw):
        return self

    def delete(self):
        return self._count


class TestGetById:
    def test_found(self):
        db = MagicMock()
        finding = SimpleNamespace(id=1)
        db.query.return_value = _ChainQuery(first_val=finding)
        repo = FindingRepository(db)
        assert repo.get_by_id(1) is finding

    def test_not_found(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=None)
        repo = FindingRepository(db)
        assert repo.get_by_id(99) is None


class TestGetFindings:
    def test_no_filters_returns_results(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[SimpleNamespace(id=1)])
        repo = FindingRepository(db)
        result = repo.get_findings(tenant_id=1)
        assert len(result) == 1

    def test_valid_severity_filter(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = FindingRepository(db)
        result = repo.get_findings(tenant_id=1, severity=["high", "critical"])
        assert result == []

    def test_invalid_severity_filter_ignored(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = FindingRepository(db)
        # Invalid severity names should be filtered out
        result = repo.get_findings(tenant_id=1, severity=["nonsense", "CRITICAL"])
        assert result == []

    def test_valid_status_filter(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = FindingRepository(db)
        result = repo.get_findings(tenant_id=1, status=["open", "fixed"])
        assert result == []

    def test_all_filters_combined(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = FindingRepository(db)
        result = repo.get_findings(
            tenant_id=1,
            severity=["high"],
            status=["open"],
            asset_id=5,
            cve_id="CVE-1",
            template_id="tpl",
            limit=10,
            offset=0,
        )
        assert result == []


class TestBulkUpsert:
    def test_empty_input(self):
        repo = FindingRepository(MagicMock())
        result = repo.bulk_upsert_findings([], tenant_id=1)
        assert result == {"created": 0, "updated": 0, "total_processed": 0, "errors": []}

    def test_missing_asset_id(self):
        db = MagicMock()
        repo = FindingRepository(db)
        result = repo.bulk_upsert_findings(
            [{"template_id": "t", "name": "n", "severity": "high"}],
            tenant_id=1,
        )
        assert result["created"] == 0
        assert len(result["errors"]) == 1
        assert "Missing asset_id" in result["errors"][0]

    def test_missing_template_id(self):
        db = MagicMock()
        repo = FindingRepository(db)
        result = repo.bulk_upsert_findings(
            [{"asset_id": 1, "name": "n", "severity": "high"}],
            tenant_id=1,
        )
        assert "Missing template_id" in result["errors"][0]

    def test_missing_name(self):
        db = MagicMock()
        repo = FindingRepository(db)
        result = repo.bulk_upsert_findings(
            [{"asset_id": 1, "template_id": "t", "severity": "high"}],
            tenant_id=1,
        )
        assert "Missing name" in result["errors"][0]

    def test_missing_severity(self):
        db = MagicMock()
        repo = FindingRepository(db)
        result = repo.bulk_upsert_findings(
            [{"asset_id": 1, "template_id": "t", "name": "n"}],
            tenant_id=1,
        )
        assert "Missing severity" in result["errors"][0]

    def test_asset_not_found_for_tenant(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=None)  # asset lookup
        repo = FindingRepository(db)
        result = repo.bulk_upsert_findings(
            [{"asset_id": 99, "template_id": "t", "name": "n", "severity": "high"}],
            tenant_id=1,
        )
        assert "Asset 99 not found" in result["errors"][0]

    def test_invalid_severity_value(self):
        asset = SimpleNamespace(id=1, identifier="x.com")
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=asset)
        repo = FindingRepository(db)
        result = repo.bulk_upsert_findings(
            [{"asset_id": 1, "template_id": "t", "name": "n", "severity": "bogus"}],
            tenant_id=1,
        )
        assert any("Invalid severity" in e for e in result["errors"])
        assert result["total_processed"] == 0


class TestUpdateFindingStatus:
    def test_not_found(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=None)
        repo = FindingRepository(db)
        assert repo.update_finding_status(1, "open") is None

    def test_invalid_status_raises(self):
        finding = SimpleNamespace(id=1, evidence=None)
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=finding)
        repo = FindingRepository(db)
        with pytest.raises(ValueError):
            repo.update_finding_status(1, "bogus")

    def test_status_updated(self):
        finding = SimpleNamespace(id=1, evidence=None, status=None)
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=finding)
        repo = FindingRepository(db)
        repo.update_finding_status(1, "fixed")
        assert finding.status == FindingStatus.FIXED
        assert db.commit.called

    def test_status_with_notes_appended_json(self):
        finding = SimpleNamespace(
            id=1,
            evidence=json.dumps({"foo": "bar"}),
            status=None,
        )
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=finding)
        repo = FindingRepository(db)
        repo.update_finding_status(1, "fixed", notes="manual close")
        data = json.loads(finding.evidence)
        assert "status_notes" in data
        assert data["status_notes"][0]["notes"] == "manual close"

    def test_bad_evidence_json_does_not_raise(self):
        finding = SimpleNamespace(id=1, evidence="not-json", status=None)
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=finding)
        repo = FindingRepository(db)
        # Should not raise despite bad JSON
        repo.update_finding_status(1, "open", notes="x")
        assert finding.status == FindingStatus.OPEN


class TestSimpleHelpers:
    def test_count_by_asset(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(count_val=5)
        repo = FindingRepository(db)
        assert repo.count_by_asset(1) == 5

    def test_delete_by_asset(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(count_val=3)
        repo = FindingRepository(db)
        assert repo.delete_by_asset(1) == 3
        assert db.commit.called
