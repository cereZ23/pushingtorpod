"""
Unit tests for app/repositories/asset_repository.py and EventRepository.

Covers pure-logic paths using mocked Session:
- get_by_id / get_by_identifier
- get_by_identifiers_bulk (empty, single type, multiple types)
- get_by_tenant (with/without filters, eager load)
- count_by_tenant
- bulk_upsert (empty, skeleton happy path via mocked execute/fetchall)
- create_batch
- update_risk_score (found/not found)
- mark_inactive
- get_critical_assets
- EventRepository.create_event, create_batch, get_by_asset, get_recent_by_tenant
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.models.database import Asset, AssetType, Event, EventKind
from app.repositories.asset_repository import AssetRepository, EventRepository


class _ChainQuery:
    def __init__(self, *, first_val=None, all_val=None, count_val=0):
        self._first = first_val
        self._all = all_val or []
        self._count = count_val

    def filter(self, *a, **kw):
        return self

    def filter_by(self, *a, **kw):
        return self

    def join(self, *a, **kw):
        return self

    def order_by(self, *a, **kw):
        return self

    def limit(self, *a, **kw):
        return self

    def offset(self, *a, **kw):
        return self

    def options(self, *a, **kw):
        return self

    def first(self):
        return self._first

    def all(self):
        return self._all

    def count(self):
        return self._count

    def update(self, *a, **kw):
        return 0


class TestAssetRepositoryGetters:
    def test_get_by_id_found(self):
        db = MagicMock()
        asset = SimpleNamespace(id=1)
        db.query.return_value = _ChainQuery(first_val=asset)
        repo = AssetRepository(db)
        assert repo.get_by_id(1) is asset

    def test_get_by_id_not_found(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=None)
        repo = AssetRepository(db)
        assert repo.get_by_id(1) is None

    def test_get_by_identifier_found(self):
        db = MagicMock()
        asset = SimpleNamespace()
        db.query.return_value = _ChainQuery(first_val=asset)
        repo = AssetRepository(db)
        result = repo.get_by_identifier(1, "x.com", AssetType.DOMAIN)
        assert result is asset


class TestBulkIdentifiers:
    def test_empty_dict(self):
        repo = AssetRepository(MagicMock())
        assert repo.get_by_identifiers_bulk(1, {}) == {}

    def test_empty_lists(self):
        repo = AssetRepository(MagicMock())
        assert repo.get_by_identifiers_bulk(1, {AssetType.DOMAIN: []}) == {}

    def test_single_type(self):
        db = MagicMock()
        a1 = SimpleNamespace(identifier="x.com", type=AssetType.DOMAIN)
        db.query.return_value = _ChainQuery(all_val=[a1])
        repo = AssetRepository(db)
        result = repo.get_by_identifiers_bulk(1, {AssetType.DOMAIN: ["x.com"]})
        assert ("x.com", AssetType.DOMAIN) in result

    def test_multiple_types(self):
        db = MagicMock()
        a1 = SimpleNamespace(identifier="x.com", type=AssetType.DOMAIN)
        a2 = SimpleNamespace(identifier="1.1.1.1", type=AssetType.IP)
        db.query.return_value = _ChainQuery(all_val=[a1, a2])
        repo = AssetRepository(db)
        result = repo.get_by_identifiers_bulk(1, {AssetType.DOMAIN: ["x.com"], AssetType.IP: ["1.1.1.1"]})
        assert len(result) == 2


class TestGetByTenant:
    def test_no_filter_active(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[SimpleNamespace(id=1)])
        repo = AssetRepository(db)
        assert len(repo.get_by_tenant(1)) == 1

    def test_with_type_filter(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = AssetRepository(db)
        assert repo.get_by_tenant(1, asset_type=AssetType.DOMAIN) == []

    def test_with_eager_load(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = AssetRepository(db)
        assert repo.get_by_tenant(1, eager_load_relations=True) == []


class TestCounts:
    def test_count_by_tenant(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(count_val=42)
        repo = AssetRepository(db)
        assert repo.count_by_tenant(1) == 42


class TestBulkUpsert:
    def test_empty(self):
        repo = AssetRepository(MagicMock())
        result = repo.bulk_upsert(1, [])
        assert result == {"created": 0, "updated": 0, "total_processed": 0}

    def test_happy_path_skeleton(self):
        db = MagicMock()
        now = datetime.now(timezone.utc)
        returning_rows = [(1, now), (2, now)]  # recent -> created

        exec_result = MagicMock()
        exec_result.fetchall.return_value = returning_rows
        db.execute.return_value = exec_result
        repo = AssetRepository(db)
        data = [
            {"identifier": "x.com", "type": AssetType.DOMAIN, "raw_metadata": {}},
            {"identifier": "y.com", "type": AssetType.DOMAIN, "raw_metadata": {}},
        ]
        result = repo.bulk_upsert(1, data)
        assert result["total_processed"] == 2
        # Both first_seen are current -> both created
        assert result["created"] == 2

    def test_updated_detection_when_first_seen_old(self):
        db = MagicMock()
        old = datetime(2020, 1, 1, tzinfo=timezone.utc)
        exec_result = MagicMock()
        exec_result.fetchall.return_value = [(1, old)]
        db.execute.return_value = exec_result
        repo = AssetRepository(db)
        data = [{"identifier": "x.com", "type": AssetType.DOMAIN}]
        result = repo.bulk_upsert(1, data)
        assert result["updated"] == 1
        assert result["created"] == 0

    def test_handles_naive_datetime(self):
        db = MagicMock()
        # Return a naive datetime (no tzinfo) — should be converted to UTC
        naive = datetime(2020, 1, 1)
        exec_result = MagicMock()
        exec_result.fetchall.return_value = [(1, naive)]
        db.execute.return_value = exec_result
        repo = AssetRepository(db)
        result = repo.bulk_upsert(1, [{"identifier": "x", "type": AssetType.DOMAIN}])
        assert result["updated"] == 1


class TestSimpleOps:
    def test_create_batch(self):
        db = MagicMock()
        assets = [SimpleNamespace(id=None), SimpleNamespace(id=None)]
        repo = AssetRepository(db)
        result = repo.create_batch(assets)
        db.add_all.assert_called_once_with(assets)
        db.flush.assert_called_once()
        assert result == assets

    def test_update_risk_score_found(self):
        db = MagicMock()
        asset = SimpleNamespace(risk_score=None)
        db.query.return_value = _ChainQuery(first_val=asset)
        repo = AssetRepository(db)
        repo.update_risk_score(1, 75.0)
        assert asset.risk_score == 75.0

    def test_update_risk_score_not_found(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(first_val=None)
        repo = AssetRepository(db)
        # should not raise
        repo.update_risk_score(999, 75.0)

    def test_mark_inactive(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery()
        repo = AssetRepository(db)
        repo.mark_inactive([1, 2, 3])
        db.commit.assert_called_once()

    def test_get_critical_assets(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[SimpleNamespace(id=1)])
        repo = AssetRepository(db)
        assert len(repo.get_critical_assets(1)) == 1

    def test_get_critical_assets_eager(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = AssetRepository(db)
        assert repo.get_critical_assets(1, eager_load_relations=True) == []


class TestEventRepository:
    def test_create_event(self):
        db = MagicMock()
        repo = EventRepository(db)
        repo.create_event(1, EventKind.NEW_ASSET, {"a": 1})
        db.add.assert_called_once()
        db.flush.assert_called_once()

    def test_create_batch(self):
        db = MagicMock()
        events = [SimpleNamespace(), SimpleNamespace()]
        repo = EventRepository(db)
        repo.create_batch(events)
        db.add_all.assert_called_once_with(events)

    def test_get_by_asset(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[SimpleNamespace(id=1)])
        repo = EventRepository(db)
        results = repo.get_by_asset(1)
        assert len(results) == 1

    def test_get_recent_by_tenant_no_filter(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[SimpleNamespace(id=1)])
        repo = EventRepository(db)
        results = repo.get_recent_by_tenant(1, hours=24)
        assert len(results) == 1

    def test_get_recent_by_tenant_with_kinds(self):
        db = MagicMock()
        db.query.return_value = _ChainQuery(all_val=[])
        repo = EventRepository(db)
        results = repo.get_recent_by_tenant(1, hours=48, event_kinds=[EventKind.NEW_ASSET])
        assert results == []
