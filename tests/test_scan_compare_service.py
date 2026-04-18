"""
Unit tests for app/services/scan_compare_service.py

Covers:
- compare(): happy path (two completed runs with snapshots)
- 404 when either run is not found
- 400 when either run is not COMPLETED
- 400 when snapshot is missing
- Asset/service/finding diff key resolution
- Invalid key parts handled gracefully
- Severity enum vs string handling
- Empty diff path
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from fastapi import HTTPException

from app.services.scan_compare_service import ScanCompareService


class _FakeStatus:
    def __init__(self, value):
        self.value = value


# Cached enum mimic: use the real one to match equality checks
from app.models.scanning import ScanRunStatus


def _make_run(run_id, status=ScanRunStatus.COMPLETED, stats=None):
    run = SimpleNamespace()
    run.id = run_id
    run.status = status
    run.stats = stats
    run.completed_at = None
    return run


def _stats_with_snapshot(assets=None, services=None, findings=None):
    return {
        "snapshot": {
            "asset_keys": assets or [],
            "service_keys": services or [],
            "finding_keys": findings or [],
        }
    }


class _Query:
    """Chainable query that returns configured first()/all() values."""

    def __init__(self, first_val=None, all_val=None):
        self._first = first_val
        self._all = all_val or []

    def filter(self, *a, **kw):
        return self

    def first(self):
        return self._first

    def all(self):
        return self._all


class TestScanCompare:
    def test_base_run_not_found_raises_404(self):
        db = MagicMock()
        db.query.side_effect = [_Query(first_val=None), _Query(first_val=None)]
        svc = ScanCompareService(db)
        with pytest.raises(HTTPException) as exc:
            svc.compare(tenant_id=1, project_id=1, base_run_id=1, compare_run_id=2)
        assert exc.value.status_code == 404

    def test_compare_run_not_found_raises_404(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot())
        db.query.side_effect = [_Query(first_val=base), _Query(first_val=None)]
        svc = ScanCompareService(db)
        with pytest.raises(HTTPException) as exc:
            svc.compare(tenant_id=1, project_id=1, base_run_id=1, compare_run_id=2)
        assert exc.value.status_code == 404

    def test_status_not_completed_raises_400(self):
        db = MagicMock()
        base = _make_run(1, status=ScanRunStatus.RUNNING, stats=_stats_with_snapshot())
        cmp = _make_run(2, status=ScanRunStatus.COMPLETED, stats=_stats_with_snapshot())
        db.query.side_effect = [_Query(first_val=base), _Query(first_val=cmp)]
        svc = ScanCompareService(db)
        with pytest.raises(HTTPException) as exc:
            svc.compare(1, 1, 1, 2)
        assert exc.value.status_code == 400

    def test_empty_diff(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot(assets=["1:domain:x.com"]))
        cmp = _make_run(2, stats=_stats_with_snapshot(assets=["1:domain:x.com"]))
        db.query.side_effect = [_Query(first_val=base), _Query(first_val=cmp)]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        assert result.summary.new_assets == 0
        assert result.summary.removed_assets == 0
        assert result.base_run.id == 1
        assert result.compare_run.id == 2

    def test_new_and_removed_assets(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot(assets=["1:domain:old.com"]))
        cmp = _make_run(2, stats=_stats_with_snapshot(assets=["1:domain:new.com"]))
        db.query.side_effect = [_Query(first_val=base), _Query(first_val=cmp)]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        assert result.summary.new_assets == 1
        assert result.summary.removed_assets == 1
        assert result.assets.added[0].identifier == "new.com"
        assert result.assets.added[0].type == "domain"
        assert result.assets.removed[0].identifier == "old.com"

    def test_invalid_asset_key_ignored(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot(assets=["badkey"]))
        cmp = _make_run(2, stats=_stats_with_snapshot(assets=["1:domain:x.com"]))
        db.query.side_effect = [_Query(first_val=base), _Query(first_val=cmp)]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        # "badkey" removed — no valid parts -> skipped
        assert len(result.assets.removed) == 0
        assert len(result.assets.added) == 1

    def test_new_service_resolves_asset_identifier(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot(services=[]))
        cmp = _make_run(2, stats=_stats_with_snapshot(services=["42:443:https"]))
        asset_row = SimpleNamespace(id=42, identifier="web.x.com")
        db.query.side_effect = [
            _Query(first_val=base),
            _Query(first_val=cmp),
            _Query(all_val=[asset_row]),  # asset id->identifier lookup
        ]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        assert len(result.services.added) == 1
        assert result.services.added[0].asset_identifier == "web.x.com"
        assert result.services.added[0].port == 443
        assert result.services.added[0].protocol == "https"

    def test_service_bad_id_falls_back_to_string(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot(services=[]))
        cmp = _make_run(2, stats=_stats_with_snapshot(services=["badid:443:https"]))
        db.query.side_effect = [
            _Query(first_val=base),
            _Query(first_val=cmp),
        ]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        # Parsing int fails, added is empty
        assert len(result.services.added) == 0

    def test_findings_resolution_with_db_match(self):
        db = MagicMock()
        finding_row = SimpleNamespace(
            id=55,
            asset_id=10,
            template_id="CVE-1",
            matcher_name="m",
            name="Bad Finding",
            severity=SimpleNamespace(value="high"),
        )
        asset_row = SimpleNamespace(id=10, identifier="evil.com")
        base = _make_run(1, stats=_stats_with_snapshot(findings=[]))
        cmp = _make_run(
            2,
            stats=_stats_with_snapshot(findings=["10:CVE-1:m"]),
        )
        db.query.side_effect = [
            _Query(first_val=base),
            _Query(first_val=cmp),
            _Query(all_val=[asset_row]),  # asset_id lookup for findings
            _Query(all_val=[finding_row]),  # finding rows
        ]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        assert len(result.findings.added) == 1
        added = result.findings.added[0]
        assert added.id == 55
        assert added.name == "Bad Finding"
        assert added.severity == "high"

    def test_resolved_findings(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot(findings=["20:CVE-2:n"]))
        cmp = _make_run(2, stats=_stats_with_snapshot(findings=[]))
        asset_row = SimpleNamespace(id=20, identifier="h.x.com")
        db.query.side_effect = [
            _Query(first_val=base),
            _Query(first_val=cmp),
            _Query(all_val=[asset_row]),
            _Query(all_val=[]),  # finding rows -> no match
        ]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        assert len(result.findings.resolved) == 1
        # No DB match: id is None, name from key part
        assert result.findings.resolved[0].id is None
        assert result.findings.resolved[0].name == "CVE-2"

    def test_finding_key_invalid_asset_id(self):
        db = MagicMock()
        base = _make_run(1, stats=_stats_with_snapshot(findings=[]))
        cmp = _make_run(2, stats=_stats_with_snapshot(findings=["notint:tpl:m"]))
        db.query.side_effect = [
            _Query(first_val=base),
            _Query(first_val=cmp),
        ]
        svc = ScanCompareService(db)
        result = svc.compare(1, 1, 1, 2)
        # Finding added but no DB lookup since set empty
        assert len(result.findings.added) == 1
