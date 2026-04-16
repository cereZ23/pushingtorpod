"""
Unit tests for app/tasks/diff_alert.py

Covers pure helpers:
- _build_snapshot from active assets, services, open findings
- _snapshot_from_stats from stored JSON dict
- _compute_diff: new/removed/suspicious detection
- RunSnapshot / DiffResult dataclasses
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app.models.database import AssetType, FindingSeverity, FindingStatus
from app.tasks.diff_alert import (
    DiffResult,
    RunSnapshot,
    _build_snapshot,
    _compute_diff,
    _snapshot_from_stats,
)


def _asset(id_, type_=AssetType.SUBDOMAIN, identifier="x", raw_metadata=None):
    a = SimpleNamespace()
    a.id = id_
    a.type = type_
    a.identifier = identifier
    a.raw_metadata = raw_metadata
    a.is_active = True
    return a


def _service(id_, asset_id, port, protocol):
    s = SimpleNamespace()
    s.id = id_
    s.asset_id = asset_id
    s.port = port
    s.protocol = protocol
    return s


def _finding(id_, asset_id, template_id, matcher_name):
    f = SimpleNamespace()
    f.id = id_
    f.asset_id = asset_id
    f.template_id = template_id
    f.matcher_name = matcher_name
    f.status = FindingStatus.OPEN
    f.severity = FindingSeverity.HIGH
    return f


class _Query:
    def __init__(self, items):
        self.items = items

    def filter(self, *a, **kw):
        return self

    def join(self, *a, **kw):
        return self

    def all(self):
        return self.items


class TestRunSnapshot:
    def test_defaults(self):
        s = RunSnapshot()
        assert s.asset_keys == set()
        assert s.service_keys == set()
        assert s.finding_keys == set()
        assert s.content_hashes == {}

    def test_independent_instances(self):
        a = RunSnapshot()
        a.asset_keys.add("x")
        b = RunSnapshot()
        assert "x" not in b.asset_keys


class TestDiffResult:
    def test_defaults(self):
        d = DiffResult()
        assert d.new_assets == []
        assert d.is_suspicious is False


class TestComputeDiff:
    def test_new_and_removed_assets(self):
        prev = RunSnapshot(asset_keys={"1:domain:a.com", "1:domain:b.com"})
        curr = RunSnapshot(asset_keys={"1:domain:b.com", "1:domain:c.com"})
        logger = MagicMock()
        diff = _compute_diff(curr, prev, logger)
        assert set(diff.new_assets) == {"1:domain:c.com"}
        assert set(diff.removed_assets) == {"1:domain:a.com"}
        assert diff.is_suspicious is False

    def test_new_and_removed_services(self):
        prev = RunSnapshot(service_keys={"10:443:https"})
        curr = RunSnapshot(service_keys={"10:80:http"})
        logger = MagicMock()
        diff = _compute_diff(curr, prev, logger)
        assert set(diff.new_services) == {"10:80:http"}
        assert set(diff.removed_services) == {"10:443:https"}

    def test_new_and_resolved_findings(self):
        prev = RunSnapshot(finding_keys={"10:tpl1:m1"})
        curr = RunSnapshot(finding_keys={"10:tpl2:m2"})
        logger = MagicMock()
        diff = _compute_diff(curr, prev, logger)
        assert set(diff.new_findings) == {"10:tpl2:m2"}
        assert set(diff.resolved_findings) == {"10:tpl1:m1"}

    def test_suspicious_when_more_than_half_removed(self):
        prev = RunSnapshot(asset_keys={f"1:d:{i}" for i in range(10)})
        # Remove 6 out of 10 -> suspicious
        curr = RunSnapshot(asset_keys={f"1:d:{i}" for i in range(4)})
        logger = MagicMock()
        diff = _compute_diff(curr, prev, logger)
        assert diff.is_suspicious is True

    def test_not_suspicious_when_exactly_half(self):
        prev = RunSnapshot(asset_keys={f"1:d:{i}" for i in range(10)})
        # Remove 5 out of 10 -> NOT suspicious (must be strictly > 0.5)
        curr = RunSnapshot(asset_keys={f"1:d:{i}" for i in range(5)})
        logger = MagicMock()
        diff = _compute_diff(curr, prev, logger)
        assert diff.is_suspicious is False

    def test_no_previous_assets_never_suspicious(self):
        prev = RunSnapshot(asset_keys=set())
        curr = RunSnapshot(asset_keys={"1:d:a", "1:d:b"})
        logger = MagicMock()
        diff = _compute_diff(curr, prev, logger)
        assert diff.is_suspicious is False


class TestSnapshotFromStats:
    def test_empty_stats(self):
        s = _snapshot_from_stats({})
        assert s.asset_keys == set()
        assert s.service_keys == set()
        assert s.finding_keys == set()

    def test_populated_snapshot(self):
        stats = {
            "snapshot": {
                "asset_keys": ["1:d:a.com"],
                "service_keys": ["5:443:https"],
                "finding_keys": ["5:t:m"],
            }
        }
        s = _snapshot_from_stats(stats)
        assert s.asset_keys == {"1:d:a.com"}
        assert s.service_keys == {"5:443:https"}
        assert s.finding_keys == {"5:t:m"}

    def test_missing_keys_defaults_empty(self):
        stats = {"snapshot": {}}
        s = _snapshot_from_stats(stats)
        assert s.asset_keys == set()


class TestBuildSnapshot:
    def test_empty_tenant(self):
        db = MagicMock()
        db.query.side_effect = [_Query([]), _Query([]), _Query([])]
        snap = _build_snapshot(db, tenant_id=1)
        assert snap.asset_keys == set()

    def test_builds_asset_service_finding_keys(self):
        db = MagicMock()
        a1 = _asset(1, AssetType.DOMAIN, "x.com", raw_metadata='{"key":"val"}')
        a2 = _asset(2, AssetType.SUBDOMAIN, "y.x.com")
        s1 = _service(10, 1, 443, "https")
        f1 = _finding(100, 1, "tpl1", "m1")
        db.query.side_effect = [_Query([a1, a2]), _Query([s1]), _Query([f1])]

        snap = _build_snapshot(db, tenant_id=1)
        assert "1:domain:x.com" in snap.asset_keys
        assert "1:subdomain:y.x.com" in snap.asset_keys
        assert "1:443:https" in snap.service_keys
        assert "1:tpl1:m1" in snap.finding_keys
        # content hash populated only for asset with raw_metadata
        assert "1:domain:x.com" in snap.content_hashes
        assert "1:subdomain:y.x.com" not in snap.content_hashes
