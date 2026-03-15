"""Tests for scan comparison (diff) endpoint."""

import pytest
from unittest.mock import MagicMock, patch
from datetime import datetime, timezone

from app.api.schemas.scan_diff import (
    ScanCompareResponse,
    ScanRunSummary,
    DiffSummary,
    DiffAssets,
    DiffAssetItem,
    DiffServices,
    DiffServiceItem,
    DiffFindings,
    DiffFindingItem,
)
from app.tasks.diff_alert import _snapshot_from_stats, _compute_diff, RunSnapshot


class TestSnapshotFromStats:
    """Test _snapshot_from_stats key reconstruction."""

    def test_empty_stats(self):
        snapshot = _snapshot_from_stats({})
        assert snapshot.asset_keys == set()
        assert snapshot.service_keys == set()
        assert snapshot.finding_keys == set()

    def test_missing_snapshot_key(self):
        snapshot = _snapshot_from_stats({"foo": "bar"})
        assert snapshot.asset_keys == set()

    def test_restores_keys(self):
        stats = {
            "snapshot": {
                "asset_keys": ["1:subdomain:a.example.com", "1:domain:example.com"],
                "service_keys": ["10:443:tcp", "10:80:tcp"],
                "finding_keys": ["10:cve-2024-1234:default"],
            }
        }
        snapshot = _snapshot_from_stats(stats)
        assert len(snapshot.asset_keys) == 2
        assert "1:subdomain:a.example.com" in snapshot.asset_keys
        assert len(snapshot.service_keys) == 2
        assert len(snapshot.finding_keys) == 1


class TestComputeDiff:
    """Test _compute_diff set logic."""

    def _make_logger(self):
        from app.utils.logger import TenantLoggerAdapter
        import logging

        return TenantLoggerAdapter(logging.getLogger("test"), {"tenant_id": 1})

    def test_identical_snapshots(self):
        s = RunSnapshot(
            asset_keys={"1:domain:example.com"},
            service_keys={"10:443:tcp"},
            finding_keys={"10:cve:default"},
        )
        diff = _compute_diff(s, s, self._make_logger())
        assert diff.new_assets == []
        assert diff.removed_assets == []
        assert diff.new_services == []
        assert diff.removed_services == []
        assert diff.new_findings == []
        assert diff.resolved_findings == []
        assert diff.is_suspicious is False

    def test_all_new(self):
        prev = RunSnapshot()
        curr = RunSnapshot(
            asset_keys={"1:domain:example.com"},
            service_keys={"10:443:tcp"},
            finding_keys={"10:cve:default"},
        )
        diff = _compute_diff(curr, prev, self._make_logger())
        assert len(diff.new_assets) == 1
        assert len(diff.new_services) == 1
        assert len(diff.new_findings) == 1
        assert len(diff.removed_assets) == 0

    def test_removed(self):
        prev = RunSnapshot(
            asset_keys={"1:domain:old.com"},
            service_keys={"5:3306:tcp"},
        )
        curr = RunSnapshot()
        diff = _compute_diff(curr, prev, self._make_logger())
        assert len(diff.removed_assets) == 1
        assert len(diff.removed_services) == 1
        assert diff.is_suspicious is True  # 100% removal

    def test_mixed_changes(self):
        prev = RunSnapshot(
            asset_keys={"1:domain:kept.com", "1:domain:removed.com"},
            service_keys={"10:80:tcp"},
            finding_keys={"10:cve-old:default"},
        )
        curr = RunSnapshot(
            asset_keys={"1:domain:kept.com", "1:subdomain:new.kept.com"},
            service_keys={"10:80:tcp", "10:443:tcp"},
            finding_keys={"10:cve-new:default"},
        )
        diff = _compute_diff(curr, prev, self._make_logger())
        assert "1:subdomain:new.kept.com" in diff.new_assets
        assert "1:domain:removed.com" in diff.removed_assets
        assert "10:443:tcp" in diff.new_services
        assert "10:cve-new:default" in diff.new_findings
        assert "10:cve-old:default" in diff.resolved_findings
        assert diff.is_suspicious is False  # only 50%, not >50%

    def test_suspicious_threshold(self):
        prev = RunSnapshot(
            asset_keys={"1:domain:a.com", "1:domain:b.com", "1:domain:c.com"},
        )
        curr = RunSnapshot(
            asset_keys={"1:domain:a.com"},
        )
        diff = _compute_diff(curr, prev, self._make_logger())
        assert diff.is_suspicious is True  # 2/3 > 50%


class TestScanDiffSchemas:
    """Test Pydantic response models."""

    def test_scan_compare_response_defaults(self):
        resp = ScanCompareResponse(
            base_run=ScanRunSummary(id=1, status="completed"),
            compare_run=ScanRunSummary(id=2, status="completed"),
            summary=DiffSummary(),
        )
        assert resp.is_suspicious is False
        assert resp.assets.added == []
        assert resp.assets.removed == []
        assert resp.services.added == []
        assert resp.findings.added == []

    def test_scan_compare_response_populated(self):
        resp = ScanCompareResponse(
            base_run=ScanRunSummary(
                id=5,
                status="completed",
                completed_at=datetime(2026, 3, 10, tzinfo=timezone.utc),
            ),
            compare_run=ScanRunSummary(
                id=7,
                status="completed",
                completed_at=datetime(2026, 3, 15, tzinfo=timezone.utc),
            ),
            is_suspicious=False,
            summary=DiffSummary(
                new_assets=3,
                removed_assets=1,
                new_services=5,
                removed_services=2,
                new_findings=8,
                resolved_findings=4,
            ),
            assets=DiffAssets(
                added=[DiffAssetItem(identifier="new.example.com", type="subdomain")],
                removed=[DiffAssetItem(identifier="old.example.com", type="subdomain")],
            ),
            services=DiffServices(
                added=[DiffServiceItem(asset_identifier="x.com", port=8080, protocol="tcp")],
                removed=[DiffServiceItem(asset_identifier="x.com", port=3306, protocol="tcp")],
            ),
            findings=DiffFindings(
                added=[DiffFindingItem(id=101, name="CVE-2024-1234", severity="critical", asset_identifier="x.com")],
                resolved=[DiffFindingItem(id=50, name="Weak TLS", severity="medium", asset_identifier="y.com")],
            ),
        )
        assert resp.summary.new_assets == 3
        assert len(resp.assets.added) == 1
        assert resp.assets.added[0].identifier == "new.example.com"
        assert resp.findings.added[0].severity == "critical"

    def test_diff_finding_item_optional_fields(self):
        item = DiffFindingItem()
        assert item.id is None
        assert item.name is None
        assert item.severity is None
        assert item.asset_identifier is None


class TestCompareEndpointTenantIsolation:
    """Verify the compare endpoint filters by tenant_id (source-level check)."""

    def test_endpoint_filters_by_tenant_id(self):
        """Source-level check: compare endpoint queries ScanRun with tenant_id filter."""
        import inspect
        from app.api.routers.projects import compare_scan_runs

        source = inspect.getsource(compare_scan_runs)
        assert "ScanRun.tenant_id == tenant_id" in source
        assert "ScanRunStatus.COMPLETED" in source
