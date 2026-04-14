"""Tests for auto-close stale nuclei findings in phase 10."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus
from app.models.scanning import ScanRun


class TestAutoCloseStaleFindings:
    def test_stale_nuclei_finding_closed(self, db_session, test_tenant):
        """Findings not seen in 48h+ are auto-closed."""
        asset = Asset(tenant_id=test_tenant.id, identifier="stale.test.com", type=AssetType.SUBDOMAIN, is_active=True)
        db_session.add(asset)
        db_session.commit()
        db_session.refresh(asset)

        old_finding = Finding(
            asset_id=asset.id,
            name="Old vuln",
            source="nuclei",
            severity=FindingSeverity.HIGH,
            status=FindingStatus.OPEN,
            last_seen=datetime.now(timezone.utc) - timedelta(days=5),
        )
        db_session.add(old_finding)
        db_session.commit()
        db_session.refresh(old_finding)

        scan_run = ScanRun(tenant_id=test_tenant.id, status="running", started_at=datetime.now(timezone.utc))
        db_session.add(scan_run)
        db_session.commit()
        db_session.refresh(scan_run)

        # Simulate phase 10 auto-close logic
        from app.tasks.pipeline_phases.detection import _phase_10_correlation
        from unittest.mock import patch, MagicMock
        from app.utils.logger import TenantLoggerAdapter
        import logging

        tenant_logger = TenantLoggerAdapter(logging.getLogger("test"), {"tenant_id": test_tenant.id})

        with patch("app.tasks.correlation.run_correlation", return_value={"issues_created": 0}):
            result = _phase_10_correlation(test_tenant.id, None, scan_run.id, db_session, tenant_logger)

        db_session.refresh(old_finding)
        assert old_finding.status == FindingStatus.FIXED

    def test_recent_finding_not_closed(self, db_session, test_tenant):
        """Findings seen recently are NOT closed."""
        asset = Asset(tenant_id=test_tenant.id, identifier="recent.test.com", type=AssetType.SUBDOMAIN, is_active=True)
        db_session.add(asset)
        db_session.commit()
        db_session.refresh(asset)

        recent_finding = Finding(
            asset_id=asset.id,
            name="Recent vuln",
            source="nuclei",
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.OPEN,
            last_seen=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        db_session.add(recent_finding)
        db_session.commit()
        db_session.refresh(recent_finding)

        scan_run = ScanRun(tenant_id=test_tenant.id, status="running", started_at=datetime.now(timezone.utc))
        db_session.add(scan_run)
        db_session.commit()
        db_session.refresh(scan_run)

        from app.tasks.pipeline_phases.detection import _phase_10_correlation
        from unittest.mock import patch
        from app.utils.logger import TenantLoggerAdapter
        import logging

        tenant_logger = TenantLoggerAdapter(logging.getLogger("test"), {"tenant_id": test_tenant.id})

        with patch("app.tasks.correlation.run_correlation", return_value={"issues_created": 0}):
            _phase_10_correlation(test_tenant.id, None, scan_run.id, db_session, tenant_logger)

        db_session.refresh(recent_finding)
        assert recent_finding.status == FindingStatus.OPEN

    def test_misconfig_finding_not_touched(self, db_session, test_tenant):
        """Misconfig findings are handled by their own auto-close, not this one."""
        asset = Asset(
            tenant_id=test_tenant.id, identifier="misconfig.test.com", type=AssetType.SUBDOMAIN, is_active=True
        )
        db_session.add(asset)
        db_session.commit()
        db_session.refresh(asset)

        misconfig_finding = Finding(
            asset_id=asset.id,
            name="Missing header",
            source="misconfig",
            severity=FindingSeverity.MEDIUM,
            status=FindingStatus.OPEN,
            last_seen=datetime.now(timezone.utc) - timedelta(days=5),
        )
        db_session.add(misconfig_finding)
        db_session.commit()
        db_session.refresh(misconfig_finding)

        scan_run = ScanRun(tenant_id=test_tenant.id, status="running", started_at=datetime.now(timezone.utc))
        db_session.add(scan_run)
        db_session.commit()
        db_session.refresh(scan_run)

        from app.tasks.pipeline_phases.detection import _phase_10_correlation
        from unittest.mock import patch
        from app.utils.logger import TenantLoggerAdapter
        import logging

        tenant_logger = TenantLoggerAdapter(logging.getLogger("test"), {"tenant_id": test_tenant.id})

        with patch("app.tasks.correlation.run_correlation", return_value={"issues_created": 0}):
            _phase_10_correlation(test_tenant.id, None, scan_run.id, db_session, tenant_logger)

        db_session.refresh(misconfig_finding)
        assert misconfig_finding.status == FindingStatus.OPEN
