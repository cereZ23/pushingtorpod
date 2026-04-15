"""Tests for scheduled scan dispatcher."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

import pytest


class TestIsDue:
    """Test cron evaluation logic."""

    def test_matching_cron_is_due(self):
        from app.tasks.scheduled_scans import _is_due

        profile = MagicMock()
        profile.schedule_cron = "* * * * *"  # every minute
        profile.project_id = 1
        profile.id = 1

        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None

        assert _is_due(profile, datetime.now(timezone.utc), db) is True

    def test_no_cron_not_due(self):
        from app.tasks.scheduled_scans import _is_due

        profile = MagicMock()
        profile.schedule_cron = "0 2 * * *"  # 2 AM only
        profile.project_id = 1
        profile.id = 1

        db = MagicMock()

        # Test at noon — should not be due
        noon = datetime(2026, 4, 15, 12, 30, 0, tzinfo=timezone.utc)
        assert _is_due(profile, noon, db) is False

    def test_recent_scan_prevents_retrigger(self):
        from app.tasks.scheduled_scans import _is_due

        profile = MagicMock()
        profile.schedule_cron = "* * * * *"
        profile.project_id = 1
        profile.id = 1

        last_scan = MagicMock()
        last_scan.completed_at = datetime.now(timezone.utc) - timedelta(minutes=5)

        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.first.return_value = last_scan

        assert _is_due(profile, datetime.now(timezone.utc), db) is False

    def test_invalid_cron_not_due(self):
        from app.tasks.scheduled_scans import _is_due

        profile = MagicMock()
        profile.schedule_cron = "invalid cron"
        profile.project_id = 1
        profile.id = 1

        db = MagicMock()
        assert _is_due(profile, datetime.now(timezone.utc), db) is False
