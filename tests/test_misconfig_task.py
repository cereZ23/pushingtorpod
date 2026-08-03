"""Integration guard for the full ``run_misconfig_detection`` task.

The unit tests exercise the pieces (controls, coverage emit, pure helpers) but never run
the whole task, so a bug in code only reached at the END of a real run — like the
``auto_closed`` NameError in the completion log — slipped through green CI. This test runs
the task to completion against the test DB (no network) and asserts it does not raise.
"""

from __future__ import annotations

from datetime import datetime, timezone

import app.tasks.misconfig as mc
from app.config import settings
from app.models.database import Asset, AssetType
from app.models.scanning import ScanRun


def _noop_check(asset, services, certificates, db):
    return []


def test_run_misconfig_detection_reaches_completion(db_session, test_tenant, monkeypatch):
    # Redirect the task's own SessionLocal to the test session (and neutralise its close() so
    # the fixture transaction survives). Disable network probes and swap the real control set
    # for a single no-op control so the run is fast and offline but still executes the full
    # per-asset loop, the coverage emit, AND the completion log.
    monkeypatch.setattr(settings, "nonweb_exposure_enabled", False)
    monkeypatch.setattr(mc, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(db_session, "close", lambda: None)
    monkeypatch.setattr(
        mc,
        "_CONTROLS",
        {
            "TEST-001": {
                "id": "TEST-001",
                "name": "Test control",
                "severity": "low",
                "confidence": 1.0,
                "category": "test",
                "asset_types": ["subdomain"],
                "dedup_scope": "asset",
                "check_fn": _noop_check,
            }
        },
    )

    asset = Asset(tenant_id=test_tenant.id, identifier="mc-int.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    run = ScanRun(tenant_id=test_tenant.id, project_id=None, status="running", started_at=datetime.now(timezone.utc))
    db_session.add(run)
    db_session.commit()

    # Must run to completion (the completion-log path where the NameError lived) without raising.
    result = mc.run_misconfig_detection(test_tenant.id, scan_run_id=run.id)

    assert isinstance(result, dict)
    assert result.get("status") == "success"
    assert result.get("assets_checked", 0) >= 1
    assert result.get("findings_auto_closed") == 0  # phase-8 no longer closes (moved to phase 10)
