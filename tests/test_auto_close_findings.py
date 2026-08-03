"""Auto-close of stale nuclei findings (phase 10), gated by the discovery-health guard."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus
from app.models.scanning import PhaseResult, PhaseStatus, ScanRun, ScanRunStatus
from app.services.discovery_health import discovery_scope_hash
from app.utils.logger import TenantLoggerAdapter

_LOG = TenantLoggerAdapter(logging.getLogger("test"), {"tenant_id": 0})


def _asset(db, tenant, ident):
    a = Asset(tenant_id=tenant.id, identifier=ident, type=AssetType.SUBDOMAIN, is_active=True)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _finding(db, asset_id, *, source, age_days):
    f = Finding(
        asset_id=asset_id,
        name="vuln",
        source=source,
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        last_seen=datetime.now(timezone.utc) - timedelta(days=age_days),
    )
    db.add(f)
    db.commit()
    db.refresh(f)
    return f


def _run(db, tenant, *, status="running", stats=None):
    r = ScanRun(tenant_id=tenant.id, status=status, started_at=datetime.now(timezone.utc), stats=stats)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _healthy_discovery(db, tenant, current_run, *, observed=5):
    """Make the guard AUTHORIZE closing: discovery phases COMPLETED + a comparable
    healthy baseline that observed >0 assets (same scope, project_id=None)."""
    db.add_all(
        [
            PhaseResult(scan_run_id=current_run.id, phase="1", status=PhaseStatus.COMPLETED),
            PhaseResult(
                scan_run_id=current_run.id, phase="3", status=PhaseStatus.COMPLETED, stats={"items_succeeded": observed}
            ),
        ]
    )
    scope_hash = discovery_scope_hash([], [])  # project_id=None → empty seeds/scopes
    baseline = ScanRun(
        tenant_id=tenant.id,
        status=ScanRunStatus.COMPLETED,
        started_at=datetime.now(timezone.utc) - timedelta(days=1),
        completed_at=datetime.now(timezone.utc) - timedelta(days=1),
        stats={"discovery_health": {"healthy": True, "observed_count": observed}, "discovery_scope_hash": scope_hash},
    )
    db.add(baseline)
    db.commit()


def _run_phase10(db, tenant, scan_run):
    from app.tasks.pipeline_phases.detection import _phase_10_correlation

    with patch("app.tasks.correlation.run_correlation", return_value={"issues_created": 0}):
        return _phase_10_correlation(tenant.id, None, scan_run.id, db, _LOG)


class TestAutoCloseStaleFindings:
    def test_stale_nuclei_not_closed_legacy_disabled(self, db_session, test_tenant):
        # Legacy tenant-wide nuclei closer is DISABLED (endpoint findings would false-FIX now that
        # HTTP-stock scans base URLs only). A stale nuclei finding stays OPEN even when discovery
        # authorizes closing; the coverage-aware close is shadow-only.
        asset = _asset(db_session, test_tenant, "stale.test.com")
        old = _finding(db_session, asset.id, source="nuclei", age_days=5)
        run = _run(db_session, test_tenant)
        _healthy_discovery(db_session, test_tenant, run)  # would authorize, but closers are off

        result = _run_phase10(db_session, test_tenant, run)

        db_session.refresh(old)
        assert old.status == FindingStatus.OPEN  # NOT closed — better false-open than false-fixed
        assert result["nuclei_auto_closed"] == 0

    def test_recent_finding_not_closed(self, db_session, test_tenant):
        asset = _asset(db_session, test_tenant, "recent.test.com")
        recent = _finding(db_session, asset.id, source="nuclei", age_days=0)
        run = _run(db_session, test_tenant)
        _healthy_discovery(db_session, test_tenant, run)

        _run_phase10(db_session, test_tenant, run)

        db_session.refresh(recent)
        assert recent.status == FindingStatus.OPEN

    def test_stale_misconfig_not_closed_legacy_disabled(self, db_session, test_tenant):
        # The legacy misconfig closer is also disabled while the coverage-aware consumer is in
        # shadow: a stale misconfig finding stays OPEN.
        asset = _asset(db_session, test_tenant, "misconfig.test.com")
        mc = _finding(db_session, asset.id, source="misconfig", age_days=5)
        run = _run(db_session, test_tenant)
        _healthy_discovery(db_session, test_tenant, run)

        result = _run_phase10(db_session, test_tenant, run)

        db_session.refresh(mc)
        assert mc.status == FindingStatus.OPEN
        assert result["misconfig_auto_closed"] == 0

    def test_misconfig_recent_not_closed_in_phase10(self, db_session, test_tenant):
        asset = _asset(db_session, test_tenant, "mc-recent.test.com")
        mc = _finding(db_session, asset.id, source="misconfig", age_days=0)  # seen this run
        run = _run(db_session, test_tenant)
        _healthy_discovery(db_session, test_tenant, run)

        _run_phase10(db_session, test_tenant, run)

        db_session.refresh(mc)
        assert mc.status == FindingStatus.OPEN

    def test_shadow_runs_before_correlation(self, db_session, test_tenant):
        # The coverage-aware consumer must still run — in SHADOW — and strictly BEFORE correlation
        # (it has to observe the full open set before anything could ever be closed).
        from app.tasks.pipeline_phases.detection import _phase_10_correlation

        asset = _asset(db_session, test_tenant, "shadow.test.com")
        _finding(db_session, asset.id, source="nuclei", age_days=5)
        run = _run(db_session, test_tenant)
        _healthy_discovery(db_session, test_tenant, run)

        order = []

        def _shadow(*a, **k):
            order.append("shadow")
            return {"decisions": {}, "would_close_ids": []}

        def _corr(*a, **k):
            order.append("correlation")
            return {"issues_created": 0}

        with (
            patch("app.services.coverage_autoclose.shadow_auto_close", _shadow),
            patch("app.tasks.correlation.run_correlation", _corr),
        ):
            _phase_10_correlation(test_tenant.id, None, run.id, db_session, _LOG)

        assert order == ["shadow", "correlation"]


class TestDiscoveryHealthGuardBlocksClose:
    def test_not_closed_when_discovery_incomplete(self, db_session, test_tenant):
        """No discovery PhaseResults → DISCOVERY_INCOMPLETE → fail-closed, no close."""
        asset = _asset(db_session, test_tenant, "incomplete.test.com")
        old = _finding(db_session, asset.id, source="nuclei", age_days=5)
        run = _run(db_session, test_tenant)  # no PhaseResults, no baseline

        _run_phase10(db_session, test_tenant, run)

        db_session.refresh(old)
        assert old.status == FindingStatus.OPEN  # guard refused to close

    def test_not_closed_when_no_baseline(self, db_session, test_tenant):
        """Discovery COMPLETED but first-ever comparable run → not authorized to close."""
        asset = _asset(db_session, test_tenant, "nobaseline.test.com")
        old = _finding(db_session, asset.id, source="nuclei", age_days=5)
        run = _run(db_session, test_tenant)
        db_session.add_all(
            [
                PhaseResult(scan_run_id=run.id, phase="1", status=PhaseStatus.COMPLETED),
                PhaseResult(scan_run_id=run.id, phase="3", status=PhaseStatus.COMPLETED, stats={"items_succeeded": 5}),
            ]
        )
        db_session.commit()  # completed discovery but NO prior baseline

        _run_phase10(db_session, test_tenant, run)

        db_session.refresh(old)
        assert old.status == FindingStatus.OPEN  # no comparable baseline → don't close

    def test_persisted_verdict_survives(self, db_session, test_tenant):
        """The discovery_health verdict is persisted on the run for the next baseline."""
        run = _run(db_session, test_tenant)
        _healthy_discovery(db_session, test_tenant, run)

        _run_phase10(db_session, test_tenant, run)

        db_session.refresh(run)
        assert run.stats and run.stats.get("discovery_health", {}).get("healthy") is True
        assert run.stats.get("discovery_scope_hash")


class TestAutoCloseAuthorization:
    """The shared verdict helper that BOTH the nuclei and misconfig closes gate on."""

    def test_missing_run_is_fail_closed(self, db_session, test_tenant):
        from app.services.discovery_health import evaluate_and_persist_discovery_health

        h = evaluate_and_persist_discovery_health(db_session, test_tenant.id, None, 999_999_999)
        assert h.auto_close_allowed is False  # no run → never authorize (misconfig manual-run case)

    def test_incomplete_discovery_is_fail_closed(self, db_session, test_tenant):
        from app.services.discovery_health import evaluate_and_persist_discovery_health

        run = _run(db_session, test_tenant)  # no PhaseResults → INCOMPLETE
        h = evaluate_and_persist_discovery_health(db_session, test_tenant.id, None, run.id)
        assert h.auto_close_allowed is False
        assert h.reason_code == "discovery_incomplete"

    def test_healthy_run_is_authorized(self, db_session, test_tenant):
        from app.services.discovery_health import evaluate_and_persist_discovery_health

        run = _run(db_session, test_tenant)
        _healthy_discovery(db_session, test_tenant, run)
        h = evaluate_and_persist_discovery_health(db_session, test_tenant.id, None, run.id)
        assert h.auto_close_allowed is True
