"""Pass-wiring emit — pure helpers, fail-open contract, and a DB round-trip.

The DB test uses the same Postgres conftest fixtures as test_coverage_repository;
the pure/fail-open tests need no DB and run anywhere.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.services import coverage_emit
from app.services.coverage_emit import _split_roots, emit_nuclei_pass_coverage
from app.services.rule_revision import RuleResolutionError


# --- pure: root splitting (stock vs absolute custom) -------------------------


def test_split_roots_stock_relative():
    base, roots = _split_roots(["http/", "ssl/"])
    assert base == coverage_emit.NUCLEI_TEMPLATES_DIR
    assert roots == ["http/", "ssl/"]


def test_split_roots_absolute_custom():
    base, roots = _split_roots(["/app/custom-nuclei-templates/"])
    assert base == "/"
    assert roots == ["app/custom-nuclei-templates/"]


# --- fail-open: emit never raises, even when resolution blows up -------------


def test_emit_is_noop_without_run_id():
    # No scan_run_id (manual run) → nothing attempted, no error.
    emit_nuclei_pass_coverage(
        db=None, tenant_id=1, scan_run_id=None, pass_name="http_stock", tier=1,
        asset_ids=[1, 2], severity=["high"], templates=["http/"], exclude_tags="",
        ran=True, errored=False, truncated=False,
    )


def test_emit_is_noop_without_assets():
    emit_nuclei_pass_coverage(
        db=None, tenant_id=1, scan_run_id=99, pass_name="http_stock", tier=1,
        asset_ids=[], severity=["high"], templates=["http/"], exclude_tags="",
        ran=True, errored=False, truncated=False,
    )


def test_emit_swallows_resolution_error(monkeypatch):
    # A revision-resolution failure must be logged, not raised (fail-open).
    def boom(*a, **k):
        raise RuleResolutionError("templates missing")

    monkeypatch.setattr(coverage_emit, "resolve_nuclei_rule_revision", boom)
    monkeypatch.setattr(coverage_emit, "_cached_nuclei_version", lambda: "3.3.1")
    # db is a dummy — we must never reach it.
    emit_nuclei_pass_coverage(
        db=object(), tenant_id=1, scan_run_id=5, pass_name="http_stock", tier=1,
        asset_ids=[1], severity=["high"], templates=["http/"], exclude_tags="",
        ran=True, errored=False, truncated=False,
    )


# --- DB round-trip: emit → COVERED verdict readable back (CI, Postgres) ------


class _Rev:
    digest = "d" * 64


def test_emit_records_covered_verdict(db_session, test_tenant, monkeypatch):
    from app.models.database import Asset, AssetType
    from app.models.scanning import ScanRun
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.coverage_emit import emit_nuclei_pass_coverage as emit

    monkeypatch.setattr(coverage_emit, "_cached_nuclei_version", lambda: "3.3.1")
    monkeypatch.setattr(coverage_emit, "resolve_nuclei_rule_revision", lambda *a, **k: _Rev())

    run = ScanRun(tenant_id=test_tenant.id, project_id=None, status="running",
                  started_at=datetime.now(timezone.utc))
    db_session.add(run)
    asset = Asset(tenant_id=test_tenant.id, identifier="a.test.com",
                  type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    emit(
        db_session, tenant_id=test_tenant.id, scan_run_id=run.id,
        pass_name="http_stock", tier=1, asset_ids=[asset.id],
        severity=["critical", "high"], templates=["http/"], exclude_tags="",
        ran=True, errored=False, truncated=False,
    )

    covered = CoverageRepository(db_session).covered_asset_ids(run.id, "http_stock")
    assert covered == {asset.id}


def test_emit_truncated_is_partial_not_covered(db_session, test_tenant, monkeypatch):
    from app.models.database import Asset, AssetType
    from app.models.scanning import ScanRun
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.coverage_emit import emit_nuclei_pass_coverage as emit

    monkeypatch.setattr(coverage_emit, "_cached_nuclei_version", lambda: "3.3.1")
    monkeypatch.setattr(coverage_emit, "resolve_nuclei_rule_revision", lambda *a, **k: _Rev())

    run = ScanRun(tenant_id=test_tenant.id, project_id=None, status="running",
                  started_at=datetime.now(timezone.utc))
    db_session.add(run)
    asset = Asset(tenant_id=test_tenant.id, identifier="b.test.com",
                  type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    emit(
        db_session, tenant_id=test_tenant.id, scan_run_id=run.id,
        pass_name="http_stock", tier=1, asset_ids=[asset.id],
        severity=["critical", "high"], templates=["http/"], exclude_tags="",
        ran=True, errored=False, truncated=True,  # hit the timeout
    )

    # Truncated must NOT authorise auto-close: no COVERED verdict.
    covered = CoverageRepository(db_session).covered_asset_ids(run.id, "http_stock")
    assert covered == set()
