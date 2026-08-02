"""Coverage ledger repository — idempotency, tenant isolation, immutability, FK (Step 2D).

DB tests (Postgres via conftest ``db_session``). ``conservative_pass_status`` is a pure
mapping and is also covered here.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.models.coverage import CoverageStatus, ScanCoverage, ScanPolicy, ScanPolicyTemplate
from app.models.database import Asset, AssetType
from app.models.scanning import ScanRun
from app.repositories.coverage_repository import (
    CoverageRepository,
    CoverageWriteError,
    conservative_pass_status,
)
from app.services.rule_catalog import ApplicableRule, ApplicableRuleSet
from app.services.scan_policy import build_nuclei_policy_manifest


# --- pure mapping (no DB) ----------------------------------------------------


def test_conservative_pass_status_precedence():
    assert conservative_pass_status(ran=False, errored=False, truncated=False) == CoverageStatus.SKIPPED
    assert conservative_pass_status(ran=True, errored=True, truncated=False) == CoverageStatus.FAILED
    assert conservative_pass_status(ran=True, errored=False, truncated=True) == CoverageStatus.PARTIAL
    assert conservative_pass_status(ran=True, errored=False, truncated=False) == CoverageStatus.COVERED
    # errored wins over truncated — never COVERED unless clean
    assert conservative_pass_status(ran=True, errored=True, truncated=True) == CoverageStatus.FAILED


# --- helpers -----------------------------------------------------------------


def _manifest():
    return build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="rev-abc",
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        template_roots=["http/cves"],
        exclude_tags=["fuzz"],
    )


def _catalog(policy_hash):
    return ApplicableRuleSet(
        policy_hash=policy_hash,
        rules=(
            ApplicableRule("nuclei", "CVE-A", "http/cves/a.yaml", "a" * 64, "high", ("cve",)),
            ApplicableRule("nuclei", "CVE-B", "http/cves/b.yaml", "b" * 64, "critical", ("cve",)),
        ),
    )


def _asset(db, tenant, ident):
    a = Asset(tenant_id=tenant.id, identifier=ident, type=AssetType.SUBDOMAIN, is_active=True)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _run(db, tenant):
    r = ScanRun(tenant_id=tenant.id, project_id=None, status="running", started_at=datetime.now(timezone.utc))
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _second_tenant(db):
    from app.models.database import Tenant

    t = Tenant(name="Other", slug="other-tenant", contact_policy="x@y.com")
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


# --- policy immutability + idempotency ---------------------------------------


def test_persist_policy_is_idempotent_and_immutable(db_session):
    repo = CoverageRepository(db_session)
    m = _manifest()
    h1 = repo.persist_policy(m)
    h2 = repo.persist_policy(m)  # no-op on conflict
    assert h1 == h2 == m.policy_hash
    rows = db_session.query(ScanPolicy).filter(ScanPolicy.policy_hash == m.policy_hash).all()
    assert len(rows) == 1
    assert rows[0].rule_revision == "rev-abc" and rows[0].engine_name == "nuclei"


def test_persist_catalog_is_idempotent(db_session):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    repo.persist_catalog(_catalog(m.policy_hash))
    repo.persist_catalog(_catalog(m.policy_hash))  # again → no duplicates
    rows = db_session.query(ScanPolicyTemplate).filter(ScanPolicyTemplate.policy_hash == m.policy_hash).all()
    assert len(rows) == 2
    assert {r.detector_id for r in rows} == {"CVE-A", "CVE-B"}
    assert repo.applicable_detector_ids(m.policy_hash) == {"CVE-A", "CVE-B"}


# --- coverage upsert + idempotency -------------------------------------------


def test_record_pass_coverage_upserts_one_row_per_asset(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    run = _run(db_session, test_tenant)
    a1 = _asset(db_session, test_tenant, "a1.test.com")
    a2 = _asset(db_session, test_tenant, "a2.test.com")

    n = repo.record_pass_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase="9",
        pass_name="http_stock",
        policy_hash=m.policy_hash,
        asset_ids=[a1.id, a2.id],
        status=CoverageStatus.COVERED,
    )
    assert n == 2
    assert repo.covered_asset_ids(run.id, "http_stock") == {a1.id, a2.id}

    # re-record with a stricter status → updates in place, no duplicate rows
    repo.record_pass_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase="9",
        pass_name="http_stock",
        policy_hash=m.policy_hash,
        asset_ids=[a1.id, a2.id],
        status=CoverageStatus.PARTIAL,
    )
    rows = db_session.query(ScanCoverage).filter(ScanCoverage.scan_run_id == run.id).all()
    assert len(rows) == 2
    assert all(r.status == CoverageStatus.PARTIAL for r in rows)
    assert repo.covered_asset_ids(run.id, "http_stock") == set()  # none COVERED anymore


def test_record_pass_coverage_empty_assets_is_noop(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    run = _run(db_session, test_tenant)
    assert (
        repo.record_pass_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=run.id,
            phase="9",
            pass_name="http_stock",
            policy_hash=m.policy_hash,
            asset_ids=[],
            status=CoverageStatus.COVERED,
        )
        == 0
    )


# --- fail-closed verification ------------------------------------------------


def test_unknown_policy_hash_is_rejected(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    run = _run(db_session, test_tenant)
    a1 = _asset(db_session, test_tenant, "a1.test.com")
    with pytest.raises(CoverageWriteError):
        repo.record_pass_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=run.id,
            phase="9",
            pass_name="http_stock",
            policy_hash="deadbeef" * 8,  # never persisted
            asset_ids=[a1.id],
            status=CoverageStatus.COVERED,
        )


def test_run_of_another_tenant_is_rejected(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    other = _second_tenant(db_session)
    other_run = _run(db_session, other)
    a1 = _asset(db_session, test_tenant, "a1.test.com")
    with pytest.raises(CoverageWriteError):
        repo.record_pass_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=other_run.id,  # belongs to `other`
            phase="9",
            pass_name="http_stock",
            policy_hash=m.policy_hash,
            asset_ids=[a1.id],
            status=CoverageStatus.COVERED,
        )


def test_asset_of_another_tenant_is_rejected(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    run = _run(db_session, test_tenant)
    other = _second_tenant(db_session)
    stray = _asset(db_session, other, "stray.other.com")
    with pytest.raises(CoverageWriteError):
        repo.record_pass_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=run.id,
            phase="9",
            pass_name="http_stock",
            policy_hash=m.policy_hash,
            asset_ids=[stray.id],  # belongs to `other`
            status=CoverageStatus.COVERED,
        )
    # nothing was written
    assert db_session.query(ScanCoverage).filter(ScanCoverage.scan_run_id == run.id).count() == 0
