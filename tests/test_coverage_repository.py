"""Coverage ledger repository — idempotency, tenant isolation, immutability, FK (Step 2D).

DB tests (Postgres via conftest ``db_session``). ``conservative_pass_status`` is a pure
mapping and is also covered here.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.models.coverage import CoverageStatus, ScanCoverage, ScanPolicy, ScanPolicyTemplate
from app.models.database import Asset, AssetType, Tenant
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


def test_persist_policy_divergent_row_is_rejected(db_session):
    # a corrupt/manual row with the same hash but different fields must be detected
    repo = CoverageRepository(db_session)
    m = _manifest()
    db_session.add(
        ScanPolicy(
            policy_hash=m.policy_hash,
            schema_version=m.schema_version,
            engine_name="nuclei",
            engine_version="WRONG",  # divergent
            rule_revision=m.rule_revision,
            phase=m.phase,
            pass_name=m.pass_name,
            tier=m.tier,
            severity=list(m.severity),
            rule_roots=list(m.rule_roots),
            exclude_tags=list(m.exclude_tags),
            relevant_flags=dict(m.relevant_flags),
            created_at=datetime.now(timezone.utc),
        )
    )
    db_session.commit()
    with pytest.raises(CoverageWriteError):
        repo.persist_policy(m)


def test_persist_catalog_divergent_digest_is_rejected(db_session):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    # a stored detector with a divergent digest — ON CONFLICT DO NOTHING keeps it,
    # so the verify pass must reject the write
    db_session.add(
        ScanPolicyTemplate(
            policy_hash=m.policy_hash,
            detector_id="CVE-A",
            relative_path="http/cves/a.yaml",
            content_digest="f" * 64,  # divergent
            severity="high",
            tags=["cve"],
        )
    )
    db_session.commit()
    with pytest.raises(CoverageWriteError):
        repo.persist_catalog(_catalog(m.policy_hash))


def test_persist_catalog_extra_stored_detector_is_rejected(db_session):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    repo.persist_catalog(_catalog(m.policy_hash))  # stores {CVE-A, CVE-B}
    # a ruleset missing CVE-B leaves it as an "extra" stored row → error
    partial = ApplicableRuleSet(
        policy_hash=m.policy_hash,
        rules=(ApplicableRule("nuclei", "CVE-A", "http/cves/a.yaml", "a" * 64, "high", ("cve",)),),
    )
    with pytest.raises(CoverageWriteError):
        repo.persist_catalog(partial)


def test_persist_catalog_unknown_policy_is_rejected(db_session):
    repo = CoverageRepository(db_session)
    with pytest.raises(CoverageWriteError):
        repo.persist_catalog(_catalog("deadbeef" * 8))


def test_persist_catalog_extra_and_missing_leaves_db_unchanged(db_session):
    # pre-existing catalog {CVE-A (matches), CVE-C (extra)}; ruleset is {CVE-A, CVE-B}
    # → one extra (C) + one missing (B). Must raise WITHOUT inserting B.
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    db_session.add_all(
        [
            ScanPolicyTemplate(
                policy_hash=m.policy_hash,
                detector_id="CVE-A",
                relative_path="http/cves/a.yaml",
                content_digest="a" * 64,
                severity="high",
                tags=["cve"],
            ),
            ScanPolicyTemplate(
                policy_hash=m.policy_hash,
                detector_id="CVE-C",
                relative_path="http/cves/c.yaml",
                content_digest="c" * 64,
                severity="high",
                tags=["cve"],
            ),
        ]
    )
    db_session.commit()
    with pytest.raises(CoverageWriteError):
        repo.persist_catalog(_catalog(m.policy_hash))  # ruleset {CVE-A, CVE-B}
    stored = {
        t.detector_id
        for t in db_session.query(ScanPolicyTemplate).filter(ScanPolicyTemplate.policy_hash == m.policy_hash)
    }
    assert stored == {"CVE-A", "CVE-C"}  # unchanged: B never inserted


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


def _cover(repo, tenant, run, m, asset, status):
    repo.record_pass_coverage(
        tenant_id=tenant.id,
        scan_run_id=run.id,
        phase="9",
        pass_name="http_stock",
        policy_hash=m.policy_hash,
        asset_ids=[asset.id],
        status=status,
    )


def _status_of(db, run, asset):
    return (
        db.query(ScanCoverage)
        .filter(ScanCoverage.scan_run_id == run.id, ScanCoverage.asset_id == asset.id)
        .one()
        .status
    )


def test_coverage_never_upgrades_partial_or_failed_to_covered(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    run = _run(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "a.test.com")

    # PARTIAL then a late/concurrent COVERED must NOT authorise
    _cover(repo, test_tenant, run, m, a, CoverageStatus.PARTIAL)
    _cover(repo, test_tenant, run, m, a, CoverageStatus.COVERED)
    assert _status_of(db_session, run, a) == CoverageStatus.PARTIAL

    b = _asset(db_session, test_tenant, "b.test.com")
    _cover(repo, test_tenant, run, m, b, CoverageStatus.FAILED)
    _cover(repo, test_tenant, run, m, b, CoverageStatus.COVERED)
    assert _status_of(db_session, run, b) == CoverageStatus.FAILED


def test_coverage_allows_downgrade_and_replaces_unstarted(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    run = _run(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "a.test.com")

    _cover(repo, test_tenant, run, m, a, CoverageStatus.UNSTARTED)
    _cover(repo, test_tenant, run, m, a, CoverageStatus.COVERED)  # placeholder replaced
    assert _status_of(db_session, run, a) == CoverageStatus.COVERED
    _cover(repo, test_tenant, run, m, a, CoverageStatus.FAILED)  # covered → failed allowed
    assert _status_of(db_session, run, a) == CoverageStatus.FAILED


def test_policy_phase_pass_mismatch_is_rejected(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m = _manifest()  # phase 9, pass http_stock
    repo.persist_policy(m)
    run = _run(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "a.test.com")
    with pytest.raises(CoverageWriteError):
        repo.record_pass_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=run.id,
            phase="8",  # wrong for this policy
            pass_name="misconfig",  # wrong for this policy
            policy_hash=m.policy_hash,
            asset_ids=[a.id],
            status=CoverageStatus.COVERED,
        )


def test_coverage_with_different_policy_hash_is_rejected(db_session, test_tenant):
    repo = CoverageRepository(db_session)
    m1 = _manifest()
    m2 = build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="DIFFERENT-rev",  # → different policy_hash, same phase 9/http_stock
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        template_roots=["http/cves"],
        exclude_tags=["fuzz"],
    )
    assert m1.policy_hash != m2.policy_hash
    repo.persist_policy(m1)
    repo.persist_policy(m2)
    run = _run(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "a.test.com")
    _cover(repo, test_tenant, run, m1, a, CoverageStatus.COVERED)

    with pytest.raises(CoverageWriteError):
        repo.record_pass_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=run.id,
            phase="9",
            pass_name="http_stock",
            policy_hash=m2.policy_hash,  # different policy for the same run/pass/asset
            asset_ids=[a.id],
            status=CoverageStatus.PARTIAL,
        )
    row = db_session.query(ScanCoverage).filter(ScanCoverage.scan_run_id == run.id).one()
    assert row.policy_hash == m1.policy_hash and row.status == CoverageStatus.COVERED  # original intact


def test_coverage_atomic_guard_rejects_concurrent_different_policy(db_session, test_tenant):
    # The pre-check is TOCTOU; this drives the upsert directly with a row already present
    # under M1 — exactly the statement worker B runs after worker A committed. The
    # DO UPDATE ... WHERE policy_hash = excluded.policy_hash skips it → rowcount shortfall
    # → fail-closed, original row untouched.
    repo = CoverageRepository(db_session)
    m1 = _manifest()
    m2 = build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="DIFFERENT-rev",
        pass_name="http_stock",
        tier=1,
        severity=["critical", "high"],
        template_roots=["http/cves"],
        exclude_tags=["fuzz"],
    )
    repo.persist_policy(m1)
    repo.persist_policy(m2)
    run = _run(db_session, test_tenant)
    run_id = run.id
    a = _asset(db_session, test_tenant, "a.test.com")
    _cover(repo, test_tenant, run, m1, a, CoverageStatus.COVERED)  # worker A committed M1

    now = datetime.now(timezone.utc)
    m2_rows = [
        {
            "tenant_id": test_tenant.id,
            "scan_run_id": run_id,
            "asset_id": a.id,
            "phase": "9",
            "pass_name": "http_stock",
            "policy_hash": m2.policy_hash,
            "status": CoverageStatus.PARTIAL,
            "created_at": now,
            "updated_at": now,
        }
    ]
    with pytest.raises(CoverageWriteError):
        repo._upsert_coverage_rows(m2_rows)
    row = db_session.query(ScanCoverage).filter(ScanCoverage.scan_run_id == run_id).one()
    assert row.policy_hash == m1.policy_hash and row.status == CoverageStatus.COVERED


def test_empty_assets_still_validates_run(db_session, test_tenant):
    # a wiring error (bad run) must NOT be hidden by an empty asset list
    repo = CoverageRepository(db_session)
    m = _manifest()
    repo.persist_policy(m)
    other = _second_tenant(db_session)
    other_run = _run(db_session, other)
    with pytest.raises(CoverageWriteError):
        repo.record_pass_coverage(
            tenant_id=test_tenant.id,
            scan_run_id=other_run.id,  # belongs to `other`
            phase="9",
            pass_name="http_stock",
            policy_hash=m.policy_hash,
            asset_ids=[],  # empty, but the run is still invalid
            status=CoverageStatus.COVERED,
        )


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


def test_invalid_status_is_rejected_by_db_check(db_session, test_tenant):
    # native_enum=False stores VARCHAR, so a raw value could bypass the app enum —
    # the DB CHECK must still reject it.
    m = _manifest()
    CoverageRepository(db_session).persist_policy(m)
    run = _run(db_session, test_tenant)
    a = _asset(db_session, test_tenant, "a.test.com")
    with pytest.raises(IntegrityError):
        db_session.execute(
            text(
                "INSERT INTO scan_coverage "
                "(tenant_id, scan_run_id, asset_id, phase, pass_name, policy_hash, status, created_at, updated_at) "
                "VALUES (:t, :r, :a, '9', 'http_stock', :p, 'bogus', now(), now())"
            ),
            {"t": test_tenant.id, "r": run.id, "a": a.id, "p": m.policy_hash},
        )
        db_session.commit()


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
