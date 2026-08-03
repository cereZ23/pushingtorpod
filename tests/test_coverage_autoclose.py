"""Coverage-aware auto-close — the pure per-finding decision and the DB shadow runner.

Pure tests lock the eligibility contract (two-consecutive-miss / no-double-count /
fail-closed). The DB tests exercise the shadow runner: it PERSISTS streak + attribution
but never changes status, matches on engine, and is safe against out-of-order runs.
"""

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone

from app.services.coverage_autoclose import (
    AutoCloseDecision,
    decide_finding_auto_close,
)


def _decide(**over):
    base = dict(
        this_run_id=100,
        detected_this_run=False,
        discovery_auto_close_allowed=True,
        coverage_covered=True,
        catalog_intact=True,
        detector_applicable=True,
        current_streak=0,
        last_eligible_run_id=None,
    )
    base.update(over)
    return decide_finding_auto_close(**base)


def test_first_eligible_miss_increments_to_one():
    v = _decide(this_run_id=10, current_streak=0, last_eligible_run_id=None)
    assert v.decision is AutoCloseDecision.ELIGIBLE_MISS
    assert v.new_streak == 1
    assert v.set_last_eligible_run_id == 10


def test_two_distinct_eligible_runs_would_close():
    # run 11 with the streak already at 1 from run 10 → threshold reached
    v = _decide(this_run_id=11, current_streak=1, last_eligible_run_id=10)
    assert v.decision is AutoCloseDecision.WOULD_CLOSE
    assert v.new_streak == 2


def test_retry_same_run_does_not_double_count():
    v = _decide(this_run_id=11, current_streak=1, last_eligible_run_id=11)
    assert v.decision is AutoCloseDecision.ELIGIBLE_MISS
    assert v.new_streak == 1  # unchanged: this run already advanced it


def test_detected_this_run_resets_and_attributes():
    v = _decide(this_run_id=12, detected_this_run=True, current_streak=1, last_eligible_run_id=10)
    assert v.decision is AutoCloseDecision.DETECTED_RESET
    assert v.new_streak == 0
    assert v.set_last_detected_run_id == 12
    assert v.set_last_eligible_run_id is None


def test_partial_coverage_is_ineligible_and_resets():
    v = _decide(coverage_covered=False, current_streak=1, last_eligible_run_id=10)
    assert v.decision is AutoCloseDecision.INELIGIBLE
    assert v.new_streak == 0


def test_tampered_catalog_is_ineligible():
    v = _decide(catalog_intact=False, current_streak=1)
    assert v.decision is AutoCloseDecision.INELIGIBLE
    assert v.new_streak == 0


def test_detector_not_applicable_is_ineligible():
    v = _decide(detector_applicable=False, current_streak=1)
    assert v.decision is AutoCloseDecision.INELIGIBLE
    assert v.new_streak == 0


def test_unhealthy_discovery_is_ineligible():
    v = _decide(discovery_auto_close_allowed=False, current_streak=1)
    assert v.decision is AutoCloseDecision.INELIGIBLE
    assert v.new_streak == 0


def test_ineligible_run_breaks_the_streak_no_false_close():
    # streak at 1, then a run where coverage can't be proven → reset, NOT close.
    v = _decide(coverage_covered=False, current_streak=1, last_eligible_run_id=10, this_run_id=11)
    assert v.decision is AutoCloseDecision.INELIGIBLE
    assert v.new_streak == 0


def test_threshold_is_configurable():
    # with threshold 3, a second miss is still just ELIGIBLE_MISS
    v = _decide(this_run_id=11, current_streak=1, last_eligible_run_id=10, close_threshold=3)
    assert v.decision is AutoCloseDecision.ELIGIBLE_MISS
    assert v.new_streak == 2


# --- DB shadow runner: persists streak + attribution, NEVER status ------------


def _allow_discovery(monkeypatch, allowed=True):
    monkeypatch.setattr(
        "app.services.discovery_health.evaluate_and_persist_discovery_health",
        lambda *a, **k: types.SimpleNamespace(auto_close_allowed=allowed),
    )


def _new_run(db_session, test_tenant, *, started=None):
    from app.models.scanning import ScanRun

    run = ScanRun(
        tenant_id=test_tenant.id,
        project_id=None,
        status="running",
        started_at=started or datetime.now(timezone.utc),
    )
    db_session.add(run)
    db_session.commit()
    return run


def _nuclei_policy_catalog(db_session, *, detector="CVE-X"):
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.rule_catalog import ApplicableRule, ApplicableRuleSet
    from app.services.scan_policy import build_nuclei_policy_manifest

    repo = CoverageRepository(db_session)
    m = build_nuclei_policy_manifest(
        nuclei_version="3.3.1", template_revision="rev-ac", pass_name="http_stock", tier=1, severity=["high"]
    )
    repo.persist_policy(m)
    repo.persist_catalog(
        ApplicableRuleSet(
            policy_hash=m.policy_hash,
            rules=(ApplicableRule("nuclei", detector, "http/x.yaml", "a" * 64, "high", ("cve",)),),
        )
    )
    return m


def _cover(db_session, test_tenant, manifest, run, asset):
    from app.repositories.coverage_repository import CoverageRepository, CoverageStatus

    CoverageRepository(db_session).record_pass_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase=manifest.phase,
        pass_name="http_stock",
        policy_hash=manifest.policy_hash,
        asset_ids=[asset.id],
        status=CoverageStatus.COVERED,
    )


def _open_finding(db_session, asset, *, source="nuclei", template_id="CVE-X", streak=0, last_eligible_run_id=None):
    from app.models.database import Finding, FindingSeverity, FindingStatus

    f = Finding(
        asset_id=asset.id,
        source=source,
        template_id=template_id,
        name="X",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        last_seen=datetime.now(timezone.utc) - timedelta(days=1),  # NOT seen this run
        eligible_miss_streak=streak,
        last_eligible_run_id=last_eligible_run_id,
    )
    db_session.add(f)
    db_session.commit()
    return f


def _asset(db_session, test_tenant, ident):
    from app.models.database import Asset, AssetType

    a = Asset(tenant_id=test_tenant.id, identifier=ident, type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(a)
    db_session.commit()
    return a


def test_shadow_persists_streak_and_would_close_never_status(db_session, test_tenant, monkeypatch):
    from app.models.database import FindingStatus
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s1.test.com")
    _cover(db_session, test_tenant, m, run, asset)
    finding = _open_finding(db_session, asset, streak=1)  # already 1 → this miss = 2 → close

    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)

    assert result["would_close_ids"] == [finding.id]
    db_session.refresh(finding)
    assert finding.status is FindingStatus.OPEN  # SHADOW: never closes
    assert finding.eligible_miss_streak == 2  # but the streak IS persisted
    assert finding.last_eligible_run_id == run.id


def test_shadow_two_distinct_runs_reach_would_close(db_session, test_tenant, monkeypatch):
    # The real validation gap 2 was about: two live runs must actually advance 0 → 1 → 2.
    from app.services.coverage_autoclose import AutoCloseDecision, shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session)
    asset = _asset(db_session, test_tenant, "s2.test.com")
    finding = _open_finding(db_session, asset, streak=0)

    run1 = _new_run(db_session, test_tenant, started=datetime.now(timezone.utc) - timedelta(hours=1))
    _cover(db_session, test_tenant, m, run1, asset)
    r1 = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run1.id)
    assert r1["decisions"][AutoCloseDecision.ELIGIBLE_MISS.value] == 1
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 1

    run2 = _new_run(db_session, test_tenant, started=datetime.now(timezone.utc))
    _cover(db_session, test_tenant, m, run2, asset)
    r2 = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run2.id)
    assert r2["would_close_ids"] == [finding.id]
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 2


def test_shadow_detected_this_run_resets(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import AutoCloseDecision, shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s3.test.com")
    _cover(db_session, test_tenant, m, run, asset)
    finding = _open_finding(db_session, asset, streak=1)
    finding.last_detected_scan_run_id = run.id  # attributed as detected THIS run
    db_session.commit()

    r = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert r["decisions"][AutoCloseDecision.DETECTED_RESET.value] == 1
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0


def test_shadow_unhealthy_discovery_never_advances(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, False)
    m = _nuclei_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s4.test.com")
    _cover(db_session, test_tenant, m, run, asset)
    finding = _open_finding(db_session, asset, streak=1)

    r = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert r["would_close_ids"] == []
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0  # ineligible → reset, never close


def test_shadow_engine_mismatch_not_authorised(db_session, test_tenant, monkeypatch):
    # A misconfig finding whose control id equals a nuclei detector id, on an asset with a
    # COVERED NUCLEI pass containing that id, must NOT be authorised (wrong engine).
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session, detector="DUP")  # nuclei pass covers "DUP"
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s5.test.com")
    _cover(db_session, test_tenant, m, run, asset)
    finding = _open_finding(db_session, asset, source="misconfig", template_id="DUP", streak=1)

    r = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert r["would_close_ids"] == []
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0  # nuclei pass can't authorise a misconfig finding


def test_shadow_out_of_order_older_run_is_noop(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session)
    asset = _asset(db_session, test_tenant, "s6.test.com")

    newer = _new_run(db_session, test_tenant, started=datetime.now(timezone.utc))
    older = _new_run(db_session, test_tenant, started=datetime.now(timezone.utc) - timedelta(hours=2))
    _cover(db_session, test_tenant, m, older, asset)
    finding = _open_finding(db_session, asset, streak=1, last_eligible_run_id=newer.id)

    r = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=older.id)
    assert r["stale_skipped"] == 1
    assert r["would_close_ids"] == []
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 1  # untouched by the older run
