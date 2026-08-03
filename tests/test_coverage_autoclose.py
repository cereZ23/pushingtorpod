"""Coverage-aware auto-close — the pure per-finding decision.

No DB: locks the eligibility contract and the two-consecutive-miss / no-double-count /
fail-closed behaviour before any dry-run runner or real close is wired.
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


# --- DB dry-run runner: joins coverage+catalog, writes NOTHING -----------------


def _allow_discovery(monkeypatch, allowed=True):
    monkeypatch.setattr(
        "app.services.discovery_health.evaluate_and_persist_discovery_health",
        lambda *a, **k: types.SimpleNamespace(auto_close_allowed=allowed),
    )


def _covered_finding_setup(db_session, test_tenant, *, template_id="CVE-X", streak=1):
    """A COVERED pass whose catalog contains `template_id`, plus an OPEN finding for it."""
    from app.models.database import Asset, AssetType, Finding, FindingSeverity, FindingStatus
    from app.models.scanning import ScanRun
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.rule_catalog import ApplicableRule, ApplicableRuleSet
    from app.services.scan_policy import build_nuclei_policy_manifest

    run = ScanRun(tenant_id=test_tenant.id, project_id=None, status="running", started_at=datetime.now(timezone.utc))
    db_session.add(run)
    asset = Asset(tenant_id=test_tenant.id, identifier="ac.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    repo = CoverageRepository(db_session)
    m = build_nuclei_policy_manifest(
        nuclei_version="3.3.1", template_revision="rev-ac", pass_name="http_stock", tier=1, severity=["high"]
    )
    repo.persist_policy(m)
    repo.persist_catalog(
        ApplicableRuleSet(
            policy_hash=m.policy_hash,
            rules=(ApplicableRule("nuclei", template_id, "http/x.yaml", "a" * 64, "high", ("cve",)),),
        )
    )
    from app.repositories.coverage_repository import CoverageStatus

    repo.record_pass_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase=m.phase,
        pass_name="http_stock",
        policy_hash=m.policy_hash,
        asset_ids=[asset.id],
        status=CoverageStatus.COVERED,
    )

    finding = Finding(
        asset_id=asset.id,
        source="nuclei",
        template_id=template_id,
        name="X",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        last_seen=datetime.now(timezone.utc) - timedelta(days=1),  # NOT seen this run
        eligible_miss_streak=streak,
        last_eligible_run_id=None,
    )
    db_session.add(finding)
    db_session.commit()
    return run, asset, finding


def test_dry_run_would_close_and_writes_nothing(db_session, test_tenant, monkeypatch):
    from app.models.database import Finding, FindingStatus
    from app.services.coverage_autoclose import dry_run_auto_close

    _allow_discovery(monkeypatch, True)
    run, asset, finding = _covered_finding_setup(db_session, test_tenant, streak=1)

    result = dry_run_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)

    assert result["would_close_ids"] == [finding.id]  # streak 1 + this eligible miss = 2 → close
    assert result["decisions"]["would_close"] == 1
    # DRY-RUN: the finding is untouched.
    db_session.refresh(finding)
    assert finding.status is FindingStatus.OPEN
    assert finding.eligible_miss_streak == 1
    assert finding.last_eligible_run_id is None


def test_dry_run_detected_this_run_resets(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import dry_run_auto_close

    _allow_discovery(monkeypatch, True)
    run, asset, finding = _covered_finding_setup(db_session, test_tenant, streak=1)
    finding.last_seen = datetime.now(timezone.utc)  # seen THIS run
    db_session.commit()

    result = dry_run_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert result["decisions"]["detected_reset"] == 1
    assert result["would_close_ids"] == []


def test_dry_run_unhealthy_discovery_never_closes(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import dry_run_auto_close

    _allow_discovery(monkeypatch, False)  # discovery not authorised
    run, asset, finding = _covered_finding_setup(db_session, test_tenant, streak=1)

    result = dry_run_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert result["would_close_ids"] == []
    assert result["decisions"]["ineligible"] == 1
