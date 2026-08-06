"""Coverage-aware auto-close — the pure per-finding decision and the DB shadow runner.

Pure tests lock the eligibility contract (two-consecutive-miss / no-double-count /
fail-closed). The DB tests exercise the shadow runner: it PERSISTS streak + attribution
but never changes status, matches on engine, and is safe against out-of-order runs.
"""

from __future__ import annotations

import types
from datetime import datetime, timedelta, timezone

import pytest

from app.services.coverage_autoclose import (
    AutoCloseDecision,
    classify_matched_at,
    decide_finding_auto_close,
    shadow_auto_close,
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


# --- endpoint-safety classifier (temporary gate while stock scans base URLs only) ----------


def test_classify_base_targets():
    assert classify_matched_at("https://host.example") == "base"
    assert classify_matched_at("http://host.example/") == "base"
    assert classify_matched_at("https://host.example:8443") == "base"
    assert classify_matched_at("https://host.example:8443/") == "base"


def test_classify_endpoint_targets():
    assert classify_matched_at("https://host.example/admin") == "endpoint"
    assert classify_matched_at("https://host.example/wp-login.php") == "endpoint"
    assert classify_matched_at("https://host.example/?q=1") == "endpoint"  # query on root
    assert classify_matched_at("http://host.example/a/b/c?id=1") == "endpoint"


def test_classify_unknown_targets():
    assert classify_matched_at(None) == "unknown"
    assert classify_matched_at("") == "unknown"
    assert classify_matched_at("host.example:443") == "unknown"  # SSL/network "host:port", no scheme
    assert classify_matched_at("not a url") == "unknown"
    assert classify_matched_at("ftp://host.example/file") == "unknown"  # non-http(s)
    assert classify_matched_at(12345) == "unknown"  # non-str


def test_non_base_target_is_ineligible_and_resets_streak():
    # An endpoint/unknown finding must NOT accrue a miss, and any prior streak is reset to 0 — so
    # the base pass (which never visits the path) can never drive it to a false close.
    for _ in ("endpoint", "unknown"):
        v = _decide(base_target=False, current_streak=1, last_eligible_run_id=10)
        assert v.decision is AutoCloseDecision.INELIGIBLE
        assert v.new_streak == 0


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


def _nuclei_policy_catalog(db_session, *, detector="CVE-X", pass_name="http_stock"):
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.rule_catalog import ApplicableRule, ApplicableRuleSet
    from app.services.scan_policy import build_nuclei_policy_manifest

    repo = CoverageRepository(db_session)
    m = build_nuclei_policy_manifest(
        nuclei_version="3.3.1", template_revision="rev-ac", pass_name=pass_name, tier=1, severity=["high"]
    )
    repo.persist_policy(m)
    repo.persist_catalog(
        ApplicableRuleSet(
            policy_hash=m.policy_hash,
            rules=(ApplicableRule("nuclei", detector, "http/x.yaml", "a" * 64, "high", ("cve",)),),
        )
    )
    return m


def _misconfig_policy_catalog(db_session, *, detector="MC-X"):
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.rule_catalog import ApplicableRule, ApplicableRuleSet
    from app.services.scan_policy import build_misconfig_policy_manifest

    repo = CoverageRepository(db_session)
    m = build_misconfig_policy_manifest(app_version="1.2.3", rule_revision="rev-mc", tier=1)
    repo.persist_policy(m)
    repo.persist_catalog(
        ApplicableRuleSet(
            policy_hash=m.policy_hash,
            rules=(ApplicableRule("builtin_misconfig", detector, "controls/x", "b" * 64, "high", ()),),
        )
    )
    return m


def _endpoint_policy_catalog(db_session, *, detector="EP-X", revision="rev-ep", tier=1):
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.rule_catalog import ApplicableRule, ApplicableRuleSet, catalog_digest_for_rules
    from app.services.scan_policy import PASS_HTTP_ENDPOINT, build_nuclei_policy_manifest

    rule = ApplicableRule("nuclei", detector, "http/ep.yaml", "e" * 64, "high", ("cve",))
    digest = catalog_digest_for_rules([rule])
    m = build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision=revision,
        pass_name=PASS_HTTP_ENDPOINT,
        tier=tier,
        severity=["high"],
        catalog_digest=digest,
        classifier_version=1,
    )
    repo = CoverageRepository(db_session)
    repo.persist_policy(m)
    repo.persist_catalog(ApplicableRuleSet(policy_hash=m.policy_hash, rules=(rule,)))
    return m


def _cover(db_session, test_tenant, manifest, run, asset, *, pass_name="http_stock"):
    from app.repositories.coverage_repository import CoverageRepository, CoverageStatus

    CoverageRepository(db_session).record_pass_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase=manifest.phase,
        pass_name=pass_name,
        policy_hash=manifest.policy_hash,
        asset_ids=[asset.id],
        status=CoverageStatus.COVERED,
    )


def _cover_endpoint(db_session, test_tenant, manifest, run, asset, shape, status):
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.scan_policy import PASS_HTTP_ENDPOINT

    CoverageRepository(db_session).record_endpoint_coverage(
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        phase=manifest.phase,
        pass_name=PASS_HTTP_ENDPOINT,
        policy_hash=manifest.policy_hash,
        entries=[(asset.id, shape)],
        status=status,
    )


_UNSET = object()


def _open_finding(
    db_session,
    asset,
    *,
    source="nuclei",
    template_id="CVE-X",
    streak=0,
    last_eligible_run_id=None,
    matched_at=_UNSET,
    endpoint_shape_hash=None,
    origin_policy_hash=None,
):
    from app.models.database import Finding, FindingSeverity, FindingStatus

    f = Finding(
        asset_id=asset.id,
        source=source,
        template_id=template_id,
        name="X",
        severity=FindingSeverity.HIGH,
        status=FindingStatus.OPEN,
        # A base-URL location by default so the finding is a `base` target (eligible). Tests override
        # with a path/query location (endpoint) or an explicit None/host:port (unknown).
        matched_at=(f"https://{asset.identifier}" if matched_at is _UNSET else matched_at),
        last_seen=datetime.now(timezone.utc) - timedelta(days=1),  # NOT seen this run
        eligible_miss_streak=streak,
        last_eligible_run_id=last_eligible_run_id,
        endpoint_shape_hash=endpoint_shape_hash,
        origin_policy_hash=origin_policy_hash,
    )
    db_session.add(f)
    db_session.commit()
    return f


def test_shadow_endpoint_exact_covered_shape_and_policy_advances(db_session, test_tenant, monkeypatch):
    from app.models.coverage import CoverageStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-shadow.test.com")
    shape = endpoint_shape_hash("https://ep-shadow.test.com/admin")
    _cover_endpoint(db_session, test_tenant, m, run, asset, shape, CoverageStatus.COVERED)
    finding = _open_finding(
        db_session,
        asset,
        template_id="EP-X",
        streak=1,
        endpoint_shape_hash=shape,
        origin_policy_hash=m.policy_hash,
        matched_at="https://ep-shadow.test.com/admin",
    )

    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert result["would_close_ids"] == [finding.id]
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 2  # shadow only; status remains OPEN


@pytest.mark.parametrize(
    "non_authorizing_status",
    ["partial", "failed", "skipped"],
)
def test_shadow_endpoint_non_covered_status_is_ineligible(db_session, test_tenant, monkeypatch, non_authorizing_status):
    from app.models.coverage import CoverageStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-partial.test.com")
    shape = endpoint_shape_hash("https://ep-partial.test.com/admin")
    _cover_endpoint(
        db_session,
        test_tenant,
        m,
        run,
        asset,
        shape,
        CoverageStatus(non_authorizing_status),
    )
    finding = _open_finding(
        db_session,
        asset,
        template_id="EP-X",
        streak=1,
        endpoint_shape_hash=shape,
        origin_policy_hash=m.policy_hash,
    )
    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert finding.id not in result["would_close_ids"]
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0


def test_shadow_endpoint_never_falls_back_to_asset_coverage(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    endpoint_policy = _endpoint_policy_catalog(db_session)
    host_policy = _nuclei_policy_catalog(db_session, detector="EP-X")
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-nofallback.test.com")
    _cover(db_session, test_tenant, host_policy, run, asset)
    finding = _open_finding(
        db_session,
        asset,
        template_id="EP-X",
        streak=1,
        endpoint_shape_hash=endpoint_shape_hash("https://ep-nofallback.test.com/admin"),
        origin_policy_hash=endpoint_policy.policy_hash,
    )
    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert finding.id not in result["would_close_ids"]
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0


def test_shadow_endpoint_policy_drift_is_ineligible(db_session, test_tenant, monkeypatch):
    from app.models.coverage import CoverageStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    old = _endpoint_policy_catalog(db_session, revision="old")
    current = _endpoint_policy_catalog(db_session, revision="new")
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-drift.test.com")
    shape = endpoint_shape_hash("https://ep-drift.test.com/admin")
    _cover_endpoint(db_session, test_tenant, current, run, asset, shape, CoverageStatus.COVERED)
    finding = _open_finding(
        db_session,
        asset,
        template_id="EP-X",
        streak=1,
        endpoint_shape_hash=shape,
        origin_policy_hash=old.policy_hash,
    )
    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert finding.id not in result["would_close_ids"]
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0


def test_shadow_incomplete_endpoint_provenance_is_ineligible_no_fallback(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    host_policy = _nuclei_policy_catalog(db_session, detector="EP-X")
    endpoint_policy = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-incomplete.test.com")
    _cover(db_session, test_tenant, host_policy, run, asset)
    shape_only = _open_finding(
        db_session,
        asset,
        template_id="EP-X",
        streak=1,
        endpoint_shape_hash=endpoint_shape_hash("https://ep-incomplete.test.com/a"),
    )
    policy_only = _open_finding(
        db_session,
        asset,
        template_id="EP-X-2",
        streak=1,
        origin_policy_hash=endpoint_policy.policy_hash,
    )
    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert not ({shape_only.id, policy_only.id} & set(result["would_close_ids"]))
    db_session.refresh(shape_only)
    db_session.refresh(policy_only)
    assert shape_only.eligible_miss_streak == policy_only.eligible_miss_streak == 0


def test_shadow_endpoint_detected_this_run_resets_even_without_covered_row(db_session, test_tenant, monkeypatch):
    from app.services.coverage_autoclose import AutoCloseDecision, shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    policy = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-detected.test.com")
    finding = _open_finding(
        db_session,
        asset,
        template_id="EP-X",
        streak=1,
        endpoint_shape_hash=endpoint_shape_hash("https://ep-detected.test.com/a"),
        origin_policy_hash=policy.policy_hash,
    )
    finding.last_detected_scan_run_id = run.id
    db_session.commit()
    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert result["decisions"][AutoCloseDecision.DETECTED_RESET.value] == 1
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0


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


def test_shadow_endpoint_finding_never_would_close(db_session, test_tenant, monkeypatch):
    # Same setup as the would-close test, but the finding's location is a deep endpoint. The stock
    # pass only scans base URLs, so this must be INELIGIBLE — never in would_close_ids — and its
    # prior streak must reset to 0 (fail-closed against a false FIXED).
    from app.models.database import FindingStatus
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s1.test.com")
    _cover(db_session, test_tenant, m, run, asset)
    finding = _open_finding(db_session, asset, streak=1, matched_at="https://s1.test.com/wp-login.php?redirect=1")

    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)

    assert finding.id not in result["would_close_ids"]  # endpoint finding is never closed by base pass
    db_session.refresh(finding)
    assert finding.status is FindingStatus.OPEN
    assert finding.eligible_miss_streak == 0  # prior streak reset (INELIGIBLE)


def test_shadow_http_stock_unknown_location_is_ineligible(db_session, test_tenant, monkeypatch):
    # HTTP-stock finding with NO location (matched_at=None → "unknown") is INELIGIBLE (fail-closed).
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session)  # http_stock
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s-unk.test.com")
    _cover(db_session, test_tenant, m, run, asset)
    finding = _open_finding(db_session, asset, streak=1, matched_at=None)

    r = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert finding.id not in r["would_close_ids"]
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 0


def test_shadow_dns_network_host_port_stays_eligible(db_session, test_tenant, monkeypatch):
    # A DNS/network finding located as "host:port" is "unknown" to the HTTP classifier, but the gate
    # must NOT apply to the dns_network pass — it stays ELIGIBLE and reaches would_close.
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _nuclei_policy_catalog(db_session, pass_name="dns_network")
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s-dns.test.com")
    _cover(db_session, test_tenant, m, run, asset, pass_name="dns_network")
    finding = _open_finding(db_session, asset, streak=1, matched_at="s-dns.test.com:53")

    r = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert finding.id in r["would_close_ids"]  # host-level pass unaffected by the HTTP endpoint gate
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 2


def test_shadow_misconfig_without_location_stays_eligible(db_session, test_tenant, monkeypatch):
    # A misconfig finding with no HTTP location must keep its coverage-aware auto-close — the HTTP
    # endpoint gate must never touch the misconfig pass (this was the regression to guard against).
    from app.services.coverage_autoclose import shadow_auto_close

    _allow_discovery(monkeypatch, True)
    m = _misconfig_policy_catalog(db_session, detector="MC-1")
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "s-mc.test.com")
    _cover(db_session, test_tenant, m, run, asset, pass_name="misconfig")
    finding = _open_finding(db_session, asset, source="misconfig", template_id="MC-1", streak=1, matched_at=None)

    r = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert finding.id in r["would_close_ids"]  # misconfig auto-close NOT disabled by the HTTP gate
    db_session.refresh(finding)
    assert finding.eligible_miss_streak == 2


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


def test_attribution_rejects_foreign_tenant_run(db_session, test_tenant):
    # bulk_upsert_findings must never write another tenant's run id onto a finding.
    from app.models.database import Finding, Tenant
    from app.models.scanning import ScanRun
    from app.repositories.finding_repository import FindingRepository

    other = Tenant(name="Other-PC", slug="other-pc", contact_policy="x@y.com")
    db_session.add(other)
    db_session.commit()
    foreign_run = ScanRun(tenant_id=other.id, project_id=None, status="running", started_at=datetime.now(timezone.utc))
    db_session.add(foreign_run)
    db_session.commit()

    asset = _asset(db_session, test_tenant, "attr.test.com")
    FindingRepository(db_session).bulk_upsert_findings(
        [{"asset_id": asset.id, "template_id": "CVE-Z", "name": "z", "severity": "high"}],
        tenant_id=test_tenant.id,
        scan_run_id=foreign_run.id,  # belongs to `other`, not test_tenant
    )
    f = db_session.query(Finding).filter(Finding.asset_id == asset.id).first()
    assert f is not None
    assert f.last_detected_scan_run_id is None  # foreign run dropped → no attribution


# --- real coverage-aware close (commit_real gate) -------------------------------------------------


def test_real_close_fixes_a_would_close_endpoint_finding(db_session, test_tenant, monkeypatch):
    from app.models.coverage import CoverageStatus
    from app.models.database import FindingStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-realclose.test.com")
    shape = endpoint_shape_hash("https://ep-realclose.test.com/admin")
    _cover_endpoint(db_session, test_tenant, m, run, asset, shape, CoverageStatus.COVERED)
    finding = _open_finding(
        db_session, asset, template_id="EP-X", streak=1, endpoint_shape_hash=shape, origin_policy_hash=m.policy_hash
    )
    result = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1}),
    )
    assert result["would_close_ids"] == [finding.id]
    assert result["closed"] == 1
    assert result["real_close_enabled"] is True
    db_session.refresh(finding)
    assert finding.status == FindingStatus.FIXED  # real OPEN → FIXED
    assert finding.eligible_miss_streak == 2


def test_default_is_shadow_no_real_close(db_session, test_tenant, monkeypatch):
    from app.models.coverage import CoverageStatus
    from app.models.database import FindingStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-shadowdefault.test.com")
    shape = endpoint_shape_hash("https://ep-shadowdefault.test.com/admin")
    _cover_endpoint(db_session, test_tenant, m, run, asset, shape, CoverageStatus.COVERED)
    finding = _open_finding(
        db_session, asset, template_id="EP-X", streak=1, endpoint_shape_hash=shape, origin_policy_hash=m.policy_hash
    )
    result = shadow_auto_close(db_session, tenant_id=test_tenant.id, project_id=1, scan_run_id=run.id)
    assert result["would_close_ids"] == [finding.id]  # WOULD close…
    assert result["closed"] == 0  # …but shadow closes nothing
    assert result["real_close_enabled"] is False
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN


def test_real_close_never_closes_an_ineligible_finding(db_session, test_tenant, monkeypatch):
    # PARTIAL coverage → ineligible → even with commit_real=True the finding is NOT closed.
    from app.models.coverage import CoverageStatus
    from app.models.database import FindingStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-ineligible-real.test.com")
    shape = endpoint_shape_hash("https://ep-ineligible-real.test.com/admin")
    _cover_endpoint(db_session, test_tenant, m, run, asset, shape, CoverageStatus.PARTIAL)
    finding = _open_finding(
        db_session, asset, template_id="EP-X", streak=1, endpoint_shape_hash=shape, origin_policy_hash=m.policy_hash
    )
    result = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1}),
    )
    assert finding.id not in result["would_close_ids"]
    assert result["closed"] == 0
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN
    assert finding.eligible_miss_streak == 0  # reset, fail-closed


def test_real_close_redetected_finding_resets_streak_and_stays_open(db_session, test_tenant, monkeypatch):
    # A finding re-detected THIS run must reset its streak and stay OPEN, even with real close ON.
    from app.models.coverage import CoverageStatus
    from app.models.database import FindingStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-redetected-real.test.com")
    shape = endpoint_shape_hash("https://ep-redetected-real.test.com/admin")
    _cover_endpoint(db_session, test_tenant, m, run, asset, shape, CoverageStatus.COVERED)
    finding = _open_finding(
        db_session, asset, template_id="EP-X", streak=1, endpoint_shape_hash=shape, origin_policy_hash=m.policy_hash
    )
    finding.last_detected_scan_run_id = run.id  # detected THIS run
    db_session.commit()
    result = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1}),
    )
    assert finding.id not in result["would_close_ids"]
    assert result["closed"] == 0
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN
    assert finding.eligible_miss_streak == 0


def test_real_close_is_idempotent_across_reruns(db_session, test_tenant, monkeypatch):
    # Re-running the SAME run must not double-close or double-audit: once FIXED, the finding is no
    # longer in the OPEN working set and the conditional update touches 0 rows.
    from app.models.coverage import CoverageStatus
    from app.models.database import FindingStatus
    from app.services.coverage_autoclose import shadow_auto_close
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session)
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, "ep-idem-real.test.com")
    shape = endpoint_shape_hash("https://ep-idem-real.test.com/admin")
    _cover_endpoint(db_session, test_tenant, m, run, asset, shape, CoverageStatus.COVERED)
    finding = _open_finding(
        db_session, asset, template_id="EP-X", streak=1, endpoint_shape_hash=shape, origin_policy_hash=m.policy_hash
    )
    r1 = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1}),
    )
    assert r1["closed"] == 1
    db_session.refresh(finding)
    assert finding.status == FindingStatus.FIXED

    r2 = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1}),
    )
    assert r2["closed"] == 0
    assert finding.id not in r2["would_close_ids"]


# --- per-tier gate (real close needs tenant AND the covering policy's tier both allow-listed) ------


def _covered_wouldclose_endpoint(db_session, test_tenant, monkeypatch, *, tier, host):
    from app.models.coverage import CoverageStatus
    from app.services.endpoint_identity import endpoint_shape_hash

    _allow_discovery(monkeypatch, True)
    m = _endpoint_policy_catalog(db_session, tier=tier, revision=f"rev-t{tier}")
    run = _new_run(db_session, test_tenant)
    asset = _asset(db_session, test_tenant, f"ep-{host}.test.com")
    shape = endpoint_shape_hash(f"https://ep-{host}.test.com/admin")
    _cover_endpoint(db_session, test_tenant, m, run, asset, shape, CoverageStatus.COVERED)
    finding = _open_finding(
        db_session, asset, template_id="EP-X", streak=1, endpoint_shape_hash=shape, origin_policy_hash=m.policy_hash
    )
    return run, finding


def test_tier_allowed_closes(db_session, test_tenant, monkeypatch):
    from app.models.database import FindingStatus

    run, finding = _covered_wouldclose_endpoint(db_session, test_tenant, monkeypatch, tier=1, host="t1ok")
    res = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1}),
    )
    assert res["closed"] == 1 and res["gate_blocked"] == {"tenant_not_allowed": 0, "tier_not_allowed": 0}
    db_session.refresh(finding)
    assert finding.status == FindingStatus.FIXED


def test_t1_policy_denied_when_only_t2_allowed(db_session, test_tenant, monkeypatch):
    from app.models.database import FindingStatus

    run, finding = _covered_wouldclose_endpoint(db_session, test_tenant, monkeypatch, tier=1, host="t1denied")
    res = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({2}),
    )
    assert res["closed"] == 0 and res["gate_blocked"]["tier_not_allowed"] == 1
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN


def test_t2_policy_denied_when_only_t1_allowed(db_session, test_tenant, monkeypatch):
    from app.models.database import FindingStatus

    run, finding = _covered_wouldclose_endpoint(db_session, test_tenant, monkeypatch, tier=2, host="t2denied")
    res = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1}),
    )
    assert res["closed"] == 0 and res["gate_blocked"]["tier_not_allowed"] == 1
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN


def test_t2_policy_closes_when_t2_allowed(db_session, test_tenant, monkeypatch):
    from app.models.database import FindingStatus

    run, finding = _covered_wouldclose_endpoint(db_session, test_tenant, monkeypatch, tier=2, host="t2ok")
    res = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset({1, 2}),
    )
    assert res["closed"] == 1
    db_session.refresh(finding)
    assert finding.status == FindingStatus.FIXED


def test_empty_tiers_blocks_everything(db_session, test_tenant, monkeypatch):
    run, finding = _covered_wouldclose_endpoint(db_session, test_tenant, monkeypatch, tier=1, host="emptytiers")
    res = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=True,
        allowed_tiers=frozenset(),
    )
    assert res["closed"] == 0 and res["gate_blocked"]["tier_not_allowed"] == 1


def test_tenant_not_allowed_is_blocked_before_tier(db_session, test_tenant, monkeypatch):
    from app.models.database import FindingStatus

    run, finding = _covered_wouldclose_endpoint(db_session, test_tenant, monkeypatch, tier=1, host="notenant")
    res = shadow_auto_close(
        db_session,
        tenant_id=test_tenant.id,
        project_id=1,
        scan_run_id=run.id,
        real_close_enabled=True,
        tenant_allowed=False,
        allowed_tiers=frozenset({1}),
    )
    assert res["closed"] == 0
    assert res["gate_blocked"] == {"tenant_not_allowed": 1, "tier_not_allowed": 0}
    db_session.refresh(finding)
    assert finding.status == FindingStatus.OPEN
