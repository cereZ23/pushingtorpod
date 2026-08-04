"""http_endpoint live orchestrator (Sprint 3, step 3b) — DB-integration tests with a FAKE runner.

The Nuclei subprocess is injected (``EndpointNucleiRunner``) so no external traffic is needed; the
stock snapshot is monkeypatched to a synthetic set so no on-disk templates are required. Coverage is
verified against Postgres. Auto-close is never exercised (shadow).
"""

from __future__ import annotations

import json
from collections import namedtuple
from datetime import datetime, timedelta, timezone

import pytest

import app.services.scanning.http_endpoint_orchestrator as orch
from app.config import settings
from app.models.coverage import CoverageStatus, ScanEndpointCoverage
from app.models.database import Asset, AssetType
from app.models.enrichment import Endpoint
from app.models.scanning import ScanRun
from app.repositories.coverage_repository import CoverageRepository
from app.services.endpoint_identity import endpoint_shape_hash
from app.services.rule_catalog import ApplicableRule, ApplicableRuleSet
from app.services.rule_revision import compute_rule_revision, content_digest
from app.services.scan_policy import build_nuclei_policy_manifest
from app.services.scanning.http_endpoint_runner import (
    BatchExecutionEvidence,
    EndpointRunnerError,
    EndpointRunnerTimeout,
)

_File = namedtuple("_File", "relative_path content")
_Rev = namedtuple("_Rev", "digest")
_Snap = namedtuple("_Snap", "revision files")

NOW = datetime(2026, 8, 4, 12, 0, 0, tzinfo=timezone.utc)


def _endpoint_tmpl(id_):
    return json.dumps(
        {"id": id_, "info": {"severity": "high", "tags": ["cve"]}, "http": [{"method": "GET", "path": ["{{BaseURL}}"]}]}
    ).encode()


_STOCK = [("http/cves/ep-a.yaml", _endpoint_tmpl("ep-a")), ("http/cves/ep-b.yaml", _endpoint_tmpl("ep-b"))]


def _snapshot(files):
    entries = [(rel, content_digest(data)) for rel, data in files]
    return _Snap(revision=_Rev(digest=compute_rule_revision(entries)), files=[_File(r, d) for r, d in files])


class _FakeRunner:
    def __init__(self, evidence_fn):
        self.calls = []
        self._fn = evidence_fn

    def run_batch(
        self,
        *,
        tenant_id,
        target_file,
        template_dir,
        expected_targets,
        expected_templates,
        timeout_seconds,
        interactsh_server,
        relevant_flags,
    ):
        self.calls.append(
            {
                "template_dir": template_dir,
                "expected_targets": expected_targets,
                "expected_templates": expected_templates,
                "timeout": timeout_seconds,
                "interactsh_server": interactsh_server,
                "flags": dict(relevant_flags),
            }
        )
        return self._fn(expected_targets, expected_templates)


def _proven(n_targets, n_templates, findings=()):
    return BatchExecutionEvidence(
        launched=True,
        exit_code=0,
        targets_loaded=n_targets,
        templates_loaded=n_templates,
        completion_percent=100,
        output_complete=True,
        catalog_verified=True,
        targets_completed=True,
        findings=tuple(findings),
    )


def _timeout(n_targets, n_templates):
    return BatchExecutionEvidence(
        launched=True, exit_code=None, timed_out=True, targets_loaded=None, templates_loaded=n_templates
    )


# --- fixtures / helpers ---------------------------------------------------------------------------


@pytest.fixture
def _enabled(monkeypatch, test_tenant):
    monkeypatch.setattr(orch, "resolve_nuclei_rule_snapshot", lambda base, roots: _snapshot(_STOCK))
    monkeypatch.setattr(orch, "_cached_nuclei_version", lambda: "3.3.1")
    monkeypatch.setattr(settings, "nuclei_http_endpoint_enabled", True)
    monkeypatch.setattr(settings, "nuclei_http_endpoint_tenant_ids", [test_tenant.id])
    return test_tenant


def _asset(db, tenant, ident="app.curci.it"):
    a = Asset(tenant_id=tenant.id, identifier=ident, type=AssetType.SUBDOMAIN, is_active=True)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _run(db, tenant):
    r = ScanRun(tenant_id=tenant.id, project_id=None, status="running", started_at=NOW)
    db.add(r)
    db.commit()
    db.refresh(r)
    return r


def _endpoint(db, asset, url, ep_type=None):
    e = Endpoint(asset_id=asset.id, url=url, endpoint_type=ep_type)
    db.add(e)
    db.commit()
    return e


def _custom_policy(db):
    repo = CoverageRepository(db)
    m = build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision="c" * 64,
        pass_name="custom_http",
        tier=1,
        severity=["critical", "high", "medium", "low"],
        template_roots=["/app/custom-nuclei-templates"],
        exclude_tags=[],
    )
    repo.persist_policy(m)
    rs = ApplicableRuleSet(
        policy_hash=m.policy_hash,
        rules=(ApplicableRule("nuclei", "custom-x", "x.yaml", "d" * 64, "high", ("cve",)),),
    )
    repo.persist_catalog(rs)
    return m.policy_hash


def _call(
    db, tenant, *, assets, runner, custom_policy_hash, deadline=None, now=NOW, interactsh_server=None, base_urls=None
):
    run = _run(db, tenant)
    if base_urls is None:
        base_urls = [f"https://{a.identifier}" for a in assets]
    return orch.run_http_endpoint_pass(
        db=db,
        tenant_id=tenant.id,
        scan_run_id=run.id,
        scan_tier=1,
        assets=assets,
        base_urls=base_urls,
        phase_9_deadline=deadline or (NOW + timedelta(seconds=3600)),
        custom_policy_hash=custom_policy_hash,
        interactsh_server=interactsh_server,
        runner=runner,
        now_fn=lambda: now,
    ), run


# --- tests ----------------------------------------------------------------------------------------


def test_flag_off_does_nothing(db_session, test_tenant, monkeypatch):
    monkeypatch.setattr(settings, "nuclei_http_endpoint_enabled", False)
    runner = _FakeRunner(_proven)
    res, run = _call(db_session, test_tenant, assets=[], runner=runner, custom_policy_hash="x" * 64)
    assert res.status == "skipped" and res.skip_reason == "feature_disabled"
    assert runner.calls == []
    assert db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).count() == 0


def test_tenant_not_allowlisted_does_nothing(db_session, test_tenant, monkeypatch):
    monkeypatch.setattr(settings, "nuclei_http_endpoint_enabled", True)
    monkeypatch.setattr(settings, "nuclei_http_endpoint_tenant_ids", [test_tenant.id + 999])
    runner = _FakeRunner(_proven)
    res, _ = _call(db_session, test_tenant, assets=[], runner=runner, custom_policy_hash="x" * 64)
    assert res.status == "skipped" and res.skip_reason == "feature_disabled"
    assert runner.calls == []


def test_custom_catalog_absent_is_failed_no_runner(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    runner = _FakeRunner(_proven)
    res, run = _call(db_session, tenant, assets=[a], runner=runner, custom_policy_hash="deadbeef" * 8)
    assert res.status == "failed"
    assert runner.calls == []  # never reached execution
    assert db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).count() == 0


def test_no_targets_is_skipped(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)  # asset with NO endpoints
    custom = _custom_policy(db_session)
    runner = _FakeRunner(_proven)
    res, run = _call(db_session, tenant, assets=[a], runner=runner, custom_policy_hash=custom)
    assert res.status == "skipped" and res.skip_reason == "no_targets"
    assert runner.calls == []
    assert db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).count() == 0


def test_happy_path_all_covered(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    _endpoint(db_session, a, "https://app.curci.it/api/v1", ep_type="api")
    custom = _custom_policy(db_session)
    runner = _FakeRunner(_proven)
    res, run = _call(db_session, tenant, assets=[a], runner=runner, custom_policy_hash=custom)
    assert res.status == "completed"
    assert len(runner.calls) == 1
    assert runner.calls[0]["template_dir"].startswith("/")  # staged dir, not stock roots
    assert runner.calls[0]["interactsh_server"] is None
    rows = db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).all()
    assert len(rows) == 2 and all(r.status == CoverageStatus.COVERED for r in rows)
    # coverage keyed by the endpoint shapes, attributed to the asset
    shapes = {r.endpoint_shape_hash for r in rows}
    assert shapes == {
        endpoint_shape_hash("https://app.curci.it/admin"),
        endpoint_shape_hash("https://app.curci.it/api/v1"),
    }
    assert all(r.asset_id == a.id for r in rows)
    assert res.stats["coverage_complete"] is True


def test_timeout_batch_is_partial(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    custom = _custom_policy(db_session)
    runner = _FakeRunner(_timeout)
    res, run = _call(db_session, tenant, assets=[a], runner=runner, custom_policy_hash=custom)
    assert res.status == "partial"
    rows = db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).all()
    assert rows and all(r.status == CoverageStatus.PARTIAL for r in rows)
    assert res.stats["coverage_complete"] is False


def test_deadline_already_passed_skips_all(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    custom = _custom_policy(db_session)
    runner = _FakeRunner(_proven)
    # phase-9 deadline is in the PAST relative to now → no budget → all batches SKIPPED
    res, run = _call(
        db_session, tenant, assets=[a], runner=runner, custom_policy_hash=custom, deadline=NOW - timedelta(seconds=1)
    )
    assert res.status == "skipped" and res.skip_reason == "insufficient_phase_budget"
    assert runner.calls == []
    rows = db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).all()
    assert rows and all(r.status == CoverageStatus.SKIPPED for r in rows)  # diagnostic SKIPPED coverage


def test_no_url_in_stats(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/reset/secret-token-abc123?token=SUPERSECRET")
    custom = _custom_policy(db_session)
    runner = _FakeRunner(_proven)
    res, _ = _call(db_session, tenant, assets=[a], runner=runner, custom_policy_hash=custom)
    blob = json.dumps(res.stats) + repr(res)
    for leak in ("secret-token-abc123", "SUPERSECRET", "app.curci.it/reset"):
        assert leak not in blob


class _RaisingRunner:
    def __init__(self, exc):
        self._exc = exc

    def run_batch(self, **kw):
        raise self._exc


def test_runner_timeout_exception_is_partial(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    custom = _custom_policy(db_session)
    res, run = _call(
        db_session, tenant, assets=[a], runner=_RaisingRunner(EndpointRunnerTimeout("t")), custom_policy_hash=custom
    )
    assert res.status == "partial"  # a runner timeout is caught → PARTIAL, not an explosion
    rows = db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).all()
    assert rows and all(r.status == CoverageStatus.PARTIAL for r in rows)


def test_runner_generic_exception_single_batch_is_failed(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    custom = _custom_policy(db_session)
    res, run = _call(
        db_session, tenant, assets=[a], runner=_RaisingRunner(EndpointRunnerError("boom")), custom_policy_hash=custom
    )
    assert res.status == "failed"  # the ONLY launched batch failed → pass FAILED (not a soft PARTIAL)
    rows = db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).all()
    assert rows and all(r.status == CoverageStatus.FAILED for r in rows)


class _SequenceRunner:
    """Returns/raises a different thing per call — proves the remaining batches still run."""

    def __init__(self, seq):
        self._seq = list(seq)
        self.calls = 0

    def run_batch(self, **kw):
        item = self._seq[self.calls]
        self.calls += 1
        if isinstance(item, Exception):
            raise item
        return item


def test_multi_batch_error_then_covered_is_partial(db_session, _enabled, monkeypatch):
    # batch 1 runner error → FAILED; batch 2 fully proven → COVERED; pass PARTIAL — proves the
    # remaining batches DO run after a batch error.
    monkeypatch.setattr(settings, "nuclei_http_endpoint_batch_size", 1)
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/a1")
    _endpoint(db_session, a, "https://app.curci.it/a2")
    custom = _custom_policy(db_session)
    runner = _SequenceRunner([EndpointRunnerError("boom"), _proven(1, 2)])
    res, run = _call(db_session, tenant, assets=[a], runner=runner, custom_policy_hash=custom)
    assert res.status == "partial"
    assert runner.calls == 2  # the second batch DID run
    statuses = {r.status for r in db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id)}
    assert statuses == {CoverageStatus.FAILED, CoverageStatus.COVERED}


def test_writer_errors_downgrade_to_partial(db_session, _enabled, monkeypatch):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    custom = _custom_policy(db_session)

    # a fully-proven run that returns one finding on the batch target...
    def _with_finding(n_targets, n_templates):
        return _proven(
            n_targets,
            n_templates,
            findings=[{"target": "https://app.curci.it/admin", "template_id": "ep-a", "name": "x", "severity": "high"}],
        )

    # ...but the finding writer reports errors → the batch must NOT stay COVERED.
    from app.repositories.finding_repository import FindingRepository

    monkeypatch.setattr(
        FindingRepository,
        "bulk_upsert_findings",
        lambda self, f, t, scan_run_id=None: {"created": 0, "updated": 0, "errors": ["bad"]},
    )
    res, run = _call(db_session, tenant, assets=[a], runner=_FakeRunner(_with_finding), custom_policy_hash=custom)
    assert res.status == "partial"
    rows = db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).all()
    assert rows and all(r.status == CoverageStatus.PARTIAL for r in rows)


def test_writer_raises_is_rolled_back_and_coverage_saved(db_session, _enabled, monkeypatch):
    # The writer RAISES a DB error → the session must be rolled back so the PARTIAL coverage still
    # persists (no PendingRollbackError on the coverage write).
    from sqlalchemy.exc import IntegrityError

    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    custom = _custom_policy(db_session)

    def _with_finding(n_targets, n_templates):
        return _proven(
            n_targets,
            n_templates,
            findings=[{"target": "https://app.curci.it/admin", "template_id": "ep-a", "name": "x", "severity": "high"}],
        )

    from app.repositories.finding_repository import FindingRepository

    def _boom(self, f, t, scan_run_id=None):
        raise IntegrityError("stmt", {}, Exception("db aborted"))

    monkeypatch.setattr(FindingRepository, "bulk_upsert_findings", _boom)
    res, run = _call(db_session, tenant, assets=[a], runner=_FakeRunner(_with_finding), custom_policy_hash=custom)
    assert res.status == "partial"
    rows = db_session.query(ScanEndpointCoverage).filter_by(scan_run_id=run.id).all()
    assert rows and all(r.status == CoverageStatus.PARTIAL for r in rows)  # coverage really persisted


def test_base_url_dropped_uses_real_base_with_odd_port(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it:8443/")  # a base URL on a non-default port
    _endpoint(db_session, a, "https://app.curci.it/admin")  # a real deep endpoint
    custom = _custom_policy(db_session)
    runner = _FakeRunner(_proven)
    # phase 9 scanned the base on :8443 → the orchestrator must drop that candidate (not reconstruct :443)
    res, run = _call(
        db_session,
        tenant,
        assets=[a],
        runner=runner,
        custom_policy_hash=custom,
        base_urls=["https://app.curci.it:8443"],
    )
    assert res.stats["base_url_dropped"] == 1
    assert res.stats["selected_count"] == 1  # only /admin survives


def test_coverage_authorizing_vs_non_degrading_signals(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    custom = _custom_policy(db_session)
    # no_targets: NOT authorizing (an absent endpoint ≠ verified/remediation), but non-degrading.
    res_nt, _ = _call(db_session, tenant, assets=[a], runner=_FakeRunner(_proven), custom_policy_hash=custom)
    assert res_nt.status == "skipped"
    assert res_nt.stats["coverage_authorizing"] is False
    assert res_nt.stats["phase_non_degrading"] is True
    # insufficient budget: neither authorizing nor non-degrading (coverage is incomplete).
    _endpoint(db_session, a, "https://app.curci.it/admin")
    res_ib, _ = _call(
        db_session,
        tenant,
        assets=[a],
        runner=_FakeRunner(_proven),
        custom_policy_hash=custom,
        deadline=NOW - timedelta(seconds=1),
    )
    assert res_ib.skip_reason == "insufficient_phase_budget"
    assert res_ib.stats["coverage_authorizing"] is False
    assert res_ib.stats["phase_non_degrading"] is False


def test_completed_pass_is_authorizing(db_session, _enabled):
    tenant = _enabled
    a = _asset(db_session, tenant)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    custom = _custom_policy(db_session)
    res, _ = _call(db_session, tenant, assets=[a], runner=_FakeRunner(_proven), custom_policy_hash=custom)
    assert res.status == "completed"
    assert res.stats["coverage_authorizing"] is True
    assert res.stats["phase_non_degrading"] is True


# --- phase-9 adapter (step 3b-2b wiring) ----------------------------------------------------------

_DISABLED = {"phase_non_degrading": True, "coverage_authorizing": False, "skip_reason": "feature_disabled"}


def _adapter(db, tenant, **over):
    base = dict(
        tenant_id=tenant.id,
        scan_run_id=_run(db, tenant).id,
        scan_tier=1,
        direct_assets=[],
        phase_9_deadline=NOW + timedelta(seconds=3600),
        custom_policy_hash="x" * 64,
        interactsh_server=None,
        severity=["high"],
        exclude_tags="fuzz",
        rate_limit=150,
        concurrency=25,
        request_timeout=6,
        max_host_errors=20,
        now_fn=lambda: NOW,
        log=None,
    )
    base.update(over)
    return orch.run_endpoint_pass_in_phase9(db, **base)


def test_adapter_feature_off_is_true_noop(db_session, test_tenant, monkeypatch):
    monkeypatch.setattr(settings, "nuclei_http_endpoint_enabled", False)
    called = {"base_urls": 0, "pass": 0}
    monkeypatch.setattr(
        orch, "build_base_urls", lambda *a, **k: called.__setitem__("base_urls", called["base_urls"] + 1) or []
    )
    monkeypatch.setattr(orch, "run_http_endpoint_pass", lambda **k: called.__setitem__("pass", called["pass"] + 1))
    stats = _adapter(db_session, test_tenant)
    assert stats["skip_reason"] == "feature_disabled" and stats["enabled"] is False
    assert called == {"base_urls": 0, "pass": 0}  # NO service query, NO runner/orchestrator
    assert orch.phase_degraded_by_endpoint(stats) is False  # a disabled feature never degrades


def test_adapter_exception_when_enabled_is_failclosed_no_url(db_session, _enabled, monkeypatch):
    # an unexpected error (message carrying a URL) must degrade the phase, non-authorizing, no leak
    def _boom(**k):
        raise RuntimeError("connect failed for https://secret.curci.it/reset?token=SUPERSECRET")

    monkeypatch.setattr(orch, "run_http_endpoint_pass", _boom)
    stats = _adapter(db_session, _enabled)
    assert stats["enabled"] is True and stats["coverage_authorizing"] is False
    assert stats["phase_non_degrading"] is False
    assert orch.phase_degraded_by_endpoint(stats) is True
    assert stats["error"] == "RuntimeError"
    blob = json.dumps(stats)
    for leak in ("secret.curci.it", "SUPERSECRET", "https://"):
        assert leak not in blob  # only the reason code, never the exception message/URL


def test_adapter_custom_policy_hash_none_is_visible_failure(db_session, _enabled):
    # feature ON + no custom catalog → the endpoint failure must be VISIBLE (FAILED), not silent
    a = _asset(db_session, _enabled)
    _endpoint(db_session, a, "https://app.curci.it/admin")
    stats = _adapter(db_session, _enabled, direct_assets=[a], custom_policy_hash=None)
    assert stats.get("coverage_complete") is False
    assert orch.phase_degraded_by_endpoint(stats) is True  # a structural failure degrades the phase


def test_phase_degraded_by_endpoint_rollup():
    from app.services.scanning.http_endpoint_orchestrator import phase_degraded_by_endpoint as deg

    assert deg({"phase_non_degrading": True}) is False  # feature_disabled / no_targets / completed
    assert deg({"phase_non_degrading": False}) is True  # insufficient_phase_budget / partial / failed / error
    assert deg({}) is True  # missing signal → fail-closed (degrades)
