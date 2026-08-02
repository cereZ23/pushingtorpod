"""Pass-wiring emit — pure helpers, fail-open contract, and a DB round-trip.

The DB test uses the same Postgres conftest fixtures as test_coverage_repository;
the pure/fail-open tests need no DB and run anywhere.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app.repositories.coverage_repository import CoverageStatus, conservative_pass_status
from app.services import coverage_emit
from app.services.coverage_emit import _split_roots, emit_nuclei_pass_coverage, nuclei_result_outcome
from app.services.rule_revision import (
    ResolvedRuleFile,
    ResolvedRuleSnapshot,
    RuleResolutionError,
    RuleRevision,
    compute_rule_revision,
    content_digest,
)
from app.services.scan_policy import build_nuclei_policy_manifest


# --- pure: run_nuclei_scan result contract -> coverage status ---------------
# A dict-reported failure ({"status":"failed"}) never raises; it must NOT become
# COVERED, or the consumer would authorise a false "fixed".


def _status(result, *, exception_occurred=False):
    errored, truncated = nuclei_result_outcome(result, exception_occurred=exception_occurred)
    return conservative_pass_status(ran=True, errored=errored, truncated=truncated)


def test_outcome_success_clean_is_covered():
    assert _status({"status": "success", "truncated": False}) is CoverageStatus.COVERED


def test_outcome_success_truncated_is_partial():
    assert _status({"status": "success", "truncated": True}) is CoverageStatus.PARTIAL


def test_outcome_dict_failed_without_exception_is_failed():
    # The critical case: failure returned as a dict, no exception raised.
    assert _status({"status": "failed", "error": "boom"}) is CoverageStatus.FAILED


def test_outcome_success_with_error_key_is_failed():
    assert _status({"status": "success", "error": "partial boom"}) is CoverageStatus.FAILED


def test_outcome_no_urls_is_failed_not_covered():
    # A pass with nothing live to scan did not verify anything -> non-authorising.
    assert _status({"status": "no_urls"}) is CoverageStatus.FAILED


def test_outcome_exception_is_failed():
    assert _status(None, exception_occurred=True) is CoverageStatus.FAILED


def test_outcome_none_or_malformed_is_failed():
    assert _status(None) is CoverageStatus.FAILED
    assert _status("not-a-dict") is CoverageStatus.FAILED


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
        db=None,
        tenant_id=1,
        scan_run_id=None,
        pass_name="http_stock",
        tier=1,
        asset_ids=[1, 2],
        severity=["high"],
        templates=["http/"],
        exclude_tags="",
        ran=True,
        errored=False,
        truncated=False,
    )


def test_emit_is_noop_without_assets():
    emit_nuclei_pass_coverage(
        db=None,
        tenant_id=1,
        scan_run_id=99,
        pass_name="http_stock",
        tier=1,
        asset_ids=[],
        severity=["high"],
        templates=["http/"],
        exclude_tags="",
        ran=True,
        errored=False,
        truncated=False,
    )


def test_emit_swallows_resolution_error(monkeypatch):
    # A revision-resolution failure must be logged, not raised (fail-open).
    def boom(*a, **k):
        raise RuleResolutionError("templates missing")

    monkeypatch.setattr(coverage_emit, "resolve_nuclei_rule_snapshot", boom)
    monkeypatch.setattr(coverage_emit, "_cached_nuclei_version", lambda: "3.3.1")
    # db is a dummy — we must never reach it.
    emit_nuclei_pass_coverage(
        db=object(),
        tenant_id=1,
        scan_run_id=5,
        pass_name="http_stock",
        tier=1,
        asset_ids=[1],
        severity=["high"],
        templates=["http/"],
        exclude_tags="",
        ran=True,
        errored=False,
        truncated=False,
    )


# --- DB round-trip: emit → COVERED verdict readable back (CI, Postgres) ------


class _Rev:
    digest = "d" * 64


class _Snap:
    # Minimal ResolvedRuleSnapshot stand-in: the emit reads .revision.digest, and the
    # (observational) catalog step reads .files — empty here, so enumeration fails closed
    # and is swallowed, leaving the COVERED verdict itself unaffected.
    revision = _Rev()
    files = ()


def test_emit_records_covered_verdict(db_session, test_tenant, monkeypatch):
    from app.models.database import Asset, AssetType
    from app.models.scanning import ScanRun
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.coverage_emit import emit_nuclei_pass_coverage as emit

    monkeypatch.setattr(coverage_emit, "_cached_nuclei_version", lambda: "3.3.1")
    monkeypatch.setattr(coverage_emit, "resolve_nuclei_rule_snapshot", lambda *a, **k: _Snap())

    run = ScanRun(tenant_id=test_tenant.id, project_id=None, status="running", started_at=datetime.now(timezone.utc))
    db_session.add(run)
    asset = Asset(tenant_id=test_tenant.id, identifier="a.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    emit(
        db_session,
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        pass_name="http_stock",
        tier=1,
        asset_ids=[asset.id],
        severity=["critical", "high"],
        templates=["http/"],
        exclude_tags="",
        ran=True,
        errored=False,
        truncated=False,
    )

    covered = CoverageRepository(db_session).covered_asset_ids(run.id, "http_stock")
    assert covered == {asset.id}


def test_emit_truncated_is_partial_not_covered(db_session, test_tenant, monkeypatch):
    from app.models.database import Asset, AssetType
    from app.models.scanning import ScanRun
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.coverage_emit import emit_nuclei_pass_coverage as emit

    monkeypatch.setattr(coverage_emit, "_cached_nuclei_version", lambda: "3.3.1")
    monkeypatch.setattr(coverage_emit, "resolve_nuclei_rule_snapshot", lambda *a, **k: _Snap())

    run = ScanRun(tenant_id=test_tenant.id, project_id=None, status="running", started_at=datetime.now(timezone.utc))
    db_session.add(run)
    asset = Asset(tenant_id=test_tenant.id, identifier="b.test.com", type=AssetType.SUBDOMAIN, is_active=True)
    db_session.add(asset)
    db_session.commit()

    emit(
        db_session,
        tenant_id=test_tenant.id,
        scan_run_id=run.id,
        pass_name="http_stock",
        tier=1,
        asset_ids=[asset.id],
        severity=["critical", "high"],
        templates=["http/"],
        exclude_tags="",
        ran=True,
        errored=False,
        truncated=True,  # hit the timeout
    )

    # Truncated must NOT authorise auto-close: no COVERED verdict.
    covered = CoverageRepository(db_session).covered_asset_ids(run.id, "http_stock")
    assert covered == set()


# --- P-B: applicable-detector catalog persisted from the same snapshot -------
# The catalog is observational + idempotent per policy_hash, and fail-open: a failure
# must never break the emit (a missing catalog only ever prevents a future auto-close).


_TPL = b"id: test-cve\ninfo:\n  name: Test\n  severity: high\n  tags: cve\n"
_REL = "http/test-cve.yaml"


def _fake_snapshot_and_manifest():
    dg = content_digest(_TPL)
    rev = compute_rule_revision([(_REL, dg)])
    snapshot = ResolvedRuleSnapshot(
        revision=RuleRevision(digest=rev, rule_count=1, total_bytes=len(_TPL), relative_paths=(_REL,)),
        files=(ResolvedRuleFile(_REL, _TPL, dg),),
    )
    manifest = build_nuclei_policy_manifest(
        nuclei_version="3.3.1",
        template_revision=rev,
        pass_name="http_stock",
        tier=1,
        severity=["high"],
        template_roots=["http/"],
        exclude_tags=[],
    )
    return snapshot, manifest


class _FakeRepo:
    def __init__(self, exists):
        self._exists = exists
        self.persisted = None

    def catalog_exists(self, policy_hash):
        return self._exists

    def persist_catalog(self, ruleset):
        self.persisted = ruleset
        return len(ruleset.rules)


def test_persist_pass_catalog_skips_when_present():
    snapshot, manifest = _fake_snapshot_and_manifest()
    repo = _FakeRepo(exists=True)
    calls = []
    coverage_emit._persist_pass_catalog(repo, manifest, snapshot, parse_yaml=lambda d: calls.append(d))
    assert repo.persisted is None  # already catalogued -> nothing written
    assert calls == []  # and the expensive YAML parse was skipped entirely


def test_persist_pass_catalog_enumerates_when_absent():
    import yaml

    snapshot, manifest = _fake_snapshot_and_manifest()
    repo = _FakeRepo(exists=False)
    coverage_emit._persist_pass_catalog(repo, manifest, snapshot, parse_yaml=yaml.safe_load)
    assert repo.persisted is not None
    assert repo.persisted.contains("test-cve")


def test_persist_pass_catalog_fail_open_on_error():
    snapshot, manifest = _fake_snapshot_and_manifest()
    repo = _FakeRepo(exists=False)

    def _boom(_data):
        raise ValueError("bad yaml")

    # Enumeration blows up -> swallowed, no persist, NO exception propagated.
    coverage_emit._persist_pass_catalog(repo, manifest, snapshot, parse_yaml=_boom)
    assert repo.persisted is None
