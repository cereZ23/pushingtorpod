"""http_endpoint pass — live orchestrator (Sprint 3, step 3b).

Runs the dedicated endpoint Nuclei pass INSIDE phase 9 (synchronously — same scan_run_id, deadline,
and coverage), behind a per-tenant feature flag. It reuses Step-1 selection, Step-2 policy/catalog,
and Step-3a batching/verdict/staging; the actual subprocess is the injected ``EndpointNucleiRunner``.

Fail-closed contract (see the step-3b spec):
- disabled/allowlist/no-target → SKIPPED with a reason, no subprocess, no coverage;
- bad config / missing-or-incoherent custom catalog / bundle mismatch / staging error → FAILED;
- COVERED only from positive proof (via ``batch_verdict``); any uncertainty → PARTIAL;
- coverage is written PER BATCH, immediately, so a later crash never loses earlier batches;
- findings go through the existing writer with NULL provenance (endpoint_shape_hash /
  origin_policy_hash stay NULL → ineligible); asset attribution comes from the batch target, never a
  tenant-wide hostname search;
- NO auto-close, no miss-streak change. No URL / path / query / target file / command / JSONL /
  finding body in any log, repr, or persisted stat.
"""

from __future__ import annotations

import logging
import math
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Callable, Optional, Sequence
from urllib.parse import urlparse

from app.config import settings
from app.models.coverage import CoverageStatus
from app.models.database import Asset
from app.repositories.coverage_repository import CoverageRepository, CoverageWriteError
from app.repositories.finding_repository import FindingRepository
from app.services.coverage_emit import NUCLEI_TEMPLATES_DIR, _cached_nuclei_version
from app.services.endpoint_identity import endpoint_shape_hash
from app.services.endpoint_policy import build_http_endpoint_policy_bundle, persist_endpoint_policy_bundle
from app.services.endpoint_selection import AuthorizedAsset, CandidateEndpoint, normalize_host, select_endpoint_targets
from app.services.rule_revision import resolve_nuclei_rule_snapshot
from app.services.scan_policy import PASS_HTTP_ENDPOINT
from app.services.scan_tiers import http_stock_roots, nuclei_relevant_flags, tier_severity
from app.services.scanning.endpoint_pass import (
    PASS_COMPLETED,
    PASS_FAILED,
    PASS_SKIPPED,
    EndpointBatch,
    TemplateStagingError,
    aggregate_pass_status,
    batch_verdict,
    compute_effective_deadline,
    plan_batches,
    remaining_budget_seconds,
    stage_selected_templates,
    validate_endpoint_pass_config,
)
from app.services.scanning.base_urls import build_base_urls
from app.services.scanning.http_endpoint_runner import (
    BatchExecutionEvidence,
    EndpointNucleiRunner,
    EndpointRunnerTimeout,
    NucleiEndpointRunner,
)

logger = logging.getLogger(__name__)

_DEFAULT_PORT = {"http": 80, "https": 443}

# The pass produces TWO orthogonal signals for the phase-9 rollup (3b-2):
#   - ``phase_non_degrading``  : this pass must NOT degrade the existing pipeline — True for a full
#     COMPLETED run and for the innocuous skips (feature_disabled / no_targets). It only means
#     "don't worsen the phase", NOT that anything was verified.
#   - ``coverage_authorizing`` : the endpoint coverage may (later) authorise a miss/close — True
#     ONLY for a COMPLETED run. Crucially, no_targets / feature_disabled are NOT authorizing: an
#     endpoint absent from the crawl (or a disabled feature) means NO historical endpoint was
#     verified, so it can never license a close (Katana: "absent ≠ remediation"). And even when the
#     pass COMPLETED, the consumer must still require the specific endpoint's COVERED row.
_NON_DEGRADING_SKIP_REASONS = frozenset({"no_targets", "feature_disabled"})


def _phase_non_degrading(status: str, skip_reason: Optional[str]) -> bool:
    return status == PASS_COMPLETED or (status == PASS_SKIPPED and skip_reason in _NON_DEGRADING_SKIP_REASONS)


def _coverage_authorizing(status: str, skip_reason: Optional[str]) -> bool:
    return status == PASS_COMPLETED


class EndpointPassStructuralError(Exception):
    """A structural failure that must map the whole pass (or its selected targets) to FAILED."""


def is_endpoint_pass_enabled(tenant_id: int) -> bool:
    """The pass runs for a tenant iff the global flag is ON AND the tenant is on the allowlist.

    An EMPTY allowlist means NO tenant (never "all") — no implicit wildcard.
    """
    return bool(settings.nuclei_http_endpoint_enabled) and tenant_id in set(
        settings.nuclei_http_endpoint_tenant_ids or []
    )


@dataclass(frozen=True)
class EndpointBatchResult:
    batch: EndpointBatch
    evidence: BatchExecutionEvidence
    status: CoverageStatus
    findings_created: int
    findings_updated: int


@dataclass
class EndpointPassResult:
    status: str
    skip_reason: Optional[str]
    policy_hash: Optional[str]
    catalog_digest: Optional[str]
    classifier_version: Optional[int]
    batch_results: list[EndpointBatchResult] = field(default_factory=list)
    stats: dict = field(default_factory=dict)

    def __repr__(self) -> str:  # no URL/target — status + hashes + counts only
        return (
            f"EndpointPassResult(status={self.status!r}, skip_reason={self.skip_reason!r}, "
            f"policy={self.policy_hash[:12] + '…' if self.policy_hash else None}, "
            f"batches={len(self.batch_results)})"
        )


def _skipped(
    reason: str, *, policy_hash=None, catalog_digest=None, classifier_version=None, stats=None
) -> EndpointPassResult:
    base = {
        "enabled": reason != "feature_disabled",
        "pass_name": PASS_HTTP_ENDPOINT,
        "skip_reason": reason,
        "coverage_complete": False,
        "coverage_authorizing": _coverage_authorizing(PASS_SKIPPED, reason),
        "phase_non_degrading": _phase_non_degrading(PASS_SKIPPED, reason),
    }
    return EndpointPassResult(
        status=PASS_SKIPPED,
        skip_reason=reason,
        policy_hash=policy_hash,
        catalog_digest=catalog_digest,
        classifier_version=classifier_version,
        stats={**base, **(stats or {})},
    )


def _base_url_keys(base_urls: Sequence[str]) -> set[tuple[str, str, int]]:
    """(scheme, normalized host, effective port) for each REAL base URL the phase already scanned.

    These come from phase 9 (http_stock etc.) — NOT reconstructed from assets — so odd ports like
    :8080 / :8443 and non-default service base targets are matched correctly, not just :80/:443.
    """
    keys: set[tuple[str, str, int]] = set()
    for url in base_urls or ():
        try:
            p = urlparse(url)
        except Exception:
            continue
        scheme = (p.scheme or "").lower()
        host = normalize_host(p.hostname)
        if not host or scheme not in _DEFAULT_PORT:
            continue
        port = p.port if p.port is not None else _DEFAULT_PORT[scheme]
        keys.add((scheme, host, port))
    return keys


def _is_base_url(url: str, base_keys: set[tuple[str, str, int]]) -> bool:
    """True iff ``url`` is one of the pass's base URLs (root path, no query) — normalized so
    ``https://host`` / ``https://host/`` / ``https://HOST:443/`` all match the same base."""
    try:
        p = urlparse(url)
    except Exception:
        return False
    scheme = (p.scheme or "").lower()
    host = normalize_host(p.hostname)
    if not host or scheme not in _DEFAULT_PORT:
        return False
    if p.query or p.path.strip("/") != "":  # a deep path or a query is NOT the base
        return False
    port = p.port if p.port is not None else _DEFAULT_PORT[scheme]
    return (scheme, host, port) in base_keys


def run_http_endpoint_pass(
    *,
    db,
    tenant_id: int,
    scan_run_id: int,
    scan_tier: int,
    assets: Sequence[Asset],
    base_urls: Sequence[str],
    phase_9_deadline: datetime,
    custom_policy_hash: str,
    interactsh_server: Optional[str],
    runner: EndpointNucleiRunner,
    now_fn: Callable[[], datetime],
) -> EndpointPassResult:
    """Execute the http_endpoint pass synchronously within phase 9. See the module docstring."""
    # --- 4.1 initial gate ---
    if not is_endpoint_pass_enabled(tenant_id):
        return _skipped("feature_disabled")

    cfg = dict(
        batch_size=settings.nuclei_http_endpoint_batch_size,
        batch_timeout_seconds=settings.nuclei_http_endpoint_batch_timeout_seconds,
        budget_seconds=settings.nuclei_http_endpoint_budget_seconds,
        max_per_host=settings.nuclei_http_endpoint_max_per_host,
    )
    repo = CoverageRepository(db)
    try:
        validate_endpoint_pass_config(**cfg)  # ValueError on a bad knob → FAILED (caught below)
        if phase_9_deadline.tzinfo is None or phase_9_deadline.tzinfo.utcoffset(phase_9_deadline) is None:
            raise EndpointPassStructuralError("phase_9_deadline_not_timezone_aware")
        _verify_run_owned_by_tenant(db, scan_run_id, tenant_id)
        # 4.2 custom catalog is MANDATORY — disjunction can't run against an empty default.
        custom_detector_ids = _require_custom_catalog(repo, custom_policy_hash)
        # 4.3 snapshot + endpoint bundle (identity verified against the persisted catalog).
        snapshot, bundle = _build_and_verify_bundle(
            repo, scan_tier=scan_tier, interactsh_server=interactsh_server, custom_detector_ids=custom_detector_ids
        )
    except (EndpointPassStructuralError, ValueError) as exc:
        # No trustworthy policy_hash yet → no coverage rows, just a FAILED pass with a reason code.
        return EndpointPassResult(
            status=PASS_FAILED,
            skip_reason=str(exc),
            policy_hash=None,
            catalog_digest=None,
            classifier_version=None,
            stats={
                "enabled": True,
                "pass_name": PASS_HTTP_ENDPOINT,
                "coverage_complete": False,
                "coverage_authorizing": False,
                "phase_non_degrading": False,
                "error": str(exc),
            },
        )

    policy_hash = bundle.manifest.policy_hash
    relevant_flags = dict(bundle.manifest.relevant_flags)

    # --- 5 endpoint selection (with explicit base-URL drop) ---
    candidates, base_url_dropped = _load_candidates(db, tenant_id, [a.id for a in assets], _base_url_keys(base_urls))
    now = now_fn()
    active_scope_entries = _active_scope_entries(db, tenant_id, now) if candidates else []
    selection = select_endpoint_targets(
        candidates,
        authorized_assets=[AuthorizedAsset(asset_id=a.id, host=a.identifier) for a in assets],
        per_host_cap=cfg["max_per_host"],
        now=now,
        scope_entries=active_scope_entries,
    )
    base_stats = _selection_stats(bundle, selection, len(candidates), base_url_dropped)

    if not selection.selected:
        return _skipped(
            "no_targets",
            policy_hash=policy_hash,
            catalog_digest=bundle.catalog_digest,
            classifier_version=bundle.classifier_version,
            stats={**base_stats, "coverage_complete": False},
        )

    # --- 6 staging + 9 batching/budget + 12 per-batch verdict/coverage ---
    batch_results: list[EndpointBatchResult] = []
    structural_error = False
    with tempfile.TemporaryDirectory(prefix="http_endpoint_templates_") as staging:
        try:
            staged = stage_selected_templates(snapshot, bundle.selected_template_paths, staging)
            if len(staged) != len(bundle.ruleset.rules) or not staged:
                raise TemplateStagingError("staged file count does not match the bundle ruleset")
        except TemplateStagingError as exc:
            # policy exists now → write FAILED for every selected target, then FAILED the pass.
            structural_error = True
            batches = plan_batches(selection.selected, batch_size=cfg["batch_size"], policy_hash=policy_hash)
            for b in batches:
                _write_coverage(repo, tenant_id, scan_run_id, b, CoverageStatus.FAILED)
                batch_results.append(EndpointBatchResult(b, _staging_failed_evidence(), CoverageStatus.FAILED, 0, 0))
            return _finalize(
                PASS_FAILED,
                batch_results,
                selection,
                bundle,
                base_stats,
                now_fn=now_fn,
                structural_error=True,
                extra_error=str(exc),
            )

        batches = plan_batches(selection.selected, batch_size=cfg["batch_size"], policy_hash=policy_hash)
        effective_deadline = compute_effective_deadline(
            phase_9_deadline=phase_9_deadline, started_at=now_fn(), endpoint_budget_seconds=cfg["budget_seconds"]
        )
        budget_out = False
        for batch in batches:
            remaining = remaining_budget_seconds(now=now_fn(), effective_deadline=effective_deadline)
            batch_timeout = min(cfg["batch_timeout_seconds"], math.floor(remaining))
            if budget_out or batch_timeout <= 0:
                budget_out = True
                _write_coverage(repo, tenant_id, scan_run_id, batch, CoverageStatus.SKIPPED)
                batch_results.append(EndpointBatchResult(batch, _skipped_evidence(), CoverageStatus.SKIPPED, 0, 0))
                continue
            result = _run_one_batch(
                db,
                repo,
                runner,
                tenant_id=tenant_id,
                scan_run_id=scan_run_id,
                batch=batch,
                template_dir=staging,
                expected_templates=len(bundle.ruleset.rules),
                timeout_seconds=batch_timeout,
                interactsh_server=interactsh_server,
                relevant_flags=relevant_flags,
            )
            batch_results.append(result)

    pass_status = _finalize(
        None, batch_results, selection, bundle, base_stats, now_fn=now_fn, structural_error=structural_error
    )
    return pass_status


# --- gate helpers -------------------------------------------------------------------------------


def _verify_run_owned_by_tenant(db, scan_run_id: int, tenant_id: int) -> None:
    from app.models.scanning import ScanRun

    owned = db.query(ScanRun.id).filter(ScanRun.id == scan_run_id, ScanRun.tenant_id == tenant_id).first()
    if owned is None:
        raise EndpointPassStructuralError("scan_run_not_owned_by_tenant")


def _require_custom_catalog(repo: CoverageRepository, custom_policy_hash: str) -> list[str]:
    if not custom_policy_hash:
        raise EndpointPassStructuralError("custom_policy_hash_missing")
    build = repo.catalog_build(custom_policy_hash)
    live = repo.catalog_fingerprint(custom_policy_hash)
    if build is None or live is None or build != live:
        raise EndpointPassStructuralError("custom_catalog_absent_or_incoherent")
    ids = repo.applicable_detector_ids(custom_policy_hash)
    if not ids:
        raise EndpointPassStructuralError("custom_catalog_empty")
    return sorted(ids)


def _build_and_verify_bundle(repo, *, scan_tier: int, interactsh_server, custom_detector_ids):
    import yaml

    base_dir = NUCLEI_TEMPLATES_DIR
    roots = http_stock_roots(scan_tier)
    exclude = [t.strip() for t in getattr(settings, f"nuclei_exclude_tags_t{scan_tier}", "").split(",") if t.strip()]
    relevant_flags = nuclei_relevant_flags(interactsh_enabled=bool(interactsh_server))
    try:
        snapshot = resolve_nuclei_rule_snapshot(base_dir, roots)
        bundle = build_http_endpoint_policy_bundle(
            snapshot=snapshot,
            tier=scan_tier,
            severity=tier_severity(scan_tier),
            exclude_tags=exclude,
            relevant_flags=relevant_flags,
            custom_detector_ids=custom_detector_ids,
            parse_yaml=yaml.safe_load,
            nuclei_version=_cached_nuclei_version(),
            template_roots=roots,
        )
        persist_endpoint_policy_bundle(repo, bundle)
    except Exception as exc:  # RuleCatalogError / EndpointDisjunctionError / CoverageWriteError / FS
        raise EndpointPassStructuralError(f"bundle_build_failed:{type(exc).__name__}") from exc

    ph = bundle.manifest.policy_hash
    build = repo.catalog_build(ph)
    live = repo.catalog_fingerprint(ph)
    if (
        build is None
        or live is None
        or build != live
        or bundle.catalog_digest != build[1]
        or bundle.ruleset.policy_hash != ph
        or set(bundle.selected_template_paths) != {r.relative_path for r in bundle.ruleset.rules}
    ):
        raise EndpointPassStructuralError("bundle_catalog_mismatch")
    return snapshot, bundle


def _active_scope_entries(db, tenant_id, now):
    from app.services.scope_authorization import _active_authorizations

    return [e for auth in _active_authorizations(db, tenant_id, now) for e in (auth.scope_entries or [])]


def _load_candidates(db, tenant_id, asset_ids, base_keys):
    from app.models.enrichment import Endpoint

    rows = (
        db.query(Endpoint.url, Endpoint.endpoint_type, Endpoint.asset_id)
        .join(Asset, Asset.id == Endpoint.asset_id)
        .filter(Asset.tenant_id == tenant_id, Asset.is_active == True, Asset.id.in_(list(asset_ids)))  # noqa: E712
        .all()
    )
    candidates, base_dropped = [], 0
    for url, ep_type, asset_id in rows:
        if url and _is_base_url(url, base_keys):
            base_dropped += 1
            continue
        candidates.append(CandidateEndpoint(url=url, endpoint_type=ep_type, asset_id=asset_id))
    return candidates, base_dropped


# --- per-batch execution ------------------------------------------------------------------------


def _run_one_batch(
    db,
    repo,
    runner,
    *,
    tenant_id,
    scan_run_id,
    batch,
    template_dir,
    expected_templates,
    timeout_seconds,
    interactsh_server,
    relevant_flags,
):
    # Contextual per-batch temp dir. Cleanup is EXPLICIT: a cleanup failure is logged with a reason
    # code (never a path/URL) and downgrades the batch to at least PARTIAL — it must NEVER raise out
    # of the pass and lose the already-computed verdict/coverage.
    td = tempfile.mkdtemp(prefix="http_endpoint_targets_")
    cleanup_failed = False
    try:
        target_file = os.path.join(td, "targets.txt")
        _write_target_file(target_file, batch)
        # A runner exception must NOT explode the whole pass: a timeout → PARTIAL, any other runner
        # failure → FAILED, so coverage is still written and the remaining batches still run.
        try:
            evidence = runner.run_batch(
                tenant_id=tenant_id,
                target_file=target_file,
                template_dir=template_dir,
                expected_targets=len(batch.targets),
                expected_templates=expected_templates,
                timeout_seconds=timeout_seconds,
                interactsh_server=interactsh_server,
                relevant_flags=relevant_flags,
            )
        except EndpointRunnerTimeout:
            evidence = BatchExecutionEvidence(launched=True, exit_code=None, timed_out=True)
        except Exception as exc:  # EndpointRunnerError or any unexpected subprocess-boundary error
            logger.warning(
                "http_endpoint batch runner error",
                extra={
                    "tenant_id": tenant_id,
                    "scan_run_id": scan_run_id,
                    "batch_index": batch.index,
                    "reason_code": type(exc).__name__,
                },
            )
            evidence = BatchExecutionEvidence(launched=False, exit_code=None, parse_incomplete=True)
    finally:
        try:
            shutil.rmtree(td)
        except Exception as exc:
            cleanup_failed = True
            logger.warning(
                "http_endpoint target_cleanup_failed",
                extra={
                    "tenant_id": tenant_id,
                    "scan_run_id": scan_run_id,
                    "batch_index": batch.index,
                    "reason_code": type(exc).__name__,
                },
            )

    # 13 attribute findings by BATCH TARGET (never a hostname search). Ambiguity → parse_incomplete.
    attributed, attribution_ok = _attribute_findings(evidence.findings, batch)
    if not evidence.launched:
        # A structural runner failure (process never started) is FAILED — batch_verdict rejects
        # launched=False, so short-circuit here rather than calling it.
        status = CoverageStatus.FAILED
    else:
        status = batch_verdict(
            launched=evidence.launched,
            exit_code=evidence.exit_code,
            output_complete=evidence.output_complete,
            catalog_verified=evidence.catalog_verified,
            targets_completed=evidence.targets_completed,
            timed_out=evidence.timed_out,
            budget_expired=evidence.budget_expired,
            truncated=evidence.truncated,
            drift=evidence.drift,
            unresponsive=evidence.unresponsive_targets > 0,
            parse_incomplete=evidence.parse_incomplete or not attribution_ok,
        )

    # Save findings FIRST, then the FINAL coverage. If the writer raises OR reports errors, the
    # detection output was not fully processed → downgrade a would-be COVERED to PARTIAL (never
    # authorise on an incomplete write).
    created = updated = 0
    writer_ok = True
    if attributed:
        try:
            res = FindingRepository(db).bulk_upsert_findings(attributed, tenant_id, scan_run_id=scan_run_id)
            created, updated = res.get("created", 0), res.get("updated", 0)
            if res.get("errors"):
                writer_ok = False
        except Exception as exc:
            # A DB error aborts the PostgreSQL transaction — roll back so the coverage write below
            # doesn't hit PendingRollbackError.
            _safe_rollback(db)
            writer_ok = False
            logger.warning(
                "http_endpoint finding write error",
                extra={
                    "tenant_id": tenant_id,
                    "scan_run_id": scan_run_id,
                    "batch_index": batch.index,
                    "reason_code": type(exc).__name__,
                },
            )
    # A failed write OR a failed target cleanup means the batch cannot be authorised → at least PARTIAL.
    if (not writer_ok or cleanup_failed) and status == CoverageStatus.COVERED:
        status = CoverageStatus.PARTIAL

    # Write coverage LAST (still per-batch + immediate). A coverage-write error FAILS the batch.
    _write_coverage(repo, tenant_id, scan_run_id, batch, status)

    # Per-batch diagnostic (shadow observability): the counts + proof flags that DECIDED the verdict,
    # so a PARTIAL/FAILED reason is visible. Fields go IN THE MESSAGE (celery's formatter drops
    # `extra`). Counts + booleans ONLY — never a URL/target/finding body.
    logger.info(
        "http_endpoint batch verdict run=%s batch=%s status=%s n_targets=%s exit=%s completion=%s "
        "requests=%s/%s templates_loaded=%s targets_loaded=%s unresponsive=%s timed_out=%s truncated=%s "
        "output_complete=%s catalog_verified=%s targets_completed=%s parse_incomplete=%s "
        "attribution_ok=%s writer_ok=%s cleanup_failed=%s findings=%s",
        scan_run_id,
        batch.index,
        status.value,
        len(batch.targets),
        evidence.exit_code,
        evidence.completion_percent,
        evidence.requests_done,
        evidence.requests_total,
        evidence.templates_loaded,
        evidence.targets_loaded,
        evidence.unresponsive_targets,
        evidence.timed_out,
        evidence.truncated,
        evidence.output_complete,
        evidence.catalog_verified,
        evidence.targets_completed,
        evidence.parse_incomplete,
        attribution_ok,
        writer_ok,
        cleanup_failed,
        len(evidence.findings),
    )
    return EndpointBatchResult(batch, evidence, status, created, updated)


def _attribute_findings(findings, batch) -> tuple[list[dict], bool]:
    """Map each finding to an asset via its INPUT target's shape (from the batch), never a hostname
    search. Returns (records-with-NULL-provenance, attribution_ok). A finding whose target can't be
    resolved to a batch target is DROPPED and flips attribution_ok=False (→ parse_incomplete → PARTIAL)."""
    by_shape = {t.shape_hash: t for t in batch.targets}
    records, ok = [], True
    for f in findings or ():
        target_url = f.get("target") or f.get("input")
        shape = None
        if target_url:
            try:
                shape = endpoint_shape_hash(target_url)
            except ValueError:
                shape = None
        tgt = by_shape.get(shape) if shape else None
        if tgt is None:
            ok = False  # cannot prove result→target → do not invent an asset
            continue
        records.append(
            {
                "asset_id": tgt.asset_id,
                "template_id": f.get("template_id") or f.get("template-id"),
                "name": f.get("name") or f.get("template_id") or "nuclei",
                "severity": f.get("severity") or "info",
                "matcher_name": f.get("matcher_name") or f.get("matcher-name"),
                "source": "nuclei",
                # provenance stays NULL (endpoint_shape_hash / origin_policy_hash) → ineligible.
            }
        )
    return records, ok


# --- coverage + finalize ------------------------------------------------------------------------


def _safe_rollback(db) -> None:
    try:
        db.rollback()
    except Exception:  # a rollback that itself fails must not mask the original error
        pass


def _write_coverage(repo, tenant_id, scan_run_id, batch: EndpointBatch, status: CoverageStatus) -> None:
    try:
        repo.record_endpoint_coverage(
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            phase="9",
            pass_name=PASS_HTTP_ENDPOINT,
            policy_hash=batch.policy_hash,
            entries=batch.entries(),
            status=status,
        )
    except CoverageWriteError as exc:
        # A batch whose coverage did not persist must NOT be reported as succeeded.
        raise EndpointPassStructuralError(f"coverage_write_failed:{exc}") from exc


def _finalize(
    forced_status, batch_results, selection, bundle, base_stats, *, now_fn, structural_error, extra_error=None
):
    statuses = [br.status for br in batch_results]
    if forced_status is not None:
        pass_status, skip_reason = forced_status, (extra_error and "staging_failed") or None
    else:
        # A run where EVERY launched batch FAILED (no COVERED, no PARTIAL) is a FAILED pass, not a
        # generic PARTIAL — a single-batch runner failure must surface as FAILED.
        launched = [s for s in statuses if s != CoverageStatus.SKIPPED]
        all_launched_failed = bool(launched) and all(s == CoverageStatus.FAILED for s in launched)
        pass_status, skip_reason = aggregate_pass_status(
            statuses,
            flag_enabled=True,
            selected_count=len(selection.selected),
            structural_error=structural_error or all_launched_failed,
        )
    stats = _rollup_stats(base_stats, batch_results, bundle, pass_status, skip_reason, extra_error)
    return EndpointPassResult(
        status=pass_status,
        skip_reason=skip_reason,
        policy_hash=bundle.manifest.policy_hash,
        catalog_digest=bundle.catalog_digest,
        classifier_version=bundle.classifier_version,
        batch_results=batch_results,
        stats=stats,
    )


def _selection_stats(bundle, selection, candidate_count, base_url_dropped) -> dict:
    return {
        "enabled": True,
        "pass_name": PASS_HTTP_ENDPOINT,
        "policy_hash": bundle.manifest.policy_hash,
        "catalog_digest": bundle.catalog_digest,
        "classifier_version": bundle.classifier_version,
        "template_count": len(bundle.ruleset.rules),
        "candidate_count": candidate_count,
        "base_url_dropped": base_url_dropped,
        "selected_count": len(selection.selected),
        "out_of_scope": len(selection.out_of_scope),
        "static_filtered": len(selection.static_filtered),
        "shape_deduplicated": len(selection.shape_deduplicated),
        "cap_dropped": len(selection.cap_dropped),
        "invalid": len(selection.invalid),
        "unassociated": len(selection.unassociated),
    }


def _rollup_stats(base_stats, batch_results, bundle, pass_status, skip_reason, extra_error) -> dict:
    def _count(s):
        return sum(1 for br in batch_results if br.status == s)

    def _eps(s):
        return sum(len(br.batch.targets) for br in batch_results if br.status == s)

    stats = dict(base_stats)
    stats.update(
        {
            "batch_count": len(batch_results),
            "batches_covered": _count(CoverageStatus.COVERED),
            "batches_partial": _count(CoverageStatus.PARTIAL),
            "batches_failed": _count(CoverageStatus.FAILED),
            "batches_skipped": _count(CoverageStatus.SKIPPED),
            "endpoints_covered": _eps(CoverageStatus.COVERED),
            "endpoints_partial": _eps(CoverageStatus.PARTIAL),
            "endpoints_failed": _eps(CoverageStatus.FAILED),
            "endpoints_skipped": _eps(CoverageStatus.SKIPPED),
            "findings_discovered": sum(br.findings_created + br.findings_updated for br in batch_results),
            "coverage_complete": pass_status == "completed",
            "coverage_authorizing": _coverage_authorizing(pass_status, skip_reason),
            "phase_non_degrading": _phase_non_degrading(pass_status, skip_reason),
            "skip_reason": skip_reason,
        }
    )
    if extra_error:
        stats["error"] = extra_error
    return stats


# --- transient target file + canned evidence ----------------------------------------------------


def _write_target_file(path: str, batch: EndpointBatch) -> None:
    """Write the batch URLs to ``path`` (0600) inside the caller's contextual temp dir. The URLs
    live transiently in the temp file only — never in DB, logs, or object storage."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write("\n".join(t.url for t in batch.targets))


def _skipped_evidence() -> BatchExecutionEvidence:
    return BatchExecutionEvidence(launched=False, exit_code=None)


def _staging_failed_evidence() -> BatchExecutionEvidence:
    return BatchExecutionEvidence(launched=False, exit_code=None, parse_incomplete=True)


# ==================================================================================================
# Phase-9 adapter (Sprint 3, step 3b-2b). Keeps the phase-9 border SMALL + testable: a real no-op
# when the feature is OFF (no DB / runner / snapshot), and fail-CLOSED on any unexpected error when
# ON. Never logs str(exc) — an unexpected exception could carry a URL/path; only the reason code.
# ==================================================================================================


def _feature_disabled_stats() -> dict:
    return {
        "enabled": False,
        "pass_name": PASS_HTTP_ENDPOINT,
        "skip_reason": "feature_disabled",
        "coverage_complete": False,
        "coverage_authorizing": False,
        "phase_non_degrading": True,  # a disabled feature must NOT degrade the existing phase
    }


def _endpoint_error_stats(reason_code: str) -> dict:
    return {
        "enabled": True,
        "pass_name": PASS_HTTP_ENDPOINT,
        "coverage_complete": False,
        "coverage_authorizing": False,
        "phase_non_degrading": False,  # an unexpected error DEGRADES the phase (fail-closed)
        "error": reason_code,
    }


def phase_degraded_by_endpoint(stats: dict) -> bool:
    """Whether the endpoint pass's outcome must mark phase 9 truncated. Driven by
    ``phase_non_degrading`` (NOT status): feature_disabled / no_targets / completed → False;
    insufficient_phase_budget / partial / failed / error → True."""
    return not bool(stats.get("phase_non_degrading", False))


def run_endpoint_pass_in_phase9(
    db,
    *,
    tenant_id: int,
    scan_run_id: int,
    scan_tier: int,
    direct_assets: Sequence[Asset],
    phase_9_deadline: datetime,
    custom_policy_hash: Optional[str],
    interactsh_server: Optional[str],
    severity: Sequence[str],
    exclude_tags,
    rate_limit: int,
    concurrency: int,
    request_timeout: int,
    max_host_errors: int,
    now_fn: Callable[[], datetime],
    log=None,
) -> dict:
    """Run the endpoint pass from phase 9 and return its stats dict. FEATURE-GATED FIRST: when
    disabled, returns immediately with NO service query / snapshot / runner. When enabled, any
    unexpected error is fail-CLOSED (degrading, non-authorizing stats) — never fail-open."""
    if not is_endpoint_pass_enabled(tenant_id):
        return _feature_disabled_stats()
    try:
        endpoint_exclude = [t.strip() for t in str(exclude_tags).split(",") if t.strip()]
        runner = NucleiEndpointRunner(
            severity=list(severity),
            exclude_tags=endpoint_exclude,
            rate_limit=rate_limit,
            concurrency=concurrency,
            request_timeout=request_timeout,
            max_host_errors=max_host_errors,
        )
        result = run_http_endpoint_pass(
            db=db,
            tenant_id=tenant_id,
            scan_run_id=scan_run_id,
            scan_tier=scan_tier,
            assets=direct_assets,
            base_urls=build_base_urls(db, direct_assets),
            phase_9_deadline=phase_9_deadline,
            custom_policy_hash=custom_policy_hash,
            interactsh_server=interactsh_server,
            runner=runner,
            now_fn=now_fn,
        )
        if log is not None:
            log.info(
                "http_endpoint pass: status=%s selected=%s batches=%s",
                result.status,
                result.stats.get("selected_count"),
                result.stats.get("batch_count"),
            )
        return result.stats
    except Exception as exc:  # fail-CLOSED — never leak str(exc) (may carry a URL/path)
        if log is not None:
            log.error("http_endpoint pass wiring error: reason=%s", type(exc).__name__)
        return _endpoint_error_stats(type(exc).__name__)
