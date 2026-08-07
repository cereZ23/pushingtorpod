"""Coverage-aware auto-close — the per-finding decision (pure) + a DRY-RUN runner.

This is the consumer the whole coverage foundation was built for, but it does NOT close
anything yet. ``decide_finding_auto_close`` is a pure function returning an explicit
verdict; ``dry_run_auto_close`` walks a run's open findings, computes what it WOULD do,
and records metrics/logs — without mutating a single finding. Real closes (and disabling
the old tenant-wide auto-close) come only after two live dry-runs are validated.

A finding is *eligible* to advance toward a close on a given run ONLY when all four hold:
  1. discovery is healthy enough to authorise closing (``auto_close_allowed``);
  2. the asset is COVERED by the pass that owns the finding's detector;
  3. that pass's applicable-detector catalog is intact (fingerprint == stamped build);
  4. the finding's detector is IN that applicable set.
Anything short of all four is fail-closed: the streak resets, never advances. A finding
that WAS detected this run resets too (it is still live). Only two *distinct* consecutive
eligible misses reach ``WOULD_CLOSE``.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

DEFAULT_CLOSE_THRESHOLD = 2


def is_awaiting_confirmation(is_open: bool, streak: int, threshold: int = DEFAULT_CLOSE_THRESHOLD) -> bool:
    """Canonical 'awaiting confirmation' predicate: an OPEN finding accumulating covered misses but not
    yet at the close threshold (``0 < streak < threshold``). Kept here — the single source of truth —
    so the dashboard aggregate and the per-finding lifecycle view never diverge on the definition."""
    return bool(is_open) and 0 < (streak or 0) < threshold


class AutoCloseDecision(str, enum.Enum):
    INELIGIBLE = "ineligible"  # can't prove coverage this run → reset streak (fail-closed)
    DETECTED_RESET = "detected_reset"  # still detected → reset streak, attribute detection
    ELIGIBLE_MISS = "eligible_miss"  # eligible + missed, but below the close threshold
    WOULD_CLOSE = "would_close"  # eligible miss reached the threshold → a real run would close


@dataclass(frozen=True)
class AutoCloseVerdict:
    """What a run WOULD do to one finding. The runner applies ``new_streak`` and, when set,
    the run attributions; in dry-run it only records them. ``*_run_id`` of ``None`` means
    "leave unchanged" (there is no path here that clears an existing attribution)."""

    decision: AutoCloseDecision
    new_streak: int
    set_last_eligible_run_id: Optional[int] = None
    set_last_detected_run_id: Optional[int] = None

    @property
    def would_close(self) -> bool:
        return self.decision is AutoCloseDecision.WOULD_CLOSE


TARGET_BASE = "base"
TARGET_ENDPOINT = "endpoint"
TARGET_UNKNOWN = "unknown"


def classify_matched_at(matched_at: Optional[str]) -> str:
    """Conservatively classify a finding's recorded location for the TEMPORARY endpoint-safety gate.

    Returns one of:
      ``"base"``     — an http(s) URL whose path is empty or ``/`` and has no query. The base-URL
                       scan re-visits it, so it MAY accrue an eligible miss.
      ``"endpoint"`` — an http(s) URL with a path beyond ``/`` or a query string: a deep endpoint
                       the base pass does not visit.
      ``"unknown"``  — absent, non-http(s), or unparseable (e.g. the ``host:port`` an SSL/network
                       template emits). Treated as ineligible, fail-closed.

    Only ``"base"`` may advance the auto-close streak; endpoint and unknown are both INELIGIBLE.
    This is a stopgap while the HTTP-stock pass scans base URLs only (endpoint CVE coverage deferred
    to the dedicated reduced endpoint pass — Traccia B). It deliberately OVER-classifies (a template
    that self-generates ``/wp-login.php`` reads as endpoint) — safe, because it only ever KEEPS a
    finding open. The durable fix persists per-target coverage identity rather than inferring it."""
    if not matched_at or not isinstance(matched_at, str):
        return TARGET_UNKNOWN
    from urllib.parse import urlparse

    try:
        parsed = urlparse(matched_at)
    except (ValueError, TypeError):
        return TARGET_UNKNOWN
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return TARGET_UNKNOWN
    if parsed.query:
        return TARGET_ENDPOINT
    return TARGET_BASE if (parsed.path or "") in ("", "/") else TARGET_ENDPOINT


def decide_finding_auto_close(
    *,
    this_run_id: int,
    detected_this_run: bool,
    discovery_auto_close_allowed: bool,
    coverage_covered: bool,
    catalog_intact: bool,
    detector_applicable: bool,
    current_streak: int,
    last_eligible_run_id: Optional[int],
    base_target: bool = True,
    close_threshold: int = DEFAULT_CLOSE_THRESHOLD,
) -> AutoCloseVerdict:
    """Pure per-finding decision. ``this_run_id`` is always a real run (the runner only
    operates inside a scan). See the module docstring for the eligibility contract.

    ``base_target`` is False for endpoint/unknown locations (see ``classify_matched_at``): while
    the stock pass scans base URLs only, only a base-target finding may accrue a miss — otherwise a
    pass that never visits the path/endpoint would false-close it."""
    # 1. Detected this run → the finding is live: reset the streak and attribute detection.
    if detected_this_run:
        return AutoCloseVerdict(
            AutoCloseDecision.DETECTED_RESET,
            new_streak=0,
            set_last_detected_run_id=this_run_id,
        )

    # 2. Fail-closed eligibility gate: every condition must hold to count a miss. A non-base target
    #    (endpoint/unknown) is never eligible while the stock pass scans base URLs only.
    eligible = (
        base_target and discovery_auto_close_allowed and coverage_covered and catalog_intact and detector_applicable
    )
    if not eligible:
        return AutoCloseVerdict(AutoCloseDecision.INELIGIBLE, new_streak=0)

    # 3. Eligible miss. A retried run must not double-count: if this run already advanced
    #    the streak, keep it as-is rather than incrementing again.
    if last_eligible_run_id == this_run_id:
        streak = current_streak
    else:
        streak = current_streak + 1

    decision = AutoCloseDecision.WOULD_CLOSE if streak >= close_threshold else AutoCloseDecision.ELIGIBLE_MISS
    return AutoCloseVerdict(decision, new_streak=streak, set_last_eligible_run_id=this_run_id)


def shadow_auto_close(
    db,
    *,
    tenant_id: int,
    project_id: Optional[int],
    scan_run_id: int,
    close_threshold: int = DEFAULT_CLOSE_THRESHOLD,
    real_close_enabled: bool = False,
    tenant_allowed: bool = False,
    allowed_tiers: frozenset = frozenset(),
) -> dict:
    """Run the coverage-aware auto-close for a run: PERSIST each finding's miss-streak and run
    attribution. By default (``real_close_enabled=False``) it is a pure SHADOW — it NEVER changes
    ``Finding.status``, so two live runs can advance a streak to WOULD_CLOSE and the decisions can
    be compared against reality without ever closing a finding.

    A finding that reaches a WOULD_CLOSE decision is REALLY closed (OPEN→FIXED, same row-locked
    transaction, durable audit line) ONLY when ALL of: ``real_close_enabled`` (global flag),
    ``tenant_allowed`` (this run's tenant is allow-listed), AND the TIER of the exact ScanPolicy that
    covers/authorises the finding is in ``allowed_tiers``. The tier is taken from the covering policy,
    NOT the run parameter, so a T1 policy can never authorise a T2 close (and vice versa); an unknown
    tier / non-canonical config is fail-closed. The two gate rejections are counted separately
    (``gate_blocked.tenant_not_allowed`` / ``gate_blocked.tier_not_allowed``).
    Every other decision (ineligible / detected_reset / eligible_miss below threshold) still only
    updates the streak, so a real close happens ONLY on a positively-decided WOULD_CLOSE.

    Fail-closed per finding: the detector must be applicable in a COVERED pass whose
    ``ScanPolicy.engine_name`` matches the finding's source (so a misconfig control id can
    never be authorised by a same-named nuclei template), the catalog must be intact, and
    discovery must authorise closing. Concurrency-safe: open findings are row-locked, and an
    out-of-order (older) run that reaches a finding after a newer one is a no-op.
    """
    from app.models.coverage import CoverageStatus, ScanCoverage, ScanEndpointCoverage, ScanPolicy
    from app.models.database import Asset, Finding, FindingStatus
    from app.models.scanning import ScanRun
    from app.repositories.coverage_repository import CoverageRepository
    from app.services.discovery_health import evaluate_and_persist_discovery_health
    from app.services.lifecycle_events import record_lifecycle_event
    from app.services.scan_policy import (
        ENGINE_BUILTIN_MISCONFIG,
        ENGINE_NUCLEI,
        PASS_CUSTOM_HTTP,
        PASS_HTTP_ENDPOINT,
        PASS_HTTP_STOCK,
    )

    # A finding's source must match the engine of the pass that authorises it.
    source_engine = {"nuclei": ENGINE_NUCLEI, "misconfig": ENGINE_BUILTIN_MISCONFIG}
    # The temporary endpoint-safety gate applies ONLY to the HTTP nuclei passes (http_stock scans
    # base URLs only now; custom_http still scans endpoints but has NO per-endpoint coverage yet).
    # For both, an endpoint-derived finding must stay ineligible until per-endpoint coverage exists
    # (Traccia B). Host-level passes (dns/network, misconfig, cdn/ssl) must NOT be gated by the HTTP
    # path/query classification, or their legitimate streaks would be wrongly reset.
    http_endpoint_gated_passes = {PASS_HTTP_STOCK, PASS_CUSTOM_HTTP}

    run = db.query(ScanRun).filter(ScanRun.id == scan_run_id).first()
    if run is None or run.tenant_id != tenant_id:
        return {"scan_run_id": scan_run_id, "skipped": "run not found or wrong tenant"}

    # Discovery gate, evaluated once for the whole run (fail-closed when unknown).
    auto_close_allowed = False
    if project_id is not None:
        auto_close_allowed = evaluate_and_persist_discovery_health(
            db, tenant_id, project_id, scan_run_id
        ).auto_close_allowed

    repo = CoverageRepository(db)
    applicable_cache: dict[str, set] = {}

    def _applicable(policy_hash: str) -> set:
        if policy_hash not in applicable_cache:
            # {} on a missing/partial/tampered catalog → fail-closed
            applicable_cache[policy_hash] = repo.applicable_detector_ids(policy_hash)
        return applicable_cache[policy_hash]

    # This run's coverage rows grouped by asset, plus each policy's engine (no cross-engine).
    coverage_by_asset: dict[int, list] = {}
    for c in db.query(ScanCoverage).filter(ScanCoverage.scan_run_id == scan_run_id).all():
        coverage_by_asset.setdefault(c.asset_id, []).append(c)
    endpoint_coverage = {
        (c.asset_id, c.endpoint_shape_hash, c.policy_hash): c
        for c in db.query(ScanEndpointCoverage).filter(ScanEndpointCoverage.scan_run_id == scan_run_id).all()
    }
    policy_engine: dict[str, str] = {}
    policy_pass: dict[str, str] = {}
    policy_tier: dict[str, int] = {}  # covering policy's tier — authorises the real close per-tier
    hashes = {c.policy_hash for rows in coverage_by_asset.values() for c in rows}
    hashes.update(c.policy_hash for c in endpoint_coverage.values())
    if hashes:
        for ph, eng, pass_name, tier in db.query(
            ScanPolicy.policy_hash, ScanPolicy.engine_name, ScanPolicy.pass_name, ScanPolicy.tier
        ).filter(ScanPolicy.policy_hash.in_(hashes)):
            policy_engine[ph] = eng
            policy_pass[ph] = pass_name
            policy_tier[ph] = tier

    # Row-lock the open findings so two concurrent shadow runners can't both advance a streak.
    findings = (
        db.query(Finding)
        .join(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Finding.status == FindingStatus.OPEN,
            Finding.source.in_(("nuclei", "misconfig")),
        )
        .with_for_update(of=Finding)
        .all()
    )

    # started_at of the runs each finding was last touched by — for the out-of-order guard.
    ref_ids = {rid for f in findings for rid in (f.last_eligible_run_id, f.last_detected_scan_run_id) if rid}
    ref_started: dict[int, object] = {}
    if ref_ids:
        for rid, started in db.query(ScanRun.id, ScanRun.started_at).filter(ScanRun.id.in_(ref_ids)):
            ref_started[rid] = started

    decisions = {d.value: 0 for d in AutoCloseDecision}
    stale_skipped = 0
    closed = 0
    gate_blocked = {"tenant_not_allowed": 0, "tier_not_allowed": 0}
    to_audit: list[tuple] = []
    would_close_ids: list[int] = []

    this_key = (run.started_at, scan_run_id)

    for f in findings:
        # Out-of-order guard: order runs by (started_at, run_id) — NOT run_id alone, since a
        # larger id is not guaranteed to be the later-started run. If a strictly-newer run
        # already touched this finding, an older run reaching it later must not advance it.
        newest_ref = None
        newest_key = None
        for rid in (f.last_eligible_run_id, f.last_detected_scan_run_id):
            if not rid:
                continue
            key = (ref_started.get(rid), rid)
            if key[0] is not None and (newest_key is None or key > newest_key):
                newest_key = key
                newest_ref = rid
        if (
            newest_ref is not None
            and newest_ref != scan_run_id
            and run.started_at is not None
            and this_key < newest_key
        ):
            stale_skipped += 1
            continue

        detected = f.last_detected_scan_run_id == scan_run_id or (
            f.last_detected_scan_run_id is None
            and run.started_at is not None
            and f.last_seen is not None
            and f.last_seen >= run.started_at
        )

        want_engine = source_engine.get(f.source)
        covered = False
        applicable = False
        covering_pass = None
        covering_policy_hash = None  # the exact policy that authorises this finding (drives the tier gate)
        has_shape = f.endpoint_shape_hash is not None
        has_origin_policy = f.origin_policy_hash is not None
        endpoint_provenance = has_shape or has_origin_policy
        if endpoint_provenance:
            # Endpoint findings NEVER fall back to asset-level coverage. Provenance must be complete,
            # the current run must contain the exact (asset, shape, origin-policy) ledger row, and
            # that immutable policy must still have an intact catalog containing this detector.
            if has_shape and has_origin_policy and want_engine is not None and f.template_id:
                c = endpoint_coverage.get((f.asset_id, f.endpoint_shape_hash, f.origin_policy_hash))
                if (
                    c is not None
                    and policy_engine.get(c.policy_hash) == want_engine
                    and policy_pass.get(c.policy_hash) == PASS_HTTP_ENDPOINT
                    and f.template_id in _applicable(c.policy_hash)
                ):
                    applicable = True
                    covered = c.status == CoverageStatus.COVERED
                    covering_pass = policy_pass.get(c.policy_hash)
                    covering_policy_hash = c.policy_hash
        elif want_engine is not None and f.template_id:
            for c in coverage_by_asset.get(f.asset_id, ()):
                if policy_engine.get(c.policy_hash) != want_engine:
                    continue  # only the finding's own engine can authorise it
                if f.template_id in _applicable(c.policy_hash):
                    applicable = True  # detector in an INTACT catalog (empty set on tamper)
                    if c.status == CoverageStatus.COVERED:
                        covered = True
                        covering_pass = policy_pass.get(c.policy_hash)
                        covering_policy_hash = c.policy_hash
                        break

        # TEMPORARY endpoint-safety gate — ONLY for the HTTP nuclei passes (http_stock, custom_http),
        # neither of which has per-endpoint coverage yet. A finding authorised by one of those whose
        # location is a deep endpoint (or unclassifiable) must not accrue a miss → never closes until
        # per-endpoint coverage exists (Traccia B). dns/network, misconfig and cdn/ssl detectors are
        # host-level: applying the HTTP path/query classification there would wrongly reset their
        # legitimate streaks, so they are left as base_target=True (unaffected by this gate).
        if endpoint_provenance:
            # Exact endpoint coverage replaces the temporary matched_at classifier. Complete or
            # incomplete provenance is handled above; never route it through the host-level gate.
            base_target = True
        elif covering_pass in http_endpoint_gated_passes:
            base_target = classify_matched_at(f.matched_at) == TARGET_BASE
        else:
            base_target = True

        prev_streak = f.eligible_miss_streak or 0
        verdict = decide_finding_auto_close(
            this_run_id=scan_run_id,
            detected_this_run=detected,
            discovery_auto_close_allowed=auto_close_allowed,
            coverage_covered=covered,
            catalog_intact=applicable,
            detector_applicable=applicable,
            current_streak=prev_streak,
            last_eligible_run_id=f.last_eligible_run_id,
            base_target=base_target,
            close_threshold=close_threshold,
        )

        # SHADOW: persist the streak + attribution, but NEVER the status (no real close).
        f.eligible_miss_streak = verdict.new_streak
        if verdict.set_last_eligible_run_id is not None:
            f.last_eligible_run_id = verdict.set_last_eligible_run_id
        if verdict.set_last_detected_run_id is not None:
            f.last_detected_scan_run_id = verdict.set_last_detected_run_id

        decisions[verdict.decision.value] += 1

        # Durable, queryable lifecycle events — written in THIS transaction (committed together
        # with the streak/close at db.commit() below), so the UI can prove WHY a finding is
        # open/ineligible/closed instead of scraping a log line. Closed-schema detail only:
        # streak/threshold/scope/tier/reason — never a URL, never a hash. Idempotent per run.
        covering_tier = policy_tier.get(covering_policy_hash) if covering_policy_hash else None
        scope = "endpoint" if endpoint_provenance else ("base" if base_target else "asset")
        _base_detail = {
            "streak": verdict.new_streak,
            "threshold": close_threshold,
            "scope": scope,
            "tier": covering_tier,
        }
        d = verdict.decision
        if d is AutoCloseDecision.DETECTED_RESET:
            record_lifecycle_event(
                db,
                tenant_id=tenant_id,
                finding_id=f.id,
                scan_run_id=scan_run_id,
                event_type="detected",
                detail={"scope": scope, "tier": covering_tier},
            )
        elif d is AutoCloseDecision.ELIGIBLE_MISS:
            record_lifecycle_event(
                db,
                tenant_id=tenant_id,
                finding_id=f.id,
                scan_run_id=scan_run_id,
                event_type="eligible_miss",
                detail=_base_detail,
            )
        elif d is AutoCloseDecision.WOULD_CLOSE:
            record_lifecycle_event(
                db,
                tenant_id=tenant_id,
                finding_id=f.id,
                scan_run_id=scan_run_id,
                event_type="would_close",
                detail=_base_detail,
            )
        elif d is AutoCloseDecision.INELIGIBLE and prev_streak > 0:
            # Only record a reset when a streak was actually lost (not every non-eligible run).
            record_lifecycle_event(
                db,
                tenant_id=tenant_id,
                finding_id=f.id,
                scan_run_id=scan_run_id,
                event_type="miss_reset",
                detail={"from_streak": prev_streak, "scope": scope, "tier": covering_tier},
            )

        if verdict.would_close:
            would_close_ids.append(f.id)
            # REAL close requires ALL: the global flag, the tenant allow-listed, AND the TIER of the
            # exact covering policy allow-listed. The tier comes from that policy (never the run
            # parameter), so a T1 policy can't authorise a T2 close; an unknown tier is fail-closed.
            # The two rejections are counted separately for observability. The close itself is a
            # CONDITIONAL update guarded by status='open' with a rowcount check (idempotent, never a
            # double close); the audit is deferred to AFTER commit for rows that actually changed.
            if real_close_enabled:
                if not tenant_allowed:
                    gate_blocked["tenant_not_allowed"] += 1
                elif covering_tier is None or covering_tier not in allowed_tiers:
                    gate_blocked["tier_not_allowed"] += 1
                else:
                    updated = (
                        db.query(Finding)
                        .filter(Finding.id == f.id, Finding.status == FindingStatus.OPEN)
                        .update({Finding.status: FindingStatus.FIXED}, synchronize_session=False)
                    )
                    if updated == 1:
                        closed += 1
                        to_audit.append((f.id, f.asset_id, f.source, f.endpoint_shape_hash, f.origin_policy_hash))
                        # ATOMIC with the OPEN→FIXED above: the auto_closed event is written in the
                        # SAME transaction. record_lifecycle_event flushes, so if it cannot be
                        # persisted the exception propagates and the close is rolled back with it —
                        # never a real close without its durable audit row.
                        record_lifecycle_event(
                            db,
                            tenant_id=tenant_id,
                            finding_id=f.id,
                            scan_run_id=scan_run_id,
                            event_type="auto_closed",
                            detail={**_base_detail, "reason": "coverage_miss_streak"},
                        )

    db.commit()

    # Durable, URL-free audit — emitted AFTER commit so it reflects ONLY findings actually closed in
    # this (now-committed) transaction: run, finding, asset, endpoint shape-hash, origin policy-hash.
    for fid, aid, src, shape, origin_policy in to_audit:
        logger.info(
            "coverage auto-close REAL: run=%s finding=%s asset=%s source=%s shape=%s origin_policy=%s",
            scan_run_id,
            fid,
            aid,
            src,
            shape or "-",
            origin_policy or "-",
        )

    result = {
        "scan_run_id": scan_run_id,
        "auto_close_allowed": auto_close_allowed,
        "open_findings": len(findings),
        "decisions": decisions,
        "stale_skipped": stale_skipped,
        "would_close_ids": would_close_ids,
        "real_close_enabled": bool(real_close_enabled),
        "closed": closed,
        "gate_blocked": gate_blocked,
    }
    logger.info(
        "coverage auto-close %s: run %s allowed=%s decisions=%s stale=%d would_close=%d closed=%d gate_blocked=%s",
        "REAL" if real_close_enabled else "SHADOW",
        scan_run_id,
        auto_close_allowed,
        decisions,
        stale_skipped,
        len(would_close_ids),
        closed,
        gate_blocked,
    )
    return result


__all__ = [
    "AutoCloseDecision",
    "AutoCloseVerdict",
    "decide_finding_auto_close",
    "shadow_auto_close",
    "DEFAULT_CLOSE_THRESHOLD",
]
