"""http_endpoint pass — pure orchestration core (Sprint 3, step 3a).

The live pass (subprocess Nuclei per batch + coverage writes + phase-9 wiring) lands in step 3b.
This module holds the PURE, deterministic, unit-testable pieces it will use:

- deterministic batching of the Step-1 selection (``plan_batches``);
- the conservative per-batch verdict mapping (``batch_verdict``);
- the pass-level status aggregation (``aggregate_pass_status``);
- the budget/deadline arithmetic (``compute_effective_deadline`` / ``remaining_budget_seconds``).

Fail-closed everywhere: a batch is COVERED only when the run was unambiguously complete; any
uncertainty (timeout, budget, truncation, drift, unresponsive targets, partial parse, "cannot tell
which endpoints finished") is PARTIAL; a structural failure is FAILED; a batch never launched
because the budget was already spent is SKIPPED. No URL / path / query is ever logged or stored —
identity is carried by ``SelectedEndpoint.shape_hash`` + ``asset_id`` only.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from itertools import groupby
from typing import Optional, Sequence

from app.models.coverage import CoverageStatus
from app.services.endpoint_selection import SelectedEndpoint


class TemplateStagingError(Exception):
    """Raised when the selected templates cannot be safely materialised (fail-closed → no run)."""


# Pass-status strings (mirror PhaseStatus values used by phase_results).
PASS_COMPLETED = "completed"
PASS_PARTIAL = "partial"
PASS_FAILED = "failed"
PASS_SKIPPED = "skipped"


@dataclass(frozen=True)
class EndpointBatch:
    """A stable, ordered slice of the selection submitted to Nuclei as one unit.

    ``targets`` carry their own ``asset_id`` + ``shape_hash`` (from Step 1), so coverage is written
    from the target itself — the URL→asset association is NEVER reconstructed after Nuclei.
    """

    index: int
    targets: tuple[SelectedEndpoint, ...]
    policy_hash: str

    def entries(self) -> list[tuple[int, str]]:
        """(asset_id, endpoint_shape_hash) pairs for ``record_endpoint_coverage`` — never a URL."""
        return [(t.asset_id, t.shape_hash) for t in self.targets]

    def __repr__(self) -> str:  # no URL/path — counts + shape-hash prefixes only
        shapes = ",".join(sorted({t.shape_hash[:8] for t in self.targets}))
        return f"EndpointBatch(index={self.index}, n={len(self.targets)}, shapes=[{shapes}])"


def plan_batches(selected: Sequence[SelectedEndpoint], *, batch_size: int, policy_hash: str) -> list[EndpointBatch]:
    """Split the selection into deterministic, HOST-HOMOGENEOUS batches of at most ``batch_size``.

    Grouped PER ASSET (host): a batch never contains more than one ``asset_id``, so when Nuclei
    declares a host unresponsive only THAT host's endpoints go PARTIAL — endpoints of other hosts in
    other batches stay COVERED. (A flat chunk let one dead host contaminate up to ``batch_size``
    endpoints across DIFFERENT hosts.) Deterministic total order ``(asset_id, shape_hash, url)`` so
    the same selection always yields the same batches — a precondition for reproducible coverage.
    """
    if batch_size <= 0:
        raise ValueError(f"batch_size must be positive, got {batch_size}")
    ordered = sorted(selected, key=lambda t: (t.asset_id, t.shape_hash, t.url))
    batches: list[EndpointBatch] = []
    for _asset_id, group in groupby(ordered, key=lambda t: t.asset_id):
        eps = list(group)
        for i in range(0, len(eps), batch_size):
            batches.append(
                EndpointBatch(index=len(batches), targets=tuple(eps[i : i + batch_size]), policy_hash=policy_hash)
            )
    return batches


def batch_verdict(
    *,
    launched: bool,
    exit_code: Optional[int],
    output_complete: bool,
    catalog_verified: bool,
    targets_completed: bool,
    timed_out: bool = False,
    budget_expired: bool = False,
    truncated: bool = False,
    drift: bool = False,
    unresponsive: bool = False,
    parse_incomplete: bool = False,
) -> CoverageStatus:
    """Map a batch run to a conservative coverage verdict — COVERED requires POSITIVE PROOF.

    COVERED is authorised ONLY by evidence of completion, never by the mere absence of negative
    flags: the launched process must have exited cleanly AND every positive proof must hold. A caller
    that forgets a signal, or that never launched Nuclei, can NOT accidentally get COVERED (the
    positive-proof kwargs are required, so ``batch_verdict()`` with no args raises).

    - ``launched=False`` → a caller error (SKIPPED is the caller's decision, not this function's) → raises.
    - ANY uncertainty signal (timeout, budget, truncation, drift, unresponsive, partial parse) → PARTIAL.
      Evaluated BEFORE the exit code: a timed-out batch is killed and returns a non-zero / None exit,
      but the contract is timeout → PARTIAL, so incompleteness caused by the run must win over the exit.
    - only THEN, a process unstartable / invalid exit code (``exit_code`` None or non-zero) not
      attributable to timeout/truncation → FAILED.
    - a missing positive proof (output not complete, catalog not verified, targets not all completed) →
      PARTIAL — the run happened but its completeness can't be proven, so it must not authorise.
    - COVERED: launched, no uncertainty signal, ``exit_code == 0``, AND output_complete AND
      catalog_verified AND targets_completed.
    """
    if not launched:
        raise ValueError("batch_verdict: launched must be True — mark an unlaunched batch SKIPPED at the caller")
    if timed_out or budget_expired or truncated or drift or unresponsive or parse_incomplete:
        return CoverageStatus.PARTIAL
    if exit_code is None or exit_code != 0:
        return CoverageStatus.FAILED
    if not (output_complete and catalog_verified and targets_completed):
        return CoverageStatus.PARTIAL
    return CoverageStatus.COVERED


def aggregate_pass_status(
    batch_statuses: Sequence[CoverageStatus],
    *,
    flag_enabled: bool,
    selected_count: int,
    structural_error: bool = False,
) -> tuple[str, Optional[str]]:
    """Aggregate per-batch verdicts into the pass-level status + an optional skip reason.

    - feature flag off → SKIPPED (``feature_disabled``);
    - no target selected → SKIPPED (``no_targets``);
    - targets selected but NOT ONE batch launched (all SKIPPED because the budget was already spent)
      → SKIPPED (``insufficient_phase_budget``) — this must NOT be reported as a generic PARTIAL;
    - a structural error with no successful batch → FAILED;
    - every batch COVERED → COMPLETED;
    - otherwise (at least one launched, but any PARTIAL/FAILED/SKIPPED alongside) → PARTIAL.

    ``batch_statuses`` carries one status per batch; a batch that was never launched for budget is
    recorded as SKIPPED by the caller.
    """
    if not flag_enabled:
        return PASS_SKIPPED, "feature_disabled"
    if selected_count == 0:
        return PASS_SKIPPED, "no_targets"
    statuses = list(batch_statuses)
    # targets selected but nothing launched — no batch ran, or every batch was budget-skipped.
    if not statuses or all(s == CoverageStatus.SKIPPED for s in statuses):
        return PASS_SKIPPED, "insufficient_phase_budget"
    covered = sum(1 for s in statuses if s == CoverageStatus.COVERED)
    if structural_error and covered == 0:
        return PASS_FAILED, "structural_error"
    if statuses and all(s == CoverageStatus.COVERED for s in statuses):
        return PASS_COMPLETED, None
    return PASS_PARTIAL, None


def stage_selected_templates(snapshot, selected_paths: Sequence[str], dest_dir: str) -> list[str]:
    """Materialise the snapshot BYTES for ``selected_paths`` under ``dest_dir``, preserving the
    relative layout. Returns the sorted absolute file paths written.

    Staging (vs referencing the stock files in place) makes policy, catalog, AND execution observe
    the EXACT same bytes the snapshot was built from — no on-disk drift during the pass.

    TWO PHASES so a failure never leaves a partial staging: the WHOLE set is validated first (every
    path present in the snapshot, safe, and unique), and only then are the files written. Fail-closed:
    a path absent from the snapshot, a duplicate path, or any path that would escape ``dest_dir``
    (absolute, ``..``, or a symlink-resolved escape) raises ``TemplateStagingError`` and NOTHING is
    written.
    """
    by_path = {f.relative_path: f.content for f in snapshot.files}
    dest_root = os.path.realpath(dest_dir)

    # --- Phase 1: preflight the entire set (no writes) ---
    seen: set[str] = set()
    plan: list[tuple[str, str]] = []  # (target_abspath, relative_path)
    for rel in selected_paths:
        if rel in seen:
            raise TemplateStagingError(f"duplicate template path in selection: {rel!r}")
        seen.add(rel)
        if rel not in by_path:
            raise TemplateStagingError(f"selected template not present in snapshot: {rel!r}")
        if not rel or os.path.isabs(rel) or ".." in rel.replace("\\", "/").split("/"):
            raise TemplateStagingError(f"unsafe template path {rel!r}")
        target = os.path.realpath(os.path.join(dest_root, rel))
        if target != dest_root and not target.startswith(dest_root + os.sep):
            raise TemplateStagingError(f"template path escapes staging dir: {rel!r}")
        plan.append((target, rel))

    # --- Phase 2: write (only reached when the whole set validated) ---
    written: list[str] = []
    for target, rel in plan:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(by_path[rel])
        written.append(target)
    return sorted(written)


def _require_aware(name: str, dt: datetime) -> datetime:
    """Reject a naive datetime — mixing naive and aware is the offset-naive-vs-aware bug class."""
    if not isinstance(dt, datetime):
        raise TypeError(f"{name} must be a datetime, got {type(dt).__name__}")
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(f"{name} must be timezone-aware (got naive {dt!r})")
    return dt


def remaining_budget_seconds(*, now: datetime, effective_deadline: datetime) -> float:
    """Seconds left before the effective deadline (never negative). Both must be tz-aware."""
    _require_aware("now", now)
    _require_aware("effective_deadline", effective_deadline)
    return max(0.0, (effective_deadline - now).total_seconds())


def compute_effective_deadline(
    *, phase_9_deadline: datetime, started_at: datetime, endpoint_budget_seconds: int
) -> datetime:
    """The pass's hard stop: the EARLIER of the phase-9 deadline and (start + endpoint budget).

    The endpoint pass never borrows time beyond phase 9, and never reuses http_stock's timeouts.
    Fail-closed: both datetimes must be timezone-aware (no naive/mixed) and the budget must be > 0.
    """
    _require_aware("phase_9_deadline", phase_9_deadline)
    _require_aware("started_at", started_at)
    if int(endpoint_budget_seconds) <= 0:
        raise ValueError(f"endpoint_budget_seconds must be > 0, got {endpoint_budget_seconds!r}")
    own = started_at + timedelta(seconds=int(endpoint_budget_seconds))
    return min(phase_9_deadline, own)


def validate_endpoint_pass_config(
    *, batch_size: int, batch_timeout_seconds: int, budget_seconds: int, max_per_host: int
) -> None:
    """Reject a misconfigured endpoint pass BEFORE it runs (fail-closed). Every knob must be > 0."""
    for name, value in (
        ("batch_size", batch_size),
        ("batch_timeout_seconds", batch_timeout_seconds),
        ("budget_seconds", budget_seconds),
        ("max_per_host", max_per_host),
    ):
        # `type(value) is int` (not isinstance) — bool is a subclass of int, so True/False must NOT
        # slip through as a valid count.
        if type(value) is not int or value <= 0:
            raise ValueError(f"http_endpoint config: {name} must be a positive int, got {value!r}")
