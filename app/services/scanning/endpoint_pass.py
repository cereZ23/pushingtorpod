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


def _stable_key(t: SelectedEndpoint) -> tuple:
    # Same total order Step 1 uses, recomputed here so batching is order-independent of the caller.
    return (t.priority, t.shape_hash, t.url, t.asset_id, t.endpoint_type or "")


def plan_batches(selected: Sequence[SelectedEndpoint], *, batch_size: int, policy_hash: str) -> list[EndpointBatch]:
    """Split the selection into stable, deterministic batches of at most ``batch_size`` targets.

    Deterministic regardless of the input order (a stable total order is applied first), so the same
    selection always yields the same batches — a precondition for reproducible coverage.
    """
    if batch_size <= 0:
        raise ValueError(f"batch_size must be positive, got {batch_size}")
    ordered = sorted(selected, key=_stable_key)
    batches: list[EndpointBatch] = []
    for i in range(0, len(ordered), batch_size):
        batches.append(
            EndpointBatch(index=len(batches), targets=tuple(ordered[i : i + batch_size]), policy_hash=policy_hash)
        )
    return batches


def batch_verdict(
    *,
    process_error: bool = False,
    exit_error: bool = False,
    timed_out: bool = False,
    budget_expired: bool = False,
    truncated: bool = False,
    drift: bool = False,
    unresponsive: bool = False,
    parse_incomplete: bool = False,
) -> CoverageStatus:
    """Map a LAUNCHED batch's observed signals to a conservative coverage verdict.

    Precedence (fail-closed): a structural failure → FAILED; ANY sign of an incomplete / uncertain
    run → PARTIAL; only a fully clean run → COVERED. (A batch that never launched because the budget
    was already exhausted is SKIPPED — decided by the caller before running, not here.)

    - FAILED: the process could not run or errored structurally (unstartable, error exit, catalog not
      loadable, staging error, uninterpretable output).
    - PARTIAL: timeout, budget expired mid-batch, Nuclei-reported skipped/unresponsive targets, output
      incomplete / partially parsed, template drift after launch, or ANY case where the exact set of
      completed endpoints cannot be known — then the WHOLE batch is PARTIAL.
    - COVERED: launched, valid exit, finished within timeout AND budget, no truncation, no drift, no
      permanently-skipped target, catalog consistent with the policy.
    """
    if process_error or exit_error:
        return CoverageStatus.FAILED
    if timed_out or budget_expired or truncated or drift or unresponsive or parse_incomplete:
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
    - a structural error with no successful batch → FAILED;
    - every batch COVERED → COMPLETED;
    - otherwise (any PARTIAL/FAILED/SKIPPED after launch) → PARTIAL.
    """
    if not flag_enabled:
        return PASS_SKIPPED, "feature_disabled"
    if selected_count == 0:
        return PASS_SKIPPED, "no_targets"
    statuses = list(batch_statuses)
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
    the EXACT same bytes the snapshot was built from — no on-disk drift during the pass. Fail-closed:
    a path absent from the snapshot, or any path that would escape ``dest_dir`` (absolute, ``..``, or
    a symlink-resolved escape), raises ``TemplateStagingError`` and no run happens.
    """
    by_path = {f.relative_path: f.content for f in snapshot.files}
    dest_root = os.path.realpath(dest_dir)
    written: list[str] = []
    for rel in selected_paths:
        if rel not in by_path:
            raise TemplateStagingError(f"selected template not present in snapshot: {rel!r}")
        if not rel or os.path.isabs(rel) or ".." in rel.replace("\\", "/").split("/"):
            raise TemplateStagingError(f"unsafe template path {rel!r}")
        target = os.path.realpath(os.path.join(dest_root, rel))
        if target != dest_root and not target.startswith(dest_root + os.sep):
            raise TemplateStagingError(f"template path escapes staging dir: {rel!r}")
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as fh:
            fh.write(by_path[rel])
        written.append(target)
    return sorted(written)


def remaining_budget_seconds(*, now: datetime, effective_deadline: datetime) -> float:
    """Seconds left before the effective deadline (never negative)."""
    return max(0.0, (effective_deadline - now).total_seconds())


def compute_effective_deadline(
    *, phase_9_deadline: datetime, started_at: datetime, endpoint_budget_seconds: int
) -> datetime:
    """The pass's hard stop: the EARLIER of the phase-9 deadline and (start + endpoint budget).

    The endpoint pass never borrows time beyond phase 9, and never reuses http_stock's timeouts.
    """
    own = started_at + timedelta(seconds=int(endpoint_budget_seconds))
    return min(phase_9_deadline, own)
