"""Canonical endpoint-verification vocabulary + snapshot builder (UI-1, PR 1a).

The http_endpoint pass already DECIDES an operational outcome per run; this module gives that
decision a stable, closed-enum shape so it can be persisted (``scan_run.stats.endpoint_verification``)
and later explained by the UI WITHOUT the frontend re-deriving anything.

Hard rules (from the spec):
* ``limitation`` is a CLOSED enum — never ``str(exception)``, never free text, never a URL/hash.
* When several causes coincide, the MOST SEVERE wins as ``limitation`` (see ``LIMITATION_PRECEDENCE``);
  the full de-duplicated, precedence-ordered set is ``limitations``.
* ``state`` and ``limitation`` are two different axes; ``state`` is the endpoint pass's operational
  state (NOT the scan-level outcome). ``execution_complete`` is independent of ``state``.
* Never guess: an uncertainty with no attributable cause is ``unknown``, not a wrong specific reason.
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence

SCHEMA_VERSION = 1

# Operational state of the endpoint pass (distinct from the scan-level `outcome`).
STATE_DISABLED = "disabled"
STATE_NO_TARGETS = "no_targets"
STATE_COMPLETE = "complete"
STATE_LIMITED = "limited"
STATE_INCOMPLETE = "incomplete"
STATE_FAILED = "failed"

VALID_STATES = frozenset(
    {STATE_DISABLED, STATE_NO_TARGETS, STATE_COMPLETE, STATE_LIMITED, STATE_INCOMPLETE, STATE_FAILED}
)

# Limitation reason codes, MOST SEVERE FIRST. `unknown` is the least severe (a real signal we cannot
# classify), still above "no limitation". `data_inconsistent` is decided by the BUILDER, not here.
LIMITATION_PRECEDENCE = (
    "configuration_error",
    "execution_error",
    "writer_error",
    "catalog_drift",
    "parser_incomplete",
    "timeout",
    "output_truncated",
    "insufficient_budget",
    "unresponsive_origins",
    "unknown",
)

_OTHER_LIMITATIONS = ("feature_disabled", "no_targets", "data_inconsistent")
VALID_LIMITATIONS = frozenset(LIMITATION_PRECEDENCE + _OTHER_LIMITATIONS)


def resolve_limitation(reasons: Iterable[Optional[str]]) -> Optional[str]:
    """The single most-severe ranked limitation present, or None if none of the ranked reasons hold."""
    present = {r for r in reasons if r in LIMITATION_PRECEDENCE}
    for reason in LIMITATION_PRECEDENCE:
        if reason in present:
            return reason
    return None


def ranked_limitations(reasons: Iterable[Optional[str]]) -> list[str]:
    """De-duplicated ranked reasons present, most-severe first (enum values only)."""
    present = {r for r in reasons if r in LIMITATION_PRECEDENCE}
    return [r for r in LIMITATION_PRECEDENCE if r in present]


def batch_limitation_reason(evidence) -> Optional[str]:
    """Map ONE batch's execution evidence to a canonical reason, or None if it carried no uncertainty.
    Checked in severity order so a batch reports its worst attributable cause. Reads only boolean/int
    completion signals — never a URL or output.

    ``truncated`` with no more-specific cause is ``output_truncated`` (a known signal), NOT a guessed
    ``unresponsive_origins`` and NOT ``unknown``.
    """
    if getattr(evidence, "launched", True) and (evidence.exit_code is None or evidence.exit_code != 0):
        return "execution_error"
    if getattr(evidence, "drift", False):
        return "catalog_drift"
    if getattr(evidence, "parse_incomplete", False):
        return "parser_incomplete"
    if getattr(evidence, "timed_out", False):
        return "timeout"
    if getattr(evidence, "truncated", False):
        return "output_truncated"
    if getattr(evidence, "budget_expired", False):
        return "insufficient_budget"
    if getattr(evidence, "unresponsive_targets", 0) and evidence.unresponsive_targets > 0:
        return "unresponsive_origins"
    return None


def _valid_count(v) -> bool:
    """A count is a non-negative int — and NOT a bool (``True``/``False`` are ``int`` subclasses in
    Python; accepting them would let a boolean masquerade as a count of 1/0)."""
    return isinstance(v, int) and not isinstance(v, bool) and v >= 0


def _counts_consistent(counts: dict) -> bool:
    """Counts are coherent iff each is a valid non-negative int AND
    ``selected == covered + partial + failed + skipped``. Anything else is ``data_inconsistent``."""
    keys = ("selected", "covered", "partial", "failed", "skipped")
    vals = [counts.get(k, 0) for k in keys]
    if not all(_valid_count(v) for v in vals):
        return False
    selected, covered, partial, failed, skipped = vals
    return selected == covered + partial + failed + skipped


def _derive_state(*, enabled, no_targets, structural_failed, pass_status, execution_complete, limitation):
    """Map the pass's signals to the operational state, per the fixed rules:
    disabled → feature off; no_targets → nothing to verify; complete → all covered; limited → ran
    fully but some origins were unresponsive; incomplete → skipped/timeout/truncated/parser/catalog/
    budget (execution not conclusively complete); failed → invalid config / runner / all-failed /
    structural. `limited` must NOT hide an interrupted execution."""
    if not enabled:
        return STATE_DISABLED
    if structural_failed or pass_status == "failed":
        return STATE_FAILED
    if no_targets:
        return STATE_NO_TARGETS
    if pass_status == "completed":
        return STATE_COMPLETE
    # partial (or anything short of completed that still ran): only unresponsive-origins with a fully
    # attributed, operationally-complete execution is `limited`; everything else is conservative.
    if execution_complete and limitation == "unresponsive_origins":
        return STATE_LIMITED
    return STATE_INCOMPLETE


def build_snapshot(
    *,
    enabled: bool,
    no_targets: bool,
    structural_failed: bool,
    pass_status: str,
    execution_complete: bool,
    phase_non_degrading: bool,
    coverage_authorizing: bool,
    counts: dict,
    batch_reasons: Sequence[Optional[str]],
    extra_reasons: Sequence[Optional[str]] = (),
    detail: Optional[dict] = None,
) -> dict:
    """Build the schema-1 ``endpoint_verification`` snapshot. Closed-enum ``limitation`` +
    precedence-ordered ``limitations``; counts are for AUDIT only (the builder re-aggregates the
    authoritative coverage rows). No URL/hash/raw error anywhere."""
    reasons = list(batch_reasons) + list(extra_reasons)
    limitation = resolve_limitation(reasons)
    limitations = ranked_limitations(reasons)
    state = _derive_state(
        enabled=enabled,
        no_targets=no_targets,
        structural_failed=structural_failed,
        pass_status=pass_status,
        execution_complete=execution_complete,
        limitation=limitation,
    )

    # Hardening: an inconsistent count set (negative / bool / selected != covered+partial+failed+skipped)
    # can NEVER be reported as complete — the headline problem is the inconsistency itself.
    if not _counts_consistent(counts):
        state = STATE_INCOMPLETE
        limitation = "data_inconsistent"
        limitations = ["data_inconsistent"] + [r for r in limitations if r != "data_inconsistent"]
    # A "complete" state with any limitation present is contradictory → downgrade to incomplete.
    elif state == STATE_COMPLETE and (limitation is not None or limitations):
        state = STATE_INCOMPLETE

    # Invariant (fail-closed): a non-conclusive state must NEVER be reasonless. An `incomplete` we
    # cannot attribute is `unknown` (a real uncertainty), a `failed` defaults to `execution_error`.
    # `complete`/`limited`/`disabled`/`no_targets` reasons are already fixed by the rules above.
    if limitation is None:
        if state == STATE_INCOMPLETE:
            limitation = "unknown"
        elif state == STATE_FAILED:
            limitation = "execution_error"
        if limitation is not None and limitation not in limitations:
            limitations = limitations + [limitation]

    # Construction-time assertions — the invariant table is executable, not just documented.
    assert state in VALID_STATES
    assert limitation is None or limitation in VALID_LIMITATIONS
    assert all(r in VALID_LIMITATIONS for r in limitations)
    assert not (state in (STATE_INCOMPLETE, STATE_FAILED) and limitation is None)
    assert not (state == STATE_COMPLETE and (limitation is not None or limitations))

    snapshot = {
        "schema_version": SCHEMA_VERSION,
        "enabled": bool(enabled),
        "execution_complete": bool(execution_complete),
        "phase_non_degrading": bool(phase_non_degrading),
        "coverage_authorizing": bool(coverage_authorizing),
        "state": state,
        "limitation": limitation,
        "limitations": limitations,
        "selected": int(counts.get("selected", 0)),
        "covered": int(counts.get("covered", 0)),
        "partial": int(counts.get("partial", 0)),
        "failed": int(counts.get("failed", 0)),
        "skipped": int(counts.get("skipped", 0)),
    }
    # Optional non-sensitive audit context (candidate_count / out_of_scope_dropped / template_count /
    # batch_count) — counts only, never URLs/targets/hashes.
    for key in ("candidate_count", "out_of_scope_dropped", "template_count", "batch_count"):
        if detail and key in detail and isinstance(detail[key], int):
            snapshot[key] = detail[key]
    return snapshot


__all__ = [
    "SCHEMA_VERSION",
    "STATE_DISABLED",
    "STATE_NO_TARGETS",
    "STATE_COMPLETE",
    "STATE_LIMITED",
    "STATE_INCOMPLETE",
    "STATE_FAILED",
    "VALID_STATES",
    "LIMITATION_PRECEDENCE",
    "VALID_LIMITATIONS",
    "resolve_limitation",
    "ranked_limitations",
    "batch_limitation_reason",
    "build_snapshot",
]
