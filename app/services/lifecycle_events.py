"""Finding lifecycle event writer (UI-2 backend, step 2).

A single, deliberately tiny primitive: append one ``FindingLifecycleEvent`` row **in the
caller's current transaction** so the auto-close audit is durable and queryable instead of
living only in a log line. It is the load-bearing part of the UI timeline, so it is blindato:

* **Same transaction, no internal commit.** The writer never calls ``commit()`` / ``rollback()``.
  It ``flush()``es, so a constraint/FK failure surfaces *inside* the caller's transaction — the
  caller either commits everything (mutation + event) or the whole transaction rolls back. In
  particular, if the ``auto_closed`` event cannot be written, the OPEN→FIXED close is rolled back
  with it (never a close without its audit row).
* **Idempotent** on ``(finding_id, event_type, scan_run_id)``: a retried run re-checks and is a
  no-op; the DB UNIQUE constraint (migration 031) is the backstop under any race.
* **Closed-schema detail.** ``detail`` is a small dict of non-sensitive context only — streak,
  threshold, coverage scope, origin tier, a reason code. NEVER a URL and NEVER a hash. Callers are
  responsible for what they pass; :func:`_sanitized` strips obvious hash/url keys as a guard.
"""

from __future__ import annotations

from typing import Optional

# Keys that must never reach a lifecycle event's detail (defence in depth against a caller
# accidentally threading a URL or a coverage/policy hash into the durable audit).
_FORBIDDEN_DETAIL_KEYS = frozenset(
    {
        "url",
        "matched_at",
        "shape_hash",
        "endpoint_shape_hash",
        "policy_hash",
        "origin_policy_hash",
        "fingerprint",
        "hash",
    }
)

VALID_EVENT_TYPES = frozenset({"detected", "eligible_miss", "miss_reset", "would_close", "auto_closed", "reopened"})


def _sanitized(detail: Optional[dict]) -> Optional[dict]:
    if not detail:
        return None
    clean = {k: v for k, v in detail.items() if k not in _FORBIDDEN_DETAIL_KEYS}
    return clean or None


def record_lifecycle_event(
    db,
    *,
    tenant_id: int,
    finding_id: int,
    scan_run_id: Optional[int],
    event_type: str,
    detail: Optional[dict] = None,
) -> bool:
    """Append one lifecycle event in the CURRENT transaction (no commit). Returns True if a row
    was added, False if it already existed (idempotent no-op).

    ``event_type`` must be one of :data:`VALID_EVENT_TYPES` (the DB CHECK enforces it too).
    Raises on an unknown type or if the flush hits a constraint — by design, so the caller's
    transaction (and any mutation in it) rolls back rather than committing a half-written audit.
    """
    if event_type not in VALID_EVENT_TYPES:
        raise ValueError(f"unknown lifecycle event_type: {event_type!r}")

    from app.models.database import FindingLifecycleEvent

    # Idempotency applies ONLY to run-attributed events: a retried scan must not duplicate its
    # (finding, type, run) row. Run-less events (scan_run_id is None — e.g. a manual reopen) are
    # NOT deduplicated: they are distinct real occurrences, and Postgres treats NULLs as distinct in
    # the UNIQUE constraint, so a permanent pre-check would wrongly swallow the 2nd manual reopen.
    if scan_run_id is not None:
        exists = (
            db.query(FindingLifecycleEvent.id)
            .filter(
                FindingLifecycleEvent.finding_id == finding_id,
                FindingLifecycleEvent.event_type == event_type,
                FindingLifecycleEvent.scan_run_id == scan_run_id,
            )
            .first()
        )
        if exists is not None:
            return False

    db.add(
        FindingLifecycleEvent(
            tenant_id=tenant_id,
            finding_id=finding_id,
            scan_run_id=scan_run_id,
            event_type=event_type,
            detail=_sanitized(detail),
        )
    )
    # Flush (not commit): make FK/unique/CHECK violations fail HERE, inside the caller's
    # transaction, so a bad audit write aborts the mutation it belongs to.
    db.flush()
    return True


__all__ = ["record_lifecycle_event", "VALID_EVENT_TYPES"]
