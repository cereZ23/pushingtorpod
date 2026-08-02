"""Stale-scan watchdog.

A scan whose worker is killed mid-run (deploy restart, OOM, crash) leaves
``ScanRun.status = RUNNING`` forever — the task's internal ``time_limit`` can't
fire because there is no live process to enforce it, so the Duration climbs
indefinitely and the UI shows a zombie.

This external reaper (Celery Beat, every few minutes) finds RUNNING scans that
have made no phase progress for longer than the tier's phase budget (+ grace)
and marks them FAILED, so deploy/OOM never leave a stuck scan behind.

Phase A (this module): heartbeat is derived from the latest ``PhaseResult``
timestamp — no schema change. The threshold is therefore generous (it must
exceed the longest single-phase budget, i.e. the nuclei group, so a legitimately
long scan is never reaped). A future Phase B could add ``ScanRun.heartbeat_at``
touched intra-phase for faster reaping.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import func

from app.celery_app import celery
from app.config import settings
from app.database import SessionLocal
from app.models.scanning import PhaseResult, PhaseStatus, ScanProfile, ScanRun, ScanRunStatus

logger = logging.getLogger(__name__)

# Per-tier nuclei/parallel-group wall-clock budget (mirrors pipeline group_timeout).
# The reaper threshold must exceed this so a legitimately long phase is never reaped.
_TIER_PHASE_BUDGET = {1: 1800, 2: 3600, 3: 10800}


def _as_aware(dt: datetime | None) -> datetime | None:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _stale_threshold_seconds(tier: int, grace: int) -> int:
    """Idle seconds after which a RUNNING scan of this tier is considered dead.

    Must exceed the tier's longest single-phase budget (the nuclei group) so a
    legitimately long scan is never reaped.
    """
    return _TIER_PHASE_BUDGET.get(tier, 3600) + grace


def _should_reap(now: datetime, last_activity: datetime | None, tier: int, grace: int) -> bool:
    """True if a RUNNING scan has been idle past its tier threshold. Pure/testable."""
    la = _as_aware(last_activity)
    if la is None:
        return False
    return (now - la).total_seconds() > _stale_threshold_seconds(tier, grace)


@celery.task(name="app.tasks.scan_watchdog.reap_stale_scans")
def reap_stale_scans(db=None) -> dict:
    """Auto-FAIL RUNNING scans with no phase progress past the tier budget.

    ``db`` is injectable for testing; beat invokes it with no args (own session).
    """
    if not getattr(settings, "stale_scan_reaper_enabled", True):
        return {"disabled": True}

    from app.core.tenant_context import allow_cross_tenant

    grace = getattr(settings, "stale_scan_grace_seconds", 1800)
    own_session = db is None
    db = db or SessionLocal()
    reaped: list[int] = []
    try:
        with allow_cross_tenant():
            now = datetime.now(timezone.utc)
            running = db.query(ScanRun).filter(ScanRun.status == ScanRunStatus.RUNNING).all()

            for run in running:
                # Resolve the scan tier (drives the idle threshold).
                tier = 1
                if run.profile_id:
                    prof = db.query(ScanProfile.scan_tier).filter(ScanProfile.id == run.profile_id).first()
                    tier = (prof.scan_tier if prof else 1) or 1
                threshold = _stale_threshold_seconds(tier, grace)

                # Heartbeat = latest phase activity, else the run's own start.
                last_phase_ts = (
                    db.query(func.max(func.coalesce(PhaseResult.completed_at, PhaseResult.started_at)))
                    .filter(PhaseResult.scan_run_id == run.id)
                    .scalar()
                )
                last_activity = _as_aware(last_phase_ts) or _as_aware(run.started_at) or _as_aware(run.created_at)
                if not _should_reap(now, last_activity, tier, grace):
                    continue
                idle = (now - last_activity).total_seconds()

                # --- reap ---
                run.status = ScanRunStatus.FAILED
                run.completed_at = now
                run.error_message = (
                    f"Stale scan reaped: no phase progress for {int(idle)}s "
                    f"(> tier {tier} budget {threshold}s). Worker likely died (deploy/OOM)."
                )
                # Mark the in-flight phase(s) FAILED too, so the phase view is honest.
                for pr in (
                    db.query(PhaseResult)
                    .filter(PhaseResult.scan_run_id == run.id, PhaseResult.status == PhaseStatus.RUNNING)
                    .all()
                ):
                    pr.status = PhaseStatus.FAILED
                    pr.completed_at = now
                    pr.error_message = "Interrupted — scan reaped as stale"

                # Best-effort: revoke the (likely dead) celery task.
                if run.celery_task_id:
                    try:
                        celery.control.revoke(run.celery_task_id, terminate=True)
                    except Exception as exc:  # pragma: no cover - control plane best effort
                        logger.warning("reap: revoke failed for task %s: %s", run.celery_task_id, exc)

                reaped.append(run.id)

            if reaped:
                db.commit()

        if reaped:
            logger.warning("Stale-scan reaper: reaped %d scan(s): %s", len(reaped), reaped)
        return {"reaped": len(reaped), "scan_run_ids": reaped, "checked": len(running)}
    except Exception as exc:  # pragma: no cover - defensive
        logger.exception("Stale-scan reaper failed: %s", exc)
        db.rollback()
        return {"error": str(exc)}
    finally:
        if own_session:
            db.close()
