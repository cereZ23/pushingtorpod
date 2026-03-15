"""
Celery task for periodic data retention and cleanup.

Removes old scan_runs, phase_results, observations, and orphaned
risk_scores beyond the configurable retention window.  Runs daily
via Celery Beat and logs every deletion batch for auditability.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.celery_app import celery
from app.config import settings
from app.database import SessionLocal
from app.models.risk import RiskScore
from app.models.scanning import Observation, PhaseResult, ScanRun, ScanRunStatus

logger = logging.getLogger(__name__)

# Only clean up terminal scan runs (never delete in-progress work)
_TERMINAL_STATUSES = {
    ScanRunStatus.COMPLETED,
    ScanRunStatus.FAILED,
    ScanRunStatus.CANCELLED,
}


@celery.task(
    name="app.tasks.cleanup.cleanup_old_scan_data",
    bind=True,
    max_retries=2,
    default_retry_delay=300,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
)
def cleanup_old_scan_data(self, retention_days: int | None = None) -> dict:
    """Delete scan_runs, phase_results, observations, and risk_scores
    older than *retention_days*.

    Processing order matters because of foreign-key constraints:
      1. phase_results   (FK -> scan_runs)
      2. observations    (FK -> scan_runs)
      3. risk_scores     (FK -> scan_runs)
      4. scan_runs       (parent table)

    Args:
        retention_days: Override the default retention window.  Falls
            back to ``settings.data_retention_days`` (default 90).

    Returns:
        Summary dict with counts per table and the cutoff date used.
    """
    if retention_days is None:
        retention_days = getattr(settings, "data_retention_days", 90)

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    logger.info(
        "Data cleanup started: retention_days=%d, cutoff=%s",
        retention_days,
        cutoff.isoformat(),
    )

    db = SessionLocal()
    summary: dict[str, int] = {
        "phase_results_deleted": 0,
        "observations_deleted": 0,
        "risk_scores_deleted": 0,
        "scan_runs_deleted": 0,
    }

    try:
        # Identify scan_run IDs eligible for deletion:
        #   - created before the cutoff
        #   - in a terminal status (COMPLETED / FAILED / CANCELLED)
        eligible_ids_query = db.query(ScanRun.id).filter(
            ScanRun.created_at < cutoff,
            ScanRun.status.in_(_TERMINAL_STATUSES),
        )
        eligible_ids = [row[0] for row in eligible_ids_query.all()]

        if not eligible_ids:
            logger.info("No scan runs older than %s eligible for cleanup.", cutoff.isoformat())
            return {**summary, "cutoff": cutoff.isoformat(), "retention_days": retention_days}

        logger.info(
            "Found %d scan run(s) eligible for cleanup (created before %s).",
            len(eligible_ids),
            cutoff.isoformat(),
        )

        # --- 1. Delete phase_results ----------------------------------
        phase_deleted = (
            db.query(PhaseResult).filter(PhaseResult.scan_run_id.in_(eligible_ids)).delete(synchronize_session=False)
        )
        summary["phase_results_deleted"] = phase_deleted
        logger.info("Deleted %d phase_result(s).", phase_deleted)

        # --- 2. Delete observations -----------------------------------
        obs_deleted = (
            db.query(Observation).filter(Observation.scan_run_id.in_(eligible_ids)).delete(synchronize_session=False)
        )
        summary["observations_deleted"] = obs_deleted
        logger.info("Deleted %d observation(s).", obs_deleted)

        # --- 3. Delete risk_scores tied to these scan runs ------------
        rs_deleted = (
            db.query(RiskScore).filter(RiskScore.scan_run_id.in_(eligible_ids)).delete(synchronize_session=False)
        )
        summary["risk_scores_deleted"] = rs_deleted
        logger.info("Deleted %d risk_score(s).", rs_deleted)

        # --- 4. Delete the scan_runs themselves -----------------------
        sr_deleted = db.query(ScanRun).filter(ScanRun.id.in_(eligible_ids)).delete(synchronize_session=False)
        summary["scan_runs_deleted"] = sr_deleted
        logger.info("Deleted %d scan_run(s).", sr_deleted)

        db.commit()

    except Exception as exc:
        logger.exception("Data cleanup task failed")
        try:
            db.rollback()
        except Exception:
            logger.debug("db.rollback() failed after cleanup error", exc_info=True)
        raise self.retry(exc=exc)
    finally:
        db.close()

    summary["cutoff"] = cutoff.isoformat()
    summary["retention_days"] = retention_days

    logger.info("Data cleanup completed: %s", summary)
    return summary
