"""
Scheduled scan dispatcher.

Called by Celery Beat every minute. Checks ScanProfile records with
schedule_cron set and triggers scans when the cron expression matches
the current time.

Uses croniter to evaluate cron expressions. Only triggers if:
- Profile is enabled
- Project is active
- No scan is currently running for the same project
- Last scan was long enough ago (respects cron interval)
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta

from app.celery_app import celery
from app.database import SessionLocal
from app.models.scanning import ScanProfile, ScanRun, ScanRunStatus, Project
from app.services.scan_run_service import ScanRunService

logger = logging.getLogger(__name__)


@celery.task(name="app.tasks.scheduled_scans.dispatch_scheduled_scans")
def dispatch_scheduled_scans() -> dict:
    """Check all enabled scan profiles and trigger due scans.

    Called by Celery Beat every minute via beat_schedule.
    """
    db = SessionLocal()
    triggered = 0
    skipped = 0

    try:
        profiles = (
            db.query(ScanProfile)
            .join(Project)
            .filter(
                ScanProfile.enabled == True,  # noqa: E712
                ScanProfile.schedule_cron.isnot(None),
                ScanProfile.schedule_cron != "",
            )
            .all()
        )

        if not profiles:
            return {"profiles_checked": 0, "triggered": 0, "skipped": 0}

        now = datetime.now(timezone.utc)

        for profile in profiles:
            try:
                if not _is_due(profile, now, db):
                    skipped += 1
                    continue

                # Check no running scan for this project
                running = (
                    db.query(ScanRun)
                    .filter(
                        ScanRun.project_id == profile.project_id,
                        ScanRun.status.in_([ScanRunStatus.RUNNING, ScanRunStatus.PENDING]),
                    )
                    .first()
                )
                if running:
                    logger.info(
                        "Skipping scheduled scan for profile %d: scan %d already running",
                        profile.id,
                        running.id,
                    )
                    skipped += 1
                    continue

                # Trigger scan
                service = ScanRunService(db)
                project = db.query(Project).filter(Project.id == profile.project_id).first()
                if not project:
                    continue

                scan_run, task_id = service.trigger_scan(
                    tenant_id=project.tenant_id,
                    project=project,
                    profile_id=profile.id,
                    scan_tier=profile.scan_tier,
                    triggered_by="scheduler",
                )

                logger.info(
                    "Scheduled scan triggered: profile=%d project=%d scan_run=%d task=%s",
                    profile.id,
                    project.id,
                    scan_run.id,
                    task_id,
                )
                triggered += 1

            except Exception as exc:
                logger.exception("Error dispatching scheduled scan for profile %d: %s", profile.id, exc)

        return {
            "profiles_checked": len(profiles),
            "triggered": triggered,
            "skipped": skipped,
        }

    finally:
        db.close()


def _is_due(profile: ScanProfile, now: datetime, db) -> bool:
    """Check if a scan profile is due based on its cron expression.

    Uses croniter to evaluate the cron schedule. A profile is due if
    the current time falls within 1 minute of a cron trigger point
    AND the last scan was completed before the previous trigger point.
    """
    try:
        from croniter import croniter
    except ImportError:
        logger.warning("croniter not installed — scheduled scans disabled")
        return False

    try:
        cron = croniter(profile.schedule_cron, now - timedelta(minutes=1))
        next_time = cron.get_next(datetime)

        # Due if next trigger is within 1 minute of now
        if abs((next_time - now).total_seconds()) > 60:
            return False

        # Check last completed scan for this profile
        last_scan = (
            db.query(ScanRun)
            .filter(
                ScanRun.project_id == profile.project_id,
                ScanRun.status == ScanRunStatus.COMPLETED,
            )
            .order_by(ScanRun.completed_at.desc())
            .first()
        )

        if last_scan and last_scan.completed_at:
            # Don't re-trigger if last scan completed less than 1 hour ago
            if (now - last_scan.completed_at.replace(tzinfo=timezone.utc)).total_seconds() < 3600:
                return False

        return True

    except (ValueError, KeyError) as exc:
        logger.warning("Invalid cron expression '%s' for profile %d: %s", profile.schedule_cron, profile.id, exc)
        return False
