"""
Celery application configuration

Provides distributed task queue with Beat scheduler for periodic tasks.
Includes multi-tenant isolation through dedicated queues.
"""

from celery import Celery, signals
from celery.schedules import crontab
import logging

from app.config import settings

logger = logging.getLogger(__name__)

# Create Celery app
celery = Celery(
    'easm',
    broker=settings.celery_broker,
    backend=settings.celery_backend,
    include=[
        'app.tasks.discovery',
        'app.tasks.enrichment',
        'app.tasks.scanning',
        'app.tasks.pipeline',
        'app.tasks.alerting',
        'app.tasks.correlation',
        'app.tasks.diff_alert',
        'app.tasks.fingerprint',
        'app.tasks.misconfig',
        'app.tasks.dnstwist_scan',
        'app.tasks.network_enrichment',
        'app.tasks.visual_recon',
        'app.tasks.threat_intel_sync',
        'app.tasks.ticket_sync',
        'app.tasks.report_delivery',
        'app.tasks.alert_evaluation',
    ]
)

# Celery configuration
celery.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone='UTC',
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    task_soft_time_limit=3300,  # Soft limit at 55 minutes
    worker_prefetch_multiplier=settings.celery_worker_prefetch_multiplier,
    worker_max_tasks_per_child=settings.celery_worker_max_tasks_per_child,
    result_expires=86400,  # Results expire after 24 hours
    task_acks_late=True,  # Acknowledge tasks after completion
    task_reject_on_worker_lost=True,  # Reject tasks if worker crashes
    worker_disable_rate_limits=False,
    task_always_eager=settings.celery_task_always_eager,  # For testing
)

# Celery Beat Schedule
celery.conf.beat_schedule = {
    'daily-full-discovery': {
        'task': 'app.tasks.discovery.run_full_discovery',
        'schedule': crontab(hour=2, minute=0),  # 2 AM daily
        'options': {'expires': 7200}  # Task expires after 2 hours
    },
    'critical-asset-watch': {
        'task': 'app.tasks.discovery.watch_critical_assets',
        'schedule': crontab(minute='*/30'),  # Every 30 minutes
        'options': {'expires': 1800}  # Task expires after 30 minutes
    },
    'refresh-threat-intel': {
        'task': 'app.tasks.threat_intel_sync.refresh_threat_intel',
        'schedule': crontab(hour=2, minute=15),  # 2:15 AM daily
        'options': {'expires': 7200}
    },
    'sync-tickets': {
        'task': 'app.tasks.ticket_sync.sync_all_tenant_tickets',
        'schedule': crontab(minute='*/15'),  # Every 15 minutes
        'options': {'expires': 900}
    },
    'deliver-scheduled-reports': {
        'task': 'app.tasks.report_delivery.deliver_scheduled_reports',
        'schedule': crontab(hour=6, minute=0),  # 6 AM UTC daily
        'options': {'expires': 3600}
    },
}


@signals.task_prerun.connect
def task_prerun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, **extra):
    """Log task start"""
    logger.info(f"Task {task.name} started with ID {task_id}")


@signals.task_postrun.connect
def task_postrun_handler(sender=None, task_id=None, task=None, args=None, kwargs=None, retval=None, **extra):
    """Log task completion"""
    logger.info(f"Task {task.name} completed with ID {task_id}")


@signals.task_retry.connect
def task_retry_handler(sender=None, request=None, reason=None, einfo=None, **extra):
    """Log task retry with attempt number"""
    retries = request.retries if request else '?'
    max_retries = sender.max_retries if sender else '?'
    logger.warning(
        "Task %s retrying (attempt %s/%s): %s",
        sender.name if sender else '?',
        retries,
        max_retries,
        reason,
    )


@signals.task_failure.connect
def task_failure_handler(sender=None, task_id=None, exception=None, traceback=None, **extra):
    """Log task failure after all retries exhausted"""
    logger.error(f"Task {sender.name} failed with ID {task_id}: {exception}", exc_info=True)

if __name__ == '__main__':
    celery.start()
