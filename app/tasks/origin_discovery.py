"""Celery task wrapper for WAF origin discovery (Phase 8c).

The logic lives in ``app.services.origin_discovery``; this module only exposes
it as a Celery task and is registered in the ``include`` list in
``app.celery_app``.
"""

from __future__ import annotations

import logging

from app.celery_app import celery
from app.services.origin_discovery import run_origin_discovery

logger = logging.getLogger(__name__)


@celery.task(
    name="app.tasks.origin_discovery.run_origin_discovery_task",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    retry_backoff=True,
    retry_jitter=True,
)
def run_origin_discovery_task(self, tenant_id: int, scan_run_id: int | None = None) -> dict:
    """Discover exposed origin servers behind WAF/CDN for a tenant."""
    logger.info("Starting origin discovery (tenant %d, scan_run %s)", tenant_id, scan_run_id)
    result = run_origin_discovery(tenant_id, scan_run_id=scan_run_id)
    logger.info("Origin discovery done (tenant %d): %s", tenant_id, result)
    return result
