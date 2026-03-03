"""
Celery tasks for bi-directional ticket synchronization.

Tasks:
    sync_all_tenant_tickets: Periodic task that iterates all tenants with
        active ticketing configs and runs full bi-directional sync.
    create_ticket_for_finding: One-off task to create a ticket for a specific finding.
    sync_single_ticket: One-off task to sync a single ticket.
"""

import logging

from app.celery_app import celery
from app.config import settings

logger = logging.getLogger(__name__)


@celery.task(
    name="app.tasks.ticket_sync.sync_all_tenant_tickets",
    bind=True,
    max_retries=2,
    default_retry_delay=60,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    acks_late=True,
)
def sync_all_tenant_tickets(self) -> dict:
    """
    Periodic bi-directional ticket sync for ALL tenants.

    Iterates every tenant with an active ticketing config and runs
    a full sync cycle (inbound + outbound).

    Scheduled via Celery Beat every 15 minutes.

    Returns:
        Summary dict per tenant.
    """
    from app.database import SessionLocal
    from app.models.ticketing import TicketingConfig
    from app.services.ticketing.sync_service import TicketSyncService

    db = SessionLocal()
    try:
        # Find all tenants with active ticketing configs
        active_configs = (
            db.query(TicketingConfig)
            .filter(TicketingConfig.is_active == True)  # noqa: E712
            .all()
        )

        if not active_configs:
            logger.info("No active ticketing configs found, skipping sync")
            return {"tenants_processed": 0}

        results = {}
        for config in active_configs:
            tenant_id = config.tenant_id
            logger.info("Starting ticket sync for tenant %d", tenant_id)
            try:
                sync_service = TicketSyncService(db, settings.secret_key)
                tenant_result = sync_service.run_full_sync(tenant_id)
                results[tenant_id] = tenant_result
            except Exception as exc:
                logger.error(
                    "Ticket sync failed for tenant %d: %s",
                    tenant_id,
                    exc,
                    exc_info=True,
                )
                results[tenant_id] = {"error": str(exc)[:500]}

        total_synced = sum(
            r.get("synced", 0) for r in results.values() if isinstance(r, dict)
        )
        total_errors = sum(
            r.get("errors", 0) for r in results.values() if isinstance(r, dict)
        )

        logger.info(
            "Ticket sync complete: %d tenants, %d synced, %d errors",
            len(results),
            total_synced,
            total_errors,
        )

        return {
            "tenants_processed": len(results),
            "total_synced": total_synced,
            "total_errors": total_errors,
            "details": {str(k): v for k, v in results.items()},
        }

    except Exception as exc:
        logger.error("sync_all_tenant_tickets failed: %s", exc, exc_info=True)
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery.task(
    name="app.tasks.ticket_sync.create_ticket_for_finding",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    acks_late=True,
)
def create_ticket_for_finding(self, tenant_id: int, finding_id: int) -> dict:
    """
    Create an external ticket for a specific finding.

    Called when an issue is triaged or when a user explicitly requests
    ticket creation from the UI.

    Args:
        tenant_id: Tenant ID.
        finding_id: Finding ID to create a ticket for.

    Returns:
        Dict with ticket info or error details.
    """
    from app.database import SessionLocal
    from app.services.ticketing.sync_service import TicketSyncService

    db = SessionLocal()
    try:
        sync_service = TicketSyncService(db, settings.secret_key)
        ticket = sync_service.create_ticket_for_finding(tenant_id, finding_id)

        if ticket:
            return {
                "status": "created",
                "ticket_id": ticket.id,
                "external_id": ticket.external_id,
                "external_url": ticket.external_url,
                "provider": ticket.provider,
            }

        return {
            "status": "failed",
            "error": "Could not create ticket. Check ticketing config and logs.",
        }

    except Exception as exc:
        logger.error(
            "create_ticket_for_finding failed for finding %d: %s",
            finding_id,
            exc,
            exc_info=True,
        )
        raise self.retry(exc=exc)
    finally:
        db.close()


@celery.task(
    name="app.tasks.ticket_sync.sync_single_ticket",
    bind=True,
    max_retries=3,
    default_retry_delay=30,
    retry_backoff=True,
    retry_backoff_max=600,
    retry_jitter=True,
    acks_late=True,
)
def sync_single_ticket(self, ticket_id: int) -> dict:
    """
    Sync a single ticket bi-directionally.

    Useful for manual/on-demand sync from the UI.

    Args:
        ticket_id: Ticket record ID.

    Returns:
        Dict with sync result.
    """
    from app.database import SessionLocal
    from app.models.ticketing import Ticket
    from app.services.ticketing.sync_service import TicketSyncService

    db = SessionLocal()
    try:
        ticket = db.query(Ticket).filter(Ticket.id == ticket_id).first()
        if not ticket:
            return {"status": "error", "error": f"Ticket {ticket_id} not found"}

        sync_service = TicketSyncService(db, settings.secret_key)

        # Inbound first, then outbound
        inbound_ok = sync_service.sync_ticket_to_finding(ticket)
        outbound_ok = sync_service.sync_finding_to_ticket(ticket)

        return {
            "status": "synced" if (inbound_ok and outbound_ok) else "partial",
            "inbound": inbound_ok,
            "outbound": outbound_ok,
            "external_status": ticket.external_status,
            "sync_status": ticket.sync_status,
        }

    except Exception as exc:
        logger.error(
            "sync_single_ticket failed for ticket %d: %s",
            ticket_id,
            exc,
            exc_info=True,
        )
        raise self.retry(exc=exc)
    finally:
        db.close()
