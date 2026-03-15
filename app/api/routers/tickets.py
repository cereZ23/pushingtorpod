"""
Tickets Router

Handles ticketing integration configuration and ticket lifecycle management.

Endpoints:
    POST   /api/v1/tenants/{tenant_id}/integrations/ticketing       - Configure ticketing
    GET    /api/v1/tenants/{tenant_id}/integrations/ticketing       - Get current config
    DELETE /api/v1/tenants/{tenant_id}/integrations/ticketing       - Deactivate config
    POST   /api/v1/tenants/{tenant_id}/integrations/ticketing/test  - Test connection
    POST   /api/v1/tenants/{tenant_id}/findings/{finding_id}/ticket - Create ticket
    GET    /api/v1/tenants/{tenant_id}/findings/{finding_id}/ticket - Get linked ticket
    POST   /api/v1/tenants/{tenant_id}/findings/{finding_id}/ticket/sync - Manual sync
    POST   /api/v1/tenants/{tenant_id}/tickets/sync                - Full tenant sync
"""

import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, verify_tenant_access
from app.api.schemas.ticket import (
    TicketingConfigCreate,
    TicketingConfigResponse,
    TicketingTestResult,
    TicketCreateRequest,
    TicketResponse,
    TicketSyncResponse,
    TicketSingleSyncResponse,
)
from app.config import settings
from app.models.database import Asset, Finding
from app.models.ticketing import Ticket, TicketingConfig
from app.services.ticketing import get_provider
from app.services.ticketing.crypto import decrypt_config, encrypt_config, mask_config
from app.services.ticketing.sync_service import TicketSyncService

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}",
    tags=["Ticketing"],
)


# ------------------------------------------------------------------
# Ticketing configuration endpoints
# ------------------------------------------------------------------


@router.post(
    "/integrations/ticketing",
    response_model=TicketingConfigResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Configure ticketing integration",
)
def create_or_update_ticketing_config(
    tenant_id: int,
    body: TicketingConfigCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Create or update the ticketing integration for a tenant.

    Requires admin permission. Stores credentials encrypted.
    Only one active config per tenant is supported; posting a new config
    deactivates the previous one.
    """
    if not membership.has_permission("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required to manage integrations",
        )

    # Validate provider-specific required fields
    _validate_provider_config(body.provider, body.config)

    # Encrypt the config
    encrypted = encrypt_config(body.config, settings.secret_key)

    # Deactivate any existing config for this tenant
    db.query(TicketingConfig).filter(
        TicketingConfig.tenant_id == tenant_id,
        TicketingConfig.is_active == True,  # noqa: E712
    ).update({"is_active": False, "updated_at": datetime.now(timezone.utc)})

    # Create new config
    config_record = TicketingConfig(
        tenant_id=tenant_id,
        provider=body.provider,
        config_encrypted=encrypted,
        is_active=True,
        auto_create_on_triage=body.auto_create_on_triage,
        sync_status_back=body.sync_status_back,
    )
    db.add(config_record)
    db.commit()
    db.refresh(config_record)

    logger.info(
        "Ticketing config created for tenant %d: provider=%s",
        tenant_id,
        body.provider,
    )

    return TicketingConfigResponse(
        id=config_record.id,
        tenant_id=config_record.tenant_id,
        provider=config_record.provider,
        config_masked=mask_config(body.config),
        is_active=config_record.is_active,
        auto_create_on_triage=config_record.auto_create_on_triage,
        sync_status_back=config_record.sync_status_back,
        created_at=config_record.created_at,
        updated_at=config_record.updated_at,
    )


@router.get(
    "/integrations/ticketing",
    response_model=TicketingConfigResponse,
    summary="Get ticketing integration config",
)
def get_ticketing_config(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get the current active ticketing integration config for a tenant.

    Credentials are returned masked.
    """
    config_record = (
        db.query(TicketingConfig)
        .filter(
            TicketingConfig.tenant_id == tenant_id,
            TicketingConfig.is_active == True,  # noqa: E712
        )
        .first()
    )

    if not config_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active ticketing integration configured for this tenant",
        )

    # Decrypt to mask
    plain_config = decrypt_config(config_record.config_encrypted, settings.secret_key)
    masked = mask_config(plain_config) if plain_config else {"error": "decryption_failed"}

    return TicketingConfigResponse(
        id=config_record.id,
        tenant_id=config_record.tenant_id,
        provider=config_record.provider,
        config_masked=masked,
        is_active=config_record.is_active,
        auto_create_on_triage=config_record.auto_create_on_triage,
        sync_status_back=config_record.sync_status_back,
        created_at=config_record.created_at,
        updated_at=config_record.updated_at,
    )


@router.delete(
    "/integrations/ticketing",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Deactivate ticketing integration",
)
def deactivate_ticketing_config(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Deactivate the current ticketing integration config for a tenant.

    Requires admin permission. Does not delete the record (audit trail).
    """
    if not membership.has_permission("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required to manage integrations",
        )

    updated = (
        db.query(TicketingConfig)
        .filter(
            TicketingConfig.tenant_id == tenant_id,
            TicketingConfig.is_active == True,  # noqa: E712
        )
        .update({"is_active": False, "updated_at": datetime.now(timezone.utc)})
    )

    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active ticketing integration to deactivate",
        )

    db.commit()
    logger.info("Ticketing config deactivated for tenant %d", tenant_id)


@router.post(
    "/integrations/ticketing/test",
    response_model=TicketingTestResult,
    summary="Test ticketing connection",
)
def test_ticketing_connection(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Test the current ticketing integration connection.

    Verifies authentication and connectivity to the external system.
    """
    config_record = (
        db.query(TicketingConfig)
        .filter(
            TicketingConfig.tenant_id == tenant_id,
            TicketingConfig.is_active == True,  # noqa: E712
        )
        .first()
    )

    if not config_record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No active ticketing integration configured",
        )

    plain_config = decrypt_config(config_record.config_encrypted, settings.secret_key)
    if not plain_config:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to decrypt ticketing configuration",
        )

    try:
        provider = get_provider(config_record.provider, plain_config)
        success = provider.test_connection()
    except Exception as exc:
        logger.error("Ticketing connection test failed: %s", exc)
        return TicketingTestResult(
            success=False,
            message=f"Connection test failed: {exc}",
            provider=config_record.provider,
        )

    if success:
        return TicketingTestResult(
            success=True,
            message="Connection successful. Authentication verified.",
            provider=config_record.provider,
        )

    return TicketingTestResult(
        success=False,
        message="Connection failed. Please check credentials and URL.",
        provider=config_record.provider,
    )


# ------------------------------------------------------------------
# Finding-level ticket endpoints
# ------------------------------------------------------------------


@router.post(
    "/findings/{finding_id}/ticket",
    response_model=TicketResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create ticket for finding",
)
def create_ticket_for_finding(
    tenant_id: int,
    finding_id: int,
    body: TicketCreateRequest = TicketCreateRequest(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Create an external ticket linked to a specific finding.

    Requires write permission. If a ticket already exists for this finding,
    returns the existing ticket with 200 instead of creating a duplicate.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required to create tickets",
        )

    # Verify finding exists and belongs to tenant
    finding = db.query(Finding).join(Asset).filter(Finding.id == finding_id, Asset.tenant_id == tenant_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    # Check for existing ticket
    existing = db.query(Ticket).filter(Ticket.finding_id == finding_id, Ticket.tenant_id == tenant_id).first()
    if existing:
        return TicketResponse.model_validate(existing)

    # Create ticket via sync service
    sync_service = TicketSyncService(db, settings.secret_key)
    ticket = sync_service.create_ticket_for_finding(tenant_id, finding_id)

    if not ticket:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Failed to create external ticket. Check ticketing configuration.",
        )

    return TicketResponse.model_validate(ticket)


@router.get(
    "/findings/{finding_id}/ticket",
    response_model=TicketResponse,
    summary="Get ticket for finding",
)
def get_ticket_for_finding(
    tenant_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get the linked ticket for a specific finding.

    Returns 404 if no ticket has been created for this finding.
    """
    # Verify finding exists and belongs to tenant
    finding = db.query(Finding).join(Asset).filter(Finding.id == finding_id, Asset.tenant_id == tenant_id).first()
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    ticket = db.query(Ticket).filter(Ticket.finding_id == finding_id, Ticket.tenant_id == tenant_id).first()

    if not ticket:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No ticket linked to this finding",
        )

    return TicketResponse.model_validate(ticket)


@router.post(
    "/findings/{finding_id}/ticket/sync",
    response_model=TicketSingleSyncResponse,
    summary="Sync ticket for finding",
)
def sync_ticket_for_finding(
    tenant_id: int,
    finding_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Manually trigger bi-directional sync for a specific finding's ticket.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    ticket = db.query(Ticket).filter(Ticket.finding_id == finding_id, Ticket.tenant_id == tenant_id).first()
    if not ticket:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No ticket linked to this finding",
        )

    sync_service = TicketSyncService(db, settings.secret_key)
    inbound_ok = sync_service.sync_ticket_to_finding(ticket)
    outbound_ok = sync_service.sync_finding_to_ticket(ticket)

    overall = "synced" if (inbound_ok and outbound_ok) else "partial"

    return TicketSingleSyncResponse(
        status=overall,
        inbound=inbound_ok,
        outbound=outbound_ok,
        external_status=ticket.external_status,
        sync_status=ticket.sync_status,
    )


# ------------------------------------------------------------------
# Bulk sync endpoint
# ------------------------------------------------------------------


@router.post(
    "/tickets/sync",
    response_model=TicketSyncResponse,
    summary="Full tenant ticket sync",
)
def trigger_full_sync(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Trigger a full bi-directional sync for all tickets in this tenant.

    This runs synchronously. For large numbers of tickets, consider using
    the async Celery task endpoint instead.
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    sync_service = TicketSyncService(db, settings.secret_key)
    result = sync_service.run_full_sync(tenant_id)

    return TicketSyncResponse(
        status="completed",
        synced=result.get("synced", 0),
        errors=result.get("errors", 0),
        skipped=result.get("skipped", 0),
        message=result.get("message"),
    )


# ------------------------------------------------------------------
# Validation helpers
# ------------------------------------------------------------------


def _validate_provider_config(provider: str, config: dict) -> None:
    """
    Validate that required fields are present in the provider config.

    Raises HTTPException 422 if validation fails.
    """
    if provider == "jira":
        required = {"url", "email", "api_token"}
        missing = required - set(config.keys())
        if missing:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required Jira config fields: {', '.join(sorted(missing))}",
            )
        if not config["url"].startswith("http"):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Jira URL must start with http:// or https://",
            )

    elif provider == "servicenow":
        required = {"instance", "username", "password"}
        missing = required - set(config.keys())
        if missing:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Missing required ServiceNow config fields: {', '.join(sorted(missing))}",
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported provider: {provider}",
        )
