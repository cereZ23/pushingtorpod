"""
Alert Policy management API router.

Provides CRUD operations for alert policies that define when and how
notifications are dispatched to channels (Slack, email, webhook) based
on event types, severity conditions, and cooldown windows.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, ConfigDict
import logging

from app.api.dependencies import get_db, verify_tenant_access
from app.models.database import Tenant
from app.models.risk import AlertPolicy

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/alert-policies",
    tags=["Alert Policies"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class ChannelConfig(BaseModel):
    """Configuration for a single notification channel."""

    type: str = Field(..., description="Channel type (slack, email, webhook)")
    webhook_url: Optional[str] = Field(None, description="Webhook URL for Slack/generic webhook")
    to: Optional[str] = Field(None, description="Destination email address")
    template: Optional[str] = Field(None, description="Optional message template name")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "type": "slack",
                "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
            }
        }
    )


class AlertPolicyCreate(BaseModel):
    """Request body for creating a new alert policy."""

    name: str = Field(..., min_length=1, max_length=255, description="Policy name")
    event_types: List[str] = Field(
        ...,
        min_length=1,
        description="Event types that trigger this policy (finding_new, asset_new, cert_expiring, score_changed)",
    )
    conditions: Optional[Dict[str, Any]] = Field(
        None,
        description="Matching conditions such as severity thresholds or pattern filters",
    )
    channels: List[ChannelConfig] = Field(
        ...,
        min_length=1,
        description="Notification channels to deliver alerts through",
    )
    cooldown_minutes: int = Field(
        default=1440,
        ge=0,
        le=43200,
        description="Cooldown window in minutes before re-alerting (default 24h)",
    )
    digest_mode: bool = Field(
        default=False,
        description="When true, batch alerts into periodic digests instead of firing individually",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "name": "Critical findings - Slack",
                "event_types": ["finding_new"],
                "conditions": {"severity": "critical"},
                "channels": [{"type": "slack", "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx"}],
                "cooldown_minutes": 60,
                "digest_mode": False,
            }
        }
    )


class AlertPolicyUpdate(BaseModel):
    """Request body for partially updating an alert policy."""

    name: Optional[str] = Field(None, min_length=1, max_length=255, description="Policy name")
    event_types: Optional[List[str]] = Field(None, description="Event types")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Matching conditions")
    channels: Optional[List[ChannelConfig]] = Field(None, description="Notification channels")
    cooldown_minutes: Optional[int] = Field(None, ge=0, le=43200, description="Cooldown in minutes")
    digest_mode: Optional[bool] = Field(None, description="Enable/disable digest mode")
    enabled: Optional[bool] = Field(None, description="Enable/disable the policy")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cooldown_minutes": 120,
                "enabled": False,
            }
        }
    )


class AlertPolicyResponse(BaseModel):
    """Response model for a single alert policy."""

    id: int = Field(..., description="Policy ID")
    tenant_id: int = Field(..., description="Tenant ID")
    name: str = Field(..., description="Policy name")
    event_types: List[str] = Field(..., description="Subscribed event types")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Matching conditions")
    channels: List[Dict[str, Any]] = Field(..., description="Notification channels")
    cooldown_minutes: int = Field(..., description="Cooldown in minutes")
    digest_mode: bool = Field(..., description="Digest mode flag")
    enabled: bool = Field(..., description="Whether the policy is active")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 1,
                "tenant_id": 1,
                "name": "Critical findings - Slack",
                "event_types": ["finding_new"],
                "conditions": {"severity": "critical"},
                "channels": [{"type": "slack", "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx"}],
                "cooldown_minutes": 60,
                "digest_mode": False,
                "enabled": True,
                "created_at": "2026-01-15T10:00:00Z",
                "updated_at": "2026-01-15T10:00:00Z",
            }
        },
    )


class TestNotificationResponse(BaseModel):
    """Response from a test notification dispatch."""

    success: bool = Field(..., description="Whether the test was dispatched")
    channels_tested: List[str] = Field(..., description="Channels that received the test")
    message: str = Field(..., description="Human-readable result summary")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "success": True,
                "channels_tested": ["slack", "email"],
                "message": "Test notification sent to 2 channel(s)",
            }
        }
    )


class SeedDefaultsResponse(BaseModel):
    """Response from seeding default policies."""

    created: int = Field(..., description="Number of policies created")
    skipped: int = Field(..., description="Number of policies skipped (already exist)")
    policies: List[AlertPolicyResponse] = Field(..., description="Created policy objects")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "created": 5,
                "skipped": 0,
                "policies": [],
            }
        }
    )


# ---------------------------------------------------------------------------
# Allowed event types (for validation)
# ---------------------------------------------------------------------------

VALID_EVENT_TYPES = frozenset(
    {
        "finding_new",
        "asset_new",
        "cert_expiring",
        "score_changed",
        "port_opened",
        "tech_change",
    }
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _verify_tenant_exists(db: Session, tenant_id: int) -> None:
    """Raise 404 if the tenant does not exist."""
    exists = db.query(Tenant.id).filter(Tenant.id == tenant_id).first()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )


def _get_policy_or_404(db: Session, tenant_id: int, policy_id: int) -> AlertPolicy:
    """Return the alert policy or raise 404."""
    policy = (
        db.query(AlertPolicy)
        .filter(
            AlertPolicy.id == policy_id,
            AlertPolicy.tenant_id == tenant_id,
        )
        .first()
    )
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert policy not found",
        )
    return policy


def _validate_event_types(event_types: List[str]) -> None:
    """Raise 400 if any event type is unknown."""
    invalid = [et for et in event_types if et not in VALID_EVENT_TYPES]
    if invalid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event types: {', '.join(invalid)}. Valid types: {', '.join(sorted(VALID_EVENT_TYPES))}",
        )


def _policy_to_response(policy: AlertPolicy) -> AlertPolicyResponse:
    """Map an ORM AlertPolicy to the response schema."""
    return AlertPolicyResponse(
        id=policy.id,
        tenant_id=policy.tenant_id,
        name=policy.name,
        event_types=policy.event_types or [],
        conditions=policy.conditions,
        channels=policy.channels or [],
        cooldown_minutes=policy.cooldown_minutes or 1440,
        digest_mode=policy.digest_mode or False,
        enabled=policy.enabled if policy.enabled is not None else True,
        created_at=policy.created_at,
        updated_at=policy.updated_at,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=List[AlertPolicyResponse])
def list_alert_policies(
    tenant_id: int,
    enabled_only: bool = Query(False, description="Filter to enabled policies only"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> List[AlertPolicyResponse]:
    """
    List all alert policies for the tenant.

    Returns policies ordered by creation date descending. Optionally
    filter to only enabled policies.

    Args:
        tenant_id: Tenant ID from path.
        enabled_only: When true, only return enabled policies.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        List of AlertPolicyResponse objects.
    """
    _verify_tenant_exists(db, tenant_id)

    query = db.query(AlertPolicy).filter(AlertPolicy.tenant_id == tenant_id)

    if enabled_only:
        query = query.filter(AlertPolicy.enabled.is_(True))

    policies = query.order_by(AlertPolicy.created_at.desc()).all()
    return [_policy_to_response(p) for p in policies]


@router.post("", response_model=AlertPolicyResponse, status_code=status.HTTP_201_CREATED)
def create_alert_policy(
    tenant_id: int,
    body: AlertPolicyCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> AlertPolicyResponse:
    """
    Create a new alert policy.

    Validates event types and channel configurations, then persists the
    policy. The policy is enabled by default.

    Args:
        tenant_id: Tenant ID from path.
        body: Policy creation payload.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        Created AlertPolicyResponse.

    Raises:
        400: Invalid event types.
        403: Insufficient permissions.
    """
    _verify_tenant_exists(db, tenant_id)

    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    _validate_event_types(body.event_types)

    policy = AlertPolicy(
        tenant_id=tenant_id,
        name=body.name,
        event_types=body.event_types,
        conditions=body.conditions,
        channels=[ch.model_dump(exclude_none=True) for ch in body.channels],
        cooldown_minutes=body.cooldown_minutes,
        digest_mode=body.digest_mode,
        enabled=True,
    )
    db.add(policy)
    db.commit()
    db.refresh(policy)

    logger.info("Created alert policy %d for tenant %d: %s", policy.id, tenant_id, policy.name)

    return _policy_to_response(policy)


@router.get("/{policy_id}", response_model=AlertPolicyResponse)
def get_alert_policy(
    tenant_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> AlertPolicyResponse:
    """
    Get a single alert policy by ID.

    Args:
        tenant_id: Tenant ID from path.
        policy_id: Policy ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        AlertPolicyResponse.

    Raises:
        404: Policy not found.
    """
    _verify_tenant_exists(db, tenant_id)
    policy = _get_policy_or_404(db, tenant_id, policy_id)
    return _policy_to_response(policy)


@router.patch("/{policy_id}", response_model=AlertPolicyResponse)
def update_alert_policy(
    tenant_id: int,
    policy_id: int,
    body: AlertPolicyUpdate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> AlertPolicyResponse:
    """
    Partially update an alert policy.

    Only fields present in the request body are updated; omitted fields
    remain unchanged.

    Args:
        tenant_id: Tenant ID from path.
        policy_id: Policy ID from path.
        body: Partial update payload.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        Updated AlertPolicyResponse.

    Raises:
        400: Invalid event types.
        403: Insufficient permissions.
        404: Policy not found.
    """
    _verify_tenant_exists(db, tenant_id)

    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    policy = _get_policy_or_404(db, tenant_id, policy_id)

    if body.name is not None:
        policy.name = body.name

    if body.event_types is not None:
        _validate_event_types(body.event_types)
        policy.event_types = body.event_types

    if body.conditions is not None:
        policy.conditions = body.conditions

    if body.channels is not None:
        policy.channels = [ch.model_dump(exclude_none=True) for ch in body.channels]

    if body.cooldown_minutes is not None:
        policy.cooldown_minutes = body.cooldown_minutes

    if body.digest_mode is not None:
        policy.digest_mode = body.digest_mode

    if body.enabled is not None:
        policy.enabled = body.enabled

    db.commit()
    db.refresh(policy)

    logger.info("Updated alert policy %d for tenant %d", policy_id, tenant_id)

    return _policy_to_response(policy)


@router.delete("/{policy_id}", response_model=AlertPolicyResponse)
def delete_alert_policy(
    tenant_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> AlertPolicyResponse:
    """
    Soft-delete an alert policy by disabling it.

    The policy record is preserved for audit purposes but will no longer
    trigger alerts. This is a non-destructive operation.

    Args:
        tenant_id: Tenant ID from path.
        policy_id: Policy ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        Disabled AlertPolicyResponse.

    Raises:
        403: Insufficient permissions.
        404: Policy not found.
    """
    _verify_tenant_exists(db, tenant_id)

    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    policy = _get_policy_or_404(db, tenant_id, policy_id)
    policy.enabled = False
    db.commit()
    db.refresh(policy)

    logger.info("Soft-deleted (disabled) alert policy %d for tenant %d", policy_id, tenant_id)

    return _policy_to_response(policy)


@router.post("/{policy_id}/test", response_model=TestNotificationResponse)
def test_alert_policy(
    tenant_id: int,
    policy_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> TestNotificationResponse:
    """
    Send a test notification through all channels configured on the policy.

    Dispatches a synthetic test alert to verify that channel
    configurations (webhooks, email addresses) are working correctly.
    Does not create a real Alert record.

    Args:
        tenant_id: Tenant ID from path.
        policy_id: Policy ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        TestNotificationResponse with dispatch results.

    Raises:
        403: Insufficient permissions.
        404: Policy not found.
    """
    _verify_tenant_exists(db, tenant_id)

    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    policy = _get_policy_or_404(db, tenant_id, policy_id)

    channels = policy.channels or []
    if not channels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Policy has no channels configured",
        )

    # Build a synthetic Alert object for the test
    from app.models.risk import Alert, AlertStatus

    test_alert = Alert(
        tenant_id=tenant_id,
        policy_id=policy.id,
        event_type="test",
        severity="info",
        title=f'[TEST] NimbusGuard alert test — policy "{policy.name}"',
        body="This is a test notification from NimbusGuard EASM.\nIf you received this, the channel is configured correctly.",
        status=AlertStatus.PENDING,
    )

    # Send through each channel, track results
    from app.tasks.alert_evaluation import _send_via_channel
    from app.utils.logger import TenantLoggerAdapter

    tenant_logger = TenantLoggerAdapter(logger, {"tenant_id": tenant_id})
    channels_ok: list[str] = []
    channels_failed: list[str] = []

    for ch in channels:
        ch_type = ch.get("type", "unknown")
        try:
            _send_via_channel(ch, test_alert, tenant_logger)
            channels_ok.append(ch_type)
        except Exception as exc:
            logger.warning("Test notification failed for channel %s: %s", ch_type, exc)
            channels_failed.append(ch_type)

    success = len(channels_ok) > 0
    parts = []
    if channels_ok:
        parts.append(f"Sent to {', '.join(channels_ok)}")
    if channels_failed:
        parts.append(f"Failed: {', '.join(channels_failed)}")
    message = ". ".join(parts) if parts else "No channels contacted"

    logger.info(
        "Test notification for policy %d (tenant %d): ok=%s failed=%s",
        policy_id,
        tenant_id,
        channels_ok,
        channels_failed,
    )

    return TestNotificationResponse(
        success=success,
        channels_tested=channels_ok + channels_failed,
        message=message,
    )


@router.post("/seed-defaults", response_model=SeedDefaultsResponse, status_code=status.HTTP_201_CREATED)
def seed_default_policies(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> SeedDefaultsResponse:
    """
    Create a set of recommended default alert policies for the tenant.

    The following policies are created if they do not already exist
    (matched by name):

    1. Critical Finding Alert - Immediate notification on critical findings.
    2. High Finding Alert - Notification on high-severity findings.
    3. New Asset Discovered - Alert when new assets appear on the surface.
    4. Certificate Expiring - Alert on certificates expiring within 30 days.
    5. Risk Score Degradation - Alert when the organization risk score increases.

    All default policies are created with a placeholder webhook channel.
    Users should update the channel configuration after seeding.

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        SeedDefaultsResponse with counts and created policies.

    Raises:
        403: Insufficient permissions.
    """
    _verify_tenant_exists(db, tenant_id)

    if not membership.has_permission("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin permission required to seed default policies",
        )

    placeholder_channel = [{"type": "webhook", "webhook_url": "https://example.com/webhook"}]

    default_policies = [
        {
            "name": "Critical Finding Alert",
            "event_types": ["finding_new"],
            "conditions": {"severity": "critical"},
            "channels": placeholder_channel,
            "cooldown_minutes": 0,
            "digest_mode": False,
        },
        {
            "name": "High Finding Alert",
            "event_types": ["finding_new"],
            "conditions": {"severity": "high"},
            "channels": placeholder_channel,
            "cooldown_minutes": 60,
            "digest_mode": False,
        },
        {
            "name": "New Asset Discovered",
            "event_types": ["asset_new"],
            "conditions": None,
            "channels": placeholder_channel,
            "cooldown_minutes": 1440,
            "digest_mode": True,
        },
        {
            "name": "Certificate Expiring",
            "event_types": ["cert_expiring"],
            "conditions": {"days_until_expiry_lte": 30},
            "channels": placeholder_channel,
            "cooldown_minutes": 1440,
            "digest_mode": True,
        },
        {
            "name": "Risk Score Degradation",
            "event_types": ["score_changed"],
            "conditions": {"delta_gte": 5.0},
            "channels": placeholder_channel,
            "cooldown_minutes": 1440,
            "digest_mode": False,
        },
    ]

    # Fetch existing policy names for dedup
    existing_names: set[str] = {
        row[0] for row in db.query(AlertPolicy.name).filter(AlertPolicy.tenant_id == tenant_id).all()
    }

    created_policies: list[AlertPolicyResponse] = []
    skipped = 0

    for definition in default_policies:
        if definition["name"] in existing_names:
            skipped += 1
            continue

        policy = AlertPolicy(
            tenant_id=tenant_id,
            name=definition["name"],
            event_types=definition["event_types"],
            conditions=definition["conditions"],
            channels=definition["channels"],
            cooldown_minutes=definition["cooldown_minutes"],
            digest_mode=definition["digest_mode"],
            enabled=True,
        )
        db.add(policy)
        db.flush()  # Populate id before mapping to response
        created_policies.append(_policy_to_response(policy))

    db.commit()

    logger.info(
        "Seeded %d default alert policies for tenant %d (%d skipped)",
        len(created_policies),
        tenant_id,
        skipped,
    )

    return SeedDefaultsResponse(
        created=len(created_policies),
        skipped=skipped,
        policies=created_policies,
    )
