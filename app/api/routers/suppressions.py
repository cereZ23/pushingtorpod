"""
Suppression Rules API router.

Provides endpoints for managing false positive suppression rules
that filter out known-benign findings from vulnerability scans.
Supports per-tenant and global rules with regex pattern matching,
priority ordering, and optional expiration.
"""

import re
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_
from pydantic import BaseModel, Field, ConfigDict, field_validator
from typing import Optional
from datetime import datetime
import logging

from app.api.dependencies import (
    get_db,
    verify_tenant_access,
    PaginationParams,
)
from app.api.schemas.common import PaginatedResponse, SuccessResponse
from app.models.database import Suppression, Finding, Asset

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/suppressions",
    tags=["Suppressions"],
)

# Valid pattern types for suppression rules
VALID_PATTERN_TYPES = {"template_id", "url", "host", "severity", "name", "regex"}


# ---------------------------------------------------------------------------
# Pydantic schemas (inline for this router)
# ---------------------------------------------------------------------------

class SuppressionCreate(BaseModel):
    """Schema for creating a new suppression rule."""

    name: str = Field(..., max_length=255, description="Human-readable rule name")
    pattern_type: str = Field(
        ...,
        description="Type of pattern to match against: template_id, url, host, severity, name, regex",
    )
    pattern: str = Field(
        ..., max_length=1000, description="Regex pattern to match"
    )
    reason: str | None = Field(None, description="Reason for suppression")
    priority: int = Field(0, ge=0, description="Higher priority rules are matched first")
    expires_at: datetime | None = Field(None, description="Optional expiration datetime")

    @field_validator("pattern_type")
    @classmethod
    def validate_pattern_type(cls, v: str) -> str:
        if v not in VALID_PATTERN_TYPES:
            raise ValueError(
                f"Invalid pattern_type '{v}'. "
                f"Must be one of: {', '.join(sorted(VALID_PATTERN_TYPES))}"
            )
        return v

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc
        return v


class SuppressionUpdate(BaseModel):
    """Schema for updating a suppression rule (partial)."""

    is_active: bool | None = None
    reason: str | None = None
    pattern: str | None = Field(None, max_length=1000)
    expires_at: datetime | None = None

    @field_validator("pattern")
    @classmethod
    def validate_regex(cls, v: str | None) -> str | None:
        if v is not None:
            try:
                re.compile(v)
            except re.error as exc:
                raise ValueError(f"Invalid regex pattern: {exc}") from exc
        return v


class SuppressionResponse(BaseModel):
    """Schema returned for suppression rule objects."""

    id: int
    tenant_id: int | None
    name: str
    pattern_type: str
    pattern: str
    reason: str | None
    is_active: bool
    is_global: bool
    priority: int
    expires_at: datetime | None
    created_at: datetime | None
    updated_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class SuppressionFromFindingCreate(BaseModel):
    """Schema for auto-creating a suppression from an existing finding."""

    pattern_type: str = Field(
        "template_id",
        description="Which finding attribute to suppress on",
    )
    reason: str | None = Field(None, description="Reason for suppression")
    priority: int = Field(0, ge=0)
    expires_at: datetime | None = None

    @field_validator("pattern_type")
    @classmethod
    def validate_pattern_type(cls, v: str) -> str:
        if v not in VALID_PATTERN_TYPES:
            raise ValueError(
                f"Invalid pattern_type '{v}'. "
                f"Must be one of: {', '.join(sorted(VALID_PATTERN_TYPES))}"
            )
        return v


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _get_suppression_or_404(
    db: Session,
    tenant_id: int,
    suppression_id: int,
) -> Suppression:
    """Fetch a suppression scoped to the given tenant, or raise 404."""
    suppression = db.query(Suppression).filter(
        Suppression.id == suppression_id,
        or_(
            Suppression.tenant_id == tenant_id,
            Suppression.is_global == True,
        ),
    ).first()
    if not suppression:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Suppression rule not found",
        )
    return suppression


def _serialize_suppression(suppression: Suppression) -> dict:
    """Convert a Suppression ORM instance to a response-friendly dict."""
    return {
        "id": suppression.id,
        "tenant_id": suppression.tenant_id,
        "name": suppression.name,
        "pattern_type": suppression.pattern_type,
        "pattern": suppression.pattern,
        "reason": suppression.reason,
        "is_active": suppression.is_active,
        "is_global": suppression.is_global,
        "priority": suppression.priority,
        "expires_at": suppression.expires_at,
        "created_at": suppression.created_at,
        "updated_at": suppression.updated_at,
    }


# ===========================================================================
# ENDPOINTS
# ===========================================================================

@router.get("", response_model=PaginatedResponse[SuppressionResponse])
def list_suppressions(
    tenant_id: int,
    is_active: bool | None = Query(None, description="Filter by active status"),
    pattern_type: str | None = Query(None, description="Filter by pattern type"),
    include_global: bool = Query(True, description="Include global rules"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    List suppression rules for a tenant with optional filtering and pagination.

    Returns tenant-specific rules and optionally global rules. Supports
    filtering by active status and pattern type.

    Args:
        tenant_id: Tenant ID (path)
        is_active: Optional active status filter
        pattern_type: Optional pattern type filter
        include_global: Whether to include global suppression rules
        pagination: Standard pagination parameters

    Returns:
        Paginated list of suppression rules ordered by priority descending
    """
    if include_global:
        query = db.query(Suppression).filter(
            or_(
                Suppression.tenant_id == tenant_id,
                Suppression.is_global == True,
            )
        )
    else:
        query = db.query(Suppression).filter(Suppression.tenant_id == tenant_id)

    if is_active is not None:
        query = query.filter(Suppression.is_active == is_active)

    if pattern_type is not None:
        if pattern_type not in VALID_PATTERN_TYPES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid pattern_type: {pattern_type}",
            )
        query = query.filter(Suppression.pattern_type == pattern_type)

    total = query.count()
    query = query.order_by(Suppression.priority.desc(), Suppression.created_at.desc())
    query = pagination.paginate_query(query)
    suppressions = query.all()

    return PaginatedResponse(
        items=[_serialize_suppression(s) for s in suppressions],
        total=total,
        page=pagination.page,
        page_size=pagination.page_size,
        total_pages=(total + pagination.page_size - 1) // pagination.page_size if total else 0,
    )


@router.post("", response_model=SuppressionResponse, status_code=status.HTTP_201_CREATED)
def create_suppression(
    tenant_id: int,
    payload: SuppressionCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Create a new suppression rule.

    The rule applies regex-based pattern matching against the specified
    finding attribute (template_id, url, host, severity, name, or generic regex).

    Args:
        tenant_id: Tenant ID (path)
        payload: Suppression rule definition

    Returns:
        The created suppression rule

    Raises:
        403: Insufficient permissions
        422: Invalid regex pattern or pattern_type
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    suppression = Suppression(
        tenant_id=tenant_id,
        name=payload.name,
        pattern_type=payload.pattern_type,
        pattern=payload.pattern,
        reason=payload.reason,
        is_active=True,
        is_global=False,
        priority=payload.priority,
        expires_at=payload.expires_at,
    )
    db.add(suppression)
    db.commit()
    db.refresh(suppression)

    logger.info(
        f"Created suppression rule '{suppression.name}' (id={suppression.id}) "
        f"for tenant {tenant_id}"
    )

    return _serialize_suppression(suppression)


@router.get("/{suppression_id}", response_model=SuppressionResponse)
def get_suppression(
    tenant_id: int,
    suppression_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Get a single suppression rule by ID.

    Returns the rule if it belongs to the tenant or is global.

    Args:
        tenant_id: Tenant ID (path)
        suppression_id: Suppression rule ID (path)

    Returns:
        The suppression rule

    Raises:
        404: Suppression rule not found
    """
    suppression = _get_suppression_or_404(db, tenant_id, suppression_id)
    return _serialize_suppression(suppression)


@router.patch("/{suppression_id}", response_model=SuppressionResponse)
def update_suppression(
    tenant_id: int,
    suppression_id: int,
    updates: SuppressionUpdate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Partially update a suppression rule.

    Allows updating is_active, reason, pattern, and expires_at. Global
    rules owned by other tenants cannot be modified.

    Args:
        tenant_id: Tenant ID (path)
        suppression_id: Suppression rule ID (path)
        updates: Fields to update

    Returns:
        The updated suppression rule

    Raises:
        404: Suppression rule not found
        403: Insufficient permissions or attempt to edit a global rule
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    suppression = _get_suppression_or_404(db, tenant_id, suppression_id)

    # Prevent editing global rules that belong to a different tenant
    if suppression.is_global and suppression.tenant_id is not None and suppression.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify a global suppression rule owned by another tenant",
        )

    if updates.is_active is not None:
        suppression.is_active = updates.is_active

    if updates.reason is not None:
        suppression.reason = updates.reason

    if updates.pattern is not None:
        suppression.pattern = updates.pattern

    if updates.expires_at is not None:
        suppression.expires_at = updates.expires_at

    db.commit()
    db.refresh(suppression)

    logger.info(f"Updated suppression rule '{suppression.name}' (id={suppression_id})")

    return _serialize_suppression(suppression)


@router.delete("/{suppression_id}", response_model=SuccessResponse)
def delete_suppression(
    tenant_id: int,
    suppression_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Delete a suppression rule.

    Global rules owned by other tenants cannot be deleted.

    Args:
        tenant_id: Tenant ID (path)
        suppression_id: Suppression rule ID (path)

    Returns:
        Success response

    Raises:
        404: Suppression rule not found
        403: Insufficient permissions
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    suppression = _get_suppression_or_404(db, tenant_id, suppression_id)

    if suppression.is_global and suppression.tenant_id is not None and suppression.tenant_id != tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete a global suppression rule owned by another tenant",
        )

    rule_name = suppression.name
    db.delete(suppression)
    db.commit()

    logger.info(f"Deleted suppression rule '{rule_name}' (id={suppression_id}) for tenant {tenant_id}")

    return SuccessResponse(
        success=True,
        message=f"Suppression rule '{rule_name}' deleted",
    )


@router.post(
    "/from-finding/{finding_id}",
    response_model=SuppressionResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_suppression_from_finding(
    tenant_id: int,
    finding_id: int,
    payload: SuppressionFromFindingCreate,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """
    Auto-create a suppression rule from an existing finding.

    Extracts the relevant attribute (template_id, host, etc.) from the
    specified finding and creates an exact-match suppression rule for it.

    Args:
        tenant_id: Tenant ID (path)
        finding_id: Finding ID to base the rule on (path)
        payload: Configuration for the suppression rule

    Returns:
        The created suppression rule

    Raises:
        404: Finding not found
        403: Insufficient permissions
        400: Finding does not have the requested attribute
    """
    if not membership.has_permission("write"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Write permission required",
        )

    # Fetch the finding with tenant isolation
    finding = db.query(Finding).join(Asset).filter(
        Finding.id == finding_id,
        Asset.tenant_id == tenant_id,
    ).first()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Finding not found",
        )

    # Extract the value to build the pattern from
    attribute_map = {
        "template_id": finding.template_id,
        "url": finding.matched_at,
        "host": finding.host,
        "severity": finding.severity.value if finding.severity else None,
        "name": finding.name,
        "regex": finding.template_id,  # Default to template_id for regex type
    }

    value = attribute_map.get(payload.pattern_type)
    if not value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Finding does not have a value for pattern_type '{payload.pattern_type}'. "
                f"Available: template_id={finding.template_id}, host={finding.host}, "
                f"name={finding.name}"
            ),
        )

    # Build an exact-match regex pattern from the value
    escaped_pattern = re.escape(str(value))
    pattern = f"^{escaped_pattern}$"

    reason = payload.reason or f"Auto-suppressed from finding #{finding_id}: {finding.name}"

    suppression = Suppression(
        tenant_id=tenant_id,
        name=f"Suppress: {finding.name[:200]}",
        pattern_type=payload.pattern_type,
        pattern=pattern,
        reason=reason,
        is_active=True,
        is_global=False,
        priority=payload.priority,
        expires_at=payload.expires_at,
    )
    db.add(suppression)
    db.commit()
    db.refresh(suppression)

    logger.info(
        f"Created suppression from finding #{finding_id} "
        f"(rule id={suppression.id}, type={payload.pattern_type}) "
        f"for tenant {tenant_id}"
    )

    return _serialize_suppression(suppression)
