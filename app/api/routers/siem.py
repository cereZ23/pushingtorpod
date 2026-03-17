"""
SIEM Integration Router

Endpoints for exporting findings to external SIEM systems
(Splunk HEC, Azure Sentinel / generic CEF).

Prefix: /api/v1/tenants/{tenant_id}/siem
"""

from __future__ import annotations

import json
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, verify_tenant_access, require_tenant_permission
from app.api.schemas.siem import (
    SIEMExportRequest,
    SIEMExportResponse,
    SIEMPushRequest,
    SIEMPushResponse,
)
from app.core.audit import log_audit_event, AuditEventType
from app.services.siem_export import export_findings_for_tenant
from app.utils.validators import validate_endpoint_url_ssrf

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/siem",
    tags=["SIEM Integration"],
)


def _validate_siem_endpoint_url(url: str) -> None:
    """Validate SIEM endpoint URL to prevent SSRF attacks.

    Delegates to the shared ``validate_endpoint_url_ssrf`` utility and
    converts any ``ValueError`` into an HTTP 422 response.

    Raises:
        HTTPException 422 if URL is invalid or targets internal resources.
    """
    try:
        validate_endpoint_url_ssrf(url, require_https=True)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc


# ------------------------------------------------------------------
# POST /export — export findings in SIEM format (read permission)
# ------------------------------------------------------------------


@router.post("/export", response_model=SIEMExportResponse)
def export_findings(
    tenant_id: int,
    body: SIEMExportRequest,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> SIEMExportResponse:
    """
    Export tenant findings formatted for SIEM ingestion.

    Supported formats:
    - **splunk_hec** -- Splunk HTTP Event Collector JSON
    - **cef** -- Common Event Format (Azure Sentinel, ArcSight, QRadar)

    Optional filters:
    - ``since``: only findings with ``first_seen >= since``
    - ``severity_min``: minimum severity threshold (info, low, medium, high, critical)
    """
    events = export_findings_for_tenant(
        db=db,
        tenant_id=tenant_id,
        fmt=body.format,
        since=body.since,
        severity_min=body.severity_min,
    )

    logger.info(
        "SIEM export completed: tenant_id=%s format=%s events=%d",
        tenant_id,
        body.format,
        len(events),
    )

    return SIEMExportResponse(
        format=body.format,
        event_count=len(events),
        events=events if body.format == "splunk_hec" else [{"cef_line": e} for e in events],
    )


# ------------------------------------------------------------------
# POST /push — push findings to a remote SIEM endpoint (admin only)
# ------------------------------------------------------------------


@router.post("/push", response_model=SIEMPushResponse)
def push_findings(
    tenant_id: int,
    body: SIEMPushRequest,
    db: Session = Depends(get_db),
    membership=Depends(require_tenant_permission("admin")),
) -> SIEMPushResponse:
    """
    Push tenant findings directly to an external SIEM endpoint.

    **Requires admin permission on the tenant.**

    Supported targets:
    - **Splunk HEC** -- POSTs individual JSON events to the collector URL.
    - **CEF / Azure Sentinel** -- POSTs newline-delimited CEF lines.

    The ``auth_token`` is sent as an ``Authorization`` header
    (``Splunk <token>`` for HEC, ``Bearer <token>`` for CEF endpoints).
    """
    # SSRF protection: validate endpoint URL before making any outbound request
    _validate_siem_endpoint_url(body.endpoint_url)

    events = export_findings_for_tenant(
        db=db,
        tenant_id=tenant_id,
        fmt=body.format,
        since=body.since,
        severity_min=body.severity_min,
    )

    if not events:
        return SIEMPushResponse(
            format=body.format,
            event_count=0,
            success=True,
            detail="No findings matched the export criteria",
        )

    try:
        if body.format == "splunk_hec":
            _push_splunk_hec(events, body.endpoint_url, body.auth_token)
        else:
            _push_cef(events, body.endpoint_url, body.auth_token)
    except httpx.HTTPStatusError as exc:
        logger.error(
            "SIEM push failed: tenant_id=%s endpoint=%s status=%s body=%s",
            tenant_id,
            body.endpoint_url,
            exc.response.status_code,
            exc.response.text[:500],
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"SIEM endpoint returned HTTP {exc.response.status_code}",
        ) from exc
    except httpx.RequestError as exc:
        logger.error(
            "SIEM push connection error: tenant_id=%s endpoint=%s error=%s",
            tenant_id,
            body.endpoint_url,
            exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to connect to SIEM endpoint: {exc}",
        ) from exc

    log_audit_event(
        event_type=AuditEventType.DATA_EXPORT,
        action=f"SIEM push ({body.format})",
        result="success",
        user_id=membership.user_id,
        tenant_id=tenant_id,
        resource="findings",
        details={"format": body.format, "event_count": len(events), "endpoint": body.endpoint_url},
    )

    return SIEMPushResponse(
        format=body.format,
        event_count=len(events),
        success=True,
        detail=None,
    )


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

_PUSH_TIMEOUT = 30.0  # seconds


def _push_splunk_hec(events: list[dict], endpoint_url: str, token: str) -> None:
    """
    POST events to Splunk HEC.

    Splunk HEC accepts multiple events in a single request when they are
    concatenated without a separator (NDJSON-style, no array wrapper).
    The auth header format is ``Splunk <token>``.
    """
    payload = "\n".join(json.dumps(evt) for evt in events)

    with httpx.Client(timeout=_PUSH_TIMEOUT, verify=True) as client:
        # endpoint_url is admin-configured and validated via validate_endpoint_url_ssrf()
        # before reaching this helper. See _validate_siem_endpoint() and push_to_siem().
        response = client.post(  # nosec: SSRF validated upstream
            endpoint_url,
            content=payload,
            headers={
                "Authorization": f"Splunk {token}",
                "Content-Type": "application/json",
            },
        )
        response.raise_for_status()


def _push_cef(events: list[str], endpoint_url: str, token: str) -> None:
    """
    POST CEF lines to a generic SIEM / Azure Sentinel HTTP Data Collector.

    Lines are newline-delimited.  Auth header uses ``Bearer <token>``.
    """
    payload = "\n".join(events)

    with httpx.Client(timeout=_PUSH_TIMEOUT, verify=True) as client:
        # endpoint_url is admin-configured and validated via validate_endpoint_url_ssrf()
        # before reaching this helper. See _validate_siem_endpoint() and push_to_siem().
        response = client.post(  # nosec: SSRF validated upstream
            endpoint_url,
            content=payload,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "text/plain",
            },
        )
        response.raise_for_status()
