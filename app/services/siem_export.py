"""
SIEM Export Service

Formats EASM findings into SIEM-compatible event structures:
  - Splunk HTTP Event Collector (HEC) JSON
  - Common Event Format (CEF) for Azure Sentinel / generic SIEM

All formatting is deterministic and side-effect-free; the caller is
responsible for transport (HTTP push, file write, etc.).
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.models.database import Asset, Finding, FindingSeverity

logger = logging.getLogger(__name__)

# Severity label -> integer mapping used by CEF
_CEF_SEVERITY: dict[str, int] = {
    "critical": 10,
    "high": 8,
    "medium": 5,
    "low": 3,
    "info": 1,
}

# Ordered severity levels for >= filtering
_SEVERITY_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _to_epoch(dt: Optional[datetime]) -> float:
    """Convert a datetime to a UNIX epoch timestamp (seconds)."""
    if dt is None:
        return 0.0
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _to_epoch_ms(dt: Optional[datetime]) -> int:
    """Convert a datetime to epoch milliseconds (used by CEF *start*/*end*)."""
    return int(_to_epoch(dt) * 1000)


def _severity_value(severity: object) -> str:
    """Safely extract the string value from an enum or plain string."""
    if hasattr(severity, "value"):
        return severity.value
    return str(severity)


def _status_value(status_field: object) -> str:
    if hasattr(status_field, "value"):
        return status_field.value
    return str(status_field)


def _asset_type_value(asset_type: object) -> str:
    if hasattr(asset_type, "value"):
        return asset_type.value
    return str(asset_type)


# ------------------------------------------------------------------
# Splunk HEC formatting
# ------------------------------------------------------------------

def format_finding_splunk_hec(finding: Finding, asset: Asset) -> dict:
    """
    Format a single finding as a Splunk HEC JSON event.

    Returns a dict ready for ``json.dumps`` or direct POST to
    ``/services/collector``.
    """
    severity_str = _severity_value(finding.severity)

    evidence_payload: Optional[str] = None
    if finding.evidence is not None:
        try:
            evidence_payload = json.dumps(finding.evidence)
        except (TypeError, ValueError):
            evidence_payload = str(finding.evidence)

    return {
        "time": _to_epoch(finding.first_seen),
        "source": "easm-platform",
        "sourcetype": "easm:finding",
        "host": asset.identifier,
        "event": {
            "finding_id": finding.id,
            "name": finding.name,
            "severity": severity_str,
            "cvss_score": finding.cvss_score,
            "template_id": finding.template_id,
            "asset_identifier": asset.identifier,
            "asset_type": _asset_type_value(asset.type),
            "status": _status_value(finding.status),
            "first_seen": finding.first_seen.isoformat() if finding.first_seen else None,
            "last_seen": finding.last_seen.isoformat() if finding.last_seen else None,
            "evidence": evidence_payload,
        },
    }


# ------------------------------------------------------------------
# CEF formatting
# ------------------------------------------------------------------

def _cef_escape(value: str) -> str:
    r"""Escape characters that have special meaning inside CEF fields (\ and |)."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def format_finding_cef(finding: Finding, asset: Asset) -> str:
    """
    Format a single finding as a CEF (Common Event Format) string.

    The CEF line follows the standard header structure:
        CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension

    Extension keys used:
        src        - asset identifier (host / IP)
        cs1/Label  - finding ID
        cs2/Label  - finding status
        start      - first_seen epoch ms
        end        - last_seen epoch ms
    """
    severity_str = _severity_value(finding.severity)
    severity_int = _CEF_SEVERITY.get(severity_str, 1)

    template_id = _cef_escape(finding.template_id or "unknown")
    name = _cef_escape(finding.name or "Unknown Finding")

    extension_parts = [
        f"src={asset.identifier}",
        f"cs1={finding.id}",
        "cs1Label=FindingID",
        f"cs2={_status_value(finding.status)}",
        "cs2Label=Status",
        f"start={_to_epoch_ms(finding.first_seen)}",
        f"end={_to_epoch_ms(finding.last_seen)}",
    ]
    extension = " ".join(extension_parts)

    return (
        f"CEF:0|EASM|Platform|1.0|{template_id}|{name}|{severity_int}|{extension}"
    )


# ------------------------------------------------------------------
# Main export function
# ------------------------------------------------------------------

def export_findings_for_tenant(
    db: Session,
    tenant_id: int,
    fmt: str,
    since: Optional[datetime] = None,
    severity_min: Optional[str] = None,
) -> list:
    """
    Query findings for a tenant and format them for SIEM ingestion.

    Args:
        db: Active SQLAlchemy session.
        tenant_id: Tenant scope.
        fmt: ``"splunk_hec"`` or ``"cef"``.
        since: Only include findings with ``first_seen >= since``.
        severity_min: Minimum severity threshold (inclusive).

    Returns:
        A list of formatted events (dicts for Splunk HEC, strings for CEF).
    """
    filters = [Asset.tenant_id == tenant_id]

    if since is not None:
        filters.append(Finding.first_seen >= since)

    if severity_min is not None:
        min_level = _SEVERITY_ORDER.get(severity_min, 0)
        valid_severities = [
            FindingSeverity(sev)
            for sev, level in _SEVERITY_ORDER.items()
            if level >= min_level
        ]
        filters.append(Finding.severity.in_(valid_severities))

    findings_with_assets = (
        db.query(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .filter(and_(*filters))
        .order_by(Finding.first_seen.asc())
        .all()
    )

    logger.info(
        "SIEM export: tenant_id=%s format=%s findings=%d since=%s severity_min=%s",
        tenant_id,
        fmt,
        len(findings_with_assets),
        since,
        severity_min,
    )

    formatter = format_finding_splunk_hec if fmt == "splunk_hec" else format_finding_cef
    return [formatter(finding, asset) for finding, asset in findings_with_assets]
