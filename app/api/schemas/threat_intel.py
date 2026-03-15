"""
Threat Intelligence Pydantic Schemas

Request and response models for the EPSS/KEV threat intelligence API endpoints.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


class ThreatIntelStatusResponse(BaseModel):
    """Response for GET /admin/threat-intel/status"""

    kev_last_refresh: Optional[str] = Field(None, description="ISO timestamp of last KEV catalog refresh")
    kev_count: int = Field(0, description="Number of CVEs in KEV catalog")
    kev_catalog_cached: bool = Field(False, description="Whether KEV catalog is currently in Redis cache")
    epss_cache_available: bool = Field(False, description="Whether EPSS cache is reachable")
    error: Optional[str] = Field(None, description="Error message if any")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "kev_last_refresh": "2026-02-25T02:00:00+00:00",
                "kev_count": 1203,
                "kev_catalog_cached": True,
                "epss_cache_available": True,
                "error": None,
            }
        }
    )


class ThreatIntelRefreshResponse(BaseModel):
    """Response for POST /admin/threat-intel/refresh"""

    task_id: str = Field(..., description="Celery task ID for tracking")
    status: str = Field(..., description="Task queue status")
    message: str = Field(..., description="Human-readable status message")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "status": "queued",
                "message": "Threat intelligence refresh queued",
            }
        }
    )


class KEVDetailResponse(BaseModel):
    """CISA KEV catalog entry details"""

    cve_id: str = Field(..., description="CVE identifier")
    vendor: str = Field("", description="Vendor/project name")
    product: str = Field("", description="Product name")
    vulnerability_name: str = Field("", description="Vulnerability name")
    date_added: str = Field("", description="Date added to KEV catalog")
    short_description: str = Field("", description="Brief description")
    required_action: str = Field("", description="Required remediation action")
    due_date: str = Field("", description="Compliance due date")
    known_ransomware_use: str = Field("Unknown", description="Whether known ransomware campaigns use this CVE")
    notes: str = Field("", description="Additional notes")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cve_id": "CVE-2024-1234",
                "vendor": "Apache",
                "product": "Log4j",
                "vulnerability_name": "Apache Log4j Remote Code Execution",
                "date_added": "2024-01-15",
                "short_description": "Apache Log4j contains a deserialization vulnerability...",
                "required_action": "Apply updates per vendor instructions.",
                "due_date": "2024-02-15",
                "known_ransomware_use": "Known",
                "notes": "",
            }
        }
    )


class FindingThreatIntelResponse(BaseModel):
    """Threat intelligence data for a specific finding"""

    finding_id: int = Field(..., description="Finding ID")
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    epss_score: float = Field(
        0.0,
        description="EPSS probability score (0.0-1.0)",
        ge=0.0,
        le=1.0,
    )
    epss_severity: str = Field(
        "low",
        description="EPSS severity category (low/medium/high/critical)",
    )
    is_kev: bool = Field(False, description="Whether CVE is in CISA KEV catalog")
    kev_details: Optional[KEVDetailResponse] = Field(None, description="KEV catalog details if applicable")
    risk_boost_description: str = Field(
        "",
        description="Human-readable description of threat intel impact on risk score",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "finding_id": 42,
                "cve_id": "CVE-2024-1234",
                "epss_score": 0.973,
                "epss_severity": "critical",
                "is_kev": True,
                "kev_details": {
                    "cve_id": "CVE-2024-1234",
                    "vendor": "Apache",
                    "product": "Log4j",
                    "vulnerability_name": "Apache Log4j RCE",
                    "date_added": "2024-01-15",
                    "short_description": "Remote code execution via JNDI injection",
                    "required_action": "Apply updates per vendor instructions.",
                    "due_date": "2024-02-15",
                    "known_ransomware_use": "Known",
                    "notes": "",
                },
                "risk_boost_description": (
                    "CRITICAL: This CVE is actively exploited (CISA KEV) with "
                    "97.3% exploitation probability (EPSS). Immediate remediation required."
                ),
            }
        }
    )


class TenantEnrichmentResponse(BaseModel):
    """Response for tenant-level threat intel enrichment"""

    task_id: str = Field(..., description="Celery task ID for tracking")
    status: str = Field(..., description="Task queue status")
    message: str = Field(..., description="Human-readable status message")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "task_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                "status": "queued",
                "message": "Threat intel enrichment queued for tenant 1",
            }
        }
    )


def classify_epss_severity(epss_score: float) -> str:
    """Classify EPSS score into a severity category.

    Thresholds based on FIRST.org guidance and industry practice:
        >= 0.7 : critical (top ~5% of CVEs)
        >= 0.4 : high
        >= 0.1 : medium
        <  0.1 : low

    Args:
        epss_score: EPSS probability score (0.0-1.0).

    Returns:
        Severity string: "critical", "high", "medium", or "low".
    """
    if epss_score >= 0.7:
        return "critical"
    if epss_score >= 0.4:
        return "high"
    if epss_score >= 0.1:
        return "medium"
    return "low"


def build_risk_boost_description(epss_score: float, is_kev: bool) -> str:
    """Build a human-readable description of threat intel risk impact.

    Args:
        epss_score: EPSS probability score.
        is_kev: Whether the CVE is in CISA KEV.

    Returns:
        Descriptive string for the UI/API consumer.
    """
    parts = []

    if is_kev:
        parts.append("This CVE is in the CISA Known Exploited Vulnerabilities catalog (confirmed active exploitation).")

    if epss_score >= 0.7:
        parts.append(
            f"EPSS score: {epss_score:.1%} - very high exploitation probability "
            "(top 5%). Immediate remediation recommended."
        )
    elif epss_score >= 0.4:
        parts.append(f"EPSS score: {epss_score:.1%} - high exploitation probability. Prioritize remediation.")
    elif epss_score >= 0.1:
        parts.append(f"EPSS score: {epss_score:.1%} - moderate exploitation probability.")
    elif epss_score > 0:
        parts.append(f"EPSS score: {epss_score:.1%} - low exploitation probability.")

    if is_kev and epss_score >= 0.5:
        parts.append("CRITICAL: Immediate remediation required.")

    return " ".join(parts) if parts else "No threat intelligence data available."
