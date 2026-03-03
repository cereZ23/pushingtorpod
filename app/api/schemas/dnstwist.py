from __future__ import annotations

"""
DNSTwist Schemas

Pydantic models for domain permutation / typosquatting detection endpoints.
"""

from typing import Optional, List
from pydantic import BaseModel, Field, ConfigDict


class DnstwistScanRequest(BaseModel):
    """Request body for triggering a DNSTwist scan."""

    domain_list: Optional[List[str]] = Field(
        None,
        description=(
            "Explicit list of root domains to scan. "
            "When omitted, all active DOMAIN assets for the tenant are used."
        ),
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "domain_list": ["example.com", "acme-corp.com"],
            }
        }
    )


class DnstwistFindingResponse(BaseModel):
    """Single typosquatting finding returned by the listing endpoint."""

    id: int = Field(..., description="Finding ID")
    asset_id: int = Field(..., description="Root asset ID")
    template_id: Optional[str] = Field(None, description="DNSTwist fuzzer template ID")
    name: str = Field(..., description="Human-readable finding name")
    severity: str = Field(..., description="Severity level (medium, high)")
    evidence: Optional[dict] = Field(None, description="Detailed evidence payload")
    first_seen: str = Field(..., description="ISO 8601 timestamp when first detected")
    last_seen: str = Field(..., description="ISO 8601 timestamp when last confirmed")
    status: str = Field(..., description="Finding status (open, suppressed, fixed)")

    # Joined from Asset
    asset_identifier: Optional[str] = Field(None, description="Root domain identifier")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 42,
                "asset_id": 7,
                "template_id": "dnstwist-homoglyph",
                "name": "Typosquat domain registered: examp1e.com",
                "severity": "high",
                "evidence": {
                    "original_domain": "example.com",
                    "permutation": "examp1e.com",
                    "fuzzer": "homoglyph",
                    "dns_a": ["93.184.216.34"],
                    "dns_aaaa": [],
                    "dns_mx": ["mail.examp1e.com"],
                    "dns_ns": [],
                },
                "first_seen": "2026-02-24T10:00:00",
                "last_seen": "2026-02-25T08:30:00",
                "status": "open",
                "asset_identifier": "example.com",
            }
        },
    )
