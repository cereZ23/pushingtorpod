"""
Compliance API Router

Provides endpoints for:
    - ISO 27001:2022 Annex A control coverage
    - Per-finding compliance mapping
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, verify_tenant_access
from app.models.database import Asset, Finding, FindingStatus
from app.services.iso27001_mapping import (
    ISO_CONTROLS,
    compute_compliance_coverage,
    map_finding_to_controls,
)

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/compliance",
    tags=["Compliance"],
)


@router.get("/iso27001")
def get_iso27001_coverage(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Get ISO 27001:2022 compliance coverage for the tenant.

    Returns per-control metrics showing how many findings map to each
    Annex A control. A clean control = no findings found. A control with
    findings indicates an area needing remediation for audit compliance.
    """
    findings = (
        db.query(Finding).join(Asset).filter(Asset.tenant_id == tenant_id, Finding.status == FindingStatus.OPEN).all()
    )

    coverage = compute_compliance_coverage(findings)
    total_controls = len(ISO_CONTROLS)
    clean_controls = sum(1 for c in coverage.values() if c["status"] == "clean")
    affected_controls = total_controls - clean_controls

    return {
        "standard": "ISO/IEC 27001:2022",
        "scope": "Annex A — Technological Controls (EASM-relevant)",
        "summary": {
            "total_controls": total_controls,
            "clean": clean_controls,
            "affected": affected_controls,
            "coverage_pct": round((clean_controls / total_controls) * 100, 1) if total_controls else 0,
            "total_findings": len(findings),
        },
        "controls": list(coverage.values()),
    }


@router.get("/iso27001/controls/{control_id}/findings")
def get_findings_for_control(
    tenant_id: int,
    control_id: str,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
):
    """Get findings that map to a specific ISO 27001 control."""
    if control_id not in ISO_CONTROLS:
        return {"error": "Unknown control ID", "valid_controls": list(ISO_CONTROLS.keys())}

    findings = (
        db.query(Finding).join(Asset).filter(Asset.tenant_id == tenant_id, Finding.status == FindingStatus.OPEN).all()
    )

    matching = []
    for f in findings:
        controls = map_finding_to_controls(template_id=f.template_id, name=f.name, source=f.source)
        if control_id in controls:
            matching.append(
                {
                    "id": f.id,
                    "name": f.name,
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "template_id": f.template_id,
                    "source": f.source,
                    "asset_id": f.asset_id,
                }
            )

    return {
        "control_id": control_id,
        "control_info": ISO_CONTROLS[control_id],
        "findings_count": len(matching),
        "findings": matching,
    }
