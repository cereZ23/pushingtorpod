"""
Global Search Router

Provides a unified search endpoint that searches across assets, findings, and issues
within a tenant.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.api.dependencies import get_db, get_current_user, verify_tenant_access, escape_like
from app.models.database import Asset, Finding
from app.models.issues import Issue

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/search",
    tags=["Search"],
)


class SearchResultItem(BaseModel):
    type: str = Field(..., description="Result type: asset, finding, or issue")
    id: int
    title: str
    subtitle: Optional[str] = None
    severity: Optional[str] = None
    status: Optional[str] = None
    url: str = Field(..., description="Frontend route to this item")


class SearchResponse(BaseModel):
    query: str
    total: int
    results: List[SearchResultItem]


@router.get("", response_model=SearchResponse)
def global_search(
    tenant_id: int,
    q: str = Query(..., min_length=2, max_length=200, description="Search query"),
    limit: int = Query(20, ge=1, le=50),
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Search across assets, findings, and issues within a tenant.

    Returns up to `limit` results matching the query string.
    """
    verify_tenant_access(db, current_user, tenant_id)

    results: List[SearchResultItem] = []
    search_term = f"%{escape_like(q)}%"

    # Search assets (identifier, type)
    assets = (
        db.query(Asset)
        .filter(
            Asset.tenant_id == tenant_id,
            Asset.is_active.is_(True),
            Asset.identifier.ilike(search_term, escape="\\"),
        )
        .order_by(Asset.risk_score.desc())
        .limit(limit)
        .all()
    )
    for a in assets:
        results.append(
            SearchResultItem(
                type="asset",
                id=a.id,
                title=a.identifier,
                subtitle=a.type.value if a.type else None,
                status=a.enrichment_status,
                url=f"/assets/{a.id}",
            )
        )

    # Search findings (name, template_id, cve_id)
    remaining = limit - len(results)
    if remaining > 0:
        findings = (
            db.query(Finding)
            .join(Asset, Finding.asset_id == Asset.id)
            .filter(
                Asset.tenant_id == tenant_id,
                or_(
                    Finding.name.ilike(search_term, escape="\\"),
                    Finding.template_id.ilike(search_term, escape="\\"),
                    Finding.cve_id.ilike(search_term, escape="\\"),
                ),
            )
            .order_by(Finding.severity.desc(), Finding.last_seen.desc())
            .limit(remaining)
            .all()
        )
        for f in findings:
            results.append(
                SearchResultItem(
                    type="finding",
                    id=f.id,
                    title=f.name,
                    subtitle=f.template_id,
                    severity=f.severity.value if f.severity else None,
                    status=f.status.value if f.status else None,
                    url=f"/findings/{f.id}",
                )
            )

    # Search issues (title, root_cause, description)
    remaining = limit - len(results)
    if remaining > 0:
        issues = (
            db.query(Issue)
            .filter(
                Issue.tenant_id == tenant_id,
                or_(
                    Issue.title.ilike(search_term, escape="\\"),
                    Issue.root_cause.ilike(search_term, escape="\\"),
                    Issue.description.ilike(search_term, escape="\\"),
                ),
            )
            .order_by(Issue.updated_at.desc())
            .limit(remaining)
            .all()
        )
        for i in issues:
            results.append(
                SearchResultItem(
                    type="issue",
                    id=i.id,
                    title=i.title,
                    subtitle=i.root_cause,
                    severity=i.severity,
                    status=i.status.value if i.status else None,
                    url=f"/issues/{i.id}",
                )
            )

    return SearchResponse(
        query=q,
        total=len(results),
        results=results,
    )
