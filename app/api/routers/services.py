"""
Services Router

Handles service data from enrichment (HTTP, ports, TLS)
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, or_
from typing import Optional, List
import logging

from app.api.dependencies import get_db, verify_tenant_access, PaginationParams, escape_like
from app.api.schemas.service import (
    ServiceResponse,
    ServiceListRequest,
    TechnologyStackResponse,
    PortDistributionResponse
)
from app.api.schemas.envelope import PaginatedEnvelope, PaginationMeta
from app.models.database import Asset, Service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/tenants/{tenant_id}/services", tags=["Services"])


@router.get("", response_model=PaginatedEnvelope[ServiceResponse])
def list_services(
    tenant_id: int,
    asset_id: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    protocol: Optional[str] = Query(None),
    has_tls: Optional[bool] = Query(None),
    product: Optional[str] = Query(None),
    enrichment_source: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("last_seen"),
    sort_order: str = Query("desc"),
    pagination: PaginationParams = Depends(),
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    List services with filtering and pagination

    Returns services discovered through enrichment

    Filters:
    - asset_id: Specific asset
    - port: Port number
    - protocol: tcp/udp
    - has_tls: TLS enabled
    - product: Product name (nginx, Apache, etc)
    - search: Full-text search
    """
    # Build query with tenant isolation
    query = db.query(Service).join(Asset).filter(
        Asset.tenant_id == tenant_id,
        Asset.is_active == True,  # noqa: E712 — exclude services on deactivated assets
    )

    # Apply filters
    if asset_id:
        query = query.filter(Service.asset_id == asset_id)

    if port:
        query = query.filter(Service.port == port)

    if protocol:
        query = query.filter(Service.protocol == protocol)

    if has_tls is not None:
        query = query.filter(Service.has_tls == has_tls)

    if product:
        safe_product = escape_like(product)
        query = query.filter(Service.product.ilike(f"%{safe_product}%", escape="\\"))

    if enrichment_source:
        query = query.filter(Service.enrichment_source == enrichment_source)

    if search:
        safe_search = escape_like(search)
        query = query.filter(
            or_(
                Service.product.ilike(f"%{safe_search}%", escape="\\"),
                Service.web_server.ilike(f"%{safe_search}%", escape="\\"),
                Service.http_title.ilike(f"%{safe_search}%", escape="\\"),
            )
        )

    # Get total count
    total = query.count()

    # Apply sorting
    ALLOWED_SORT_COLUMNS = {
        "port": Service.port,
        "protocol": Service.protocol,
        "product": Service.product,
        "last_seen": Service.last_seen,
        "has_tls": Service.has_tls,
    }
    sort_column = ALLOWED_SORT_COLUMNS.get(sort_by, Service.last_seen)
    if sort_order.lower() == "desc":
        query = query.order_by(sort_column.desc())
    else:
        query = query.order_by(sort_column.asc())

    # Apply pagination
    query = pagination.paginate_query(query)

    services = query.all()

    # Build responses with asset info
    items = []
    for s in services:
        resp = ServiceResponse.model_validate(s)
        if s.asset:
            resp.asset_identifier = s.asset.identifier
            resp.asset_type = s.asset.type.value if hasattr(s.asset.type, 'value') else str(s.asset.type)
        items.append(resp)

    return PaginatedEnvelope(
        data=items,
        meta=PaginationMeta(
            total=total,
            page=pagination.page,
            page_size=pagination.page_size,
            total_pages=(total + pagination.page_size - 1) // pagination.page_size,
        ),
    )


@router.get("/tech-stack", response_model=List[TechnologyStackResponse])
def get_technology_stack(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Get technology stack summary

    Returns aggregated view of technologies in use

    Useful for:
    - Patch management
    - License tracking
    - Security posture assessment
    """
    # Query for products
    products = db.query(
        Service.product,
        Service.version,
        func.count(Service.id).label('count')
    ).join(Asset).filter(
        Asset.tenant_id == tenant_id,
        Service.product.isnot(None)
    ).group_by(Service.product, Service.version).all()

    # Aggregate by product
    tech_stack = {}
    for product, version, count in products:
        if product not in tech_stack:
            tech_stack[product] = {
                'technology': product,
                'count': 0,
                'versions': {}
            }

        tech_stack[product]['count'] += count
        if version:
            tech_stack[product]['versions'][version] = count

    # Convert to response format
    return [
        TechnologyStackResponse(
            technology=tech['technology'],
            count=tech['count'],
            versions=tech['versions'],
            risk_level=None  # TODO: Add risk assessment logic
        )
        for tech in sorted(tech_stack.values(), key=lambda x: x['count'], reverse=True)
    ]


@router.get("/ports/distribution", response_model=List[PortDistributionResponse])
def get_port_distribution(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Get port distribution statistics

    Shows which ports are most commonly open

    Useful for:
    - Attack surface analysis
    - Firewall rule validation
    - Service discovery
    """
    # Query for port distribution
    ports = db.query(
        Service.port,
        Service.protocol,
        Service.product,
        func.count(Service.id).label('count')
    ).join(Asset).filter(
        Asset.tenant_id == tenant_id,
        Service.port.isnot(None)
    ).group_by(Service.port, Service.protocol, Service.product).all()

    # Aggregate by port
    port_dist = {}
    for port, protocol, product, count in ports:
        if port not in port_dist:
            port_dist[port] = {
                'port': port,
                'count': 0,
                'protocols': set(),
                'products': []
            }

        port_dist[port]['count'] += count
        if protocol:
            port_dist[port]['protocols'].add(protocol)
        if product and product not in port_dist[port]['products']:
            port_dist[port]['products'].append(product)

    # Convert to response format
    return [
        PortDistributionResponse(
            port=data['port'],
            count=data['count'],
            protocols=list(data['protocols']),
            common_products=data['products'][:5]  # Top 5 products
        )
        for data in sorted(port_dist.values(), key=lambda x: x['count'], reverse=True)[:50]
    ]


@router.get("/{service_id}", response_model=ServiceResponse)
def get_service(
    tenant_id: int,
    service_id: int,
    db: Session = Depends(get_db),
    membership = Depends(verify_tenant_access)
):
    """
    Get service by ID

    Raises:
        - 404: Service not found
    """
    service = db.query(Service).join(Asset).filter(
        Service.id == service_id,
        Asset.tenant_id == tenant_id
    ).first()

    if not service:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service not found"
        )

    return ServiceResponse.model_validate(service)
