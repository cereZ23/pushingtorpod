"""
Asset Graph API router for relationship visualization.

Provides nodes (assets) and edges (relationships) suitable for rendering
an interactive attack-surface graph, plus a neighbors endpoint for
drill-down exploration.
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, or_
from sqlalchemy.orm import Session
import logging

from app.api.dependencies import get_db, verify_tenant_access
from app.core.cache import cache_get_sync, cache_set_sync
from app.models.database import (
    Asset,
    Finding,
    FindingStatus,
    Service,
    Tenant,
)
from app.models.risk import Relationship
from app.models.database import AssetType
from app.api.schemas.graph import (
    GraphNode,
    GraphEdge,
    GraphStats,
    MostConnectedNode,
    NeighborsResponse,
)

GRAPH_CACHE_TTL = 300  # 5 minutes

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/tenants/{tenant_id}/graph",
    tags=["Graph"],
)


@router.get("/nodes", response_model=list[GraphNode])
def get_graph_nodes(
    tenant_id: int,
    asset_type: Optional[str] = Query(
        default=None,
        description="Filter by asset type (domain, subdomain, ip, url, service)",
    ),
    limit: int = Query(default=2000, ge=1, le=10000, description="Maximum nodes to return"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> list[GraphNode]:
    """
    Get all asset nodes for graph visualization.

    Each node includes the asset's risk score, criticality tier,
    and pre-computed counts of related findings and services so
    the frontend can size/color nodes without extra requests.

    Args:
        tenant_id: Tenant ID from path.
        asset_type: Optional asset type filter.
        limit: Maximum number of nodes (default 500, max 5000).
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        List of GraphNode objects.
    """
    cache_key = f"cache:tenant:{tenant_id}:graph:nodes:{asset_type}:{limit}"
    cached = cache_get_sync(cache_key)
    if cached is not None:
        return [GraphNode(**n) for n in cached]

    _verify_tenant_exists(db, tenant_id)

    # Subquery: open finding count per asset
    finding_count_sq = (
        db.query(
            Finding.asset_id,
            func.count(Finding.id).label("finding_count"),
        )
        .filter(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.asset_id)
        .subquery()
    )

    # Subquery: service count per asset
    service_count_sq = (
        db.query(
            Service.asset_id,
            func.count(Service.id).label("service_count"),
        )
        .group_by(Service.asset_id)
        .subquery()
    )

    query = (
        db.query(
            Asset,
            func.coalesce(finding_count_sq.c.finding_count, 0).label("finding_count"),
            func.coalesce(service_count_sq.c.service_count, 0).label("service_count"),
        )
        .outerjoin(finding_count_sq, Asset.id == finding_count_sq.c.asset_id)
        .outerjoin(service_count_sq, Asset.id == service_count_sq.c.asset_id)
        .filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
    )

    if asset_type is not None:
        query = query.filter(Asset.type == asset_type)

    results = query.order_by(Asset.risk_score.desc()).limit(limit).all()

    nodes = [
        GraphNode(
            id=asset.id,
            identifier=asset.identifier,
            type=asset.type.value,
            risk_score=round(asset.risk_score or 0.0, 2),
            criticality=_risk_to_criticality(asset.risk_score),
            finding_count=finding_count,
            service_count=service_count,
        )
        for asset, finding_count, service_count in results
    ]
    cache_set_sync(cache_key, [n.model_dump(mode="json") for n in nodes], ttl=GRAPH_CACHE_TTL)
    return nodes


@router.get("/edges", response_model=list[GraphEdge])
def get_graph_edges(
    tenant_id: int,
    rel_type: Optional[str] = Query(
        default=None,
        description=(
            "Filter by relationship type "
            "(resolves_to, cname_to, ns_for, mx_for, redirects_to, cert_covers, hosts, parent_domain)"
        ),
    ),
    limit: int = Query(default=2000, ge=1, le=10000, description="Maximum edges to return"),
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> list[GraphEdge]:
    """
    Get all relationship edges for graph visualization.

    Edges represent directed relationships between assets such as
    DNS resolution, CNAME chains, redirects, certificate coverage,
    and parent-domain hierarchies.

    Args:
        tenant_id: Tenant ID from path.
        rel_type: Optional relationship type filter.
        limit: Maximum number of edges (default 2000, max 10000).
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        List of GraphEdge objects.
    """
    cache_key = f"cache:tenant:{tenant_id}:graph:edges:{rel_type}:{limit}"
    cached = cache_get_sync(cache_key)
    if cached is not None:
        return [GraphEdge(**e) for e in cached]

    _verify_tenant_exists(db, tenant_id)

    query = (
        db.query(Relationship)
        .filter(Relationship.tenant_id == tenant_id)
    )

    if rel_type is not None:
        query = query.filter(Relationship.rel_type == rel_type)

    edges = query.order_by(Relationship.last_seen_at.desc()).limit(limit).all()

    edge_items = [
        GraphEdge(
            id=edge.id,
            source_id=edge.source_asset_id,
            target_id=edge.target_asset_id,
            rel_type=edge.rel_type,
            metadata=edge.rel_metadata,
            first_seen_at=edge.first_seen_at,
        )
        for edge in edges
    ]
    cache_set_sync(cache_key, [e.model_dump(mode="json") for e in edge_items], ttl=GRAPH_CACHE_TTL)
    return edge_items


@router.get("/neighbors/{asset_id}", response_model=NeighborsResponse)
def get_asset_neighbors(
    tenant_id: int,
    asset_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> NeighborsResponse:
    """
    Get the immediate neighborhood of a single asset.

    Returns the requested asset as the central node together with all
    edges where it appears as source or target and the corresponding
    neighbor nodes. Useful for drill-down exploration without loading
    the full graph.

    Args:
        tenant_id: Tenant ID from path.
        asset_id: Asset ID to explore.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        NeighborsResponse containing the central node, edges, and neighbor nodes.

    Raises:
        HTTPException: 404 when the asset is not found or does not belong to the tenant.
    """
    _verify_tenant_exists(db, tenant_id)

    # Load the central asset
    central_asset = (
        db.query(Asset)
        .filter(Asset.id == asset_id, Asset.tenant_id == tenant_id)
        .first()
    )
    if not central_asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Asset not found in this tenant",
        )

    # Edges where this asset is source or target
    edges = (
        db.query(Relationship)
        .filter(
            Relationship.tenant_id == tenant_id,
            or_(
                Relationship.source_asset_id == asset_id,
                Relationship.target_asset_id == asset_id,
            ),
        )
        .all()
    )

    # Collect unique neighbor IDs
    neighbor_ids: set[int] = set()
    for edge in edges:
        if edge.source_asset_id != asset_id:
            neighbor_ids.add(edge.source_asset_id)
        if edge.target_asset_id != asset_id:
            neighbor_ids.add(edge.target_asset_id)

    # Load neighbor assets with counts
    finding_count_sq = (
        db.query(
            Finding.asset_id,
            func.count(Finding.id).label("finding_count"),
        )
        .filter(Finding.status == FindingStatus.OPEN)
        .group_by(Finding.asset_id)
        .subquery()
    )

    service_count_sq = (
        db.query(
            Service.asset_id,
            func.count(Service.id).label("service_count"),
        )
        .group_by(Service.asset_id)
        .subquery()
    )

    neighbor_nodes: list[GraphNode] = []
    if neighbor_ids:
        neighbor_results = (
            db.query(
                Asset,
                func.coalesce(finding_count_sq.c.finding_count, 0).label("finding_count"),
                func.coalesce(service_count_sq.c.service_count, 0).label("service_count"),
            )
            .outerjoin(finding_count_sq, Asset.id == finding_count_sq.c.asset_id)
            .outerjoin(service_count_sq, Asset.id == service_count_sq.c.asset_id)
            .filter(Asset.id.in_(neighbor_ids), Asset.tenant_id == tenant_id)
            .all()
        )
        neighbor_nodes = [
            GraphNode(
                id=asset.id,
                identifier=asset.identifier,
                type=asset.type.value,
                risk_score=round(asset.risk_score or 0.0, 2),
                criticality=_risk_to_criticality(asset.risk_score),
                finding_count=finding_count,
                service_count=service_count,
            )
            for asset, finding_count, service_count in neighbor_results
        ]

    # Build central node with counts
    central_finding_count = (
        db.query(func.count(Finding.id))
        .filter(Finding.asset_id == asset_id, Finding.status == FindingStatus.OPEN)
        .scalar()
        or 0
    )
    central_service_count = (
        db.query(func.count(Service.id))
        .filter(Service.asset_id == asset_id)
        .scalar()
        or 0
    )

    central_node = GraphNode(
        id=central_asset.id,
        identifier=central_asset.identifier,
        type=central_asset.type.value,
        risk_score=round(central_asset.risk_score or 0.0, 2),
        criticality=_risk_to_criticality(central_asset.risk_score),
        finding_count=central_finding_count,
        service_count=central_service_count,
    )

    edge_items = [
        GraphEdge(
            id=edge.id,
            source_id=edge.source_asset_id,
            target_id=edge.target_asset_id,
            rel_type=edge.rel_type,
            metadata=edge.rel_metadata,
            first_seen_at=edge.first_seen_at,
        )
        for edge in edges
    ]

    return NeighborsResponse(
        node=central_node,
        edges=edge_items,
        neighbors=neighbor_nodes,
    )


@router.get("/stats", response_model=GraphStats)
def get_graph_stats(
    tenant_id: int,
    db: Session = Depends(get_db),
    membership=Depends(verify_tenant_access),
) -> GraphStats:
    """
    Get aggregated graph statistics.

    Returns node count by asset type, edge count by relationship type,
    total counts, and the top 10 most connected nodes (by total edges).

    Args:
        tenant_id: Tenant ID from path.
        db: Database session.
        membership: Verified tenant membership.

    Returns:
        GraphStats with breakdown counts and most connected nodes.
    """
    cache_key = f"cache:tenant:{tenant_id}:graph:stats"
    cached = cache_get_sync(cache_key)
    if cached is not None:
        return GraphStats(**cached)

    _verify_tenant_exists(db, tenant_id)

    # Node count by type
    node_type_rows = (
        db.query(Asset.type, func.count(Asset.id))
        .filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
        .group_by(Asset.type)
        .all()
    )
    node_count_by_type: dict[str, int] = {}
    total_nodes = 0
    for asset_type, count in node_type_rows:
        key = asset_type.value if isinstance(asset_type, AssetType) else str(asset_type)
        node_count_by_type[key] = count
        total_nodes += count

    # Edge count by type
    edge_type_rows = (
        db.query(Relationship.rel_type, func.count(Relationship.id))
        .filter(Relationship.tenant_id == tenant_id)
        .group_by(Relationship.rel_type)
        .all()
    )
    edge_count_by_type: dict[str, int] = {}
    total_edges = 0
    for rel_type, count in edge_type_rows:
        edge_count_by_type[rel_type] = count
        total_edges += count

    # Most connected nodes (top 10)
    # Count edges where asset appears as source or target
    source_counts = (
        db.query(
            Relationship.source_asset_id.label("asset_id"),
            func.count(Relationship.id).label("cnt"),
        )
        .filter(Relationship.tenant_id == tenant_id)
        .group_by(Relationship.source_asset_id)
        .subquery()
    )
    target_counts = (
        db.query(
            Relationship.target_asset_id.label("asset_id"),
            func.count(Relationship.id).label("cnt"),
        )
        .filter(Relationship.tenant_id == tenant_id)
        .group_by(Relationship.target_asset_id)
        .subquery()
    )

    # Combine source + target counts
    connection_count = (
        func.coalesce(source_counts.c.cnt, 0) + func.coalesce(target_counts.c.cnt, 0)
    ).label("connection_count")

    most_connected_rows = (
        db.query(Asset, connection_count)
        .outerjoin(source_counts, Asset.id == source_counts.c.asset_id)
        .outerjoin(target_counts, Asset.id == target_counts.c.asset_id)
        .filter(Asset.tenant_id == tenant_id, Asset.is_active.is_(True))
        .order_by(connection_count.desc())
        .limit(10)
        .all()
    )

    most_connected = [
        MostConnectedNode(
            id=asset.id,
            identifier=asset.identifier,
            type=asset.type.value,
            connection_count=conn_count or 0,
            risk_score=round(asset.risk_score or 0.0, 2),
        )
        for asset, conn_count in most_connected_rows
        if (conn_count or 0) > 0
    ]

    graph_stats = GraphStats(
        node_count_by_type=node_count_by_type,
        edge_count_by_type=edge_count_by_type,
        total_nodes=total_nodes,
        total_edges=total_edges,
        most_connected=most_connected,
    )
    cache_set_sync(cache_key, graph_stats.model_dump(mode="json"), ttl=GRAPH_CACHE_TTL)
    return graph_stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _verify_tenant_exists(db: Session, tenant_id: int) -> None:
    """
    Raise 404 if the tenant does not exist.

    Args:
        db: Database session.
        tenant_id: Tenant ID to verify.

    Raises:
        HTTPException: 404 when tenant is not found.
    """
    exists = db.query(Tenant.id).filter(Tenant.id == tenant_id).first()
    if not exists:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found",
        )


def _risk_to_criticality(risk_score: Optional[float]) -> str:
    """Map a numeric risk score to a criticality tier.

    Thresholds aligned with GRADE_THRESHOLDS in risk_engine.py:
    F/critical > 80, D/high > 60, C/medium > 40, A-B/low <= 40.
    """
    if risk_score is None:
        return "low"
    if risk_score > 80:
        return "critical"
    if risk_score > 60:
        return "high"
    if risk_score > 40:
        return "medium"
    return "low"
