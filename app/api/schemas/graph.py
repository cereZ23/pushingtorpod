"""
Graph Schemas

Pydantic models for the asset relationship graph API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class GraphNode(BaseModel):
    """Asset node for graph visualization."""

    id: int = Field(..., description="Asset ID")
    identifier: str = Field(..., description="Asset identifier (domain, IP, URL, etc.)")
    type: str = Field(..., description="Asset type")
    risk_score: float = Field(..., description="Current risk score (0-100)")
    criticality: str = Field(..., description="Criticality tier (critical, high, medium, low)")
    finding_count: int = Field(..., description="Number of open findings")
    service_count: int = Field(..., description="Number of discovered services")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 42,
                "identifier": "api.example.com",
                "type": "subdomain",
                "risk_score": 75.0,
                "criticality": "high",
                "finding_count": 4,
                "service_count": 2,
            }
        }
    )


class GraphEdge(BaseModel):
    """Directed relationship edge between two asset nodes."""

    id: int = Field(..., description="Relationship ID")
    source_id: int = Field(..., description="Source asset ID")
    target_id: int = Field(..., description="Target asset ID")
    rel_type: str = Field(
        ...,
        description=(
            "Relationship type (resolves_to, cname_to, ns_for, mx_for, redirects_to, cert_covers, hosts, parent_domain)"
        ),
    )
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional edge metadata")
    first_seen_at: Optional[datetime] = Field(None, description="When this relationship was first observed")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 101,
                "source_id": 42,
                "target_id": 99,
                "rel_type": "resolves_to",
                "metadata": {"record_type": "A"},
                "first_seen_at": "2026-02-15T10:00:00Z",
            }
        }
    )


class MostConnectedNode(BaseModel):
    """A node ranked by connection count for the stats endpoint."""

    id: int = Field(..., description="Asset ID")
    identifier: str = Field(..., description="Asset identifier")
    type: str = Field(..., description="Asset type")
    connection_count: int = Field(..., description="Total edges connected to this node")
    risk_score: float = Field(..., description="Current risk score (0-100)")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "id": 42,
                "identifier": "api.example.com",
                "type": "subdomain",
                "connection_count": 15,
                "risk_score": 75.0,
            }
        }
    )


class GraphStats(BaseModel):
    """Aggregated statistics for the asset relationship graph."""

    node_count_by_type: Dict[str, int] = Field(..., description="Number of nodes grouped by asset type")
    edge_count_by_type: Dict[str, int] = Field(..., description="Number of edges grouped by relationship type")
    total_nodes: int = Field(..., description="Total number of nodes")
    total_edges: int = Field(..., description="Total number of edges")
    most_connected: list[MostConnectedNode] = Field(..., description="Top 10 most connected nodes")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "node_count_by_type": {"domain": 5, "subdomain": 80, "ip": 30},
                "edge_count_by_type": {"resolves_to": 60, "parent_domain": 80},
                "total_nodes": 115,
                "total_edges": 140,
                "most_connected": [
                    {
                        "id": 1,
                        "identifier": "example.com",
                        "type": "domain",
                        "connection_count": 42,
                        "risk_score": 35.0,
                    }
                ],
            }
        }
    )


class NeighborsResponse(BaseModel):
    """Response for the neighbors endpoint containing the central node, its edges, and adjacent nodes."""

    node: GraphNode = Field(..., description="The requested asset node")
    edges: list[GraphEdge] = Field(..., description="All edges connected to this node")
    neighbors: list[GraphNode] = Field(..., description="Adjacent asset nodes")

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "node": {
                    "id": 42,
                    "identifier": "api.example.com",
                    "type": "subdomain",
                    "risk_score": 75.0,
                    "criticality": "high",
                    "finding_count": 4,
                    "service_count": 2,
                },
                "edges": [
                    {
                        "id": 101,
                        "source_id": 42,
                        "target_id": 99,
                        "rel_type": "resolves_to",
                        "metadata": {"record_type": "A"},
                        "first_seen_at": "2026-02-15T10:00:00Z",
                    }
                ],
                "neighbors": [
                    {
                        "id": 99,
                        "identifier": "203.0.113.50",
                        "type": "ip",
                        "risk_score": 45.0,
                        "criticality": "medium",
                        "finding_count": 1,
                        "service_count": 3,
                    }
                ],
            }
        }
    )
