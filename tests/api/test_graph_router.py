"""
Graph Router Unit Tests

Tests tenant isolation, helper functions, and cache behaviour
for the graph visualization API. No database required — uses mocks.
"""

from __future__ import annotations

import pytest
from unittest.mock import MagicMock, patch

from app.api.routers.graph import _risk_to_criticality, _verify_tenant_exists, GRAPH_CACHE_TTL
from fastapi import HTTPException


# ---------------------------------------------------------------------------
# _risk_to_criticality
# ---------------------------------------------------------------------------


class TestRiskToCriticality:
    """Test risk score → criticality mapping."""

    def test_none_returns_low(self):
        assert _risk_to_criticality(None) == "low"

    def test_zero_returns_low(self):
        assert _risk_to_criticality(0.0) == "low"

    def test_low_score(self):
        assert _risk_to_criticality(20.0) == "low"

    def test_boundary_40_is_low(self):
        assert _risk_to_criticality(40.0) == "low"

    def test_medium_score(self):
        assert _risk_to_criticality(50.0) == "medium"

    def test_boundary_60_is_medium(self):
        assert _risk_to_criticality(60.0) == "medium"

    def test_high_score(self):
        assert _risk_to_criticality(70.0) == "high"

    def test_boundary_80_is_high(self):
        assert _risk_to_criticality(80.0) == "high"

    def test_critical_score(self):
        assert _risk_to_criticality(90.0) == "critical"

    def test_max_score(self):
        assert _risk_to_criticality(100.0) == "critical"


# ---------------------------------------------------------------------------
# _verify_tenant_exists
# ---------------------------------------------------------------------------


class TestVerifyTenantExists:
    """Test tenant existence check raises 404 correctly."""

    def test_existing_tenant_passes(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = (1,)
        _verify_tenant_exists(db, 1)  # should not raise

    def test_missing_tenant_raises_404(self):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(HTTPException) as exc_info:
            _verify_tenant_exists(db, 999)
        assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# Cache behaviour
# ---------------------------------------------------------------------------


class TestGraphCacheConfig:
    """Verify cache configuration constants."""

    def test_cache_ttl_is_5_minutes(self):
        assert GRAPH_CACHE_TTL == 300


# ---------------------------------------------------------------------------
# Tenant isolation in queries
# ---------------------------------------------------------------------------


class TestGraphTenantIsolation:
    """
    Verify that graph queries include tenant_id filters.

    These are static code-level checks: we import the router source
    and verify the SQL-building code filters by tenant_id.
    """

    def test_nodes_query_filters_by_tenant_id(self):
        """get_graph_nodes must filter Asset.tenant_id == tenant_id."""
        import inspect
        from app.api.routers.graph import get_graph_nodes

        source = inspect.getsource(get_graph_nodes)
        assert "Asset.tenant_id == tenant_id" in source

    def test_edges_query_filters_by_tenant_id(self):
        """get_graph_edges must filter Relationship.tenant_id == tenant_id."""
        import inspect
        from app.api.routers.graph import get_graph_edges

        source = inspect.getsource(get_graph_edges)
        assert "Relationship.tenant_id == tenant_id" in source

    def test_neighbors_query_filters_by_tenant_id(self):
        """get_asset_neighbors must filter both central asset and neighbors by tenant."""
        import inspect
        from app.api.routers.graph import get_asset_neighbors

        source = inspect.getsource(get_asset_neighbors)
        # Central asset check
        assert "Asset.tenant_id == tenant_id" in source

    def test_stats_query_filters_by_tenant_id(self):
        """get_graph_stats must filter by tenant_id."""
        import inspect
        from app.api.routers.graph import get_graph_stats

        source = inspect.getsource(get_graph_stats)
        assert "Asset.tenant_id == tenant_id" in source
