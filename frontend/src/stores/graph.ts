import { defineStore } from "pinia";
import { ref, computed } from "vue";
import apiClient from "@/api/client";
import { useTenantStore } from "./tenant";

// --- Types ---

export type AssetNodeType = "domain" | "subdomain" | "ip" | "service" | "url";

export type EdgeRelType =
  | "resolves_to"
  | "cname_to"
  | "ns_for"
  | "mx_for"
  | "redirects_to"
  | "cert_covers"
  | "hosts";

export interface GraphNode {
  id: number;
  identifier: string;
  type: AssetNodeType;
  risk_score: number;
  finding_count: number;
  // D3 simulation properties (added at runtime)
  x?: number;
  y?: number;
  fx?: number | null;
  fy?: number | null;
  vx?: number;
  vy?: number;
}

export interface GraphEdge {
  source_id: number;
  target_id: number;
  rel_type: EdgeRelType;
}

/** D3 expects source/target as node references or ids */
export interface SimulationEdge {
  source: number;
  target: number;
  rel_type: EdgeRelType;
}

export interface NeighborResponse {
  node: GraphNode;
  neighbors: GraphNode[];
  edges: GraphEdge[];
}

export interface MostConnectedNode {
  id: number;
  identifier: string;
  type: string;
  connection_count: number;
  risk_score: number;
}

export interface GraphStatsData {
  node_count_by_type: Record<string, number>;
  edge_count_by_type: Record<string, number>;
  total_nodes: number;
  total_edges: number;
  most_connected: MostConnectedNode[];
}

// --- Store ---

export const useGraphStore = defineStore("graph", () => {
  const tenantStore = useTenantStore();

  const nodes = ref<GraphNode[]>([]);
  const edges = ref<GraphEdge[]>([]);
  const stats = ref<GraphStatsData | null>(null);
  const isLoadingNodes = ref(false);
  const isLoadingEdges = ref(false);
  const isLoadingStats = ref(false);
  const isExpandingNode = ref(false);
  const error = ref("");
  const expandedNodeIds = ref<Set<number>>(new Set());

  // AbortControllers for cancelling stale in-flight requests
  let fetchNodesAbort: AbortController | null = null;
  let fetchEdgesAbort: AbortController | null = null;

  const tenantId = computed(() => tenantStore.currentTenantId);

  const simulationEdges = computed<SimulationEdge[]>(() =>
    edges.value.map((e) => ({
      source: e.source_id,
      target: e.target_id,
      rel_type: e.rel_type,
    })),
  );

  const totalNodes = computed(() => nodes.value.length);
  const totalEdges = computed(() => edges.value.length);

  const highestRiskNode = computed<GraphNode | null>(() => {
    if (nodes.value.length === 0) return null;
    return nodes.value.reduce((max, node) =>
      node.risk_score > max.risk_score ? node : max,
    );
  });

  /** Fetch all graph nodes for the current tenant */
  async function fetchNodes(): Promise<void> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return;
    }

    fetchNodesAbort?.abort();
    fetchNodesAbort = new AbortController();

    isLoadingNodes.value = true;
    error.value = "";

    try {
      const response = await apiClient.get<GraphNode[]>(
        `/api/v1/tenants/${tenantId.value}/graph/nodes`,
        { signal: fetchNodesAbort.signal },
      );
      nodes.value = response.data;
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        (err.name === "CanceledError" || err.name === "AbortError")
      )
        return;
      const message =
        err instanceof Error ? err.message : "Failed to fetch graph nodes";
      error.value = message;
    } finally {
      isLoadingNodes.value = false;
    }
  }

  /** Fetch all graph edges for the current tenant */
  async function fetchEdges(): Promise<void> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return;
    }

    fetchEdgesAbort?.abort();
    fetchEdgesAbort = new AbortController();

    isLoadingEdges.value = true;
    error.value = "";

    try {
      const response = await apiClient.get<GraphEdge[]>(
        `/api/v1/tenants/${tenantId.value}/graph/edges`,
        { signal: fetchEdgesAbort.signal },
      );
      edges.value = response.data;
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        (err.name === "CanceledError" || err.name === "AbortError")
      )
        return;
      const message =
        err instanceof Error ? err.message : "Failed to fetch graph edges";
      error.value = message;
    } finally {
      isLoadingEdges.value = false;
    }
  }

  /** Fetch graph stats (node/edge counts, most connected) */
  async function fetchStats(): Promise<void> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return;
    }

    isLoadingStats.value = true;

    try {
      const response = await apiClient.get<GraphStatsData>(
        `/api/v1/tenants/${tenantId.value}/graph/stats`,
      );
      stats.value = response.data;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch graph stats";
      error.value = message;
    } finally {
      isLoadingStats.value = false;
    }
  }

  /** Fetch full graph (nodes + edges + stats) */
  async function fetchGraph(): Promise<void> {
    await Promise.all([fetchNodes(), fetchEdges(), fetchStats()]);
  }

  /** Expand a node by loading its neighbors */
  async function expandNode(assetId: number): Promise<NeighborResponse | null> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return null;
    }

    if (expandedNodeIds.value.has(assetId)) {
      return null;
    }

    isExpandingNode.value = true;
    error.value = "";

    try {
      const response = await apiClient.get<NeighborResponse>(
        `/api/v1/tenants/${tenantId.value}/graph/neighbors/${assetId}`,
      );

      const data = response.data;
      const existingIds = new Set(nodes.value.map((n) => n.id));

      // Add new neighbor nodes that are not already in the graph
      for (const neighbor of data.neighbors) {
        if (!existingIds.has(neighbor.id)) {
          nodes.value.push(neighbor);
        }
      }

      // Add new edges, deduplicating by source+target+rel_type
      const existingEdgeKeys = new Set(
        edges.value.map((e) => `${e.source_id}-${e.target_id}-${e.rel_type}`),
      );

      for (const edge of data.edges) {
        const key = `${edge.source_id}-${edge.target_id}-${edge.rel_type}`;
        if (!existingEdgeKeys.has(key)) {
          edges.value.push(edge);
          existingEdgeKeys.add(key);
        }
      }

      expandedNodeIds.value.add(assetId);
      return data;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to expand node";
      error.value = message;
      return null;
    } finally {
      isExpandingNode.value = false;
    }
  }

  /** Find a node by identifier (case-insensitive partial match) */
  function findNodeByIdentifier(query: string): GraphNode | undefined {
    const lowerQuery = query.toLowerCase();
    // Exact match first
    const exact = nodes.value.find(
      (n) => n.identifier.toLowerCase() === lowerQuery,
    );
    if (exact) return exact;
    // Partial match
    return nodes.value.find((n) =>
      n.identifier.toLowerCase().includes(lowerQuery),
    );
  }

  /** Get matching nodes for search suggestions */
  function searchNodes(query: string, limit = 10): GraphNode[] {
    if (!query.trim()) return [];
    const lowerQuery = query.toLowerCase();
    return nodes.value
      .filter((n) => n.identifier.toLowerCase().includes(lowerQuery))
      .slice(0, limit);
  }

  function clearGraph(): void {
    nodes.value = [];
    edges.value = [];
    expandedNodeIds.value.clear();
    error.value = "";
  }

  function clearError(): void {
    error.value = "";
  }

  function $reset(): void {
    clearGraph();
    stats.value = null;
  }

  return {
    // State
    nodes,
    edges,
    stats,
    isLoadingNodes,
    isLoadingEdges,
    isLoadingStats,
    isExpandingNode,
    error,
    expandedNodeIds,

    // Computed
    simulationEdges,
    totalNodes,
    totalEdges,
    highestRiskNode,

    // Actions
    fetchNodes,
    fetchEdges,
    fetchStats,
    fetchGraph,
    expandNode,
    findNodeByIdentifier,
    searchNodes,
    clearGraph,
    clearError,
    $reset,
  };
});
