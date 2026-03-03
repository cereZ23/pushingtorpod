import { vi, describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// Mock the API client module
vi.mock('@/api/client', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: 'http://test' },
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
}))

// Mock the tenant store dependency
vi.mock('./tenant', () => ({
  useTenantStore: vi.fn(() => ({
    currentTenantId: 1,
  })),
}))

import apiClient from '@/api/client'
import { useTenantStore } from './tenant'
import {
  useGraphStore,
  type GraphNode,
  type GraphEdge,
  type NeighborResponse,
  type GraphStatsData,
} from './graph'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeNode(overrides: Partial<GraphNode> = {}): GraphNode {
  return {
    id: 1,
    identifier: 'acme.com',
    type: 'domain',
    risk_score: 50,
    finding_count: 3,
    ...overrides,
  }
}

function makeEdge(overrides: Partial<GraphEdge> = {}): GraphEdge {
  return {
    source_id: 1,
    target_id: 2,
    rel_type: 'resolves_to',
    ...overrides,
  }
}

function makeStatsData(overrides: Partial<GraphStatsData> = {}): GraphStatsData {
  return {
    node_count_by_type: { domain: 5, subdomain: 20, ip: 10 },
    edge_count_by_type: { resolves_to: 15, cname_to: 5 },
    total_nodes: 35,
    total_edges: 20,
    most_connected: [
      { id: 1, identifier: 'acme.com', type: 'domain', connection_count: 15, risk_score: 80 },
    ],
    ...overrides,
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('graph store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------
  describe('initial state', () => {
    it('has empty nodes, edges, and default values', () => {
      const store = useGraphStore()
      expect(store.nodes).toEqual([])
      expect(store.edges).toEqual([])
      expect(store.stats).toBeNull()
      expect(store.isLoadingNodes).toBe(false)
      expect(store.isLoadingEdges).toBe(false)
      expect(store.isLoadingStats).toBe(false)
      expect(store.isExpandingNode).toBe(false)
      expect(store.error).toBe('')
      expect(store.expandedNodeIds.size).toBe(0)
    })
  })

  // -----------------------------------------------------------------------
  // Computed properties
  // -----------------------------------------------------------------------
  describe('computed properties', () => {
    it('totalNodes reflects nodes array length', () => {
      const store = useGraphStore()
      store.nodes = [makeNode({ id: 1 }), makeNode({ id: 2 })]

      expect(store.totalNodes).toBe(2)
    })

    it('totalEdges reflects edges array length', () => {
      const store = useGraphStore()
      store.edges = [makeEdge(), makeEdge({ source_id: 3, target_id: 4 })]

      expect(store.totalEdges).toBe(2)
    })

    it('simulationEdges maps source_id/target_id to source/target', () => {
      const store = useGraphStore()
      store.edges = [
        makeEdge({ source_id: 1, target_id: 2, rel_type: 'resolves_to' }),
        makeEdge({ source_id: 3, target_id: 4, rel_type: 'cname_to' }),
      ]

      expect(store.simulationEdges).toEqual([
        { source: 1, target: 2, rel_type: 'resolves_to' },
        { source: 3, target: 4, rel_type: 'cname_to' },
      ])
    })

    it('highestRiskNode returns the node with the highest risk_score', () => {
      const store = useGraphStore()
      store.nodes = [
        makeNode({ id: 1, risk_score: 30 }),
        makeNode({ id: 2, risk_score: 95 }),
        makeNode({ id: 3, risk_score: 60 }),
      ]

      expect(store.highestRiskNode?.id).toBe(2)
      expect(store.highestRiskNode?.risk_score).toBe(95)
    })

    it('highestRiskNode returns null when no nodes', () => {
      const store = useGraphStore()
      expect(store.highestRiskNode).toBeNull()
    })
  })

  // -----------------------------------------------------------------------
  // fetchNodes
  // -----------------------------------------------------------------------
  describe('fetchNodes', () => {
    it('loads nodes from API', async () => {
      const nodes = [
        makeNode({ id: 1, identifier: 'acme.com' }),
        makeNode({ id: 2, identifier: 'sub.acme.com', type: 'subdomain' }),
      ]
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: nodes })

      const store = useGraphStore()
      await store.fetchNodes()

      expect(store.nodes).toHaveLength(2)
      expect(store.nodes[0].identifier).toBe('acme.com')
      expect(store.isLoadingNodes).toBe(false)
    })

    it('sets loading state during fetch', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: [] })

      const store = useGraphStore()
      const promise = store.fetchNodes()

      expect(store.isLoadingNodes).toBe(true)
      await promise
      expect(store.isLoadingNodes).toBe(false)
    })

    it('calls correct API endpoint', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: [] })

      const store = useGraphStore()
      await store.fetchNodes()

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/graph/nodes',
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      )
    })

    it('sets error on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Server Error'))

      const store = useGraphStore()
      await store.fetchNodes()

      expect(store.error).toBe('Server Error')
      expect(store.isLoadingNodes).toBe(false)
    })

    it('returns early when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useGraphStore()
      await store.fetchNodes()

      expect(store.error).toBe('No tenant selected')
      expect(apiClient.get).not.toHaveBeenCalled()
    })

    it('silently ignores CanceledError', async () => {
      const err = new Error('canceled')
      err.name = 'CanceledError'
      vi.mocked(apiClient.get).mockRejectedValueOnce(err)

      const store = useGraphStore()
      await store.fetchNodes()

      expect(store.error).toBe('')
    })

    it('aborts previous fetchNodes request', async () => {
      let firstSignal: AbortSignal | undefined

      vi.mocked(apiClient.get)
        .mockImplementationOnce((_url, config) => {
          firstSignal = config?.signal as AbortSignal
          return new Promise(() => {})
        })
        .mockImplementationOnce(() => Promise.resolve({ data: [] }))

      const store = useGraphStore()
      store.fetchNodes()
      await store.fetchNodes()

      expect(firstSignal?.aborted).toBe(true)
    })
  })

  // -----------------------------------------------------------------------
  // fetchEdges
  // -----------------------------------------------------------------------
  describe('fetchEdges', () => {
    it('loads edges from API', async () => {
      const edges = [
        makeEdge({ source_id: 1, target_id: 2 }),
        makeEdge({ source_id: 1, target_id: 3, rel_type: 'cname_to' }),
      ]
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: edges })

      const store = useGraphStore()
      await store.fetchEdges()

      expect(store.edges).toHaveLength(2)
      expect(store.isLoadingEdges).toBe(false)
    })

    it('calls correct API endpoint', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: [] })

      const store = useGraphStore()
      await store.fetchEdges()

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/graph/edges',
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      )
    })

    it('sets error on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Timeout'))

      const store = useGraphStore()
      await store.fetchEdges()

      expect(store.error).toBe('Timeout')
    })

    it('aborts previous fetchEdges request', async () => {
      let firstSignal: AbortSignal | undefined

      vi.mocked(apiClient.get)
        .mockImplementationOnce((_url, config) => {
          firstSignal = config?.signal as AbortSignal
          return new Promise(() => {})
        })
        .mockImplementationOnce(() => Promise.resolve({ data: [] }))

      const store = useGraphStore()
      store.fetchEdges()
      await store.fetchEdges()

      expect(firstSignal?.aborted).toBe(true)
    })
  })

  // -----------------------------------------------------------------------
  // fetchStats
  // -----------------------------------------------------------------------
  describe('fetchStats', () => {
    it('loads graph stats', async () => {
      const statsData = makeStatsData()
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: statsData })

      const store = useGraphStore()
      await store.fetchStats()

      expect(store.stats).toEqual(statsData)
      expect(store.stats?.total_nodes).toBe(35)
      expect(store.isLoadingStats).toBe(false)
    })

    it('calls correct endpoint', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: makeStatsData() })

      const store = useGraphStore()
      await store.fetchStats()

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/graph/stats'
      )
    })

    it('sets error on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Stats failed'))

      const store = useGraphStore()
      await store.fetchStats()

      expect(store.error).toBe('Stats failed')
      expect(store.isLoadingStats).toBe(false)
    })
  })

  // -----------------------------------------------------------------------
  // fetchGraph (combined)
  // -----------------------------------------------------------------------
  describe('fetchGraph', () => {
    it('fetches nodes, edges, and stats concurrently', async () => {
      const nodes = [makeNode()]
      const edges = [makeEdge()]
      const statsData = makeStatsData()

      vi.mocked(apiClient.get)
        .mockResolvedValueOnce({ data: nodes })   // fetchNodes
        .mockResolvedValueOnce({ data: edges })   // fetchEdges
        .mockResolvedValueOnce({ data: statsData }) // fetchStats

      const store = useGraphStore()
      await store.fetchGraph()

      expect(store.nodes).toHaveLength(1)
      expect(store.edges).toHaveLength(1)
      expect(store.stats).toEqual(statsData)
      expect(apiClient.get).toHaveBeenCalledTimes(3)
    })
  })

  // -----------------------------------------------------------------------
  // expandNode
  // -----------------------------------------------------------------------
  describe('expandNode', () => {
    it('fetches neighbors and adds new nodes/edges', async () => {
      const neighborResponse: NeighborResponse = {
        node: makeNode({ id: 1 }),
        neighbors: [
          makeNode({ id: 10, identifier: '1.2.3.4', type: 'ip' }),
          makeNode({ id: 11, identifier: '5.6.7.8', type: 'ip' }),
        ],
        edges: [
          makeEdge({ source_id: 1, target_id: 10, rel_type: 'resolves_to' }),
          makeEdge({ source_id: 1, target_id: 11, rel_type: 'resolves_to' }),
        ],
      }
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: neighborResponse })

      const store = useGraphStore()
      store.nodes = [makeNode({ id: 1 })]
      store.edges = []

      const result = await store.expandNode(1)

      expect(result).toEqual(neighborResponse)
      expect(store.nodes).toHaveLength(3)
      expect(store.edges).toHaveLength(2)
      expect(store.expandedNodeIds.has(1)).toBe(true)
    })

    it('deduplicates nodes that already exist', async () => {
      const neighborResponse: NeighborResponse = {
        node: makeNode({ id: 1 }),
        neighbors: [
          makeNode({ id: 2, identifier: 'existing.com' }),
          makeNode({ id: 3, identifier: 'new.com' }),
        ],
        edges: [
          makeEdge({ source_id: 1, target_id: 2 }),
          makeEdge({ source_id: 1, target_id: 3 }),
        ],
      }
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: neighborResponse })

      const store = useGraphStore()
      store.nodes = [
        makeNode({ id: 1, identifier: 'acme.com' }),
        makeNode({ id: 2, identifier: 'existing.com' }),
      ]
      store.edges = []

      await store.expandNode(1)

      // Should have 3 nodes (1 + 2 existing, 3 new) not 4
      expect(store.nodes).toHaveLength(3)
      expect(store.nodes.map(n => n.id).sort()).toEqual([1, 2, 3])
    })

    it('deduplicates edges that already exist', async () => {
      const existingEdge = makeEdge({ source_id: 1, target_id: 2, rel_type: 'resolves_to' })
      const neighborResponse: NeighborResponse = {
        node: makeNode({ id: 1 }),
        neighbors: [makeNode({ id: 2 }), makeNode({ id: 3 })],
        edges: [
          makeEdge({ source_id: 1, target_id: 2, rel_type: 'resolves_to' }), // duplicate
          makeEdge({ source_id: 1, target_id: 3, rel_type: 'cname_to' }),     // new
        ],
      }
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: neighborResponse })

      const store = useGraphStore()
      store.nodes = [makeNode({ id: 1 }), makeNode({ id: 2 })]
      store.edges = [existingEdge]

      await store.expandNode(1)

      // Should have 2 edges (1 existing + 1 new), not 3
      expect(store.edges).toHaveLength(2)
    })

    it('does not re-fetch already expanded nodes', async () => {
      const store = useGraphStore()
      store.expandedNodeIds.add(5)

      const result = await store.expandNode(5)

      expect(result).toBeNull()
      expect(apiClient.get).not.toHaveBeenCalled()
    })

    it('tracks expanded node ids', async () => {
      const neighborResponse: NeighborResponse = {
        node: makeNode({ id: 1 }),
        neighbors: [],
        edges: [],
      }
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: neighborResponse })

      const store = useGraphStore()
      store.nodes = [makeNode({ id: 1 })]

      await store.expandNode(1)

      expect(store.expandedNodeIds.has(1)).toBe(true)
      expect(store.expandedNodeIds.size).toBe(1)
    })

    it('sets isExpandingNode loading state', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({
        data: { node: makeNode(), neighbors: [], edges: [] },
      })

      const store = useGraphStore()
      store.nodes = [makeNode()]
      const promise = store.expandNode(1)

      expect(store.isExpandingNode).toBe(true)
      await promise
      expect(store.isExpandingNode).toBe(false)
    })

    it('calls correct API endpoint', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({
        data: { node: makeNode({ id: 42 }), neighbors: [], edges: [] },
      })

      const store = useGraphStore()
      await store.expandNode(42)

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/graph/neighbors/42'
      )
    })

    it('sets error and returns null on failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Expand failed'))

      const store = useGraphStore()
      const result = await store.expandNode(1)

      expect(result).toBeNull()
      expect(store.error).toBe('Expand failed')
      expect(store.isExpandingNode).toBe(false)
    })

    it('returns null when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useGraphStore()
      const result = await store.expandNode(1)

      expect(result).toBeNull()
      expect(store.error).toBe('No tenant selected')
    })
  })

  // -----------------------------------------------------------------------
  // findNodeByIdentifier
  // -----------------------------------------------------------------------
  describe('findNodeByIdentifier', () => {
    it('finds exact match (case-insensitive)', () => {
      const store = useGraphStore()
      store.nodes = [
        makeNode({ id: 1, identifier: 'acme.com' }),
        makeNode({ id: 2, identifier: 'sub.acme.com' }),
      ]

      const result = store.findNodeByIdentifier('ACME.COM')

      expect(result?.id).toBe(1)
    })

    it('finds partial match when no exact match', () => {
      const store = useGraphStore()
      store.nodes = [
        makeNode({ id: 1, identifier: 'api.acme.com' }),
        makeNode({ id: 2, identifier: 'mail.acme.com' }),
      ]

      const result = store.findNodeByIdentifier('api')

      expect(result?.id).toBe(1)
    })

    it('prefers exact match over partial match', () => {
      const store = useGraphStore()
      store.nodes = [
        makeNode({ id: 1, identifier: 'api.acme.com' }),
        makeNode({ id: 2, identifier: 'api' }),
      ]

      const result = store.findNodeByIdentifier('api')

      expect(result?.id).toBe(2)
    })

    it('returns undefined when no match', () => {
      const store = useGraphStore()
      store.nodes = [makeNode({ id: 1, identifier: 'acme.com' })]

      expect(store.findNodeByIdentifier('google.com')).toBeUndefined()
    })

    it('returns undefined for empty nodes', () => {
      const store = useGraphStore()
      expect(store.findNodeByIdentifier('anything')).toBeUndefined()
    })
  })

  // -----------------------------------------------------------------------
  // searchNodes
  // -----------------------------------------------------------------------
  describe('searchNodes', () => {
    it('returns matching nodes up to limit', () => {
      const store = useGraphStore()
      store.nodes = Array.from({ length: 20 }, (_, i) =>
        makeNode({ id: i + 1, identifier: `host-${i + 1}.acme.com` })
      )

      const results = store.searchNodes('acme', 5)

      expect(results).toHaveLength(5)
    })

    it('returns empty array for empty query', () => {
      const store = useGraphStore()
      store.nodes = [makeNode()]

      expect(store.searchNodes('')).toEqual([])
      expect(store.searchNodes('   ')).toEqual([])
    })

    it('performs case-insensitive search', () => {
      const store = useGraphStore()
      store.nodes = [
        makeNode({ id: 1, identifier: 'API.acme.com' }),
        makeNode({ id: 2, identifier: 'mail.acme.com' }),
      ]

      const results = store.searchNodes('api')
      expect(results).toHaveLength(1)
      expect(results[0].id).toBe(1)
    })

    it('uses default limit of 10', () => {
      const store = useGraphStore()
      store.nodes = Array.from({ length: 15 }, (_, i) =>
        makeNode({ id: i + 1, identifier: `node-${i + 1}.test` })
      )

      const results = store.searchNodes('test')
      expect(results).toHaveLength(10)
    })
  })

  // -----------------------------------------------------------------------
  // clearGraph
  // -----------------------------------------------------------------------
  describe('clearGraph', () => {
    it('resets all graph state', () => {
      const store = useGraphStore()
      store.nodes = [makeNode()]
      store.edges = [makeEdge()]
      store.expandedNodeIds.add(1)
      store.error = 'some error'

      store.clearGraph()

      expect(store.nodes).toEqual([])
      expect(store.edges).toEqual([])
      expect(store.expandedNodeIds.size).toBe(0)
      expect(store.error).toBe('')
    })
  })

  // -----------------------------------------------------------------------
  // clearError
  // -----------------------------------------------------------------------
  describe('clearError', () => {
    it('resets the error string', () => {
      const store = useGraphStore()
      store.error = 'something broke'

      store.clearError()

      expect(store.error).toBe('')
    })
  })
})
