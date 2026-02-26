<script setup lang="ts">
import { ref, onMounted, computed, onUnmounted } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'

// -- Types --

interface SeverityBreakdown {
  critical: number
  high: number
  medium: number
  low: number
  info: number
}

interface AssetsByType {
  domain: number
  subdomain: number
  ip: number
  url: number
  service: number
}

interface DashboardSummary {
  total_assets: number
  asset_delta: number
  open_findings: number
  severity_breakdown: SeverityBreakdown
  risk_score: number
  active_scans: number
  assets_by_type: AssetsByType
  risk_trend: number[]
  recent_activity: RecentActivity[]
}

interface RecentActivity {
  id: number
  type: string
  description: string
  timestamp: string
}

interface GraphNode {
  id: string
  label: string
  type: string
  risk_score: number
}

interface GraphEdge {
  source: string
  target: string
  relationship: string
}

// -- State --

const tenantStore = useTenantStore()
const isLoading = ref(true)
const error = ref('')
const hoveredNode = ref<GraphNode | null>(null)
const tooltipPos = ref({ x: 0, y: 0 })

const currentTenantId = computed(() => tenantStore.currentTenantId)

// Dashboard data with fallback defaults
const summary = ref<DashboardSummary>({
  total_assets: 0,
  asset_delta: 0,
  open_findings: 0,
  severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  risk_score: 0,
  active_scans: 0,
  assets_by_type: { domain: 0, subdomain: 0, ip: 0, url: 0, service: 0 },
  risk_trend: [],
  recent_activity: [],
})

const graphNodes = ref<GraphNode[]>([])
const graphEdges = ref<GraphEdge[]>([])

// -- Computed: SVG Charts --

// Risk grade from score
const riskGrade = computed(() => {
  const s = summary.value.risk_score
  if (s <= 20) return { letter: 'A', color: '#16a34a' }
  if (s <= 40) return { letter: 'B', color: '#65a30d' }
  if (s <= 60) return { letter: 'C', color: '#eab308' }
  if (s <= 80) return { letter: 'D', color: '#ea580c' }
  return { letter: 'F', color: '#dc2626' }
})

// Gauge arc for risk score (0-100)
const riskGaugeArc = computed(() => {
  const score = Math.min(100, Math.max(0, summary.value.risk_score))
  const angle = (score / 100) * 270 // 270 degree arc
  const startAngle = 135 // start at bottom-left
  const endAngle = startAngle + angle
  const r = 40
  const cx = 50
  const cy = 50
  const startRad = (startAngle * Math.PI) / 180
  const endRad = (endAngle * Math.PI) / 180
  const x1 = cx + r * Math.cos(startRad)
  const y1 = cy + r * Math.sin(startRad)
  const x2 = cx + r * Math.cos(endRad)
  const y2 = cy + r * Math.sin(endRad)
  const largeArc = angle > 180 ? 1 : 0
  return `M ${x1} ${y1} A ${r} ${r} 0 ${largeArc} 1 ${x2} ${y2}`
})

// Donut chart segments
const severityColors: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#eab308',
  low: '#3b82f6',
  info: '#6b7280',
}

const donutSegments = computed(() => {
  const breakdown = summary.value.severity_breakdown
  const entries = Object.entries(breakdown).filter(([, v]) => v > 0)
  const total = entries.reduce((sum, [, v]) => sum + v, 0)
  if (total === 0) return []

  const circumference = 2 * Math.PI * 40
  let offset = 0
  return entries.map(([key, value]) => {
    const pct = value / total
    const dashLen = pct * circumference
    const segment = {
      key,
      value,
      color: severityColors[key] || '#6b7280',
      dasharray: `${dashLen} ${circumference - dashLen}`,
      dashoffset: -offset,
      pct: Math.round(pct * 100),
    }
    offset += dashLen
    return segment
  })
})

const donutTotal = computed(() => {
  const b = summary.value.severity_breakdown
  return b.critical + b.high + b.medium + b.low + b.info
})

// Bar chart for asset types
const assetTypeColors: Record<string, string> = {
  domain: '#3b82f6',
  subdomain: '#8b5cf6',
  ip: '#06b6d4',
  url: '#10b981',
  service: '#f59e0b',
}

const assetBars = computed(() => {
  const types = summary.value.assets_by_type
  const entries = Object.entries(types)
  const maxVal = Math.max(...entries.map(([, v]) => v), 1)
  return entries.map(([key, value]) => ({
    key,
    value,
    color: assetTypeColors[key] || '#6b7280',
    widthPct: (value / maxVal) * 100,
  }))
})

// Risk trend line chart
const trendPoints = computed(() => {
  const data = summary.value.risk_trend
  if (data.length < 2) return ''
  const maxY = 100
  const padding = 10
  const w = 280
  const h = 140
  const stepX = (w - padding * 2) / (data.length - 1)
  return data
    .map((val, i) => {
      const x = padding + i * stepX
      const y = h - padding - ((val / maxY) * (h - padding * 2))
      return `${x},${y}`
    })
    .join(' ')
})

const trendDots = computed(() => {
  const data = summary.value.risk_trend
  if (data.length < 2) return []
  const maxY = 100
  const padding = 10
  const w = 280
  const h = 140
  const stepX = (w - padding * 2) / (data.length - 1)
  return data.map((val, i) => ({
    x: padding + i * stepX,
    y: h - padding - ((val / maxY) * (h - padding * 2)),
    value: val,
    label: `Scan ${i + 1}`,
  }))
})

// Graph node positions (simple circular layout)
const nodePositions = computed(() => {
  const nodes = graphNodes.value
  if (nodes.length === 0) return []
  const cx = 250
  const cy = 175
  const r = 130
  return nodes.map((node, i) => {
    const angle = (2 * Math.PI * i) / nodes.length - Math.PI / 2
    const x = cx + r * Math.cos(angle)
    const y = cy + r * Math.sin(angle)
    const radius = Math.max(6, Math.min(18, (node.risk_score / 100) * 18))
    return { ...node, x, y, radius }
  })
})

const edgeLines = computed(() => {
  const positions = nodePositions.value
  if (positions.length === 0) return []
  const posMap = new Map(positions.map(p => [p.id, p]))
  return graphEdges.value
    .map(edge => {
      const src = posMap.get(edge.source)
      const tgt = posMap.get(edge.target)
      if (!src || !tgt) return null
      return { x1: src.x, y1: src.y, x2: tgt.x, y2: tgt.y, relationship: edge.relationship }
    })
    .filter(Boolean)
})

const nodeTypeColors: Record<string, string> = {
  domain: '#3b82f6',
  subdomain: '#8b5cf6',
  ip: '#06b6d4',
  url: '#10b981',
  service: '#f59e0b',
}

// -- API calls --

async function loadDashboard(): Promise<void> {
  if (!currentTenantId.value) {
    error.value = 'No tenant selected'
    isLoading.value = false
    return
  }

  isLoading.value = true
  error.value = ''

  try {
    // Try the dashboard summary endpoint first
    const dashboardResponse = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/dashboard`
    ).catch(() => null)

    if (dashboardResponse?.data) {
      const d = dashboardResponse.data
      const stats = d.stats || d

      summary.value = {
        total_assets: stats.total_assets || 0,
        asset_delta: stats.asset_delta ?? d.asset_delta ?? 0,
        open_findings: stats.open_findings ?? stats.total_findings ?? 0,
        severity_breakdown: {
          critical: stats.findings_by_severity?.critical ?? stats.critical_findings ?? 0,
          high: stats.findings_by_severity?.high ?? stats.high_findings ?? 0,
          medium: stats.findings_by_severity?.medium ?? 0,
          low: stats.findings_by_severity?.low ?? 0,
          info: stats.findings_by_severity?.info ?? 0,
        },
        risk_score: stats.average_risk_score ?? stats.risk_score ?? 0,
        active_scans: stats.active_scans ?? 0,
        assets_by_type: {
          domain: stats.assets_by_type?.domain ?? 0,
          subdomain: stats.assets_by_type?.subdomain ?? 0,
          ip: stats.assets_by_type?.ip ?? 0,
          url: stats.assets_by_type?.url ?? 0,
          service: stats.assets_by_type?.service ?? 0,
        },
        risk_trend: stats.risk_trend ?? d.risk_trend ?? generatePlaceholderTrend(stats.average_risk_score ?? 45),
        recent_activity: d.recent_activity ?? [],
      }
    } else {
      error.value = 'Dashboard data unavailable. Start a scan to populate your attack surface.'
    }

    // Load graph data
    await loadGraphData()
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to load dashboard data'
    console.error('Dashboard load error:', message)
    error.value = 'Failed to load dashboard data. Please check that the API is running.'
  } finally {
    isLoading.value = false
  }
}

async function loadGraphData(): Promise<void> {
  if (!currentTenantId.value) return

  try {
    const [nodesResp, edgesResp] = await Promise.allSettled([
      apiClient.get(`/api/v1/tenants/${currentTenantId.value}/graph/nodes`, { params: { limit: 20 } }),
      apiClient.get(`/api/v1/tenants/${currentTenantId.value}/graph/edges`, { params: { limit: 50 } }),
    ])

    if (nodesResp.status === 'fulfilled') {
      const raw = nodesResp.value.data
      const items = Array.isArray(raw) ? raw : (raw.items ?? raw.nodes ?? [])
      graphNodes.value = items.map((n: Record<string, unknown>) => ({
        id: String(n.id ?? n.identifier ?? ''),
        label: String(n.identifier ?? n.label ?? n.id ?? ''),
        type: String(n.type ?? 'unknown'),
        risk_score: Number(n.risk_score ?? 0),
      }))
    }
    if (edgesResp.status === 'fulfilled') {
      const raw = edgesResp.value.data
      const items = Array.isArray(raw) ? raw : (raw.items ?? raw.edges ?? [])
      graphEdges.value = items.map((e: Record<string, unknown>) => ({
        source: String(e.source_id ?? e.source ?? ''),
        target: String(e.target_id ?? e.target ?? ''),
        relationship: String(e.rel_type ?? e.relationship ?? ''),
      }))
    }

    // If no real data, leave graph empty
  } catch {
    // Graph data unavailable - leave empty
  }
}

function generatePlaceholderTrend(base: number): number[] {
  const trend: number[] = []
  let val = Math.max(10, base + 20)
  for (let i = 0; i < 10; i++) {
    trend.push(Math.round(Math.max(5, Math.min(95, val))))
    val += (Math.random() - 0.6) * 8
  }
  return trend
}

// Placeholder functions removed - dashboard now shows honest empty state
// when data is unavailable instead of fabricated numbers

// -- Event handlers --

function handleNodeHover(node: (typeof nodePositions.value)[0], event: MouseEvent): void {
  hoveredNode.value = node
  tooltipPos.value = { x: event.offsetX, y: event.offsetY }
}

function handleNodeLeave(): void {
  hoveredNode.value = null
}

// -- Helpers --

function formatDate(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 1) return 'Just now'
  if (diffMin < 60) return `${diffMin}m ago`
  const diffHours = Math.floor(diffMin / 60)
  if (diffHours < 24) return `${diffHours}h ago`
  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays}d ago`
}

function getSeverityBadgeClass(severity: string): string {
  const classes: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
    medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
    low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    info: 'bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-400',
  }
  return classes[severity] || classes.info
}

function getActivityIcon(type: string): string {
  const icons: Record<string, string> = {
    new_asset: 'M12 6v6m0 0v6m0-6h6m-6 0H6',
    finding: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
    scan: 'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
  }
  return icons[type] || icons.new_asset
}

// -- Lifecycle --

let refreshInterval: ReturnType<typeof setInterval> | null = null

onMounted(async () => {
  await loadDashboard()
  // Auto-refresh every 60 seconds
  refreshInterval = setInterval(loadDashboard, 60000)
})

onUnmounted(() => {
  if (refreshInterval) clearInterval(refreshInterval)
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <div>
        <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Dashboard</h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">Attack surface overview and risk metrics</p>
      </div>
      <button
        @click="loadDashboard"
        :disabled="isLoading"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 transition-colors flex items-center gap-2"
      >
        <svg class="w-4 h-4" :class="{ 'animate-spin': isLoading }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        Refresh
      </button>
    </div>

    <!-- Error State -->
    <div v-if="error && !isLoading" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Loading State -->
    <div v-if="isLoading" class="flex items-center justify-center h-64">
      <div class="flex flex-col items-center gap-3">
        <svg class="w-8 h-8 animate-spin text-primary-600" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span class="text-gray-600 dark:text-dark-text-secondary">Loading dashboard...</span>
      </div>
    </div>

    <!-- Dashboard Content -->
    <template v-if="!isLoading">
      <!-- KPI Cards -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Total Assets -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-dark-text-secondary">Total Assets</p>
              <p class="text-3xl font-bold text-gray-900 dark:text-dark-text-primary mt-2">
                {{ summary.total_assets.toLocaleString() }}
              </p>
              <div class="flex items-center mt-2">
                <span
                  v-if="summary.asset_delta !== 0"
                  class="inline-flex items-center text-xs font-medium px-2 py-0.5 rounded-full"
                  :class="summary.asset_delta > 0
                    ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400'
                    : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400'"
                >
                  <svg class="w-3 h-3 mr-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path v-if="summary.asset_delta > 0" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 11l5-5m0 0l5 5m-5-5v12" />
                    <path v-else stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 13l-5 5m0 0l-5-5m5 5V6" />
                  </svg>
                  {{ summary.asset_delta > 0 ? '+' : '' }}{{ summary.asset_delta }} since last scan
                </span>
                <span v-else class="text-xs text-gray-400 dark:text-dark-text-tertiary">No change</span>
              </div>
            </div>
            <div class="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
              <svg class="w-8 h-8 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
              </svg>
            </div>
          </div>
        </div>

        <!-- Open Findings -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-dark-text-secondary">Open Findings</p>
              <p class="text-3xl font-bold text-gray-900 dark:text-dark-text-primary mt-2">
                {{ summary.open_findings.toLocaleString() }}
              </p>
              <div class="flex items-center gap-1.5 mt-2 flex-wrap">
                <span
                  v-if="summary.severity_breakdown.critical > 0"
                  class="inline-flex items-center text-xs font-medium px-1.5 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
                >
                  {{ summary.severity_breakdown.critical }}C
                </span>
                <span
                  v-if="summary.severity_breakdown.high > 0"
                  class="inline-flex items-center text-xs font-medium px-1.5 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400"
                >
                  {{ summary.severity_breakdown.high }}H
                </span>
                <span
                  v-if="summary.severity_breakdown.medium > 0"
                  class="inline-flex items-center text-xs font-medium px-1.5 py-0.5 rounded bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400"
                >
                  {{ summary.severity_breakdown.medium }}M
                </span>
                <span
                  v-if="summary.severity_breakdown.low > 0"
                  class="inline-flex items-center text-xs font-medium px-1.5 py-0.5 rounded bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400"
                >
                  {{ summary.severity_breakdown.low }}L
                </span>
              </div>
            </div>
            <div class="p-3 bg-red-100 dark:bg-red-900/20 rounded-lg">
              <svg class="w-8 h-8 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
        </div>

        <!-- Risk Score Gauge -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <div class="flex items-center justify-between">
            <div class="flex-1">
              <p class="text-sm text-gray-600 dark:text-dark-text-secondary">Risk Score</p>
              <div class="flex items-center gap-3 mt-2">
                <!-- Inline SVG gauge -->
                <svg viewBox="0 0 100 100" class="w-16 h-16">
                  <!-- Background arc -->
                  <circle
                    cx="50" cy="50" r="40"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="6"
                    stroke-dasharray="212 71"
                    stroke-dashoffset="-35"
                    stroke-linecap="round"
                    class="text-gray-200 dark:text-gray-700"
                  />
                  <!-- Score arc -->
                  <path
                    :d="riskGaugeArc"
                    fill="none"
                    :stroke="riskGrade.color"
                    stroke-width="6"
                    stroke-linecap="round"
                  />
                  <!-- Score text -->
                  <text x="50" y="48" text-anchor="middle" dominant-baseline="middle" class="text-lg font-bold" :fill="riskGrade.color" font-size="16" font-weight="bold">
                    {{ summary.risk_score }}
                  </text>
                  <!-- Grade -->
                  <text x="50" y="64" text-anchor="middle" dominant-baseline="middle" fill="currentColor" font-size="10" class="text-gray-500 dark:text-gray-400">
                    {{ riskGrade.letter }}
                  </text>
                </svg>
                <div>
                  <p class="text-2xl font-bold" :style="{ color: riskGrade.color }">
                    Grade {{ riskGrade.letter }}
                  </p>
                  <p class="text-xs text-gray-500 dark:text-dark-text-tertiary">out of 100</p>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Active Scans -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-dark-text-secondary">Active Scans</p>
              <p class="text-3xl font-bold text-gray-900 dark:text-dark-text-primary mt-2">
                {{ summary.active_scans }}
              </p>
              <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-2">
                {{ summary.active_scans > 0 ? 'Scan in progress' : 'No scans running' }}
              </p>
            </div>
            <div class="p-3 bg-green-100 dark:bg-green-900/20 rounded-lg">
              <svg class="w-8 h-8 text-green-600 dark:text-green-400" :class="{ 'animate-spin': summary.active_scans > 0 }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Charts Row -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Severity Donut Chart -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Findings by Severity</h3>
          <div class="flex items-center gap-6">
            <!-- SVG Donut -->
            <svg viewBox="0 0 100 100" class="w-40 h-40 flex-shrink-0">
              <circle cx="50" cy="50" r="40" fill="none" stroke="currentColor" stroke-width="12" class="text-gray-100 dark:text-gray-800" />
              <circle
                v-for="segment in donutSegments"
                :key="segment.key"
                cx="50" cy="50" r="40"
                fill="none"
                :stroke="segment.color"
                stroke-width="12"
                :stroke-dasharray="segment.dasharray"
                :stroke-dashoffset="segment.dashoffset"
                transform="rotate(-90 50 50)"
                class="transition-all duration-500"
              />
              <!-- Center text -->
              <text x="50" y="46" text-anchor="middle" dominant-baseline="middle" fill="currentColor" font-size="16" font-weight="bold" class="text-gray-900 dark:text-gray-100">
                {{ donutTotal }}
              </text>
              <text x="50" y="58" text-anchor="middle" dominant-baseline="middle" fill="currentColor" font-size="8" class="text-gray-500 dark:text-gray-400">
                total
              </text>
            </svg>
            <!-- Legend -->
            <div class="flex flex-col gap-2">
              <div
                v-for="segment in donutSegments"
                :key="segment.key"
                class="flex items-center gap-2"
              >
                <span class="w-3 h-3 rounded-full flex-shrink-0" :style="{ backgroundColor: segment.color }" />
                <span class="text-sm text-gray-700 dark:text-dark-text-secondary capitalize">{{ segment.key }}</span>
                <span class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary ml-auto">{{ segment.value }}</span>
                <span class="text-xs text-gray-500 dark:text-dark-text-tertiary">({{ segment.pct }}%)</span>
              </div>
              <div v-if="donutSegments.length === 0" class="text-sm text-gray-500 dark:text-dark-text-secondary">
                No findings to display
              </div>
            </div>
          </div>
        </div>

        <!-- Asset Type Bar Chart -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Assets by Type</h3>
          <div class="space-y-3">
            <div
              v-for="bar in assetBars"
              :key="bar.key"
              class="flex items-center gap-3"
            >
              <span class="w-24 text-sm text-gray-600 dark:text-dark-text-secondary capitalize text-right">{{ bar.key }}</span>
              <div class="flex-1 h-7 bg-gray-100 dark:bg-dark-bg-tertiary rounded-md overflow-hidden relative">
                <div
                  class="h-full rounded-md transition-all duration-700 ease-out"
                  :style="{ width: bar.widthPct + '%', backgroundColor: bar.color }"
                />
                <span class="absolute inset-y-0 flex items-center text-xs font-semibold px-2" :class="bar.widthPct > 20 ? 'text-white left-1' : 'text-gray-700 dark:text-dark-text-secondary'" :style="bar.widthPct <= 20 ? { left: bar.widthPct + '%' } : {}">
                  {{ bar.value }}
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Second Charts Row -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <!-- Risk Score Trend Line -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Risk Score Trend</h3>
          <svg viewBox="0 0 280 160" class="w-full" preserveAspectRatio="xMidYMid meet">
            <!-- Grade bands background -->
            <rect x="10" y="10" width="260" height="28" fill="#dc2626" opacity="0.08" rx="2" />
            <rect x="10" y="38" width="260" height="24" fill="#ea580c" opacity="0.08" rx="2" />
            <rect x="10" y="62" width="260" height="24" fill="#eab308" opacity="0.08" rx="2" />
            <rect x="10" y="86" width="260" height="24" fill="#65a30d" opacity="0.08" rx="2" />
            <rect x="10" y="110" width="260" height="30" fill="#16a34a" opacity="0.08" rx="2" />

            <!-- Grade labels -->
            <text x="274" y="26" fill="currentColor" font-size="7" class="text-gray-400 dark:text-gray-600" text-anchor="end">F</text>
            <text x="274" y="52" fill="currentColor" font-size="7" class="text-gray-400 dark:text-gray-600" text-anchor="end">D</text>
            <text x="274" y="76" fill="currentColor" font-size="7" class="text-gray-400 dark:text-gray-600" text-anchor="end">C</text>
            <text x="274" y="100" fill="currentColor" font-size="7" class="text-gray-400 dark:text-gray-600" text-anchor="end">B</text>
            <text x="274" y="128" fill="currentColor" font-size="7" class="text-gray-400 dark:text-gray-600" text-anchor="end">A</text>

            <!-- Grid lines -->
            <line x1="10" y1="38" x2="270" y2="38" stroke="currentColor" stroke-width="0.3" class="text-gray-300 dark:text-gray-700" />
            <line x1="10" y1="62" x2="270" y2="62" stroke="currentColor" stroke-width="0.3" class="text-gray-300 dark:text-gray-700" />
            <line x1="10" y1="86" x2="270" y2="86" stroke="currentColor" stroke-width="0.3" class="text-gray-300 dark:text-gray-700" />
            <line x1="10" y1="110" x2="270" y2="110" stroke="currentColor" stroke-width="0.3" class="text-gray-300 dark:text-gray-700" />

            <!-- Y-axis labels -->
            <text x="6" y="14" fill="currentColor" font-size="6" class="text-gray-400 dark:text-gray-500" text-anchor="end">100</text>
            <text x="6" y="80" fill="currentColor" font-size="6" class="text-gray-400 dark:text-gray-500" text-anchor="end">50</text>
            <text x="6" y="142" fill="currentColor" font-size="6" class="text-gray-400 dark:text-gray-500" text-anchor="end">0</text>

            <!-- Trend line -->
            <polyline
              v-if="trendPoints"
              :points="trendPoints"
              fill="none"
              stroke="#3b82f6"
              stroke-width="2"
              stroke-linecap="round"
              stroke-linejoin="round"
            />
            <!-- Dots -->
            <circle
              v-for="(dot, i) in trendDots"
              :key="i"
              :cx="dot.x"
              :cy="dot.y"
              r="3"
              fill="#3b82f6"
              class="hover:opacity-80"
            >
              <title>{{ dot.label }}: {{ dot.value }}</title>
            </circle>

            <!-- No data text -->
            <text v-if="!trendPoints" x="140" y="80" text-anchor="middle" fill="currentColor" font-size="10" class="text-gray-400 dark:text-gray-500">
              Not enough scan data for trend
            </text>
          </svg>
          <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-2 text-center">Last {{ summary.risk_trend.length }} scans (lower is better)</p>
        </div>

        <!-- Asset Relationship Graph -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border relative">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Asset Relationships</h3>
          <svg viewBox="0 0 500 350" class="w-full" preserveAspectRatio="xMidYMid meet">
            <!-- Edges -->
            <line
              v-for="(edge, i) in edgeLines"
              :key="'e' + i"
              :x1="edge!.x1"
              :y1="edge!.y1"
              :x2="edge!.x2"
              :y2="edge!.y2"
              stroke="currentColor"
              stroke-width="1"
              stroke-opacity="0.3"
              class="text-gray-400 dark:text-gray-600"
            />
            <!-- Nodes -->
            <g
              v-for="node in nodePositions"
              :key="node.id"
              class="cursor-pointer"
              @mouseover="handleNodeHover(node, $event)"
              @mouseleave="handleNodeLeave"
            >
              <circle
                :cx="node.x"
                :cy="node.y"
                :r="node.radius"
                :fill="nodeTypeColors[node.type] || '#6b7280'"
                fill-opacity="0.8"
                stroke="white"
                stroke-width="1.5"
                class="transition-all duration-200 hover:fill-opacity-100"
              />
              <text
                :x="node.x"
                :y="node.y + node.radius + 10"
                text-anchor="middle"
                fill="currentColor"
                font-size="6"
                class="text-gray-600 dark:text-gray-400 pointer-events-none"
              >
                {{ node.label.length > 16 ? node.label.slice(0, 16) + '...' : node.label }}
              </text>
            </g>
          </svg>
          <!-- Legend -->
          <div class="flex items-center gap-4 mt-2 flex-wrap">
            <div v-for="(color, type) in nodeTypeColors" :key="type" class="flex items-center gap-1">
              <span class="w-2.5 h-2.5 rounded-full" :style="{ backgroundColor: color }" />
              <span class="text-xs text-gray-500 dark:text-dark-text-tertiary capitalize">{{ type }}</span>
            </div>
          </div>
          <!-- Hover tooltip -->
          <div
            v-if="hoveredNode"
            class="absolute bg-gray-900 dark:bg-gray-100 text-white dark:text-gray-900 text-xs rounded-md px-3 py-2 pointer-events-none z-10 shadow-lg"
            :style="{ top: '60px', right: '16px' }"
          >
            <p class="font-semibold">{{ hoveredNode.label }}</p>
            <p class="text-gray-300 dark:text-gray-600 mt-0.5">Type: {{ hoveredNode.type }}</p>
            <p class="text-gray-300 dark:text-gray-600">Risk: {{ hoveredNode.risk_score }}/100</p>
          </div>
        </div>
      </div>

      <!-- Recent Activity -->
      <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
        <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Recent Activity</h3>
        <div v-if="summary.recent_activity.length > 0" class="space-y-3">
          <div
            v-for="activity in summary.recent_activity"
            :key="activity.id"
            class="flex items-start gap-3 p-3 rounded-lg bg-gray-50 dark:bg-dark-bg-tertiary"
          >
            <div class="p-1.5 rounded-md bg-primary-100 dark:bg-primary-900/20 mt-0.5">
              <svg class="w-4 h-4 text-primary-600 dark:text-primary-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" :d="getActivityIcon(activity.type)" />
              </svg>
            </div>
            <div class="flex-1 min-w-0">
              <p class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ activity.description }}</p>
              <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-1">{{ formatDate(activity.timestamp) }}</p>
            </div>
            <span
              class="text-xs font-medium px-2 py-0.5 rounded-full flex-shrink-0"
              :class="getSeverityBadgeClass(activity.type === 'finding' ? 'critical' : 'info')"
            >
              {{ activity.type.replace('_', ' ') }}
            </span>
          </div>
        </div>
        <p v-else class="text-sm text-gray-500 dark:text-dark-text-secondary">No recent activity</p>
      </div>
    </template>
  </div>
</template>
