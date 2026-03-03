<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'
import { formatDate } from '@/utils/formatters'

// -- Types --

interface ExposedAssetItem {
  id: number
  identifier: string
  type: string
  risk_score: number
  open_findings_count: number
  highest_severity: string | null
  services_count: number
  last_seen: string | null
}

interface ExposureSummary {
  total_exposed_assets: number
  total_assets: number
  severity_breakdown: Record<string, number>
  exposure_score: number
  most_exposed: ExposedAssetItem[]
}

interface ExposureChangeItem {
  id: number
  asset_id: number
  asset_identifier: string
  finding_name: string
  severity: string
  change_type: string
  detected_at: string
}

interface ExposureChanges {
  period: string
  new_exposures: ExposureChangeItem[]
  resolved_exposures: ExposureChangeItem[]
  new_count: number
  resolved_count: number
}

interface ExposedAssetListResponse {
  items: ExposedAssetItem[]
  total: number
  page: number
  page_size: number
  total_pages: number
}

// -- State --

const tenantStore = useTenantStore()
const currentTenantId = computed(() => tenantStore.currentTenantId)

const isLoading = ref(true)
const error = ref('')

const summary = ref<ExposureSummary>({
  total_exposed_assets: 0,
  total_assets: 0,
  severity_breakdown: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  exposure_score: 0,
  most_exposed: [],
})

const assetList = ref<ExposedAssetListResponse>({
  items: [],
  total: 0,
  page: 1,
  page_size: 50,
  total_pages: 0,
})

const changes = ref<ExposureChanges>({
  period: '24h',
  new_exposures: [],
  resolved_exposures: [],
  new_count: 0,
  resolved_count: 0,
})

// Filters
const filterType = ref('')
const filterSeverity = ref('')
const filterSearch = ref('')
const sortBy = ref('risk_score')
const sortOrder = ref('desc')
const changesPeriod = ref('24h')
const currentPage = ref(1)

// -- Computed --

const exposurePercent = computed(() => {
  if (summary.value.total_assets === 0) return 0
  return Math.round(
    (summary.value.total_exposed_assets / summary.value.total_assets) * 100
  )
})

const exposureScoreColor = computed(() => {
  const s = summary.value.exposure_score
  if (s >= 80) return '#dc2626'
  if (s >= 60) return '#ea580c'
  if (s >= 40) return '#eab308'
  if (s >= 20) return '#65a30d'
  return '#16a34a'
})

const exposureGaugeArc = computed(() => {
  const score = Math.min(100, Math.max(0, summary.value.exposure_score))
  const angle = (score / 100) * 270
  const startAngle = 135
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

// -- API calls --

async function loadSummary(): Promise<void> {
  if (!currentTenantId.value) return

  try {
    const response = await apiClient.get<ExposureSummary>(
      `/api/v1/tenants/${currentTenantId.value}/exposure/summary`
    )
    summary.value = response.data
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to load exposure summary'
    error.value = message
  }
}

async function loadAssets(): Promise<void> {
  if (!currentTenantId.value) return

  const params: Record<string, string | number> = {
    page: currentPage.value,
    page_size: 50,
    sort_by: sortBy.value,
    sort_order: sortOrder.value,
  }

  if (filterType.value) params.asset_type = filterType.value
  if (filterSeverity.value) params.min_severity = filterSeverity.value
  if (filterSearch.value) params.search = filterSearch.value

  try {
    const response = await apiClient.get<ExposedAssetListResponse>(
      `/api/v1/tenants/${currentTenantId.value}/exposure/assets`,
      { params }
    )
    assetList.value = response.data
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to load exposed assets'
    error.value = message
  }
}

async function loadChanges(): Promise<void> {
  if (!currentTenantId.value) return

  try {
    const response = await apiClient.get<ExposureChanges>(
      `/api/v1/tenants/${currentTenantId.value}/exposure/changes`,
      { params: { period: changesPeriod.value } }
    )
    changes.value = response.data
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to load exposure changes'
    error.value = message
  }
}

async function loadAll(): Promise<void> {
  isLoading.value = true
  error.value = ''

  try {
    await Promise.all([loadSummary(), loadAssets(), loadChanges()])
  } catch {
    // Individual errors already handled
  } finally {
    isLoading.value = false
  }
}

function applyFilters(): void {
  currentPage.value = 1
  loadAssets()
}

function changePage(page: number): void {
  currentPage.value = page
  loadAssets()
}

function changeSort(field: string): void {
  if (sortBy.value === field) {
    sortOrder.value = sortOrder.value === 'desc' ? 'asc' : 'desc'
  } else {
    sortBy.value = field
    sortOrder.value = 'desc'
  }
  currentPage.value = 1
  loadAssets()
}

function onPeriodChange(): void {
  loadChanges()
}

// -- Helpers --

function severityBadgeClass(severity: string): string {
  const classes: Record<string, string> = {
    critical: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
    high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
    medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
    low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    info: 'bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-400',
  }
  return classes[severity] || classes.info
}

function severityCardColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'border-red-200 dark:border-red-800',
    high: 'border-orange-200 dark:border-orange-800',
    medium: 'border-yellow-200 dark:border-yellow-800',
    low: 'border-blue-200 dark:border-blue-800',
  }
  return colors[severity] || 'border-gray-200 dark:border-dark-border'
}

function severityIconColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'text-red-600 dark:text-red-400 bg-red-100 dark:bg-red-900/20',
    high: 'text-orange-600 dark:text-orange-400 bg-orange-100 dark:bg-orange-900/20',
    medium: 'text-yellow-600 dark:text-yellow-400 bg-yellow-100 dark:bg-yellow-900/20',
    low: 'text-blue-600 dark:text-blue-400 bg-blue-100 dark:bg-blue-900/20',
  }
  return colors[severity] || 'text-gray-600 dark:text-gray-400 bg-gray-100 dark:bg-gray-700/20'
}

function sortIndicator(field: string): string {
  if (sortBy.value !== field) return ''
  return sortOrder.value === 'desc' ? ' \u2193' : ' \u2191'
}

// -- Lifecycle --

onMounted(async () => {
  await loadAll()
})

watch(currentTenantId, () => {
  if (currentTenantId.value) {
    currentPage.value = 1
    loadAll()
  }
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <div>
        <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Exposure Management</h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">
          Track and manage your attack surface exposure posture
        </p>
      </div>
      <button
        @click="loadAll"
        :disabled="isLoading"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 transition-colors flex items-center gap-2"
      >
        <svg aria-hidden="true" class="w-4 h-4" :class="{ 'animate-spin': isLoading }" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
        Refresh
      </button>
    </div>

    <!-- Error -->
    <div v-if="error && !isLoading" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Loading -->
    <div v-if="isLoading" class="flex items-center justify-center h-64">
      <div class="flex flex-col items-center gap-3">
        <svg class="w-8 h-8 animate-spin text-primary-600" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span class="text-gray-600 dark:text-dark-text-secondary">Loading exposure data...</span>
      </div>
    </div>

    <!-- Content -->
    <template v-if="!isLoading">
      <!-- Summary Cards Row -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <!-- Total Exposed -->
        <div class="bg-white dark:bg-dark-bg-secondary p-5 rounded-lg border border-gray-200 dark:border-dark-border">
          <p class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Total Exposed</p>
          <p class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary mt-2">
            {{ summary.total_exposed_assets }}
            <span class="text-sm font-normal text-gray-500 dark:text-dark-text-tertiary">
              / {{ summary.total_assets }}
            </span>
          </p>
          <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-1">
            {{ exposurePercent }}% of assets exposed
          </p>
        </div>

        <!-- Critical -->
        <div class="bg-white dark:bg-dark-bg-secondary p-5 rounded-lg border-l-4" :class="severityCardColor('critical')">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Critical</p>
              <p class="text-2xl font-bold text-red-600 dark:text-red-400 mt-2">
                {{ summary.severity_breakdown.critical || 0 }}
              </p>
            </div>
            <div class="p-2 rounded-lg" :class="severityIconColor('critical')">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
          </div>
        </div>

        <!-- High -->
        <div class="bg-white dark:bg-dark-bg-secondary p-5 rounded-lg border-l-4" :class="severityCardColor('high')">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">High</p>
              <p class="text-2xl font-bold text-orange-600 dark:text-orange-400 mt-2">
                {{ summary.severity_breakdown.high || 0 }}
              </p>
            </div>
            <div class="p-2 rounded-lg" :class="severityIconColor('high')">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
        </div>

        <!-- Medium -->
        <div class="bg-white dark:bg-dark-bg-secondary p-5 rounded-lg border-l-4" :class="severityCardColor('medium')">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Medium</p>
              <p class="text-2xl font-bold text-yellow-600 dark:text-yellow-400 mt-2">
                {{ summary.severity_breakdown.medium || 0 }}
              </p>
            </div>
            <div class="p-2 rounded-lg" :class="severityIconColor('medium')">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
        </div>

        <!-- Low -->
        <div class="bg-white dark:bg-dark-bg-secondary p-5 rounded-lg border-l-4" :class="severityCardColor('low')">
          <div class="flex items-center justify-between">
            <div>
              <p class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Low</p>
              <p class="text-2xl font-bold text-blue-600 dark:text-blue-400 mt-2">
                {{ summary.severity_breakdown.low || 0 }}
              </p>
            </div>
            <div class="p-2 rounded-lg" :class="severityIconColor('low')">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          </div>
        </div>
      </div>

      <!-- Exposure Score Gauge + Most Exposed -->
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Exposure Score Gauge -->
        <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Exposure Score</h3>
          <div class="flex flex-col items-center">
            <svg viewBox="0 0 100 100" class="w-40 h-40">
              <!-- Background arc -->
              <circle
                cx="50" cy="50" r="40"
                fill="none"
                stroke="currentColor"
                stroke-width="8"
                stroke-dasharray="212 71"
                stroke-dashoffset="-35"
                stroke-linecap="round"
                class="text-gray-200 dark:text-gray-700"
              />
              <!-- Score arc -->
              <path
                :d="exposureGaugeArc"
                fill="none"
                :stroke="exposureScoreColor"
                stroke-width="8"
                stroke-linecap="round"
              />
              <!-- Score text -->
              <text
                x="50" y="46" text-anchor="middle" dominant-baseline="middle"
                :fill="exposureScoreColor" font-size="20" font-weight="bold"
              >
                {{ Math.round(summary.exposure_score) }}
              </text>
              <text
                x="50" y="62" text-anchor="middle" dominant-baseline="middle"
                fill="currentColor" font-size="9"
                class="text-gray-500 dark:text-gray-400"
              >
                out of 100
              </text>
            </svg>
            <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-2 text-center">
              {{ summary.exposure_score <= 20 ? 'Low exposure' : summary.exposure_score <= 40 ? 'Moderate exposure' : summary.exposure_score <= 60 ? 'Elevated exposure' : summary.exposure_score <= 80 ? 'High exposure' : 'Critical exposure' }}
            </p>
          </div>
        </div>

        <!-- Most Exposed Assets -->
        <div class="lg:col-span-2 bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Most Exposed Assets</h3>
          <div v-if="summary.most_exposed.length > 0" class="space-y-2">
            <div
              v-for="asset in summary.most_exposed.slice(0, 8)"
              :key="'me-' + asset.id"
              class="flex items-center justify-between py-2 px-3 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
            >
              <div class="flex items-center gap-3 min-w-0">
                <span
                  class="inline-flex items-center justify-center px-2 py-0.5 text-[10px] font-semibold rounded uppercase"
                  :class="severityBadgeClass(asset.highest_severity || 'info')"
                >
                  {{ asset.highest_severity || 'N/A' }}
                </span>
                <div class="min-w-0">
                  <p class="text-sm font-medium text-gray-900 dark:text-dark-text-primary truncate">{{ asset.identifier }}</p>
                  <p class="text-xs text-gray-500 dark:text-dark-text-tertiary capitalize">{{ asset.type }}</p>
                </div>
              </div>
              <div class="flex items-center gap-4 flex-shrink-0">
                <div class="text-right">
                  <p class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">{{ asset.risk_score }}</p>
                  <p class="text-[10px] text-gray-500 dark:text-dark-text-tertiary">risk</p>
                </div>
                <div class="text-right">
                  <p class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">{{ asset.open_findings_count }}</p>
                  <p class="text-[10px] text-gray-500 dark:text-dark-text-tertiary">findings</p>
                </div>
              </div>
            </div>
          </div>
          <p v-else class="text-sm text-gray-500 dark:text-dark-text-secondary text-center py-8">
            No exposed assets found
          </p>
        </div>
      </div>

      <!-- Exposed Assets Table -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border">
        <div class="p-4 border-b border-gray-200 dark:border-dark-border">
          <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Exposed Assets</h3>
            <div class="flex items-center gap-2 flex-wrap">
              <!-- Search -->
              <input
                v-model="filterSearch"
                type="text"
                placeholder="Search assets..."
                class="px-3 py-1.5 text-sm border border-gray-300 dark:border-dark-border rounded-md bg-white dark:bg-dark-bg-tertiary text-gray-900 dark:text-dark-text-primary placeholder-gray-400 focus:outline-none focus:ring-1 focus:ring-primary-500 w-48"
                @keydown.enter="applyFilters"
              />
              <!-- Type filter -->
              <select
                v-model="filterType"
                class="px-3 py-1.5 text-sm border border-gray-300 dark:border-dark-border rounded-md bg-white dark:bg-dark-bg-tertiary text-gray-900 dark:text-dark-text-primary focus:outline-none focus:ring-1 focus:ring-primary-500"
                @change="applyFilters"
              >
                <option value="">All Types</option>
                <option value="domain">Domain</option>
                <option value="subdomain">Subdomain</option>
                <option value="ip">IP</option>
                <option value="url">URL</option>
                <option value="service">Service</option>
              </select>
              <!-- Severity filter -->
              <select
                v-model="filterSeverity"
                class="px-3 py-1.5 text-sm border border-gray-300 dark:border-dark-border rounded-md bg-white dark:bg-dark-bg-tertiary text-gray-900 dark:text-dark-text-primary focus:outline-none focus:ring-1 focus:ring-primary-500"
                @change="applyFilters"
              >
                <option value="">All Severities</option>
                <option value="critical">Critical+</option>
                <option value="high">High+</option>
                <option value="medium">Medium+</option>
                <option value="low">Low+</option>
              </select>
              <button
                @click="applyFilters"
                class="px-3 py-1.5 text-sm font-medium bg-primary-600 text-white rounded-md hover:bg-primary-700"
              >
                Filter
              </button>
            </div>
          </div>
        </div>

        <!-- Table -->
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="border-b border-gray-200 dark:border-dark-border bg-gray-50 dark:bg-dark-bg-tertiary">
                <th
                  class="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-dark-text-secondary uppercase tracking-wider cursor-pointer hover:text-gray-900 dark:hover:text-dark-text-primary"
                >
                  Asset
                </th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-dark-text-secondary uppercase tracking-wider">
                  Type
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-dark-text-secondary uppercase tracking-wider cursor-pointer hover:text-gray-900 dark:hover:text-dark-text-primary"
                  @click="changeSort('risk_score')"
                >
                  Risk Score{{ sortIndicator('risk_score') }}
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-dark-text-secondary uppercase tracking-wider cursor-pointer hover:text-gray-900 dark:hover:text-dark-text-primary"
                  @click="changeSort('findings_count')"
                >
                  Findings{{ sortIndicator('findings_count') }}
                </th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-dark-text-secondary uppercase tracking-wider">
                  Severity
                </th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-dark-text-secondary uppercase tracking-wider">
                  Services
                </th>
                <th class="px-4 py-3 text-left text-xs font-semibold text-gray-600 dark:text-dark-text-secondary uppercase tracking-wider">
                  Last Seen
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-200 dark:divide-dark-border">
              <tr
                v-for="asset in assetList.items"
                :key="'al-' + asset.id"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                <td class="px-4 py-3">
                  <router-link
                    :to="'/assets/' + asset.id"
                    class="text-sm font-medium text-primary-600 dark:text-primary-400 hover:underline truncate block max-w-xs"
                  >
                    {{ asset.identifier }}
                  </router-link>
                </td>
                <td class="px-4 py-3">
                  <span class="text-xs font-medium text-gray-600 dark:text-dark-text-secondary capitalize bg-gray-100 dark:bg-dark-bg-tertiary px-2 py-0.5 rounded">
                    {{ asset.type }}
                  </span>
                </td>
                <td class="px-4 py-3">
                  <div class="flex items-center gap-2">
                    <div class="w-16 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <div
                        class="h-full rounded-full transition-all duration-300"
                        :style="{
                          width: Math.min(100, asset.risk_score) + '%',
                          backgroundColor: asset.risk_score >= 80 ? '#dc2626' : asset.risk_score >= 60 ? '#ea580c' : asset.risk_score >= 40 ? '#eab308' : '#16a34a'
                        }"
                      ></div>
                    </div>
                    <span class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">{{ asset.risk_score }}</span>
                  </div>
                </td>
                <td class="px-4 py-3">
                  <span class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">{{ asset.open_findings_count }}</span>
                </td>
                <td class="px-4 py-3">
                  <span
                    v-if="asset.highest_severity"
                    class="inline-flex items-center text-xs font-semibold px-2 py-0.5 rounded capitalize"
                    :class="severityBadgeClass(asset.highest_severity)"
                  >
                    {{ asset.highest_severity }}
                  </span>
                  <span v-else class="text-xs text-gray-400">N/A</span>
                </td>
                <td class="px-4 py-3">
                  <span class="text-sm text-gray-700 dark:text-dark-text-secondary">{{ asset.services_count }}</span>
                </td>
                <td class="px-4 py-3">
                  <span class="text-xs text-gray-500 dark:text-dark-text-tertiary">{{ formatDate(asset.last_seen, 'relative') }}</span>
                </td>
              </tr>
              <tr v-if="assetList.items.length === 0">
                <td colspan="7" class="px-4 py-8 text-center text-sm text-gray-500 dark:text-dark-text-secondary">
                  No exposed assets match the current filters.
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        <div
          v-if="assetList.total_pages > 1"
          class="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-dark-border"
        >
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
            Showing {{ (assetList.page - 1) * assetList.page_size + 1 }} to
            {{ Math.min(assetList.page * assetList.page_size, assetList.total) }}
            of {{ assetList.total }} assets
          </p>
          <div class="flex items-center gap-1">
            <button
              :disabled="assetList.page <= 1"
              class="px-3 py-1 text-sm rounded border border-gray-300 dark:border-dark-border hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed"
              @click="changePage(assetList.page - 1)"
            >
              Previous
            </button>
            <span class="px-3 py-1 text-sm text-gray-700 dark:text-dark-text-secondary">
              {{ assetList.page }} / {{ assetList.total_pages }}
            </span>
            <button
              :disabled="assetList.page >= assetList.total_pages"
              class="px-3 py-1 text-sm rounded border border-gray-300 dark:border-dark-border hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed"
              @click="changePage(assetList.page + 1)"
            >
              Next
            </button>
          </div>
        </div>
      </div>

      <!-- Recent Changes Section -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border">
        <div class="p-4 border-b border-gray-200 dark:border-dark-border">
          <div class="flex items-center justify-between">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Recent Changes</h3>
            <div class="flex items-center gap-2">
              <select
                v-model="changesPeriod"
                class="px-3 py-1.5 text-sm border border-gray-300 dark:border-dark-border rounded-md bg-white dark:bg-dark-bg-tertiary text-gray-900 dark:text-dark-text-primary focus:outline-none focus:ring-1 focus:ring-primary-500"
                @change="onPeriodChange"
              >
                <option value="24h">Last 24 hours</option>
                <option value="7d">Last 7 days</option>
                <option value="30d">Last 30 days</option>
              </select>
            </div>
          </div>
          <div class="flex items-center gap-4 mt-2">
            <span class="inline-flex items-center gap-1.5 text-sm">
              <span class="w-2.5 h-2.5 rounded-full bg-red-500"></span>
              <span class="text-gray-700 dark:text-dark-text-secondary">{{ changes.new_count }} new</span>
            </span>
            <span class="inline-flex items-center gap-1.5 text-sm">
              <span class="w-2.5 h-2.5 rounded-full bg-green-500"></span>
              <span class="text-gray-700 dark:text-dark-text-secondary">{{ changes.resolved_count }} resolved</span>
            </span>
          </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-2 divide-y lg:divide-y-0 lg:divide-x divide-gray-200 dark:divide-dark-border">
          <!-- New Exposures -->
          <div class="p-4">
            <h4 class="text-sm font-semibold text-red-600 dark:text-red-400 mb-3 flex items-center gap-1.5">
              <svg aria-hidden="true" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
              New Exposures
            </h4>
            <div v-if="changes.new_exposures.length > 0" class="space-y-2 max-h-64 overflow-y-auto">
              <div
                v-for="item in changes.new_exposures"
                :key="'new-' + item.id"
                class="flex items-start gap-3 p-2 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <span
                  class="inline-flex items-center text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase mt-0.5 flex-shrink-0"
                  :class="severityBadgeClass(item.severity)"
                >
                  {{ item.severity }}
                </span>
                <div class="min-w-0">
                  <p class="text-sm font-medium text-gray-900 dark:text-dark-text-primary truncate">{{ item.finding_name }}</p>
                  <p class="text-xs text-gray-500 dark:text-dark-text-tertiary">
                    {{ item.asset_identifier }} -- {{ formatDate(item.detected_at, 'relative') }}
                  </p>
                </div>
              </div>
            </div>
            <p v-else class="text-sm text-gray-500 dark:text-dark-text-secondary text-center py-6">
              No new exposures in this period.
            </p>
          </div>

          <!-- Resolved Exposures -->
          <div class="p-4">
            <h4 class="text-sm font-semibold text-green-600 dark:text-green-400 mb-3 flex items-center gap-1.5">
              <svg aria-hidden="true" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Resolved Exposures
            </h4>
            <div v-if="changes.resolved_exposures.length > 0" class="space-y-2 max-h-64 overflow-y-auto">
              <div
                v-for="item in changes.resolved_exposures"
                :key="'res-' + item.id"
                class="flex items-start gap-3 p-2 rounded-lg hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <span
                  class="inline-flex items-center text-[10px] font-semibold px-1.5 py-0.5 rounded uppercase mt-0.5 flex-shrink-0"
                  :class="severityBadgeClass(item.severity)"
                >
                  {{ item.severity }}
                </span>
                <div class="min-w-0">
                  <p class="text-sm font-medium text-gray-900 dark:text-dark-text-primary truncate line-through decoration-green-500">{{ item.finding_name }}</p>
                  <p class="text-xs text-gray-500 dark:text-dark-text-tertiary">
                    {{ item.asset_identifier }} -- {{ formatDate(item.detected_at, 'relative') }}
                  </p>
                </div>
              </div>
            </div>
            <p v-else class="text-sm text-gray-500 dark:text-dark-text-secondary text-center py-6">
              No resolved exposures in this period.
            </p>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
