<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { findingApi } from '@/api/findings'
import { assetApi } from '@/api/assets'
import type { Finding, Asset } from '@/api/types'
import { ArrowLeftIcon } from '@heroicons/vue/24/outline'

const route = useRoute()
const router = useRouter()
const tenantStore = useTenantStore()

const findingId = computed(() => parseInt(route.params.id as string))
const finding = ref<Finding | null>(null)
const asset = ref<Asset | null>(null)
const isLoading = ref(true)
const error = ref('')

async function loadFindingDetails() {
  try {
    isLoading.value = true
    error.value = ''

    if (!tenantStore.currentTenantId) {
      await tenantStore.fetchTenants()
    }

    if (!tenantStore.currentTenantId) {
      error.value = 'No tenant available'
      return
    }

    // Fetch finding details by ID
    finding.value = await findingApi.get(tenantStore.currentTenantId, findingId.value)

    if (!finding.value) {
      error.value = 'Finding not found'
      return
    }

    // Fetch related asset by ID
    if (finding.value.asset_id) {
      try {
        asset.value = await assetApi.get(tenantStore.currentTenantId, finding.value.asset_id)
      } catch {
        // Asset may have been deleted
        asset.value = null
      }
    }

  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to load finding details'
  } finally {
    isLoading.value = false
  }
}

function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'bg-severity-critical text-white',
    high: 'bg-severity-high text-white',
    medium: 'bg-severity-medium text-white',
    low: 'bg-severity-low text-white',
    info: 'bg-severity-info text-white',
  }
  return colors[severity.toLowerCase()] || 'bg-gray-500 text-white'
}

function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    open: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300',
    suppressed: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-300',
    fixed: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300',
  }
  return colors[status.toLowerCase()] || 'bg-gray-100 text-gray-800 dark:bg-gray-900/30 dark:text-gray-300'
}

function formatDate(dateString: string): string {
  return new Date(dateString).toLocaleString()
}

// Threat intelligence helpers
const threatIntel = computed(() => finding.value?.evidence?.threat_intel as { epss_score?: number; is_kev?: boolean } | undefined)

const hasEpss = computed(() => threatIntel.value?.epss_score != null)
const hasKev = computed(() => threatIntel.value?.is_kev === true)
const hasThreatIntel = computed(() => hasEpss.value || hasKev.value)

const epssPercent = computed(() => {
  const score = threatIntel.value?.epss_score
  if (score == null) return 0
  return Math.round(score * 100)
})

const epssPercentExact = computed(() => {
  const score = threatIntel.value?.epss_score
  if (score == null) return '0.0'
  return (score * 100).toFixed(1)
})

function getEpssBarColor(score: number): string {
  if (score >= 0.7) return 'bg-red-500 dark:bg-red-400'
  if (score >= 0.4) return 'bg-orange-500 dark:bg-orange-400'
  if (score >= 0.1) return 'bg-yellow-500 dark:bg-yellow-400'
  return 'bg-green-500 dark:bg-green-400'
}

function getEpssTextColor(score: number): string {
  if (score >= 0.7) return 'text-red-700 dark:text-red-300'
  if (score >= 0.4) return 'text-orange-700 dark:text-orange-300'
  if (score >= 0.1) return 'text-yellow-700 dark:text-yellow-300'
  return 'text-green-700 dark:text-green-300'
}

function getEpssBgColor(score: number): string {
  if (score >= 0.7) return 'bg-red-50 dark:bg-red-900/10'
  if (score >= 0.4) return 'bg-orange-50 dark:bg-orange-900/10'
  if (score >= 0.1) return 'bg-yellow-50 dark:bg-yellow-900/10'
  return 'bg-green-50 dark:bg-green-900/10'
}

onMounted(() => {
  loadFindingDetails()
})
</script>

<template>
  <div>
    <!-- Header with back button -->
    <div class="mb-6 flex items-center">
      <button
        @click="router.push('/findings')"
        class="mr-4 p-2 rounded-md text-gray-500 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
      >
        <ArrowLeftIcon class="h-5 w-5" />
      </button>
      <div>
        <h1 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
          Finding Details
        </h1>
        <p v-if="finding" class="mt-1 text-sm text-gray-500 dark:text-dark-text-secondary">
          {{ finding.name }}
        </p>
      </div>
    </div>

    <!-- Error State -->
    <div v-if="error" class="rounded-md bg-red-50 dark:bg-red-900/20 p-4 mb-6">
      <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Loading State -->
    <div v-if="isLoading" class="bg-white dark:bg-dark-bg-secondary shadow rounded-lg p-8">
      <div class="animate-pulse space-y-4">
        <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-full"></div>
        <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4"></div>
      </div>
    </div>

    <!-- Finding Details -->
    <div v-else-if="finding" class="space-y-6">
      <!-- Overview Card -->
      <div class="bg-white dark:bg-dark-bg-secondary shadow rounded-lg p-6">
        <div class="flex items-start justify-between mb-4">
          <div class="flex items-center gap-3 flex-wrap">
            <span
              :class="['inline-flex items-center px-3 py-1 rounded-full text-sm font-medium', getSeverityColor(finding.severity)]"
            >
              {{ finding.severity.toUpperCase() }}
            </span>
            <span
              v-if="hasKev"
              class="inline-flex items-center px-2.5 py-1 rounded-full text-sm font-bold bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
              title="CISA Known Exploited Vulnerability"
            >
              KEV
            </span>
            <span
              :class="['inline-flex items-center px-3 py-1 rounded-full text-sm font-medium', getStatusColor(finding.status)]"
            >
              {{ finding.status }}
            </span>
            <span
              v-if="hasEpss"
              class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold"
              :class="getEpssTextColor(threatIntel!.epss_score!) + ' ' + getEpssBgColor(threatIntel!.epss_score!)"
              :title="`EPSS: ${epssPercentExact}% exploitation probability in next 30 days`"
            >
              EPSS: {{ epssPercentExact }}%
            </span>
          </div>
          <div class="flex items-center gap-3">
            <span v-if="finding.occurrence_count > 1"
              class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300"
              :title="`Detected ${finding.occurrence_count} times across scans`"
            >
              {{ finding.occurrence_count }}x seen
            </span>
            <span v-if="finding.cvss_score" class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">
              CVSS: {{ finding.cvss_score }}
            </span>
          </div>
        </div>

        <h2 class="text-xl font-semibold text-gray-900 dark:text-dark-text-primary mb-4">
          {{ finding.name }}
        </h2>

        <dl class="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div v-if="finding.cve_id">
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">CVE ID</dt>
            <dd class="mt-1 text-sm font-mono text-gray-900 dark:text-dark-text-primary">
              {{ finding.cve_id }}
            </dd>
          </div>
          <div>
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Source</dt>
            <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary capitalize">
              {{ finding.source }}
            </dd>
          </div>
          <div v-if="finding.template_id">
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Template ID</dt>
            <dd class="mt-1 text-sm font-mono text-gray-900 dark:text-dark-text-primary">
              {{ finding.template_id }}
            </dd>
          </div>
          <div v-if="finding.matcher_name">
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Matcher</dt>
            <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary">
              {{ finding.matcher_name }}
            </dd>
          </div>
          <div>
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">First Seen</dt>
            <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary">
              {{ formatDate(finding.first_seen) }}
            </dd>
          </div>
          <div>
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Last Seen</dt>
            <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary">
              {{ formatDate(finding.last_seen) }}
            </dd>
          </div>
          <div v-if="finding.host" class="sm:col-span-2">
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Host</dt>
            <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary">
              {{ finding.host }}
            </dd>
          </div>
          <div v-if="finding.matched_at" class="sm:col-span-2">
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Matched At</dt>
            <dd class="mt-1 text-sm text-blue-600 dark:text-blue-400 break-all">
              <a :href="finding.matched_at" target="_blank" rel="noopener">
                {{ finding.matched_at }}
              </a>
            </dd>
          </div>
        </dl>
      </div>

      <!-- Threat Intelligence -->
      <div v-if="hasThreatIntel" class="bg-white dark:bg-dark-bg-secondary shadow rounded-lg p-6">
        <h3 class="text-lg font-medium text-gray-900 dark:text-dark-text-primary mb-4">
          Threat Intelligence
        </h3>
        <div class="grid grid-cols-1 gap-6 sm:grid-cols-2">
          <!-- EPSS Score -->
          <div v-if="hasEpss" class="rounded-lg border border-gray-200 dark:border-dark-border p-4">
            <div class="flex items-center justify-between mb-2">
              <h4 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">
                EPSS Score
              </h4>
              <span
                class="text-lg font-bold"
                :class="getEpssTextColor(threatIntel!.epss_score!)"
              >
                {{ epssPercentExact }}%
              </span>
            </div>
            <!-- Progress bar -->
            <div class="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2.5 mb-3">
              <div
                class="h-2.5 rounded-full transition-all duration-300"
                :class="getEpssBarColor(threatIntel!.epss_score!)"
                :style="{ width: `${Math.max(epssPercent, 2)}%` }"
              ></div>
            </div>
            <!-- Explanation -->
            <p class="text-xs text-gray-500 dark:text-dark-text-secondary">
              The Exploit Prediction Scoring System (EPSS) estimates a
              <span class="font-medium" :class="getEpssTextColor(threatIntel!.epss_score!)">
                {{ epssPercentExact }}%
              </span>
              probability that this vulnerability will be exploited in the wild within the next 30 days.
            </p>
            <div
              v-if="threatIntel!.epss_score! >= 0.7"
              class="mt-2 flex items-center gap-1.5 text-xs font-medium text-red-700 dark:text-red-300"
            >
              <svg class="h-3.5 w-3.5 flex-shrink-0" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M8.485 2.495c.673-1.167 2.357-1.167 3.03 0l6.28 10.875c.673 1.167-.17 2.625-1.516 2.625H3.72c-1.347 0-2.189-1.458-1.515-2.625L8.485 2.495zM10 5a.75.75 0 01.75.75v3.5a.75.75 0 01-1.5 0v-3.5A.75.75 0 0110 5zm0 9a1 1 0 100-2 1 1 0 000 2z" clip-rule="evenodd" />
              </svg>
              High exploitation probability -- prioritize remediation.
            </div>
          </div>

          <!-- KEV Status -->
          <div v-if="hasKev" class="rounded-lg border border-red-200 dark:border-red-800/50 p-4" :class="getEpssBgColor(1)">
            <div class="flex items-center gap-2 mb-2">
              <span class="inline-flex items-center px-2.5 py-1 rounded-full text-sm font-bold bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300">
                KEV
              </span>
              <h4 class="text-sm font-semibold text-red-800 dark:text-red-300">
                Known Exploited Vulnerability
              </h4>
            </div>
            <div class="flex items-start gap-2 mt-3">
              <svg class="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fill-rule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a.75.75 0 000 1.5h.253a.25.25 0 01.244.304l-.459 2.066A1.75 1.75 0 0010.747 15H11a.75.75 0 000-1.5h-.253a.25.25 0 01-.244-.304l.459-2.066A1.75 1.75 0 009.253 9H9z" clip-rule="evenodd" />
              </svg>
              <p class="text-xs text-red-700 dark:text-red-300">
                This vulnerability is listed in CISA's Known Exploited Vulnerabilities (KEV) catalog,
                meaning it has been actively exploited in the wild. Federal agencies are mandated to
                remediate KEV entries within prescribed timelines. Immediate action is strongly recommended.
              </p>
            </div>
          </div>

          <!-- KEV not present, but EPSS is -- show a neutral KEV status -->
          <div v-if="hasEpss && !hasKev" class="rounded-lg border border-gray-200 dark:border-dark-border p-4">
            <div class="flex items-center gap-2 mb-2">
              <span class="inline-flex items-center px-2.5 py-1 rounded-full text-sm font-medium bg-gray-100 text-gray-600 dark:bg-gray-800 dark:text-gray-400">
                KEV
              </span>
              <h4 class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary">
                Not in KEV Catalog
              </h4>
            </div>
            <p class="text-xs text-gray-500 dark:text-dark-text-secondary mt-2">
              This vulnerability is not currently listed in CISA's Known Exploited Vulnerabilities catalog.
              It has not been confirmed as actively exploited, but should still be assessed based on EPSS
              score and severity.
            </p>
          </div>
        </div>
      </div>

      <!-- Evidence -->
      <div v-if="finding.evidence" class="bg-white dark:bg-dark-bg-secondary shadow rounded-lg p-6">
        <h3 class="text-lg font-medium text-gray-900 dark:text-dark-text-primary mb-4">
          Evidence
        </h3>
        <pre class="bg-gray-50 dark:bg-dark-bg-tertiary rounded-lg p-4 text-xs overflow-x-auto">
          <code class="text-gray-900 dark:text-dark-text-primary">{{ JSON.stringify(finding.evidence, null, 2) }}</code>
        </pre>
      </div>

      <!-- Related Asset -->
      <div v-if="asset" class="bg-white dark:bg-dark-bg-secondary shadow rounded-lg p-6">
        <h3 class="text-lg font-medium text-gray-900 dark:text-dark-text-primary mb-4">
          Related Asset
        </h3>
        <div
          @click="router.push(`/assets/${asset.id}`)"
          class="border border-gray-200 dark:border-dark-border rounded-lg p-4 cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
        >
          <div class="flex justify-between items-start">
            <div>
              <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">
                {{ asset.identifier }}
              </div>
              <div class="mt-1 text-xs text-gray-500 dark:text-dark-text-secondary capitalize">
                {{ asset.type }}
              </div>
            </div>
            <div class="text-right">
              <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">
                Risk: {{ asset.risk_score?.toFixed(1) || 'N/A' }}
              </div>
              <div class="mt-1">
                <span v-if="asset.is_active" class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-300">
                  Active
                </span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
