<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { useScanStore } from '@/stores/scans'
import type { PhaseStatus } from '@/stores/scans'
import { formatDate } from '@/utils/formatters'

const route = useRoute()
const router = useRouter()
const tenantStore = useTenantStore()
const scanStore = useScanStore()

const currentTenantId = computed(() => tenantStore.currentTenantId)
const runId = computed(() => Number(route.params.runId))

let refreshInterval: ReturnType<typeof setInterval> | null = null

const isRunning = computed(() => {
  return scanStore.currentScanRun?.status === 'running' || scanStore.currentScanRun?.status === 'pending'
})

const isCancelling = ref(false)

onMounted(async () => {
  await loadScanData()
  startAutoRefresh()
})

onUnmounted(() => {
  stopAutoRefresh()
})

watch(currentTenantId, async () => {
  if (currentTenantId.value) {
    await loadScanData()
  }
})

watch(isRunning, (running) => {
  if (running) {
    startAutoRefresh()
  } else {
    stopAutoRefresh()
  }
})

async function loadScanData(): Promise<void> {
  if (!runId.value) return
  // fetchProgress returns both scan_run and phases in one call
  await scanStore.fetchProgress(runId.value)
}

function startAutoRefresh(): void {
  stopAutoRefresh()
  if (isRunning.value) {
    refreshInterval = setInterval(async () => {
      await loadScanData()
    }, 4000)
  }
}

function stopAutoRefresh(): void {
  if (refreshInterval !== null) {
    clearInterval(refreshInterval)
    refreshInterval = null
  }
}

async function handleCancelScan(): Promise<void> {
  if (!scanStore.currentScanRun) return
  isCancelling.value = true
  await scanStore.cancelScan(scanStore.currentScanRun.id)
  isCancelling.value = false
}

function goBack(): void {
  router.push({ name: 'Scans' })
}

function getPhaseIcon(status: PhaseStatus): string {
  const icons: Record<PhaseStatus, string> = {
    pending: 'clock',
    running: 'spinner',
    completed: 'check',
    failed: 'x',
    skipped: 'dash',
  }
  return icons[status]
}

function getPhaseStatusClass(status: PhaseStatus): string {
  const classes: Record<PhaseStatus, string> = {
    pending: 'text-gray-400 dark:text-gray-500',
    running: 'text-blue-500 dark:text-blue-400',
    completed: 'text-green-500 dark:text-green-400',
    failed: 'text-red-500 dark:text-red-400',
    skipped: 'text-gray-400 dark:text-gray-500',
  }
  return classes[status]
}

function getPhaseStatusBadge(status: PhaseStatus): string {
  const classes: Record<PhaseStatus, string> = {
    pending: 'bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400',
    running: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
    completed: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
    failed: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400',
    skipped: 'bg-gray-100 text-gray-500 dark:bg-gray-700/30 dark:text-gray-400',
  }
  return classes[status]
}

function getRunStatusBadge(status: string): string {
  const classes: Record<string, string> = {
    pending: 'bg-gray-100 text-gray-800 dark:bg-gray-700/30 dark:text-gray-300',
    running: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
    completed: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
    failed: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400',
    cancelled: 'bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400',
  }
  return classes[status] || classes.pending
}

function formatPhaseDuration(phase: { started_at: string | null; completed_at: string | null }): string {
  if (!phase.started_at) return '-'
  const start = new Date(phase.started_at).getTime()
  const end = phase.completed_at ? new Date(phase.completed_at).getTime() : Date.now()
  const seconds = Math.floor((end - start) / 1000)

  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${minutes}m`
}

function formatTotalDuration(): string {
  const run = scanStore.currentScanRun
  if (!run?.started_at) return '-'
  const start = new Date(run.started_at).getTime()
  const end = run.completed_at ? new Date(run.completed_at).getTime() : Date.now()
  const seconds = Math.floor((end - start) / 1000)

  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const hours = Math.floor(seconds / 3600)
  const minutes = Math.floor((seconds % 3600) / 60)
  return `${hours}h ${minutes}m`
}

const PHASE_LABELS: Record<string, { name: string; description: string }> = {
  '0':   { name: 'Seed Ingestion',        description: 'Loading root domains and IP ranges' },
  '1':   { name: 'Passive Discovery',     description: 'Subdomain enumeration via Subfinder + crt.sh' },
  '1b':  { name: 'GitHub Dorking',        description: 'Searching leaked secrets and configs on GitHub' },
  '1c':  { name: 'WHOIS / RDAP',          description: 'Domain registration and ownership lookup' },
  '1d':  { name: 'Cloud Buckets',         description: 'Scanning for exposed S3/GCS/Azure buckets' },
  '1e':  { name: 'Cloud Enum',            description: 'Enumerating cloud assets via cloudlist (Tier 2+)' },
  '2':   { name: 'DNS Bruteforce',        description: 'DNS permutation & resolution via alterx + puredns (Tier 2+)' },
  '3':   { name: 'DNS Resolution',        description: 'Resolving A/AAAA/CNAME/MX records' },
  '4':   { name: 'HTTP Probing',          description: 'Probing live web servers with HTTPX' },
  '5':   { name: 'Port Scanning',         description: 'Discovering open ports via Naabu' },
  '5b':  { name: 'CDN/WAF Detection',     description: 'Detecting CDN, WAF and cloud providers via cdncheck' },
  '5c':  { name: 'Service Fingerprint',   description: 'Protocol-level service fingerprinting via fingerprintx (Tier 2+)' },
  '6':   { name: 'Fingerprinting',        description: 'Technology and service fingerprinting' },
  '6b':  { name: 'Web Crawling',          description: 'Crawling web pages with Katana' },
  '6c':  { name: 'Sensitive Paths',       description: 'Checking for exposed files and directories' },
  '7':   { name: 'Visual Recon',          description: 'Taking screenshots of live web pages' },
  '8':   { name: 'Misconfig Detection',   description: 'Checking for security misconfigurations' },
  '9':   { name: 'Vuln Scanning',         description: 'Running Nuclei vulnerability templates' },
  '10':  { name: 'Correlation',           description: 'Grouping findings into issues' },
  '11':  { name: 'Risk Scoring',          description: 'Calculating risk scores per asset' },
  '12':  { name: 'Diff & Alerting',       description: 'Detecting changes and sending notifications' },
}

function formatPhaseLabel(phase: string): string {
  return PHASE_LABELS[phase]?.name ?? phase
    .replace(/_/g, ' ')
    .replace(/\b\w/g, (c: string) => c.toUpperCase())
}

function getPhaseDescription(phase: string): string {
  return PHASE_LABELS[phase]?.description ?? ''
}

function getStatsEntries(stats: Record<string, unknown> | null): Array<{ key: string; value: string }> {
  if (!stats) return []
  return Object.entries(stats).map(([key, value]) => ({
    key: key.replace(/_/g, ' '),
    value: String(value),
  }))
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center gap-4">
      <button
        @click="goBack"
        class="p-2 rounded-md text-gray-600 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
      >
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
      </button>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
        Scan Run #{{ runId }}
      </h2>
    </div>

    <!-- Error -->
    <div v-if="scanStore.error" role="alert" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200">{{ scanStore.error }}</p>
    </div>

    <!-- Loading state -->
    <div v-if="!scanStore.currentScanRun && !scanStore.error" role="status" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading scan details...</div>
    </div>

    <template v-if="scanStore.currentScanRun">
      <!-- Scan Run Info -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6">
        <div class="flex justify-between items-start">
          <div class="grid grid-cols-2 md:grid-cols-4 gap-6 flex-1">
            <div>
              <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Status</dt>
              <dd class="mt-1">
                <span
                  class="px-2.5 py-0.5 inline-flex items-center text-xs font-semibold rounded-full"
                  :class="getRunStatusBadge(scanStore.currentScanRun.status)"
                >
                  <span
                    v-if="scanStore.currentScanRun.status === 'running'"
                    class="w-2 h-2 mr-1.5 rounded-full bg-blue-500 animate-pulse"
                  />
                  {{ scanStore.currentScanRun.status }}
                </span>
              </dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Triggered By</dt>
              <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary">
                {{ scanStore.currentScanRun.triggered_by }}
              </dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Started At</dt>
              <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary">
                {{ formatDate(scanStore.currentScanRun.started_at) }}
              </dd>
            </div>
            <div>
              <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary">Duration</dt>
              <dd class="mt-1 text-sm text-gray-900 dark:text-dark-text-primary">
                {{ formatTotalDuration() }}
              </dd>
            </div>
          </div>
          <button
            v-if="isRunning"
            @click="handleCancelScan"
            :disabled="isCancelling"
            class="ml-4 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
          >
            {{ isCancelling ? 'Cancelling...' : 'Cancel Scan' }}
          </button>
        </div>

        <!-- Error message -->
        <div
          v-if="scanStore.currentScanRun.error_message"
          class="mt-4 p-3 bg-red-50 dark:bg-red-900/20 rounded-md"
        >
          <p class="text-sm text-red-700 dark:text-red-300">
            <span class="font-medium">Error:</span> {{ scanStore.currentScanRun.error_message }}
          </p>
        </div>
      </div>

      <!-- Phase Progress Timeline -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6">
        <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-6">Phase Progress</h3>

        <div v-if="scanStore.isLoadingProgress && scanStore.phaseProgress.length === 0" class="text-center py-8 text-gray-500 dark:text-dark-text-secondary">
          Loading progress...
        </div>

        <div v-else-if="scanStore.phaseProgress.length === 0" class="text-center py-8 text-gray-500 dark:text-dark-text-secondary">
          No phase data available yet
        </div>

        <div v-else class="relative">
          <!-- Vertical line -->
          <div class="absolute left-5 top-0 bottom-0 w-0.5 bg-gray-200 dark:bg-dark-border" />

          <div class="space-y-6">
            <div
              v-for="(phase, index) in scanStore.phaseProgress"
              :key="index"
              class="relative flex items-start gap-4"
            >
              <!-- Phase Icon -->
              <div
                class="relative z-10 flex items-center justify-center w-10 h-10 rounded-full border-2 bg-white dark:bg-dark-bg-secondary"
                :class="{
                  'border-gray-300 dark:border-gray-600': phase.status === 'pending' || phase.status === 'skipped',
                  'border-blue-500 dark:border-blue-400': phase.status === 'running',
                  'border-green-500 dark:border-green-400': phase.status === 'completed',
                  'border-red-500 dark:border-red-400': phase.status === 'failed',
                }"
              >
                <!-- Pending: clock -->
                <svg v-if="getPhaseIcon(phase.status) === 'clock'" class="w-5 h-5" :class="getPhaseStatusClass(phase.status)" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <!-- Running: spinner -->
                <svg v-else-if="getPhaseIcon(phase.status) === 'spinner'" class="w-5 h-5 animate-spin" :class="getPhaseStatusClass(phase.status)" fill="none" viewBox="0 0 24 24">
                  <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
                  <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                <!-- Completed: check -->
                <svg v-else-if="getPhaseIcon(phase.status) === 'check'" class="w-5 h-5" :class="getPhaseStatusClass(phase.status)" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
                </svg>
                <!-- Failed: x -->
                <svg v-else-if="getPhaseIcon(phase.status) === 'x'" class="w-5 h-5" :class="getPhaseStatusClass(phase.status)" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                </svg>
                <!-- Skipped: dash -->
                <svg v-else class="w-5 h-5" :class="getPhaseStatusClass(phase.status)" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20 12H4" />
                </svg>
              </div>

              <!-- Phase Content -->
              <div class="flex-1 min-w-0 pb-2">
                <div class="flex items-center gap-3">
                  <h4 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">
                    {{ formatPhaseLabel(phase.phase) }}
                  </h4>
                  <span
                    class="px-2 py-0.5 text-xs font-medium rounded-full"
                    :class="getPhaseStatusBadge(phase.status)"
                  >
                    {{ phase.status }}
                  </span>
                  <span
                    v-if="phase.started_at"
                    class="text-xs text-gray-500 dark:text-dark-text-secondary"
                  >
                    {{ formatPhaseDuration(phase) }}
                  </span>
                </div>
                <p
                  v-if="getPhaseDescription(phase.phase)"
                  class="text-xs text-gray-500 dark:text-dark-text-secondary mt-0.5"
                >
                  {{ getPhaseDescription(phase.phase) }}
                </p>

                <!-- Phase Stats -->
                <div
                  v-if="phase.stats && Object.keys(phase.stats).length > 0"
                  class="mt-2 flex flex-wrap gap-3"
                >
                  <span
                    v-for="entry in getStatsEntries(phase.stats)"
                    :key="entry.key"
                    class="inline-flex items-center text-xs text-gray-600 dark:text-dark-text-secondary"
                  >
                    <span class="font-medium capitalize">{{ entry.key }}:</span>
                    <span class="ml-1">{{ entry.value }}</span>
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Stats Summary -->
      <div
        v-if="scanStore.currentScanRun.stats && Object.keys(scanStore.currentScanRun.stats).length > 0"
        class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
      >
        <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4">Scan Summary</h3>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div
            v-for="entry in getStatsEntries(scanStore.currentScanRun.stats)"
            :key="entry.key"
            class="bg-gray-50 dark:bg-dark-bg-tertiary rounded-lg p-4"
          >
            <dt class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary capitalize">
              {{ entry.key }}
            </dt>
            <dd class="mt-1 text-2xl font-semibold text-gray-900 dark:text-dark-text-primary">
              {{ entry.value }}
            </dd>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>
