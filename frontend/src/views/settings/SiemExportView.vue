<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'

// --- Types ---

type SiemFormat = 'splunk_hec' | 'cef'
type SeverityLevel = 'info' | 'low' | 'medium' | 'high' | 'critical'

interface FormatOption {
  value: SiemFormat
  label: string
  description: string
}

interface SeverityOption {
  value: SeverityLevel | ''
  label: string
}

interface SiemEvent {
  [key: string]: unknown
}

interface ExportResponse {
  format: string
  event_count: number
  events: SiemEvent[]
}

interface PushResponse {
  format: string
  event_count: number
  success: boolean
  detail?: string
}

interface AxiosErrorShape {
  response?: {
    data?: { detail?: string }
    status?: number
  }
  message?: string
}

// --- Stores ---

const tenantStore = useTenantStore()
const tid = computed(() => tenantStore.currentTenantId)

// --- Format / severity options ---

const formatOptions: FormatOption[] = [
  { value: 'splunk_hec', label: 'Splunk HEC', description: 'Splunk HTTP Event Collector JSON format' },
  { value: 'cef', label: 'CEF (Azure Sentinel)', description: 'Common Event Format for Azure Sentinel, ArcSight, QRadar' },
]

const severityOptions: SeverityOption[] = [
  { value: '', label: 'All severities' },
  { value: 'info', label: 'Info and above' },
  { value: 'low', label: 'Low and above' },
  { value: 'medium', label: 'Medium and above' },
  { value: 'high', label: 'High and above' },
  { value: 'critical', label: 'Critical only' },
]

// --- Export Preview state ---

const exportFormat = ref<SiemFormat>('splunk_hec')
const exportSeverity = ref<SeverityLevel | ''>('')
const exportSince = ref('')
const isExporting = ref(false)
const exportResult = ref<ExportResponse | null>(null)
const exportEventsExpanded = ref(false)

// --- Push Configuration state ---

const pushFormat = ref<SiemFormat>('splunk_hec')
const pushSeverity = ref<SeverityLevel | ''>('')
const pushSince = ref('')
const pushEndpointUrl = ref('')
const pushAuthToken = ref('')
const isPushing = ref(false)
const isTesting = ref(false)
const showPushConfirm = ref(false)

// --- Feedback state ---

const error = ref('')
const successMessage = ref('')

// --- Helpers ---

function showSuccess(msg: string) {
  successMessage.value = msg
  setTimeout(() => { successMessage.value = '' }, 3000)
}

function showError(msg: string) {
  error.value = msg
  setTimeout(() => { error.value = '' }, 5000)
}

function buildExportPayload(format: SiemFormat, severity: SeverityLevel | '', since: string): Record<string, unknown> {
  const payload: Record<string, unknown> = { format }
  if (severity) {
    payload.severity_min = severity
  }
  if (since) {
    payload.since = new Date(since).toISOString()
  }
  return payload
}

function formatEventJson(event: SiemEvent): string {
  return JSON.stringify(event, null, 2)
}

// --- Export Preview ---

async function handlePreviewExport() {
  if (!tid.value) return
  isExporting.value = true
  error.value = ''
  exportResult.value = null

  try {
    const payload = buildExportPayload(exportFormat.value, exportSeverity.value, exportSince.value)
    const response = await apiClient.post<ExportResponse>(
      `/api/v1/tenants/${tid.value}/siem/export`,
      payload,
    )
    exportResult.value = response.data
    exportEventsExpanded.value = false
  } catch (err: unknown) {
    const axiosErr = err as AxiosErrorShape
    showError(axiosErr.response?.data?.detail || axiosErr.message || 'Failed to preview export')
  } finally {
    isExporting.value = false
  }
}

// --- Push ---

function buildPushPayload(): Record<string, unknown> {
  const payload = buildExportPayload(pushFormat.value, pushSeverity.value, pushSince.value)
  payload.endpoint_url = pushEndpointUrl.value.trim()
  payload.auth_token = pushAuthToken.value
  return payload
}

const canPush = computed(() =>
  pushEndpointUrl.value.trim().length > 0 && pushAuthToken.value.length > 0,
)

async function handleTestPush() {
  if (!tid.value || !canPush.value) return
  isTesting.value = true
  error.value = ''

  try {
    const response = await apiClient.post<PushResponse>(
      `/api/v1/tenants/${tid.value}/siem/push`,
      buildPushPayload(),
    )
    if (response.data.success) {
      showSuccess(`Test push successful: ${response.data.event_count} events sent`)
    } else {
      showError(response.data.detail || 'Push failed with unknown error')
    }
  } catch (err: unknown) {
    const axiosErr = err as AxiosErrorShape
    showError(axiosErr.response?.data?.detail || axiosErr.message || 'Test push failed')
  } finally {
    isTesting.value = false
  }
}

function requestPushConfirmation() {
  showPushConfirm.value = true
}

function cancelPush() {
  showPushConfirm.value = false
}

async function handlePushNow() {
  showPushConfirm.value = false
  if (!tid.value || !canPush.value) return
  isPushing.value = true
  error.value = ''

  try {
    const response = await apiClient.post<PushResponse>(
      `/api/v1/tenants/${tid.value}/siem/push`,
      buildPushPayload(),
    )
    if (response.data.success) {
      showSuccess(`Push completed: ${response.data.event_count} events delivered to SIEM endpoint`)
    } else {
      showError(response.data.detail || 'Push failed with unknown error')
    }
  } catch (err: unknown) {
    const axiosErr = err as AxiosErrorShape
    showError(axiosErr.response?.data?.detail || axiosErr.message || 'Push failed')
  } finally {
    isPushing.value = false
  }
}

// --- Clear results on tenant change ---

watch(tid, () => {
  exportResult.value = null
  error.value = ''
  successMessage.value = ''
  // No data to reload -- SIEM export is action-based, not data-loaded
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">SIEM Export</h2>
      <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">
        Export findings to Splunk or Azure Sentinel in SIEM-compatible formats
      </p>
    </div>

    <!-- Success Banner -->
    <Transition
      enter-active-class="transition ease-out duration-200"
      enter-from-class="opacity-0 -translate-y-1"
      enter-to-class="opacity-100 translate-y-0"
      leave-active-class="transition ease-in duration-150"
      leave-from-class="opacity-100 translate-y-0"
      leave-to-class="opacity-0 -translate-y-1"
    >
      <div
        v-if="successMessage"
        role="alert"
        class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 rounded-md"
      >
        <p class="text-green-800 dark:text-green-200 text-sm">{{ successMessage }}</p>
      </div>
    </Transition>

    <!-- Error Banner -->
    <Transition
      enter-active-class="transition ease-out duration-200"
      enter-from-class="opacity-0 -translate-y-1"
      enter-to-class="opacity-100 translate-y-0"
      leave-active-class="transition ease-in duration-150"
      leave-from-class="opacity-100 translate-y-0"
      leave-to-class="opacity-0 -translate-y-1"
    >
      <div
        v-if="error"
        role="alert"
        class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 rounded-md"
      >
        <p class="text-red-800 dark:text-red-200 text-sm">{{ error }}</p>
      </div>
    </Transition>

    <!-- ===== Section 1: Export Preview ===== -->
    <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
        <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Export Preview</h3>
        <p class="text-sm text-gray-500 dark:text-dark-text-secondary mt-1">
          Test and preview SIEM-formatted events before configuring a live push
        </p>
      </div>

      <div class="p-6 space-y-6">
        <!-- Format Selection -->
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Format</label>
          <div class="flex gap-4">
            <label
              v-for="opt in formatOptions"
              :key="opt.value"
              class="flex items-center gap-3 p-4 rounded-lg border-2 cursor-pointer transition-all flex-1"
              :class="exportFormat === opt.value
                ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                : 'border-gray-200 dark:border-dark-border hover:border-gray-300 dark:hover:border-gray-600'"
            >
              <input
                v-model="exportFormat"
                :value="opt.value"
                type="radio"
                name="export-format"
                class="sr-only"
              />
              <div>
                <span class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">
                  {{ opt.label }}
                </span>
                <p class="text-xs text-gray-500 dark:text-dark-text-secondary mt-0.5">
                  {{ opt.description }}
                </p>
              </div>
            </label>
          </div>
        </div>

        <!-- Filters Row -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label
              for="export-severity"
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >
              Minimum Severity
            </label>
            <select
              id="export-severity"
              v-model="exportSeverity"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option v-for="opt in severityOptions" :key="opt.value" :value="opt.value">
                {{ opt.label }}
              </option>
            </select>
          </div>

          <div>
            <label
              for="export-since"
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >
              Since Date
              <span class="text-gray-400 dark:text-dark-text-tertiary font-normal">(optional)</span>
            </label>
            <input
              id="export-since"
              v-model="exportSince"
              type="datetime-local"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>
        </div>

        <!-- Preview Button -->
        <div>
          <button
            type="button"
            :disabled="isExporting"
            @click="handlePreviewExport"
            class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
          >
            <span v-if="isExporting" role="status">Exporting...</span>
            <span v-else>Preview Export</span>
          </button>
        </div>

        <!-- Export Result -->
        <div v-if="exportResult" class="space-y-3">
          <div class="flex items-center gap-3">
            <span class="text-sm font-medium text-gray-700 dark:text-dark-text-secondary">
              Events returned:
            </span>
            <span
              class="px-2.5 py-0.5 text-xs font-semibold rounded-full"
              :class="exportResult.event_count > 0
                ? 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
                : 'bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400'"
            >
              {{ exportResult.event_count }}
            </span>
            <span class="text-sm text-gray-500 dark:text-dark-text-tertiary">
              (format: {{ exportResult.format === 'splunk_hec' ? 'Splunk HEC' : 'CEF' }})
            </span>
          </div>

          <!-- Sample Events (collapsible) -->
          <div v-if="exportResult.events.length > 0">
            <button
              type="button"
              @click="exportEventsExpanded = !exportEventsExpanded"
              class="flex items-center gap-2 text-sm font-medium text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300 transition-colors"
            >
              <svg
                class="w-4 h-4 transition-transform duration-200"
                :class="{ 'rotate-90': exportEventsExpanded }"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7" />
              </svg>
              {{ exportEventsExpanded ? 'Hide' : 'Show' }} sample events
              (first {{ Math.min(5, exportResult.events.length) }} of {{ exportResult.event_count }})
            </button>

            <Transition
              enter-active-class="transition ease-out duration-200"
              enter-from-class="opacity-0 max-h-0"
              enter-to-class="opacity-100 max-h-[2000px]"
              leave-active-class="transition ease-in duration-150"
              leave-from-class="opacity-100 max-h-[2000px]"
              leave-to-class="opacity-0 max-h-0"
            >
              <div v-if="exportEventsExpanded" class="mt-3 overflow-hidden">
                <pre
                  class="bg-gray-50 dark:bg-dark-bg-primary border border-gray-200 dark:border-dark-border rounded-md p-4 text-xs text-gray-800 dark:text-dark-text-secondary overflow-x-auto max-h-96 overflow-y-auto"
                >{{ exportResult.events.slice(0, 5).map(formatEventJson).join('\n\n') }}</pre>
              </div>
            </Transition>
          </div>

          <div v-else class="text-sm text-gray-500 dark:text-dark-text-tertiary italic">
            No events matched the current filters.
          </div>
        </div>
      </div>
    </div>

    <!-- ===== Section 2: Push Configuration ===== -->
    <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
        <div class="flex items-center justify-between">
          <div>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Push Configuration</h3>
            <p class="text-sm text-gray-500 dark:text-dark-text-secondary mt-1">
              Push findings directly to your SIEM endpoint
            </p>
          </div>
          <span class="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-amber-100 text-amber-700 dark:bg-amber-900/20 dark:text-amber-400">
            Admin only
          </span>
        </div>
      </div>

      <div class="p-6 space-y-6">
        <!-- Format Selection -->
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Format</label>
          <div class="flex gap-4">
            <label
              v-for="opt in formatOptions"
              :key="opt.value"
              class="flex items-center gap-3 p-4 rounded-lg border-2 cursor-pointer transition-all flex-1"
              :class="pushFormat === opt.value
                ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                : 'border-gray-200 dark:border-dark-border hover:border-gray-300 dark:hover:border-gray-600'"
            >
              <input
                v-model="pushFormat"
                :value="opt.value"
                type="radio"
                name="push-format"
                class="sr-only"
              />
              <div>
                <span class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">
                  {{ opt.label }}
                </span>
                <p class="text-xs text-gray-500 dark:text-dark-text-secondary mt-0.5">
                  {{ opt.description }}
                </p>
              </div>
            </label>
          </div>
        </div>

        <!-- Filters Row -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label
              for="push-severity"
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >
              Minimum Severity
            </label>
            <select
              id="push-severity"
              v-model="pushSeverity"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option v-for="opt in severityOptions" :key="opt.value" :value="opt.value">
                {{ opt.label }}
              </option>
            </select>
          </div>

          <div>
            <label
              for="push-since"
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >
              Since Date
              <span class="text-gray-400 dark:text-dark-text-tertiary font-normal">(optional)</span>
            </label>
            <input
              id="push-since"
              v-model="pushSince"
              type="datetime-local"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>
        </div>

        <!-- Endpoint Configuration -->
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div class="md:col-span-2">
            <label
              for="push-endpoint"
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >
              Endpoint URL
            </label>
            <input
              id="push-endpoint"
              v-model="pushEndpointUrl"
              type="url"
              required
              placeholder="https://splunk:8088/services/collector"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 placeholder:text-gray-400 dark:placeholder:text-dark-text-tertiary"
            />
            <p class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-1">
              For Splunk HEC use <code class="px-1 py-0.5 bg-gray-100 dark:bg-dark-bg-primary rounded text-xs">https://&lt;host&gt;:8088/services/collector</code>.
              For Azure Sentinel use your Log Analytics Data Collector URL.
            </p>
          </div>

          <div class="md:col-span-2">
            <label
              for="push-token"
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >
              Auth Token
            </label>
            <input
              id="push-token"
              v-model="pushAuthToken"
              type="password"
              required
              placeholder="Enter authentication token"
              autocomplete="off"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 placeholder:text-gray-400 dark:placeholder:text-dark-text-tertiary"
            />
            <p class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-1">
              Sent as <code class="px-1 py-0.5 bg-gray-100 dark:bg-dark-bg-primary rounded text-xs">Splunk &lt;token&gt;</code>
              for HEC or <code class="px-1 py-0.5 bg-gray-100 dark:bg-dark-bg-primary rounded text-xs">Bearer &lt;token&gt;</code>
              for CEF endpoints.
            </p>
          </div>
        </div>

        <!-- Actions -->
        <div class="flex items-center justify-end gap-3 pt-4 border-t border-gray-200 dark:border-dark-border">
          <button
            type="button"
            :disabled="isTesting || !canPush"
            @click="handleTestPush"
            class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span v-if="isTesting" role="status">Testing...</span>
            <span v-else>Test Push</span>
          </button>
          <button
            type="button"
            :disabled="isPushing || !canPush"
            @click="requestPushConfirmation"
            class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
          >
            <span v-if="isPushing" role="status">Pushing...</span>
            <span v-else>Push Now</span>
          </button>
        </div>
      </div>
    </div>

    <!-- ===== Confirmation Dialog ===== -->
    <Teleport to="body">
      <Transition
        enter-active-class="transition ease-out duration-200"
        enter-from-class="opacity-0"
        enter-to-class="opacity-100"
        leave-active-class="transition ease-in duration-150"
        leave-from-class="opacity-100"
        leave-to-class="opacity-0"
      >
        <div
          v-if="showPushConfirm"
          class="fixed inset-0 z-50 flex items-center justify-center"
        >
          <!-- Backdrop -->
          <div
            class="absolute inset-0 bg-black/50"
            @click="cancelPush"
          />

          <!-- Dialog -->
          <div
            role="alertdialog"
            aria-labelledby="push-confirm-title"
            aria-describedby="push-confirm-description"
            class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl border border-gray-200 dark:border-dark-border p-6 max-w-md w-full mx-4"
          >
            <h4
              id="push-confirm-title"
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Confirm SIEM Push
            </h4>
            <p
              id="push-confirm-description"
              class="text-sm text-gray-600 dark:text-dark-text-secondary mt-2"
            >
              This will push all matching findings to
              <strong class="text-gray-900 dark:text-dark-text-primary">{{ pushEndpointUrl }}</strong>
              using the {{ pushFormat === 'splunk_hec' ? 'Splunk HEC' : 'CEF' }} format.
              This action cannot be undone.
            </p>

            <div class="flex justify-end gap-3 mt-6">
              <button
                type="button"
                @click="cancelPush"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm"
              >
                Cancel
              </button>
              <button
                type="button"
                @click="handlePushNow"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm font-medium"
              >
                Confirm Push
              </button>
            </div>
          </div>
        </div>
      </Transition>
    </Teleport>
  </div>
</template>
