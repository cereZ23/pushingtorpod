<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'
import { formatDate } from '@/utils/formatters'
import { useWindowedPagination } from '@/composables/usePagination'

interface AuditEntry {
  id: number
  timestamp: string | null
  event_type: string
  user_id: number | null
  action: string
  resource: string | null
  resource_id: string | null
  result: string
  severity: string
  ip_address: string | null
  endpoint: string | null
  method: string | null
  error_message: string | null
}

const tenantStore = useTenantStore()
const tid = computed(() => tenantStore.currentTenantId)

const entries = ref<AuditEntry[]>([])
const isLoading = ref(true)
const error = ref('')
const currentPage = ref(1)
const pageSize = ref(25)
const totalItems = ref(0)
const totalPages = ref(0)

// Filters
const filterEventType = ref('')
const filterSeverity = ref('')
const filterStartDate = ref('')
const filterEndDate = ref('')

const { pages: paginationPages } = useWindowedPagination(currentPage, totalPages)

const eventTypes = [
  'auth.login.success',
  'auth.login.failure',
  'auth.logout',
  'auth.password.change',
  'auth.password.reset',
  'authz.access.denied',
  'authz.permission.denied',
  'data.create',
  'data.update',
  'data.delete',
  'data.export',
  'user.create',
  'user.delete',
  'user.role.change',
  'config.change',
  'suspicious.rate_limit',
  'suspicious.brute_force',
]

async function fetchLogs() {
  if (!tid.value) return
  isLoading.value = true
  error.value = ''

  try {
    const params: Record<string, string | number> = {
      page: currentPage.value,
      page_size: pageSize.value,
    }
    if (filterEventType.value) params.event_type = filterEventType.value
    if (filterSeverity.value) params.severity = filterSeverity.value
    if (filterStartDate.value) params.start_date = new Date(filterStartDate.value).toISOString()
    if (filterEndDate.value) params.end_date = new Date(filterEndDate.value).toISOString()

    const response = await apiClient.get(`/api/v1/tenants/${tid.value}/audit-logs`, { params })
    entries.value = response.data.data
    totalItems.value = response.data.meta.total
    totalPages.value = response.data.meta.total_pages
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to load audit logs'
  } finally {
    isLoading.value = false
  }
}

function applyFilters() {
  currentPage.value = 1
  fetchLogs()
}

function goToPage(page: number) {
  currentPage.value = page
  fetchLogs()
}

function getResultBadgeClass(result: string): string {
  switch (result) {
    case 'success': return 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
    case 'failure': return 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
    case 'denied': return 'bg-orange-100 text-orange-700 dark:bg-orange-900/20 dark:text-orange-400'
    case 'blocked': return 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
    default: return 'bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-400'
  }
}

function getSeverityBadgeClass(severity: string): string {
  switch (severity) {
    case 'critical': return 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
    case 'warning': return 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400'
    case 'info': return 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400'
    default: return 'bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-400'
  }
}

onMounted(fetchLogs)

watch(tid, () => {
  if (tid.value) {
    currentPage.value = 1
    fetchLogs()
  }
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Audit Log</h2>
      <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">Security events and activity history</p>
    </div>

    <!-- Filters -->
    <div class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border">
      <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Event Type</label>
          <select
            v-model="filterEventType"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm"
          >
            <option value="">All Events</option>
            <option v-for="et in eventTypes" :key="et" :value="et">{{ et }}</option>
          </select>
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Severity</label>
          <select
            v-model="filterSeverity"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm"
          >
            <option value="">All Severities</option>
            <option value="info">Info</option>
            <option value="warning">Warning</option>
            <option value="critical">Critical</option>
          </select>
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Start Date</label>
          <input
            v-model="filterStartDate"
            type="date"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">End Date</label>
          <input
            v-model="filterEndDate"
            type="date"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm"
          />
        </div>

        <div class="flex items-end">
          <button
            @click="applyFilters"
            class="w-full px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 text-sm font-medium"
          >
            Apply
          </button>
        </div>
      </div>
    </div>

    <!-- Loading -->
    <div v-if="isLoading" role="status" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading audit logs...</div>
    </div>

    <!-- Error -->
    <div v-else-if="error" role="alert" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Table -->
    <div v-else class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
          <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
            <tr>
              <th scope="col" class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Timestamp</th>
              <th scope="col" class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Event Type</th>
              <th scope="col" class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Action</th>
              <th scope="col" class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Resource</th>
              <th scope="col" class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Result</th>
              <th scope="col" class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Severity</th>
              <th scope="col" class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">IP</th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
            <tr v-for="entry in entries" :key="entry.id" class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary">
              <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary">
                {{ entry.timestamp ? formatDate(entry.timestamp) : '-' }}
              </td>
              <td class="px-4 py-3 whitespace-nowrap">
                <span class="text-xs font-mono text-gray-700 dark:text-dark-text-primary">{{ entry.event_type }}</span>
              </td>
              <td class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary max-w-xs truncate">
                {{ entry.action }}
              </td>
              <td class="px-4 py-3 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary">
                <span v-if="entry.resource">{{ entry.resource }}<span v-if="entry.resource_id"> #{{ entry.resource_id }}</span></span>
                <span v-else>-</span>
              </td>
              <td class="px-4 py-3 whitespace-nowrap">
                <span class="px-2 py-0.5 text-xs font-semibold rounded-full" :class="getResultBadgeClass(entry.result)">
                  {{ entry.result }}
                </span>
              </td>
              <td class="px-4 py-3 whitespace-nowrap">
                <span class="px-2 py-0.5 text-xs font-semibold rounded-full" :class="getSeverityBadgeClass(entry.severity)">
                  {{ entry.severity }}
                </span>
              </td>
              <td class="px-4 py-3 whitespace-nowrap text-xs font-mono text-gray-500 dark:text-dark-text-secondary">
                {{ entry.ip_address || '-' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Empty -->
      <div v-if="entries.length === 0" class="flex items-center justify-center py-16">
        <p class="text-sm text-gray-500 dark:text-dark-text-secondary">No audit log entries found</p>
      </div>

      <!-- Pagination -->
      <div v-if="totalPages > 1" class="px-6 py-4 border-t border-gray-200 dark:border-dark-border">
        <div class="flex items-center justify-between">
          <div class="text-sm text-gray-700 dark:text-dark-text-secondary">
            Showing {{ ((currentPage - 1) * pageSize) + 1 }} to {{ Math.min(currentPage * pageSize, totalItems) }} of {{ totalItems }}
          </div>
          <div class="flex space-x-1">
            <button
              @click="goToPage(currentPage - 1)"
              :disabled="currentPage === 1"
              class="px-3 py-1 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              Previous
            </button>
            <template v-for="pg in paginationPages" :key="pg.value">
              <span
                v-if="pg.type === 'ellipsis'"
                class="px-2 py-1 text-sm text-gray-500 dark:text-dark-text-secondary"
              >...</span>
              <button
                v-else
                @click="goToPage(pg.value)"
                :aria-current="pg.value === currentPage ? 'page' : undefined"
                :class="[
                  'px-3 py-1 border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary-500',
                  pg.value === currentPage
                    ? 'bg-primary-600 text-white border-primary-600'
                    : 'border-gray-300 dark:border-dark-border text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary'
                ]"
              >
                {{ pg.value }}
              </button>
            </template>
            <button
              @click="goToPage(currentPage + 1)"
              :disabled="currentPage === totalPages"
              class="px-3 py-1 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
