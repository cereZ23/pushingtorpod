<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { findingApi } from '@/api/findings'
import type { Finding, PaginatedResponse } from '@/api/types'

const router = useRouter()
const tenantStore = useTenantStore()

const findings = ref<Finding[]>([])
const isLoading = ref(true)
const error = ref('')
const currentPage = ref(1)
const pageSize = ref(25)
const totalItems = ref(0)
const totalPages = ref(0)

// Filters
const searchQuery = ref('')
const selectedSeverity = ref('')
const selectedStatus = ref('')
const selectedSource = ref('')

const currentTenantId = computed(() => tenantStore.currentTenantId)

onMounted(async () => {
  await loadFindings()
})

watch(currentTenantId, () => {
  if (currentTenantId.value) {
    loadFindings()
  }
})

async function loadFindings() {
  if (!currentTenantId.value) {
    error.value = 'No tenant selected'
    isLoading.value = false
    return
  }

  isLoading.value = true
  error.value = ''

  try {
    const params = {
      page: currentPage.value,
      page_size: pageSize.value,
      search: searchQuery.value || undefined,
      severity: selectedSeverity.value || undefined,
      status: selectedStatus.value || undefined,
      source: selectedSource.value || undefined,
    }

    const response: PaginatedResponse<Finding> = await findingApi.list(currentTenantId.value, params)
    findings.value = response.data
    totalItems.value = response.meta.total
    totalPages.value = response.meta.total_pages
  } catch (err: unknown) {
    const axiosErr = err as { message?: string }
    error.value = axiosErr.message || 'Failed to load findings'
  } finally {
    isLoading.value = false
  }
}

function handleSearch() {
  currentPage.value = 1
  loadFindings()
}

function goToPage(page: number) {
  currentPage.value = page
  loadFindings()
}

function viewFinding(findingId: number) {
  router.push({ name: 'FindingDetail', params: { id: findingId } })
}

function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400',
    high: 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400',
    medium: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400',
    low: 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400',
    info: 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400',
  }
  return colors[severity] || colors.info
}

function getStatusColor(status: string): string {
  const colors: Record<string, string> = {
    open: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400',
    suppressed: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400',
    fixed: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
  }
  return colors[status] || 'bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400'
}

function formatDate(dateString: string): string {
  const date = new Date(dateString)
  return date.toLocaleDateString()
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Findings</h2>
      <button
        @click="loadFindings"
        :disabled="isLoading"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50"
      >
        Refresh
      </button>
    </div>

    <!-- Filters -->
    <div class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border">
      <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Search</label>
          <input
            v-model="searchQuery"
            @keyup.enter="handleSearch"
            type="text"
            placeholder="Search findings..."
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Severity</label>
          <select
            v-model="selectedSeverity"
            @change="handleSearch"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Status</label>
          <select
            v-model="selectedStatus"
            @change="handleSearch"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="">All Statuses</option>
            <option value="open">Open</option>
            <option value="suppressed">Suppressed</option>
            <option value="fixed">Fixed</option>
          </select>
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Source</label>
          <select
            v-model="selectedSource"
            @change="handleSearch"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="">All Sources</option>
            <option value="nuclei">Nuclei</option>
            <option value="manual">Manual</option>
          </select>
        </div>

        <div class="flex items-end">
          <button
            @click="handleSearch"
            class="w-full px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700"
          >
            Apply Filters
          </button>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="isLoading" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading findings...</div>
    </div>

    <!-- Error State -->
    <div v-else-if="error" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Findings Table -->
    <div v-else class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
          <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Name
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Severity
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Status
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Asset
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Source
              </th>
              <th class="px-6 py-3 text-center text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Seen
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                First Seen
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
            <tr v-for="finding in findings" :key="finding.id" class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary">
              <td class="px-6 py-4">
                <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ finding.name }}</div>
                <div v-if="finding.cve_id" class="text-xs text-gray-500 dark:text-dark-text-secondary">{{ finding.cve_id }}</div>
                <div v-if="finding.template_id" class="text-xs text-gray-500 dark:text-dark-text-secondary">{{ finding.template_id }}</div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center gap-1.5 flex-wrap">
                  <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full" :class="getSeverityColor(finding.severity)">
                    {{ finding.severity }}
                  </span>
                  <span
                    v-if="finding.evidence?.threat_intel?.is_kev === true"
                    class="px-1.5 inline-flex text-xs leading-5 font-bold rounded-full bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-300"
                    title="CISA Known Exploited Vulnerability"
                  >
                    KEV
                  </span>
                </div>
                <div class="flex items-center gap-2 mt-1">
                  <span v-if="finding.cvss_score" class="text-xs text-gray-500 dark:text-dark-text-secondary">
                    CVSS: {{ finding.cvss_score }}
                  </span>
                  <span
                    v-if="finding.evidence?.threat_intel?.epss_score != null"
                    class="text-xs font-medium"
                    :class="finding.evidence.threat_intel.epss_score >= 0.7
                      ? 'text-red-600 dark:text-red-400'
                      : finding.evidence.threat_intel.epss_score >= 0.4
                        ? 'text-orange-600 dark:text-orange-400'
                        : 'text-gray-500 dark:text-dark-text-secondary'"
                    :title="`Exploit Prediction Scoring System: ${(finding.evidence.threat_intel.epss_score * 100).toFixed(1)}% probability of exploitation in the next 30 days`"
                  >
                    EPSS: {{ Math.round(finding.evidence.threat_intel.epss_score * 100) }}%
                  </span>
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full" :class="getStatusColor(finding.status)">
                  {{ finding.status }}
                </span>
              </td>
              <td class="px-6 py-4">
                <div class="text-sm text-gray-900 dark:text-dark-text-primary">{{ finding.asset_identifier || '-' }}</div>
                <div v-if="finding.asset_type" class="text-xs text-gray-500 dark:text-dark-text-secondary">{{ finding.asset_type }}</div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary">
                {{ finding.source }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-center">
                <span
                  v-if="finding.occurrence_count > 1"
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300"
                  :title="`Detected ${finding.occurrence_count} times`"
                >
                  {{ finding.occurrence_count }}x
                </span>
                <span v-else class="text-xs text-gray-400 dark:text-dark-text-secondary">1x</span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary">
                {{ formatDate(finding.first_seen) }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                <button
                  @click="viewFinding(finding.id)"
                  class="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300"
                >
                  View
                </button>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Empty State -->
      <div v-if="findings.length === 0" class="flex flex-col items-center justify-center py-16 px-4">
        <svg class="w-16 h-16 text-gray-300 dark:text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285zm0 13.036h.008v.008H12v-.008z" />
        </svg>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-1">No vulnerabilities found</h3>
        <p class="text-sm text-gray-500 dark:text-dark-text-secondary mb-6 max-w-md text-center">
          Vulnerabilities detected by Nuclei scans and other scanning engines will be listed here. Run a vulnerability scan to start identifying security issues.
        </p>
        <router-link
          to="/scans"
          class="inline-flex items-center px-4 py-2 bg-primary-600 text-white text-sm font-medium rounded-md hover:bg-primary-700 transition-colors"
        >
          <svg class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
          </svg>
          Run a Vulnerability Scan
        </router-link>
      </div>

      <!-- Pagination -->
      <div v-if="totalPages > 1" class="px-6 py-4 border-t border-gray-200 dark:border-dark-border">
        <div class="flex items-center justify-between">
          <div class="text-sm text-gray-700 dark:text-dark-text-secondary">
            Showing {{ ((currentPage - 1) * pageSize) + 1 }} to {{ Math.min(currentPage * pageSize, totalItems) }} of {{ totalItems }} results
          </div>
          <div class="flex space-x-2">
            <button
              @click="goToPage(currentPage - 1)"
              :disabled="currentPage === 1"
              class="px-3 py-1 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Previous
            </button>
            <button
              v-for="page in Math.min(5, totalPages)"
              :key="page"
              @click="goToPage(page)"
              :class="[
                'px-3 py-1 border rounded-md text-sm',
                page === currentPage
                  ? 'bg-primary-600 text-white border-primary-600'
                  : 'border-gray-300 dark:border-dark-border text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary'
              ]"
            >
              {{ page }}
            </button>
            <button
              @click="goToPage(currentPage + 1)"
              :disabled="currentPage === totalPages"
              class="px-3 py-1 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
