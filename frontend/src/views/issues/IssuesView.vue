<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useRouter } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { useIssueStore } from '@/stores/issues'
import type { Issue, IssueStatus } from '@/stores/issues'
import { getSeverityBadgeClass, getIssueStatusBadgeClass, formatIssueStatusLabel } from '@/utils/severity'
import { formatDate } from '@/utils/formatters'
import { useWindowedPagination } from '@/composables/usePagination'

const router = useRouter()
const tenantStore = useTenantStore()
const issueStore = useIssueStore()

const currentTenantId = computed(() => tenantStore.currentTenantId)

const issueCurrentPage = computed(() => issueStore.currentPage)
const issueTotalPages = computed(() => issueStore.totalPages)
const { pages: issuePaginationPages } = useWindowedPagination(issueCurrentPage, issueTotalPages)

// Bulk selection
const selectedIds = ref<Set<number>>(new Set())
const isBulkUpdating = ref(false)

// Filters
const searchQuery = ref('')
const selectedSeverity = ref('')
const selectedStatus = ref('')

onMounted(async () => {
  await loadIssues()
})

watch(currentTenantId, async (newId, oldId) => {
  if (newId && oldId && newId !== oldId) {
    issueStore.currentPage = 1
    await loadIssues()
  }
})

async function loadIssues(): Promise<void> {
  selectedIds.value = new Set()
  await issueStore.fetchIssues({
    page: issueStore.currentPage,
    page_size: issueStore.pageSize,
    search: searchQuery.value || undefined,
    severity: selectedSeverity.value || undefined,
    status: selectedStatus.value || undefined,
  })
}

function handleSearch(): void {
  issueStore.currentPage = 1
  loadIssues()
}

function goToPage(page: number): void {
  issueStore.currentPage = page
  loadIssues()
}

function viewIssue(issue: Issue): void {
  router.push({ name: 'IssueDetail', params: { id: issue.id } })
}

function toggleSelectAll(): void {
  const allIssues = issueStore.issues
  if (selectedIds.value.size === allIssues.length) {
    selectedIds.value = new Set()
  } else {
    selectedIds.value = new Set(allIssues.map(i => i.id))
  }
}

function toggleSelect(id: number): void {
  const next = new Set(selectedIds.value)
  if (next.has(id)) {
    next.delete(id)
  } else {
    next.add(id)
  }
  selectedIds.value = next
}

async function bulkChangeStatus(newStatus: string): Promise<void> {
  if (selectedIds.value.size === 0) return
  isBulkUpdating.value = true

  try {
    const results = await Promise.allSettled(
      Array.from(selectedIds.value).map(id =>
        issueStore.updateIssueStatus(id, newStatus as IssueStatus)
      )
    )
    const failed = results.filter(r => r.status === 'rejected').length
    if (failed > 0) {
      issueStore.error = `${failed} of ${selectedIds.value.size} updates failed`
    }
    selectedIds.value = new Set()
    await loadIssues()
  } catch {
    issueStore.error = 'Bulk update failed'
  } finally {
    isBulkUpdating.value = false
  }
}

function getSeverityColor(severity: string): string {
  return getSeverityBadgeClass(severity)
}

function getStatusColor(status: string): string {
  return getIssueStatusBadgeClass(status)
}

function formatStatusLabel(status: string): string {
  return formatIssueStatusLabel(status)
}

function handleBulkStatusChange(event: Event): void {
  const select = event.target as HTMLSelectElement
  const value = select.value
  if (value) {
    bulkChangeStatus(value)
    select.value = ''
  }
}

function isSlaOverdue(sla: string | null): boolean {
  if (!sla) return false
  return new Date(sla) < new Date()
}

function formatSla(sla: string | null): string {
  if (!sla) return '-'
  const date = new Date(sla)
  if (isSlaOverdue(sla)) {
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
    if (diffDays > 0) return `${diffDays}d overdue`
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    return `${diffHours}h overdue`
  }
  const now = new Date()
  const diffMs = date.getTime() - now.getTime()
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
  if (diffDays > 0) return `${diffDays}d remaining`
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
  return `${diffHours}h remaining`
}

</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Issues</h2>
      <button
        @click="loadIssues"
        :disabled="issueStore.isLoading"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50"
      >
        Refresh
      </button>
    </div>

    <!-- Filter Bar -->
    <div class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border">
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Search</label>
          <input
            v-model="searchQuery"
            @keyup.enter="handleSearch"
            type="text"
            placeholder="Search issues..."
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
            <option value="triaged">Triaged</option>
            <option value="in_progress">In Progress</option>
            <option value="mitigated">Mitigated</option>
            <option value="verifying">Verifying</option>
            <option value="verified_fixed">Verified Fixed</option>
            <option value="closed">Closed</option>
            <option value="false_positive">False Positive</option>
            <option value="accepted_risk">Accepted Risk</option>
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
    <div v-if="issueStore.isLoading" role="status" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading issues...</div>
    </div>

    <!-- Error State -->
    <div v-else-if="issueStore.error" role="alert" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200">{{ issueStore.error }}</p>
    </div>

    <!-- Issues Table -->
    <div v-else class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
      <!-- Bulk Action Bar -->
      <div v-if="selectedIds.size > 0" class="bg-primary-50 dark:bg-primary-900/20 px-6 py-3 flex items-center justify-between border-b border-primary-200 dark:border-primary-800">
        <span class="text-sm font-medium text-primary-700 dark:text-primary-300">
          {{ selectedIds.size }} selected
        </span>
        <div class="flex items-center gap-2">
          <select
            @change="handleBulkStatusChange"
            :disabled="isBulkUpdating"
            class="text-sm border border-gray-300 dark:border-dark-border rounded-md px-2 py-1 dark:bg-dark-bg-tertiary dark:text-dark-text-primary"
          >
            <option value="">Change Status...</option>
            <option value="triaged">Triaged</option>
            <option value="in_progress">In Progress</option>
            <option value="mitigated">Mitigated</option>
            <option value="closed">Closed</option>
          </select>
          <button
            @click="selectedIds = new Set()"
            class="text-sm text-gray-600 dark:text-dark-text-secondary hover:text-gray-800 dark:hover:text-dark-text-primary"
          >
            Clear
          </button>
        </div>
      </div>
      <div class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
          <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
            <tr>
              <th scope="col" class="px-3 py-3 text-left">
                <input
                  type="checkbox"
                  :checked="selectedIds.size === issueStore.issues.length && issueStore.issues.length > 0"
                  :indeterminate="selectedIds.size > 0 && selectedIds.size < issueStore.issues.length"
                  @change="toggleSelectAll"
                  class="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  aria-label="Select all issues"
                />
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Title
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Severity
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Status
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Affected Assets
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Findings
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Risk Score
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                SLA
              </th>
              <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">
                Assigned To
              </th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
            <tr
              v-for="issue in issueStore.issues"
              :key="issue.id"
              @click="viewIssue(issue)"
              class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary cursor-pointer"
            >
              <td class="px-3 py-4" @click.stop>
                <input
                  type="checkbox"
                  :checked="selectedIds.has(issue.id)"
                  @change="toggleSelect(issue.id)"
                  class="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  :aria-label="`Select issue ${issue.title}`"
                />
              </td>
              <td class="px-6 py-4">
                <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ issue.title }}</div>
                <div class="text-xs text-gray-500 dark:text-dark-text-secondary">{{ formatDate(issue.created_at) }}</div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span
                  class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                  :class="getSeverityColor(issue.severity)"
                >
                  {{ issue.severity }}
                </span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <span
                  class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                  :class="getStatusColor(issue.status)"
                >
                  {{ formatStatusLabel(issue.status) }}
                </span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary">
                {{ issue.affected_assets_count }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary">
                {{ issue.finding_count }}
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center">
                  <span class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ issue.risk_score }}</span>
                  <div class="ml-2 w-16 h-2 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden">
                    <div
                      class="h-full rounded-full"
                      :class="{
                        'bg-red-500': issue.risk_score >= 80,
                        'bg-orange-500': issue.risk_score >= 60 && issue.risk_score < 80,
                        'bg-yellow-500': issue.risk_score >= 40 && issue.risk_score < 60,
                        'bg-blue-500': issue.risk_score < 40,
                      }"
                      :style="{ width: `${Math.min(issue.risk_score, 100)}%` }"
                    />
                  </div>
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm">
                <span
                  v-if="issue.sla_due_at"
                  :class="isSlaOverdue(issue.sla_due_at) ? 'text-red-600 dark:text-red-400 font-medium' : 'text-gray-500 dark:text-dark-text-secondary'"
                >
                  {{ formatSla(issue.sla_due_at) }}
                </span>
                <span v-else class="text-gray-400 dark:text-dark-text-tertiary">-</span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary">
                {{ issue.assigned_to_name || 'Unassigned' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- Empty State -->
      <div v-if="issueStore.issues.length === 0" class="flex flex-col items-center justify-center py-16 px-4">
        <svg aria-hidden="true" class="w-16 h-16 text-gray-300 dark:text-gray-600 mb-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15a2.25 2.25 0 012.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
        </svg>
        <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-1">No issues yet</h3>
        <p class="text-sm text-gray-500 dark:text-dark-text-secondary mb-6 max-w-md text-center">
          Issues are automatically created by correlating related findings across multiple assets. Once vulnerability scans produce findings, the correlation engine will group them into actionable issues with SLA tracking.
        </p>
        <router-link
          to="/findings"
          class="inline-flex items-center px-4 py-2 bg-primary-600 text-white text-sm font-medium rounded-md hover:bg-primary-700 transition-colors"
        >
          <svg aria-hidden="true" class="w-4 h-4 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285zm0 13.036h.008v.008H12v-.008z" />
          </svg>
          View Findings
        </router-link>
      </div>

      <!-- Pagination -->
      <div v-if="issueStore.totalPages > 1" class="px-6 py-4 border-t border-gray-200 dark:border-dark-border">
        <div class="flex items-center justify-between">
          <div class="text-sm text-gray-700 dark:text-dark-text-secondary">
            Showing {{ ((issueStore.currentPage - 1) * issueStore.pageSize) + 1 }}
            to {{ Math.min(issueStore.currentPage * issueStore.pageSize, issueStore.totalItems) }}
            of {{ issueStore.totalItems }} results
          </div>
          <div class="flex space-x-2">
            <button
              @click="goToPage(issueStore.currentPage - 1)"
              :disabled="issueStore.currentPage === 1"
              class="px-3 py-1 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              Previous
            </button>
            <template v-for="pg in issuePaginationPages" :key="pg.value">
              <span
                v-if="pg.type === 'ellipsis'"
                class="px-3 py-1 text-sm text-gray-500 dark:text-dark-text-secondary"
              >...</span>
              <button
                v-else
                @click="goToPage(pg.value)"
                :aria-current="pg.value === issueStore.currentPage ? 'page' : undefined"
                :class="[
                  'px-3 py-1 border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary-500',
                  pg.value === issueStore.currentPage
                    ? 'bg-primary-600 text-white border-primary-600'
                    : 'border-gray-300 dark:border-dark-border text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary'
                ]"
              >
                {{ pg.value }}
              </button>
            </template>
            <button
              @click="goToPage(issueStore.currentPage + 1)"
              :disabled="issueStore.currentPage === issueStore.totalPages"
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
