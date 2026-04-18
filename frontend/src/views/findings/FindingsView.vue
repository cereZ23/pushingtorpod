<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { useTenantStore } from "@/stores/tenant";
import { findingApi } from "@/api/findings";
import apiClient from "@/api/client";
import type { Finding, PaginatedResponse } from "@/api/types";
import {
  getSeverityBadgeClass,
  getFindingStatusBadgeClass,
} from "@/utils/severity";
import { formatDate } from "@/utils/formatters";
import { useWindowedPagination } from "@/composables/usePagination";
import SkeletonLoader from "@/components/SkeletonLoader.vue";

const router = useRouter();
const tenantStore = useTenantStore();

const findings = ref<Finding[]>([]);
const isLoading = ref(true);
const error = ref("");
const currentPage = ref(1);
const pageSize = ref(25);
const totalItems = ref(0);
const totalPages = ref(0);

// Filters
const searchQuery = ref("");
const selectedSeverity = ref("");
const selectedStatus = ref("open");
const selectedSource = ref("");

// Sorting
const sortBy = ref("last_seen");
const sortOrder = ref<"asc" | "desc">("desc");

function handleSort(column: string) {
  if (sortBy.value === column) {
    sortOrder.value = sortOrder.value === "asc" ? "desc" : "asc";
  } else {
    sortBy.value = column;
    sortOrder.value = "desc";
  }
  currentPage.value = 1;
  loadFindings();
}

// View mode
const viewMode = ref<"list" | "grouped">("list");

// Grouped findings by host
const groupedByHost = computed(() => {
  const groups: Record<
    string,
    { findings: Finding[]; critical: number; high: number; medium: number }
  > = {};
  for (const f of findings.value) {
    const host = (f as any).asset_identifier || (f as any).host || "Unknown";
    if (!groups[host]) {
      groups[host] = { findings: [], critical: 0, high: 0, medium: 0 };
    }
    groups[host].findings.push(f);
    const sev = ((f as any).severity || "").toLowerCase();
    if (sev === "critical") groups[host].critical++;
    else if (sev === "high") groups[host].high++;
    else if (sev === "medium") groups[host].medium++;
  }
  // Sort by critical desc, then high, then count
  return Object.entries(groups).sort(
    ([, a], [, b]) =>
      b.critical - a.critical ||
      b.high - a.high ||
      b.findings.length - a.findings.length,
  );
});

const expandedHosts = ref<Set<string>>(new Set());

function toggleHost(host: string) {
  if (expandedHosts.value.has(host)) {
    expandedHosts.value.delete(host);
  } else {
    expandedHosts.value.add(host);
  }
}

// Bulk selection
const selectedIds = ref<Set<number>>(new Set());
const isBulkUpdating = ref(false);

const currentTenantId = computed(() => tenantStore.currentTenantId);

// AbortController for cancelling in-flight API requests on navigation
let abortController: AbortController | null = null;

onMounted(async () => {
  await loadFindings();
});

watch(currentTenantId, () => {
  if (currentTenantId.value) {
    currentPage.value = 1;
    loadFindings();
  }
});

const {
  pages: paginationPages,
  hasPrevious,
  hasNext,
} = useWindowedPagination(currentPage, totalPages);

async function loadFindings() {
  selectedIds.value = new Set();

  if (!currentTenantId.value) {
    error.value = "No tenant selected";
    isLoading.value = false;
    return;
  }

  abortController?.abort();
  abortController = new AbortController();

  isLoading.value = true;
  error.value = "";

  try {
    const params = {
      page: currentPage.value,
      page_size: pageSize.value,
      search: searchQuery.value || undefined,
      severity: selectedSeverity.value || undefined,
      status: selectedStatus.value || undefined,
      source: selectedSource.value || undefined,
      sort_by: sortBy.value,
      sort_order: sortOrder.value,
    };

    const response: PaginatedResponse<Finding> = await findingApi.list(
      currentTenantId.value,
      params,
    );
    findings.value = response.data;
    totalItems.value = response.meta.total;
    totalPages.value = response.meta.total_pages;
  } catch (err: unknown) {
    if (
      err instanceof Error &&
      (err.name === "CanceledError" || err.name === "AbortError")
    )
      return;
    const axiosErr = err as { message?: string };
    error.value = axiosErr.message || "Failed to load findings";
  } finally {
    isLoading.value = false;
  }
}

onUnmounted(() => {
  abortController?.abort();
});

function handleSearch() {
  currentPage.value = 1;
  loadFindings();
}

function goToPage(page: number) {
  currentPage.value = page;
  loadFindings();
}

function viewFinding(findingId: number) {
  router.push({ name: "FindingDetail", params: { id: findingId } });
}

function toggleSelectAll() {
  if (selectedIds.value.size === findings.value.length) {
    selectedIds.value = new Set();
  } else {
    selectedIds.value = new Set(findings.value.map((f) => f.id));
  }
}

function toggleSelect(id: number) {
  const next = new Set(selectedIds.value);
  if (next.has(id)) {
    next.delete(id);
  } else {
    next.add(id);
  }
  selectedIds.value = next;
}

async function bulkChangeStatus(newStatus: string) {
  if (selectedIds.value.size === 0) return;
  isBulkUpdating.value = true;

  try {
    const tid = currentTenantId.value;
    if (!tid) return;
    const results = await Promise.allSettled(
      Array.from(selectedIds.value).map((id) =>
        findingApi.update(tid, id, { status: newStatus } as Partial<Finding>),
      ),
    );
    const failed = results.filter((r) => r.status === "rejected").length;
    if (failed > 0) {
      error.value = `${failed} of ${selectedIds.value.size} updates failed`;
    }
    selectedIds.value = new Set();
    await loadFindings();
  } catch {
    error.value = "Bulk update failed";
  } finally {
    isBulkUpdating.value = false;
  }
}

function handleBulkStatusChange(event: Event) {
  const select = event.target as HTMLSelectElement;
  const value = select.value;
  if (value) {
    bulkChangeStatus(value);
    select.value = "";
  }
}

async function exportCsv() {
  const tid = currentTenantId.value;
  if (!tid) return;

  try {
    const response = await apiClient.get(
      `/api/v1/tenants/${tid}/reports/export/csv`,
      { responseType: "blob" },
    );
    const url = URL.createObjectURL(response.data);
    const a = document.createElement("a");
    a.href = url;
    a.download = "findings_export.csv";
    a.click();
    URL.revokeObjectURL(url);
  } catch {
    error.value = "Failed to export CSV";
  }
}

// Color functions and formatDate imported from @/utils/severity and @/utils/formatters
const getSeverityColor = getSeverityBadgeClass;
const getStatusColor = getFindingStatusBadgeClass;
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
        Findings
      </h2>
      <div class="flex items-center gap-2">
        <div
          class="flex rounded-md border border-gray-300 dark:border-dark-border overflow-hidden"
        >
          <button
            @click="viewMode = 'list'"
            class="px-3 py-2 text-sm font-medium transition-colors"
            :class="
              viewMode === 'list'
                ? 'bg-primary-600 text-white'
                : 'bg-white dark:bg-dark-bg-secondary text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary'
            "
          >
            List
          </button>
          <button
            @click="viewMode = 'grouped'"
            class="px-3 py-2 text-sm font-medium transition-colors"
            :class="
              viewMode === 'grouped'
                ? 'bg-primary-600 text-white'
                : 'bg-white dark:bg-dark-bg-secondary text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary'
            "
          >
            By Host
          </button>
        </div>
        <button
          @click="exportCsv"
          class="px-4 py-2 border border-gray-300 dark:border-dark-border text-gray-700 dark:text-dark-text-secondary rounded-md hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary text-sm font-medium"
        >
          Export CSV
        </button>
        <button
          @click="loadFindings"
          :disabled="isLoading"
          class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50"
        >
          Refresh
        </button>
      </div>
    </div>

    <!-- Filters -->
    <div
      class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border"
    >
      <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div>
          <label
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
            >Search</label
          >
          <input
            v-model="searchQuery"
            @keyup.enter="handleSearch"
            type="text"
            placeholder="Search findings..."
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>

        <div>
          <label
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
            >Severity</label
          >
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
          <label
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
            >Status</label
          >
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
          <label
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
            >Source</label
          >
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

    <!-- Loading State (Skeleton) -->
    <div
      v-if="isLoading"
      role="status"
      class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
    >
      <SkeletonLoader variant="table-row" :rows="10" />
    </div>

    <!-- Error State -->
    <div
      v-else-if="error"
      role="alert"
      class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md"
    >
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Findings Table -->
    <div
      v-else
      class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
    >
      <!-- Bulk Actions -->
      <div
        v-if="selectedIds.size > 0"
        class="bg-primary-50 dark:bg-primary-900/20 px-6 py-3 flex items-center justify-between border-b border-primary-200 dark:border-primary-800"
      >
        <span
          class="text-sm font-medium text-primary-700 dark:text-primary-300"
        >
          {{ selectedIds.size }} selected
        </span>
        <div class="flex items-center gap-2">
          <select
            @change="handleBulkStatusChange"
            :disabled="isBulkUpdating"
            class="text-sm border border-gray-300 dark:border-dark-border rounded-md px-2 py-1 dark:bg-dark-bg-tertiary dark:text-dark-text-primary"
          >
            <option value="">Change Status...</option>
            <option value="open">Open</option>
            <option value="suppressed">Suppressed</option>
            <option value="fixed">Fixed</option>
          </select>
          <button
            @click="selectedIds = new Set()"
            class="text-sm text-gray-600 dark:text-dark-text-secondary hover:text-gray-800 dark:hover:text-dark-text-primary"
          >
            Clear
          </button>
        </div>
      </div>
      <!-- Grouped by Host View -->
      <div v-if="viewMode === 'grouped'" class="space-y-3">
        <div
          v-for="[host, group] in groupedByHost"
          :key="host"
          class="border border-gray-200 dark:border-dark-border rounded-lg overflow-hidden"
        >
          <button
            @click="toggleHost(host)"
            class="w-full px-4 py-3 flex items-center justify-between bg-gray-50 dark:bg-dark-bg-tertiary hover:bg-gray-100 dark:hover:bg-dark-bg-secondary transition-colors"
          >
            <div class="flex items-center gap-3">
              <svg
                class="w-4 h-4 text-gray-400 transition-transform"
                :class="{ 'rotate-90': expandedHosts.has(host) }"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M9 5l7 7-7 7"
                />
              </svg>
              <span
                class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary font-mono"
                >{{ host }}</span
              >
              <span class="text-xs text-gray-500 dark:text-dark-text-tertiary"
                >({{ group.findings.length }} findings)</span
              >
            </div>
            <div class="flex items-center gap-2">
              <span
                v-if="group.critical > 0"
                class="px-2 py-0.5 text-xs font-semibold rounded-full bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
              >
                {{ group.critical }} critical
              </span>
              <span
                v-if="group.high > 0"
                class="px-2 py-0.5 text-xs font-semibold rounded-full bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400"
              >
                {{ group.high }} high
              </span>
              <span
                v-if="group.medium > 0"
                class="px-2 py-0.5 text-xs font-semibold rounded-full bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400"
              >
                {{ group.medium }} medium
              </span>
            </div>
          </button>
          <div
            v-if="expandedHosts.has(host)"
            class="divide-y divide-gray-200 dark:divide-dark-border"
          >
            <div
              v-for="f in group.findings"
              :key="f.id"
              class="px-4 py-2.5 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary cursor-pointer"
              @click="
                router.push({ name: 'FindingDetail', params: { id: f.id } })
              "
            >
              <div class="flex items-center gap-3 min-w-0">
                <span
                  class="px-2 py-0.5 text-xs font-semibold rounded-full flex-shrink-0"
                  :class="getSeverityBadgeClass((f as any).severity)"
                >
                  {{ (f as any).severity }}
                </span>
                <span
                  class="text-sm text-gray-900 dark:text-dark-text-primary truncate"
                  >{{ f.name }}</span
                >
              </div>
              <span
                class="text-xs text-gray-400 dark:text-dark-text-tertiary flex-shrink-0 ml-2"
                >{{ (f as any).source }}</span
              >
            </div>
          </div>
        </div>
        <div
          v-if="groupedByHost.length === 0"
          class="text-center py-8 text-gray-500 dark:text-dark-text-secondary"
        >
          No findings match current filters
        </div>
      </div>

      <!-- List View (existing table) -->
      <div v-if="viewMode === 'list'" class="overflow-x-auto">
        <table
          class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
        >
          <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
            <tr>
              <th scope="col" class="px-3 py-3 text-left">
                <input
                  type="checkbox"
                  :checked="
                    selectedIds.size === findings.length && findings.length > 0
                  "
                  :indeterminate="
                    selectedIds.size > 0 && selectedIds.size < findings.length
                  "
                  @change="toggleSelectAll"
                  class="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  aria-label="Select all findings"
                />
              </th>
              <th
                v-for="col in [
                  { key: 'name', label: 'Name' },
                  { key: 'severity', label: 'Severity' },
                  { key: 'status', label: 'Status' },
                  { key: 'asset_identifier', label: 'Asset' },
                ]"
                :key="col.key"
                scope="col"
                class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider cursor-pointer select-none hover:text-gray-700 dark:hover:text-gray-200"
                :aria-sort="
                  sortBy === col.key
                    ? sortOrder === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : undefined
                "
                @click="handleSort(col.key)"
              >
                <div class="flex items-center gap-1">
                  {{ col.label }}
                  <!-- Active sort: up arrow -->
                  <svg
                    v-if="sortBy === col.key && sortOrder === 'asc'"
                    class="w-3.5 h-3.5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M5 15l7-7 7 7"
                    />
                  </svg>
                  <!-- Active sort: down arrow -->
                  <svg
                    v-else-if="sortBy === col.key && sortOrder === 'desc'"
                    class="w-3.5 h-3.5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                  <!-- Inactive: up/down arrows dimmed -->
                  <svg
                    v-else
                    class="w-3.5 h-3.5 opacity-30"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"
                    />
                  </svg>
                </div>
              </th>
              <th
                scope="col"
                class="hidden xl:table-cell px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
              >
                Source
              </th>
              <th
                scope="col"
                class="hidden 2xl:table-cell px-3 py-3 text-center text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
              >
                Seen
              </th>
              <th
                scope="col"
                class="hidden 2xl:table-cell px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider cursor-pointer select-none hover:text-gray-700 dark:hover:text-gray-200"
                :aria-sort="
                  sortBy === 'first_seen'
                    ? sortOrder === 'asc'
                      ? 'ascending'
                      : 'descending'
                    : undefined
                "
                @click="handleSort('first_seen')"
              >
                <div class="flex items-center gap-1">
                  First Seen
                  <svg
                    v-if="sortBy === 'first_seen' && sortOrder === 'asc'"
                    class="w-3.5 h-3.5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M5 15l7-7 7 7"
                    />
                  </svg>
                  <svg
                    v-else-if="sortBy === 'first_seen' && sortOrder === 'desc'"
                    class="w-3.5 h-3.5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M19 9l-7 7-7-7"
                    />
                  </svg>
                  <svg
                    v-else
                    class="w-3.5 h-3.5 opacity-30"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                    aria-hidden="true"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4"
                    />
                  </svg>
                </div>
              </th>
              <th
                scope="col"
                class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
              >
                Actions
              </th>
            </tr>
          </thead>
          <tbody
            class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border"
          >
            <tr
              v-for="finding in findings"
              :key="finding.id"
              class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
            >
              <td class="px-3 py-4">
                <input
                  type="checkbox"
                  :checked="selectedIds.has(finding.id)"
                  @change="toggleSelect(finding.id)"
                  class="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
                  :aria-label="`Select finding ${finding.name}`"
                />
              </td>
              <td class="px-3 py-4">
                <div
                  class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
                >
                  {{ finding.name }}
                </div>
                <div
                  v-if="finding.cve_id"
                  class="text-xs text-gray-500 dark:text-dark-text-secondary"
                >
                  {{ finding.cve_id }}
                </div>
                <div
                  v-if="finding.template_id"
                  class="text-xs text-gray-500 dark:text-dark-text-secondary"
                >
                  {{ finding.template_id }}
                </div>
              </td>
              <td class="px-3 py-4 whitespace-nowrap">
                <div class="flex items-center gap-1.5 flex-wrap">
                  <span
                    class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                    :class="getSeverityColor(finding.severity)"
                  >
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
                  <span
                    v-if="finding.cvss_score"
                    class="text-xs text-gray-500 dark:text-dark-text-secondary"
                  >
                    CVSS: {{ finding.cvss_score }}
                  </span>
                  <span
                    v-if="finding.evidence?.threat_intel?.epss_score != null"
                    class="text-xs font-medium"
                    :class="
                      finding.evidence.threat_intel.epss_score >= 0.7
                        ? 'text-red-600 dark:text-red-400'
                        : finding.evidence.threat_intel.epss_score >= 0.4
                          ? 'text-orange-600 dark:text-orange-400'
                          : 'text-gray-500 dark:text-dark-text-secondary'
                    "
                    :title="`Exploit Prediction Scoring System: ${(finding.evidence.threat_intel.epss_score * 100).toFixed(1)}% probability of exploitation in the next 30 days`"
                  >
                    EPSS:
                    {{
                      Math.round(
                        finding.evidence.threat_intel.epss_score * 100,
                      )
                    }}%
                  </span>
                </div>
              </td>
              <td class="px-3 py-4 whitespace-nowrap">
                <span
                  class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                  :class="getStatusColor(finding.status)"
                >
                  {{ finding.status }}
                </span>
              </td>
              <td class="px-3 py-4">
                <div class="text-sm text-gray-900 dark:text-dark-text-primary">
                  {{ finding.asset_identifier || "-" }}
                </div>
                <div
                  v-if="finding.asset_type"
                  class="text-xs text-gray-500 dark:text-dark-text-secondary"
                >
                  {{ finding.asset_type }}
                </div>
              </td>
              <td
                class="hidden xl:table-cell px-3 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary"
              >
                {{ finding.source }}
              </td>
              <td
                class="hidden 2xl:table-cell px-3 py-4 whitespace-nowrap text-center"
              >
                <span
                  v-if="finding.occurrence_count > 1"
                  class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-indigo-100 text-indigo-800 dark:bg-indigo-900/30 dark:text-indigo-300"
                  :title="`Detected ${finding.occurrence_count} times`"
                >
                  {{ finding.occurrence_count }}x
                </span>
                <span
                  v-else
                  class="text-xs text-gray-400 dark:text-dark-text-secondary"
                  >1x</span
                >
              </td>
              <td
                class="hidden 2xl:table-cell px-3 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary"
              >
                {{ formatDate(finding.first_seen) }}
              </td>
              <td class="px-3 py-4 whitespace-nowrap text-sm font-medium">
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
      <div
        v-if="findings.length === 0"
        class="flex flex-col items-center justify-center py-16 px-4"
      >
        <svg
          aria-hidden="true"
          class="w-16 h-16 text-gray-300 dark:text-gray-600 mb-4"
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          stroke-width="1.5"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285zm0 13.036h.008v.008H12v-.008z"
          />
        </svg>
        <h3
          class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-1"
        >
          No vulnerabilities found
        </h3>
        <p
          class="text-sm text-gray-500 dark:text-dark-text-secondary mb-6 max-w-md text-center"
        >
          Vulnerabilities detected by Nuclei scans and other scanning engines
          will be listed here. Run a vulnerability scan to start identifying
          security issues.
        </p>
        <router-link
          to="/scans"
          class="inline-flex items-center px-4 py-2 bg-primary-600 text-white text-sm font-medium rounded-md hover:bg-primary-700 transition-colors"
        >
          <svg
            aria-hidden="true"
            class="w-4 h-4 mr-2"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
            stroke-width="2"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z"
            />
          </svg>
          Run a Vulnerability Scan
        </router-link>
      </div>

      <!-- Pagination -->
      <div
        v-if="totalPages > 1"
        class="px-6 py-4 border-t border-gray-200 dark:border-dark-border"
      >
        <div class="flex items-center justify-between">
          <div class="text-sm text-gray-700 dark:text-dark-text-secondary">
            Showing {{ (currentPage - 1) * pageSize + 1 }} to
            {{ Math.min(currentPage * pageSize, totalItems) }} of
            {{ totalItems }} results
          </div>
          <div class="flex space-x-1">
            <button
              @click="goToPage(currentPage - 1)"
              :disabled="!hasPrevious"
              class="px-3 py-1 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              Previous
            </button>
            <template v-for="pg in paginationPages" :key="pg.value">
              <span
                v-if="pg.type === 'ellipsis'"
                class="px-2 py-1 text-sm text-gray-500 dark:text-dark-text-secondary"
                >...</span
              >
              <button
                v-else
                @click="goToPage(pg.value)"
                :aria-current="pg.value === currentPage ? 'page' : undefined"
                :class="[
                  'px-3 py-1 border rounded-md text-sm focus:outline-none focus:ring-2 focus:ring-primary-500',
                  pg.value === currentPage
                    ? 'bg-primary-600 text-white border-primary-600'
                    : 'border-gray-300 dark:border-dark-border text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary',
                ]"
              >
                {{ pg.value }}
              </button>
            </template>
            <button
              @click="goToPage(currentPage + 1)"
              :disabled="!hasNext"
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
