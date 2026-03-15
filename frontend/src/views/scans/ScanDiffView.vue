<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted, watch } from "vue";
import { useRoute, useRouter } from "vue-router";
import { useTenantStore } from "@/stores/tenant";
import apiClient from "@/api/client";
import { getSeverityBadgeClass } from "@/utils/severity";
import { formatDate } from "@/utils/formatters";
import SkeletonLoader from "@/components/SkeletonLoader.vue";

interface ScanRunOption {
  id: number;
  status: string;
  completed_at: string | null;
  started_at: string | null;
}

interface ScanRunSummary {
  id: number;
  status: string;
  completed_at: string | null;
}

interface DiffSummary {
  new_assets: number;
  removed_assets: number;
  new_services: number;
  removed_services: number;
  new_findings: number;
  resolved_findings: number;
}

interface DiffAssetItem {
  identifier: string;
  type: string;
}

interface DiffServiceItem {
  asset_identifier: string;
  port: number;
  protocol: string;
}

interface DiffFindingItem {
  id: number | null;
  name: string | null;
  severity: string | null;
  asset_identifier: string | null;
}

interface ScanCompareResponse {
  base_run: ScanRunSummary;
  compare_run: ScanRunSummary;
  is_suspicious: boolean;
  summary: DiffSummary;
  assets: { added: DiffAssetItem[]; removed: DiffAssetItem[] };
  services: { added: DiffServiceItem[]; removed: DiffServiceItem[] };
  findings: { added: DiffFindingItem[]; resolved: DiffFindingItem[] };
}

const route = useRoute();
const router = useRouter();
const tenantStore = useTenantStore();

const tenantId = computed(() => tenantStore.currentTenantId);
const projectId = computed(() => Number(route.params.projectId));

const completedRuns = ref<ScanRunOption[]>([]);
const baseRunId = ref<number | null>(null);
const compareRunId = ref<number | null>(null);

const diffResult = ref<ScanCompareResponse | null>(null);
const isLoadingRuns = ref(false);
const isLoadingDiff = ref(false);
const error = ref("");
const activeTab = ref<"assets" | "services" | "findings">("assets");

let abortController: AbortController | null = null;

onMounted(async () => {
  await loadCompletedRuns();

  // Pre-fill from query params
  const base = route.query.base;
  const compare = route.query.compare;
  if (base) baseRunId.value = Number(base);
  if (compare) compareRunId.value = Number(compare);

  if (baseRunId.value && compareRunId.value) {
    await loadDiff();
  }
});

onUnmounted(() => {
  abortController?.abort();
});

watch(tenantId, async () => {
  if (tenantId.value) {
    await loadCompletedRuns();
  }
});

async function loadCompletedRuns(): Promise<void> {
  if (!tenantId.value || !projectId.value) return;
  isLoadingRuns.value = true;
  error.value = "";

  try {
    const response = await apiClient.get(
      `/api/v1/tenants/${tenantId.value}/projects/${projectId.value}/scans`,
    );
    const data = response.data;
    const runs: ScanRunOption[] = Array.isArray(data)
      ? data
      : (data.items ?? []);
    completedRuns.value = runs.filter(
      (r: ScanRunOption) => r.status === "completed",
    );
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "CanceledError") return;
    error.value =
      err instanceof Error ? err.message : "Failed to load scan runs";
  } finally {
    isLoadingRuns.value = false;
  }
}

async function loadDiff(): Promise<void> {
  if (!tenantId.value || !projectId.value) return;
  if (!baseRunId.value || !compareRunId.value) return;

  abortController?.abort();
  abortController = new AbortController();

  isLoadingDiff.value = true;
  error.value = "";
  diffResult.value = null;

  try {
    const response = await apiClient.get<ScanCompareResponse>(
      `/api/v1/tenants/${tenantId.value}/projects/${projectId.value}/scans/compare`,
      {
        params: {
          base_run_id: baseRunId.value,
          compare_run_id: compareRunId.value,
        },
        signal: abortController.signal,
      },
    );
    diffResult.value = response.data;

    // Update URL query params without navigation
    router.replace({
      query: {
        base: String(baseRunId.value),
        compare: String(compareRunId.value),
      },
    });
  } catch (err: unknown) {
    if (err instanceof Error && err.name === "CanceledError") return;
    const axiosErr = err as { response?: { data?: { detail?: string } } };
    error.value =
      axiosErr?.response?.data?.detail ??
      (err instanceof Error ? err.message : "Failed to compare scans");
  } finally {
    isLoadingDiff.value = false;
  }
}

function handleCompare(): void {
  if (baseRunId.value && compareRunId.value) {
    loadDiff();
  }
}

function goBack(): void {
  router.push({ name: "Scans" });
}

const canCompare = computed(
  () =>
    baseRunId.value &&
    compareRunId.value &&
    baseRunId.value !== compareRunId.value,
);

const totalChanges = computed(() => {
  if (!diffResult.value) return 0;
  const s = diffResult.value.summary;
  return (
    s.new_assets +
    s.removed_assets +
    s.new_services +
    s.removed_services +
    s.new_findings +
    s.resolved_findings
  );
});
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center gap-4">
      <button
        @click="goBack"
        class="p-2 rounded-md text-gray-600 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
      >
        <svg
          class="w-5 h-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M15 19l-7-7 7-7"
          />
        </svg>
      </button>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
        Scan Comparison
      </h2>
    </div>

    <!-- Error -->
    <div
      v-if="error"
      role="alert"
      class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md"
    >
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Run Selector -->
    <div
      class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
    >
      <h3
        class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4"
      >
        Select Scans to Compare
      </h3>

      <SkeletonLoader v-if="isLoadingRuns" variant="text" />

      <div v-else class="flex items-end gap-4 flex-wrap">
        <div class="flex-1 min-w-[200px]">
          <label
            for="base-run"
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
          >
            Base Scan (older)
          </label>
          <select
            id="base-run"
            v-model="baseRunId"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-900 dark:text-dark-text-primary bg-white dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option :value="null" disabled>Select base scan...</option>
            <option
              v-for="run in completedRuns"
              :key="run.id"
              :value="run.id"
              :disabled="run.id === compareRunId"
            >
              Run #{{ run.id }} — {{ formatDate(run.completed_at) }}
            </option>
          </select>
        </div>

        <div class="flex items-center pb-2">
          <svg
            class="w-5 h-5 text-gray-400"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M13 7l5 5m0 0l-5 5m5-5H6"
            />
          </svg>
        </div>

        <div class="flex-1 min-w-[200px]">
          <label
            for="compare-run"
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
          >
            Compare Scan (newer)
          </label>
          <select
            id="compare-run"
            v-model="compareRunId"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-900 dark:text-dark-text-primary bg-white dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option :value="null" disabled>Select compare scan...</option>
            <option
              v-for="run in completedRuns"
              :key="run.id"
              :value="run.id"
              :disabled="run.id === baseRunId"
            >
              Run #{{ run.id }} — {{ formatDate(run.completed_at) }}
            </option>
          </select>
        </div>

        <button
          @click="handleCompare"
          :disabled="!canCompare || isLoadingDiff"
          class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm font-medium"
        >
          {{ isLoadingDiff ? "Comparing..." : "Compare" }}
        </button>
      </div>

      <p
        v-if="completedRuns.length < 2"
        class="mt-3 text-sm text-gray-500 dark:text-dark-text-secondary"
      >
        At least 2 completed scan runs are needed for comparison.
      </p>
    </div>

    <!-- Loading state -->
    <SkeletonLoader v-if="isLoadingDiff" variant="card" />

    <!-- Diff Results -->
    <template v-if="diffResult">
      <!-- Suspicious warning -->
      <div
        v-if="diffResult.is_suspicious"
        role="alert"
        class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 p-4 rounded-md"
      >
        <div class="flex items-center gap-2">
          <svg
            class="w-5 h-5 text-yellow-600 dark:text-yellow-400 flex-shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
          </svg>
          <p class="text-sm font-medium text-yellow-800 dark:text-yellow-300">
            Suspicious diff: more than 50% of assets were removed. This may
            indicate a scan failure rather than real changes.
          </p>
        </div>
      </div>

      <!-- Run info -->
      <div
        class="flex items-center justify-between text-sm text-gray-500 dark:text-dark-text-secondary"
      >
        <span>
          Run #{{ diffResult.base_run.id }} ({{
            formatDate(diffResult.base_run.completed_at)
          }})
        </span>
        <svg
          class="w-5 h-5"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M13 7l5 5m0 0l-5 5m5-5H6"
          />
        </svg>
        <span>
          Run #{{ diffResult.compare_run.id }} ({{
            formatDate(diffResult.compare_run.completed_at)
          }})
        </span>
      </div>

      <!-- Summary Cards -->
      <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <div
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
        >
          <dt
            class="text-xs font-medium text-gray-500 dark:text-dark-text-secondary"
          >
            New Assets
          </dt>
          <dd
            class="mt-1 text-2xl font-bold text-green-600 dark:text-green-400"
          >
            +{{ diffResult.summary.new_assets }}
          </dd>
        </div>
        <div
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
        >
          <dt
            class="text-xs font-medium text-gray-500 dark:text-dark-text-secondary"
          >
            Removed Assets
          </dt>
          <dd class="mt-1 text-2xl font-bold text-red-600 dark:text-red-400">
            -{{ diffResult.summary.removed_assets }}
          </dd>
        </div>
        <div
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
        >
          <dt
            class="text-xs font-medium text-gray-500 dark:text-dark-text-secondary"
          >
            New Services
          </dt>
          <dd
            class="mt-1 text-2xl font-bold text-green-600 dark:text-green-400"
          >
            +{{ diffResult.summary.new_services }}
          </dd>
        </div>
        <div
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
        >
          <dt
            class="text-xs font-medium text-gray-500 dark:text-dark-text-secondary"
          >
            Removed Services
          </dt>
          <dd class="mt-1 text-2xl font-bold text-red-600 dark:text-red-400">
            -{{ diffResult.summary.removed_services }}
          </dd>
        </div>
        <div
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
        >
          <dt
            class="text-xs font-medium text-gray-500 dark:text-dark-text-secondary"
          >
            New Findings
          </dt>
          <dd
            class="mt-1 text-2xl font-bold text-green-600 dark:text-green-400"
          >
            +{{ diffResult.summary.new_findings }}
          </dd>
        </div>
        <div
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
        >
          <dt
            class="text-xs font-medium text-gray-500 dark:text-dark-text-secondary"
          >
            Resolved Findings
          </dt>
          <dd class="mt-1 text-2xl font-bold text-blue-600 dark:text-blue-400">
            -{{ diffResult.summary.resolved_findings }}
          </dd>
        </div>
      </div>

      <!-- No changes -->
      <div
        v-if="totalChanges === 0"
        class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-8 text-center"
      >
        <p class="text-gray-500 dark:text-dark-text-secondary">
          No differences found between these two scan runs.
        </p>
      </div>

      <!-- Tabs + Content -->
      <div
        v-else
        class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border"
      >
        <!-- Tab bar -->
        <div class="border-b border-gray-200 dark:border-dark-border px-4">
          <nav class="-mb-px flex space-x-6" aria-label="Diff tabs">
            <button
              @click="activeTab = 'assets'"
              :class="[
                'py-3 px-1 border-b-2 text-sm font-medium transition-colors',
                activeTab === 'assets'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-dark-text-secondary hover:text-gray-700 dark:hover:text-dark-text-primary hover:border-gray-300',
              ]"
            >
              Assets
              <span
                v-if="
                  diffResult.summary.new_assets +
                    diffResult.summary.removed_assets >
                  0
                "
                class="ml-1.5 px-1.5 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-dark-bg-tertiary"
              >
                {{
                  diffResult.summary.new_assets +
                  diffResult.summary.removed_assets
                }}
              </span>
            </button>
            <button
              @click="activeTab = 'services'"
              :class="[
                'py-3 px-1 border-b-2 text-sm font-medium transition-colors',
                activeTab === 'services'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-dark-text-secondary hover:text-gray-700 dark:hover:text-dark-text-primary hover:border-gray-300',
              ]"
            >
              Services
              <span
                v-if="
                  diffResult.summary.new_services +
                    diffResult.summary.removed_services >
                  0
                "
                class="ml-1.5 px-1.5 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-dark-bg-tertiary"
              >
                {{
                  diffResult.summary.new_services +
                  diffResult.summary.removed_services
                }}
              </span>
            </button>
            <button
              @click="activeTab = 'findings'"
              :class="[
                'py-3 px-1 border-b-2 text-sm font-medium transition-colors',
                activeTab === 'findings'
                  ? 'border-primary-500 text-primary-600 dark:text-primary-400'
                  : 'border-transparent text-gray-500 dark:text-dark-text-secondary hover:text-gray-700 dark:hover:text-dark-text-primary hover:border-gray-300',
              ]"
            >
              Findings
              <span
                v-if="
                  diffResult.summary.new_findings +
                    diffResult.summary.resolved_findings >
                  0
                "
                class="ml-1.5 px-1.5 py-0.5 text-xs rounded-full bg-gray-100 dark:bg-dark-bg-tertiary"
              >
                {{
                  diffResult.summary.new_findings +
                  diffResult.summary.resolved_findings
                }}
              </span>
            </button>
          </nav>
        </div>

        <!-- Tab content -->
        <div class="p-4 overflow-x-auto">
          <!-- Assets Tab -->
          <table
            v-if="activeTab === 'assets'"
            class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
          >
            <thead>
              <tr>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Change
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Identifier
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Type
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-border">
              <tr
                v-for="asset in diffResult.assets.added"
                :key="'add-' + asset.identifier"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400"
                  >
                    Added
                  </span>
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary font-mono"
                >
                  {{ asset.identifier }}
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-500 dark:text-dark-text-secondary"
                >
                  {{ asset.type }}
                </td>
              </tr>
              <tr
                v-for="asset in diffResult.assets.removed"
                :key="'rem-' + asset.identifier"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400"
                  >
                    Removed
                  </span>
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary font-mono"
                >
                  {{ asset.identifier }}
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-500 dark:text-dark-text-secondary"
                >
                  {{ asset.type }}
                </td>
              </tr>
              <tr
                v-if="
                  diffResult.assets.added.length === 0 &&
                  diffResult.assets.removed.length === 0
                "
              >
                <td
                  colspan="3"
                  class="px-4 py-8 text-center text-sm text-gray-500 dark:text-dark-text-secondary"
                >
                  No asset changes
                </td>
              </tr>
            </tbody>
          </table>

          <!-- Services Tab -->
          <table
            v-if="activeTab === 'services'"
            class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
          >
            <thead>
              <tr>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Change
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Asset
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Port
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Protocol
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-border">
              <tr
                v-for="svc in diffResult.services.added"
                :key="'add-' + svc.asset_identifier + svc.port + svc.protocol"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400"
                  >
                    Added
                  </span>
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary font-mono"
                >
                  {{ svc.asset_identifier }}
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary"
                >
                  {{ svc.port }}
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-500 dark:text-dark-text-secondary uppercase"
                >
                  {{ svc.protocol }}
                </td>
              </tr>
              <tr
                v-for="svc in diffResult.services.removed"
                :key="'rem-' + svc.asset_identifier + svc.port + svc.protocol"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400"
                  >
                    Removed
                  </span>
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary font-mono"
                >
                  {{ svc.asset_identifier }}
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary"
                >
                  {{ svc.port }}
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-500 dark:text-dark-text-secondary uppercase"
                >
                  {{ svc.protocol }}
                </td>
              </tr>
              <tr
                v-if="
                  diffResult.services.added.length === 0 &&
                  diffResult.services.removed.length === 0
                "
              >
                <td
                  colspan="4"
                  class="px-4 py-8 text-center text-sm text-gray-500 dark:text-dark-text-secondary"
                >
                  No service changes
                </td>
              </tr>
            </tbody>
          </table>

          <!-- Findings Tab -->
          <table
            v-if="activeTab === 'findings'"
            class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
          >
            <thead>
              <tr>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Change
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Name
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Severity
                </th>
                <th
                  class="px-4 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                >
                  Asset
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-border">
              <tr
                v-for="(finding, idx) in diffResult.findings.added"
                :key="'add-' + idx"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400"
                  >
                    New
                  </span>
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary"
                >
                  {{ finding.name ?? "Unknown" }}
                </td>
                <td class="px-4 py-3">
                  <span
                    v-if="finding.severity"
                    class="px-2 py-0.5 text-xs font-semibold rounded-full"
                    :class="getSeverityBadgeClass(finding.severity)"
                  >
                    {{ finding.severity }}
                  </span>
                  <span
                    v-else
                    class="text-sm text-gray-400 dark:text-dark-text-tertiary"
                    >-</span
                  >
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-500 dark:text-dark-text-secondary font-mono"
                >
                  {{ finding.asset_identifier ?? "-" }}
                </td>
              </tr>
              <tr
                v-for="(finding, idx) in diffResult.findings.resolved"
                :key="'res-' + idx"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-4 py-3">
                  <span
                    class="inline-flex items-center px-2 py-0.5 text-xs font-semibold rounded-full bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400"
                  >
                    Resolved
                  </span>
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-900 dark:text-dark-text-primary"
                >
                  {{ finding.name ?? "Unknown" }}
                </td>
                <td class="px-4 py-3">
                  <span
                    v-if="finding.severity"
                    class="px-2 py-0.5 text-xs font-semibold rounded-full"
                    :class="getSeverityBadgeClass(finding.severity)"
                  >
                    {{ finding.severity }}
                  </span>
                  <span
                    v-else
                    class="text-sm text-gray-400 dark:text-dark-text-tertiary"
                    >-</span
                  >
                </td>
                <td
                  class="px-4 py-3 text-sm text-gray-500 dark:text-dark-text-secondary font-mono"
                >
                  {{ finding.asset_identifier ?? "-" }}
                </td>
              </tr>
              <tr
                v-if="
                  diffResult.findings.added.length === 0 &&
                  diffResult.findings.resolved.length === 0
                "
              >
                <td
                  colspan="4"
                  class="px-4 py-8 text-center text-sm text-gray-500 dark:text-dark-text-secondary"
                >
                  No finding changes
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- Empty state -->
    <div
      v-if="!diffResult && !isLoadingDiff && !error"
      class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-12 text-center"
    >
      <svg
        class="mx-auto w-12 h-12 text-gray-400 dark:text-dark-text-tertiary"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="1.5"
          d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"
        />
      </svg>
      <p class="mt-3 text-gray-500 dark:text-dark-text-secondary text-sm">
        Select two completed scans above to compare their results.
      </p>
    </div>
  </div>
</template>
