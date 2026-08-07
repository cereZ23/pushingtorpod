<script setup lang="ts">
// UI-3 operational dashboard. Purely data-driven: it LABELS the backend's operational-summary
// aggregate (scan outcomes, endpoint verification, finding lifecycle) and never re-derives anything.
// No charts, no click-through (the lists don't yet support equivalent filters).
import { ref, computed, watch } from "vue";
import { useTenantStore } from "@/stores/tenant";
import {
  dashboardSummaryApi,
  type OperationalDashboard,
  type DashTierBlock,
  type DashboardPeriod,
} from "@/api/dashboardSummary";

const tenantStore = useTenantStore();
const tenantId = computed(() => tenantStore.currentTenantId);

const PERIODS: DashboardPeriod[] = [7, 30, 90];
const TIERS = ["1", "2"] as const;
const period = ref<DashboardPeriod>(30);
const data = ref<OperationalDashboard | null>(null);
const loading = ref(false);
const error = ref("");

// The backend guarantees both tier keys; a response missing either is malformed, not "zero" —
// we surface it as inconsistent rather than inventing zeros.
const inconsistent = computed(() => {
  const d = data.value;
  if (!d) return false;
  // The contract guarantees both keys; at runtime a malformed response might not, so check as partial.
  const bt = d.by_tier as Partial<Record<"1" | "2", DashTierBlock>> | undefined;
  return !bt || !bt["1"] || !bt["2"];
});

const isEmpty = computed(() => {
  const d = data.value;
  if (!d || inconsistent.value) return false;
  return (
    d.scans.total === 0 &&
    d.scans.cancelled === 0 &&
    d.endpoints.selected === 0 &&
    d.findings.auto_closed === 0 &&
    d.findings.reopened === 0 &&
    d.findings.awaiting_confirmation === 0
  );
});

// "96%" for a percent, an em dash when null (never "100%" for an empty set).
function pct(p: number | null): string {
  return p === null || p === undefined ? "—" : `${p}%`;
}

// Race-safe: only the LATEST request may mutate state. A stale response (slower older request, or a
// request from a previous tenant/period) is discarded via the generation token.
let requestGeneration = 0;

async function load(): Promise<void> {
  const generation = ++requestGeneration;
  const requestedTenant = tenantId.value;
  const requestedPeriod = period.value;

  if (!requestedTenant) {
    data.value = null;
    error.value = "No tenant selected";
    loading.value = false;
    return;
  }

  loading.value = true;
  error.value = "";
  try {
    const result = await dashboardSummaryApi.getOperational(requestedTenant, requestedPeriod);
    if (generation !== requestGeneration) return; // superseded → ignore
    data.value = result;
  } catch (err: unknown) {
    if (generation !== requestGeneration) return; // superseded → don't show a stale error
    data.value = null;
    error.value = err instanceof Error ? err.message : "Failed to load the operational dashboard";
  } finally {
    if (generation === requestGeneration) loading.value = false;
  }
}

function setPeriod(p: DashboardPeriod): void {
  period.value = p; // the watcher fires the (deduped) reload
}

// One watcher owns loading: fires immediately on mount and on any tenant/period change. No manual
// onMounted/setPeriod calls → no double requests.
watch([tenantId, period], load, { immediate: true });
</script>

<template>
  <div class="space-y-6">
    <!-- Header + period selector -->
    <div class="flex items-center justify-between flex-wrap gap-3">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
        Operational dashboard
      </h2>
      <div
        class="inline-flex rounded-md border border-gray-300 dark:border-dark-border overflow-hidden"
        data-testid="period-selector"
        role="group"
        aria-label="Time window"
      >
        <button
          v-for="p in PERIODS"
          :key="p"
          type="button"
          :data-testid="`period-${p}`"
          :aria-pressed="p === period"
          @click="setPeriod(p)"
          class="px-3 py-1.5 text-sm font-medium focus:outline-none focus:ring-2 focus:ring-primary-500"
          :class="
            p === period
              ? 'bg-primary-600 text-white'
              : 'bg-white dark:bg-dark-bg-secondary text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary'
          "
        >
          {{ p }}d
        </button>
      </div>
    </div>

    <!-- Loading -->
    <div
      v-if="loading"
      role="status"
      class="text-sm text-gray-500 dark:text-dark-text-secondary"
      data-testid="dash-loading"
    >
      Loading operational summary…
    </div>

    <!-- Error -->
    <div
      v-else-if="error"
      role="alert"
      class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md"
      data-testid="dash-error"
    >
      <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
    </div>

    <!-- Inconsistent data (a response missing a guaranteed tier block) -->
    <div
      v-else-if="inconsistent"
      role="alert"
      class="text-sm text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-900/20 p-4 rounded-md"
      data-testid="dash-inconsistent"
    >
      The operational summary came back incomplete. Some tier data is unavailable — please retry.
    </div>

    <!-- Empty -->
    <div
      v-else-if="isEmpty"
      class="text-sm text-gray-500 dark:text-dark-text-secondary bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
      data-testid="dash-empty"
    >
      No scan, endpoint, or finding activity in the last {{ data?.period_days }} days.
    </div>

    <!-- Data -->
    <template v-else-if="data">
      <p class="text-xs text-gray-500 dark:text-dark-text-secondary" data-testid="dash-window">
        {{ data.from }} → {{ data.to }}
      </p>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <!-- Scans -->
        <section
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
          data-testid="dash-scans"
        >
          <h3 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary mb-4">
            Scan outcomes
          </h3>
          <dl class="grid grid-cols-2 gap-3 text-sm">
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Completed</dt>
              <dd class="text-green-700 dark:text-green-400 font-semibold" data-testid="scans-completed">
                {{ data.scans.completed }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">With limitations</dt>
              <dd class="text-amber-700 dark:text-amber-400 font-semibold" data-testid="scans-cwl">
                {{ data.scans.completed_with_limitations }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Failed</dt>
              <dd class="text-red-700 dark:text-red-400 font-semibold" data-testid="scans-failed">
                {{ data.scans.failed }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Cancelled</dt>
              <dd class="text-gray-700 dark:text-dark-text-primary font-semibold" data-testid="scans-cancelled">
                {{ data.scans.cancelled }}
              </dd>
            </div>
          </dl>
        </section>

        <!-- Endpoints -->
        <section
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
          data-testid="dash-endpoints"
        >
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">
              Endpoint verification
            </h3>
            <span class="text-sm text-gray-700 dark:text-dark-text-secondary" data-testid="endpoints-coverage">
              {{ pct(data.endpoints.coverage_percent) }}
            </span>
          </div>
          <dl class="grid grid-cols-2 gap-3 text-sm">
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Verified</dt>
              <dd class="text-green-700 dark:text-green-400 font-semibold" data-testid="endpoints-verified">
                {{ data.endpoints.verified }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Not verifiable</dt>
              <dd class="text-amber-700 dark:text-amber-400 font-semibold" data-testid="endpoints-not-verifiable">
                {{ data.endpoints.not_verifiable }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Failed</dt>
              <dd class="text-red-700 dark:text-red-400 font-semibold" data-testid="endpoints-failed">
                {{ data.endpoints.failed }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Selected</dt>
              <dd class="text-gray-900 dark:text-dark-text-primary font-semibold" data-testid="endpoints-selected">
                {{ data.endpoints.selected }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Skipped</dt>
              <dd class="text-gray-900 dark:text-dark-text-primary font-semibold" data-testid="endpoints-skipped">
                {{ data.endpoints.skipped }}
              </dd>
            </div>
          </dl>
        </section>

        <!-- Findings -->
        <section
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
          data-testid="dash-findings"
        >
          <h3 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary mb-4">
            Finding lifecycle
          </h3>
          <dl class="grid grid-cols-2 gap-3 text-sm">
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Automatically fixed</dt>
              <dd class="text-green-700 dark:text-green-400 font-semibold" data-testid="findings-auto-closed">
                {{ data.findings.auto_closed }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Reopened</dt>
              <dd class="text-gray-900 dark:text-dark-text-primary font-semibold" data-testid="findings-reopened">
                {{ data.findings.reopened }}
              </dd>
            </div>
            <div>
              <dt class="text-gray-500 dark:text-dark-text-secondary">Awaiting confirmation</dt>
              <dd class="text-amber-700 dark:text-amber-400 font-semibold" data-testid="findings-awaiting">
                {{ data.findings.awaiting_confirmation }}
              </dd>
            </div>
          </dl>
        </section>
      </div>

      <!-- T1/T2 breakdown -->
      <section
        class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
        data-testid="dash-by-tier"
      >
        <h3 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary mb-4">
          By tier
        </h3>
        <div class="overflow-x-auto">
          <table class="min-w-full text-sm">
            <thead>
              <tr class="text-left text-gray-500 dark:text-dark-text-secondary">
                <th class="py-1 pr-4 font-medium">Tier</th>
                <th class="py-1 pr-4 font-medium">Completed</th>
                <th class="py-1 pr-4 font-medium">With limits</th>
                <th class="py-1 pr-4 font-medium">Scan failed</th>
                <th class="py-1 pr-4 font-medium">Verified</th>
                <th class="py-1 pr-4 font-medium">Not verifiable</th>
                <th class="py-1 pr-4 font-medium">Ep failed</th>
                <th class="py-1 pr-4 font-medium">Ep skipped</th>
                <th class="py-1 pr-4 font-medium">Coverage</th>
                <th class="py-1 pr-4 font-medium">Auto-fixed</th>
                <th class="py-1 pr-4 font-medium">Reopened</th>
                <th class="py-1 font-medium">Awaiting</th>
              </tr>
            </thead>
            <tbody>
              <tr
                v-for="t in TIERS"
                :key="t"
                :data-testid="`tier-${t}`"
                class="border-t border-gray-100 dark:border-dark-border text-gray-900 dark:text-dark-text-primary"
              >
                <td class="py-1.5 pr-4 font-medium">T{{ t }}</td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].scans.completed }}</td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].scans.completed_with_limitations }}</td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].scans.failed }}</td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].endpoints.verified }}</td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].endpoints.not_verifiable }}</td>
                <td
                  class="py-1.5 pr-4"
                  :class="data.by_tier[t].endpoints.failed > 0 ? 'text-red-700 dark:text-red-400 font-medium' : ''"
                >
                  {{ data.by_tier[t].endpoints.failed }}
                </td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].endpoints.skipped }}</td>
                <td class="py-1.5 pr-4">{{ pct(data.by_tier[t].endpoints.coverage_percent) }}</td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].findings.auto_closed }}</td>
                <td class="py-1.5 pr-4">{{ data.by_tier[t].findings.reopened }}</td>
                <td class="py-1.5">{{ data.by_tier[t].findings.awaiting_confirmation }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </div>
</template>
