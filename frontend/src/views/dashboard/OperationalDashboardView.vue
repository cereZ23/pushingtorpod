<script setup lang="ts">
// UI-3 operational dashboard. Purely data-driven: it LABELS the backend's operational-summary
// aggregate (scan outcomes, endpoint verification, finding lifecycle) and never re-derives anything.
// No charts, no click-through (the lists don't yet support equivalent filters).
import { ref, computed, onMounted, watch } from "vue";
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

const isEmpty = computed(() => {
  const d = data.value;
  if (!d) return false;
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

function tierBlock(t: "1" | "2"): DashTierBlock | null {
  return data.value?.by_tier?.[t] ?? null;
}

async function load(): Promise<void> {
  if (!tenantId.value) {
    error.value = "No tenant selected";
    return;
  }
  loading.value = true;
  error.value = "";
  try {
    data.value = await dashboardSummaryApi.getOperational(tenantId.value, period.value);
  } catch (err: unknown) {
    error.value = err instanceof Error ? err.message : "Failed to load the operational dashboard";
    data.value = null;
  } finally {
    loading.value = false;
  }
}

function setPeriod(p: DashboardPeriod): void {
  if (p === period.value) return;
  period.value = p;
  load();
}

onMounted(load);
watch(tenantId, load);
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
                <th class="py-1 pr-4 font-medium">Failed</th>
                <th class="py-1 pr-4 font-medium">Verified</th>
                <th class="py-1 pr-4 font-medium">Not verifiable</th>
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
                <td class="py-1.5 pr-4">{{ tierBlock(t)?.scans.completed ?? 0 }}</td>
                <td class="py-1.5 pr-4">{{ tierBlock(t)?.scans.completed_with_limitations ?? 0 }}</td>
                <td class="py-1.5 pr-4">{{ tierBlock(t)?.scans.failed ?? 0 }}</td>
                <td class="py-1.5 pr-4">{{ tierBlock(t)?.endpoints.verified ?? 0 }}</td>
                <td class="py-1.5 pr-4">{{ tierBlock(t)?.endpoints.not_verifiable ?? 0 }}</td>
                <td class="py-1.5 pr-4">{{ pct(tierBlock(t)?.endpoints.coverage_percent ?? null) }}</td>
                <td class="py-1.5 pr-4">{{ tierBlock(t)?.findings.auto_closed ?? 0 }}</td>
                <td class="py-1.5 pr-4">{{ tierBlock(t)?.findings.reopened ?? 0 }}</td>
                <td class="py-1.5">{{ tierBlock(t)?.findings.awaiting_confirmation ?? 0 }}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </section>
    </template>
  </div>
</template>
