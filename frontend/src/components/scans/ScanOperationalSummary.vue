<script setup lang="ts">
// UI-1: "Scan result" card. Renders the backend-decided operational_summary — it NEVER recomputes
// outcome/state, only labels the closed-enum codes. No policy_hash / shape_hash / raw error is ever
// present in this contract, so nothing sensitive can leak here.
import { computed } from "vue";
import type { OperationalSummary } from "@/stores/scans";
import {
  outcomeBadge,
  endpointStateBadge,
  limitationTexts,
  coveragePercentText,
} from "@/utils/scanOutcome";

const props = defineProps<{ summary: OperationalSummary }>();

const outcome = computed(() => outcomeBadge(props.summary.outcome));
const ev = computed(() => props.summary.endpoint_verification);
const stateBadge = computed(() => endpointStateBadge(ev.value.state));
const reasons = computed(() => limitationTexts(ev.value.limitations));
const ac = computed(() => props.summary.auto_close);

// Show the endpoint block whenever the backend has a state to report — a valid snapshot (available)
// OR a legacy run whose ledger proved something was unverified (state set, available false). Only a
// legacy CLEAN run (state === null) hides the block behind the "not available" message.
const showEndpoint = computed(() => ev.value.state !== null);
// Show the auto-close block only when this scan recorded lifecycle activity.
const showAutoClose = computed(
  () =>
    ac.value.detected > 0 ||
    ac.value.eligible_miss > 0 ||
    ac.value.would_close > 0 ||
    ac.value.closed > 0 ||
    ac.value.reopened > 0,
);
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
  >
    <div class="flex items-center justify-between mb-4">
      <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">
        Scan result
      </h3>
      <span
        class="px-2.5 py-0.5 inline-flex items-center text-xs font-semibold rounded-full"
        :class="outcome.classes"
        data-testid="scan-outcome-badge"
      >
        {{ outcome.label }}
      </span>
    </div>

    <!-- Endpoint verification -->
    <div v-if="showEndpoint" class="space-y-3" data-testid="endpoint-verification">
      <div class="flex items-center gap-3 flex-wrap">
        <span
          class="px-2.5 py-0.5 inline-flex items-center text-xs font-semibold rounded-full"
          :class="stateBadge.classes"
          data-testid="endpoint-state-badge"
        >
          {{ stateBadge.label }}
        </span>
        <span
          class="text-sm text-gray-700 dark:text-dark-text-secondary"
          data-testid="coverage-percent"
        >
          Coverage {{ coveragePercentText(ev.coverage_percent) }}
        </span>
      </div>

      <!-- Counts -->
      <dl class="grid grid-cols-2 sm:grid-cols-5 gap-3 text-sm">
        <div>
          <dt class="text-gray-500 dark:text-dark-text-secondary">Selected</dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ev.selected }}
          </dd>
        </div>
        <div>
          <dt class="text-gray-500 dark:text-dark-text-secondary">Verified</dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ev.covered }}
          </dd>
        </div>
        <div>
          <dt class="text-gray-500 dark:text-dark-text-secondary">
            Not verifiable
          </dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ev.not_verifiable }}
          </dd>
        </div>
        <div>
          <dt class="text-gray-500 dark:text-dark-text-secondary">Failed</dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ev.failed }}
          </dd>
        </div>
        <div>
          <dt class="text-gray-500 dark:text-dark-text-secondary">Skipped</dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ev.skipped }}
          </dd>
        </div>
        <div v-if="ev.unstarted > 0">
          <dt class="text-gray-500 dark:text-dark-text-secondary">
            Not reached
          </dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ev.unstarted }}
          </dd>
        </div>
      </dl>

      <!-- Limitation reasons (human text) -->
      <ul
        v-if="reasons.length"
        class="list-disc list-inside text-sm text-amber-700 dark:text-amber-400 space-y-0.5"
        data-testid="limitation-reasons"
      >
        <li v-for="(text, i) in reasons" :key="i">{{ text }}</li>
      </ul>

      <p
        v-if="ev.data_inconsistent"
        class="text-sm text-amber-700 dark:text-amber-400"
        data-testid="data-inconsistent-note"
      >
        Verification data was inconsistent — counts shown are the authoritative
        coverage results.
      </p>
    </div>

    <!-- Legacy run: no endpoint snapshot -->
    <p
      v-else
      class="text-sm text-gray-500 dark:text-dark-text-secondary"
      data-testid="endpoint-unavailable"
    >
      Endpoint verification data is not available for this scan.
    </p>

    <!-- Auto-close activity -->
    <div
      v-if="showAutoClose"
      class="mt-4 pt-4 border-t border-gray-100 dark:border-dark-border"
      data-testid="auto-close-summary"
    >
      <h4
        class="text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
      >
        Auto-close activity
      </h4>
      <dl class="grid grid-cols-2 sm:grid-cols-5 gap-3 text-sm">
        <div v-if="ac.closed > 0" data-testid="auto-close-closed">
          <dt class="text-gray-500 dark:text-dark-text-secondary">
            Automatically fixed
          </dt>
          <dd class="text-green-700 dark:text-green-400 font-medium">
            {{ ac.closed }}
          </dd>
        </div>
        <div v-if="ac.would_close > 0" data-testid="auto-close-would-close">
          <dt class="text-gray-500 dark:text-dark-text-secondary">
            Reached close threshold
          </dt>
          <dd class="text-amber-700 dark:text-amber-400 font-medium">
            {{ ac.would_close }}
          </dd>
        </div>
        <div v-if="ac.eligible_miss > 0" data-testid="auto-close-eligible-miss">
          <dt class="text-gray-500 dark:text-dark-text-secondary">
            Awaiting confirmation
          </dt>
          <dd class="text-amber-700 dark:text-amber-400 font-medium">
            {{ ac.eligible_miss }}
          </dd>
        </div>
        <div v-if="ac.reopened > 0" data-testid="auto-close-reopened">
          <dt class="text-gray-500 dark:text-dark-text-secondary">Reopened</dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ac.reopened }}
          </dd>
        </div>
        <div v-if="ac.detected > 0" data-testid="auto-close-detected">
          <dt class="text-gray-500 dark:text-dark-text-secondary">Detected</dt>
          <dd class="text-gray-900 dark:text-dark-text-primary font-medium">
            {{ ac.detected }}
          </dd>
        </div>
      </dl>
    </div>
  </div>
</template>
