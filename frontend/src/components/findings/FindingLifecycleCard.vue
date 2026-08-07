<script setup lang="ts">
import { computed } from "vue";
import type { FindingLifecycle } from "@/api/types";
import { autoCloseStateInfo, lifecycleEventText, coverageScopeLabel } from "@/utils/lifecycleLabels";
import { formatDate } from "@/utils/formatters";

const props = defineProps<{
  lifecycle: FindingLifecycle | null;
  loading: boolean;
}>();

const state = computed(() =>
  props.lifecycle ? autoCloseStateInfo(props.lifecycle.auto_close.state) : null,
);
const scope = computed(() =>
  props.lifecycle ? coverageScopeLabel(props.lifecycle.auto_close.coverage_scope) : null,
);
// coverage_scope === null → the finding's source is not coverage-aware (e.g. manual).
const monitored = computed(() => scope.value !== null);
const showMisses = computed(
  () =>
    props.lifecycle != null &&
    (props.lifecycle.auto_close.state === "eligible_miss" ||
      props.lifecycle.auto_close.state === "awaiting_confirmation"),
);
</script>

<template>
  <section
    class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6"
  >
    <h3 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary mb-4">
      Verification status
    </h3>

    <div v-if="loading" class="text-sm text-gray-500 dark:text-dark-text-secondary">
      Loading lifecycle…
    </div>

    <template v-else-if="lifecycle && state">
      <!-- State + monitored -->
      <div class="flex flex-wrap items-center gap-2 mb-2">
        <span
          class="px-2.5 py-0.5 inline-flex items-center text-xs font-semibold rounded-full"
          :class="state.classes"
        >
          {{ state.label }}
        </span>
        <span
          class="px-2 py-0.5 inline-flex items-center text-xs rounded-full"
          :class="
            monitored
              ? 'bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400'
              : 'bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400'
          "
        >
          {{ monitored ? "Automatically monitored" : "Not automatically monitored" }}
        </span>
        <span
          v-if="scope"
          class="px-2 py-0.5 inline-flex items-center text-xs rounded-full bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300"
        >
          {{ scope }}
        </span>
        <span
          v-if="lifecycle.auto_close.origin_tier"
          class="px-2 py-0.5 inline-flex items-center text-xs rounded-full bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300"
        >
          Tier T{{ lifecycle.auto_close.origin_tier }}
        </span>
      </div>

      <p class="text-sm text-gray-600 dark:text-dark-text-secondary mb-3">
        {{ state.description }}
      </p>

      <!-- Miss progression -->
      <div
        v-if="showMisses"
        class="text-sm text-gray-700 dark:text-dark-text-primary mb-3"
      >
        <span class="font-medium">{{ lifecycle.auto_close.current_streak }}</span>
        of
        <span class="font-medium">{{ lifecycle.auto_close.threshold }}</span>
        covered misses
      </div>

      <!-- Last detection -->
      <div
        v-if="lifecycle.auto_close.last_detected_run_id"
        class="text-sm text-gray-600 dark:text-dark-text-secondary mb-4"
      >
        Last detected in
        <RouterLink
          :to="{ name: 'ScanDetail', params: { runId: lifecycle.auto_close.last_detected_run_id } }"
          class="text-primary-600 dark:text-primary-400 hover:underline"
          >Run #{{ lifecycle.auto_close.last_detected_run_id }}</RouterLink
        >
      </div>

      <!-- Timeline -->
      <h4 class="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-dark-text-secondary mt-4 mb-2">
        Timeline
      </h4>
      <ol v-if="lifecycle.events.length" class="space-y-3">
        <li
          v-for="(e, i) in lifecycle.events"
          :key="i"
          class="flex items-start gap-3"
        >
          <span class="mt-1.5 w-2 h-2 rounded-full bg-primary-500 shrink-0" />
          <div class="min-w-0">
            <p class="text-sm text-gray-900 dark:text-dark-text-primary">
              {{ lifecycleEventText(e.type, e.reason_code) }}
            </p>
            <p class="text-xs text-gray-500 dark:text-dark-text-secondary">
              {{ formatDate(e.created_at) }}
              <template v-if="e.scan_run_id">
                ·
                <RouterLink
                  :to="{ name: 'ScanDetail', params: { runId: e.scan_run_id } }"
                  class="text-primary-600 dark:text-primary-400 hover:underline"
                  >Run #{{ e.scan_run_id }}</RouterLink
                >
              </template>
            </p>
          </div>
        </li>
      </ol>

      <!-- Conservative backfill note: no invented history for legacy findings -->
      <p
        v-else
        class="text-sm text-gray-500 dark:text-dark-text-secondary italic"
      >
        No lifecycle events recorded for this finding. History is available from migration 031
        onward; earlier activity was not tracked.
      </p>

      <p
        v-if="lifecycle.has_more"
        class="mt-3 text-xs text-gray-500 dark:text-dark-text-secondary"
      >
        Showing the most recent {{ lifecycle.events.length }} of
        {{ lifecycle.total_events }} events.
      </p>
    </template>

    <div v-else class="text-sm text-gray-500 dark:text-dark-text-secondary">
      Lifecycle information is unavailable.
    </div>
  </section>
</template>
