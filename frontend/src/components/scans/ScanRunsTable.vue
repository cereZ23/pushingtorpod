<script setup lang="ts">
import type { ScanRun, ScanRunStatus } from "@/stores/scans";
import { formatDate } from "@/utils/formatters";

interface Props {
  runs: ScanRun[];
  isLoading: boolean;
}

defineProps<Props>();

const emit = defineEmits<{
  "view-detail": [run: ScanRun];
  "delete-run": [run: ScanRun];
  "trigger-scan": [];
}>();

function getStatusBadgeClass(status: ScanRunStatus): string {
  const classes: Record<ScanRunStatus, string> = {
    pending: "bg-gray-100 text-gray-800 dark:bg-gray-700/30 dark:text-gray-300",
    running: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
    completed:
      "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400",
    failed: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
    cancelled:
      "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
  };
  return classes[status] || classes.pending;
}

function canDelete(run: ScanRun): boolean {
  return (
    run.status === "completed" ||
    run.status === "failed" ||
    run.status === "cancelled"
  );
}

function formatDuration(run: ScanRun): string {
  if (!run.started_at) return "-";
  const start = new Date(run.started_at).getTime();
  const end = run.completed_at
    ? new Date(run.completed_at).getTime()
    : Date.now();
  const seconds = Math.floor((end - start) / 1000);

  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
  >
    <!-- Loading -->
    <div
      v-if="isLoading"
      role="status"
      class="p-8 text-center text-gray-500 dark:text-dark-text-secondary"
    >
      Loading scan runs...
    </div>

    <!-- Empty -->
    <div v-else-if="runs.length === 0" class="p-8 text-center">
      <p class="text-gray-500 dark:text-dark-text-secondary">
        No scan runs yet for this project
      </p>
      <button
        @click="emit('trigger-scan')"
        class="mt-2 text-primary-600 dark:text-primary-400 text-sm hover:text-primary-700 dark:hover:text-primary-300"
      >
        Run your first scan
      </button>
    </div>

    <!-- Table -->
    <div v-else class="overflow-x-auto">
      <table
        class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
      >
        <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
          <tr>
            <th
              scope="col"
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              ID
            </th>
            <th
              scope="col"
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Status
            </th>
            <th
              scope="col"
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Triggered By
            </th>
            <th
              scope="col"
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Started
            </th>
            <th
              scope="col"
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Duration
            </th>
            <th
              scope="col"
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Actions
            </th>
          </tr>
        </thead>
        <tbody
          class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border"
        >
          <tr
            v-for="run in runs"
            :key="run.id"
            class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary cursor-pointer"
            @click="emit('view-detail', run)"
          >
            <td
              class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-dark-text-primary"
            >
              #{{ run.id }}
            </td>
            <td class="px-6 py-4 whitespace-nowrap">
              <span
                class="px-2 inline-flex items-center text-xs leading-5 font-semibold rounded-full"
                :class="getStatusBadgeClass(run.status)"
              >
                <span
                  v-if="run.status === 'running'"
                  class="w-2 h-2 mr-1.5 rounded-full bg-blue-500 animate-pulse"
                />
                {{ run.status }}
              </span>
            </td>
            <td
              class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary"
            >
              {{ run.triggered_by }}
            </td>
            <td
              class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary"
            >
              {{ formatDate(run.started_at) }}
            </td>
            <td
              class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary"
            >
              {{ formatDuration(run) }}
            </td>
            <td
              class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-3"
            >
              <button
                @click.stop="emit('view-detail', run)"
                class="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300"
              >
                View
              </button>
              <button
                v-if="canDelete(run)"
                @click.stop="emit('delete-run', run)"
                class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
              >
                Delete
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
