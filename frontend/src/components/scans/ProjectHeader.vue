<script setup lang="ts">
import type { Project } from "@/stores/scans";

interface Props {
  project: Project;
  completedRunsCount: number;
  isTriggering: boolean;
}

defineProps<Props>();

const emit = defineEmits<{
  edit: [];
  delete: [];
  "trigger-scan": [];
  compare: [];
}>();
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
  >
    <div class="flex justify-between items-start">
      <div>
        <h3
          class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
        >
          {{ project.name }}
        </h3>
        <p
          v-if="project.description"
          class="text-sm text-gray-500 dark:text-dark-text-secondary mt-1"
        >
          {{ project.description }}
        </p>
        <div class="flex gap-2 mt-2">
          <span
            v-for="seed in project.seeds || []"
            :key="seed.value"
            class="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded bg-gray-100 text-gray-700 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary"
          >
            {{ seed.type }}: {{ seed.value }}
          </span>
        </div>
      </div>
      <div class="flex gap-2">
        <button
          @click="emit('delete')"
          class="px-3 py-2 border border-red-300 dark:border-red-700 rounded-md text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/10 transition-colors text-sm"
        >
          Delete
        </button>
        <button
          @click="emit('edit')"
          class="px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm"
        >
          Edit
        </button>
        <button
          v-if="completedRunsCount >= 2"
          @click="emit('compare')"
          class="px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm"
        >
          Compare Scans
        </button>
        <button
          @click="emit('trigger-scan')"
          :disabled="isTriggering"
          class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
        >
          {{ isTriggering ? "Triggering..." : "Trigger Scan" }}
        </button>
      </div>
    </div>
  </div>
</template>
