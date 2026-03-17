<script setup lang="ts">
import type { Project } from "@/stores/scans";

interface Props {
  projects: Project[];
  selectedProjectId: number | null;
  isLoading: boolean;
}

defineProps<Props>();

const emit = defineEmits<{
  "select-project": [project: Project];
  "create-project": [];
}>();
</script>

<template>
  <div class="w-[300px] shrink-0">
    <div
      class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
    >
      <div class="px-4 py-3 border-b border-gray-200 dark:border-dark-border">
        <h3
          class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider"
        >
          Projects
        </h3>
      </div>

      <!-- Loading state -->
      <div
        v-if="isLoading"
        role="status"
        class="p-4 text-center text-gray-500 dark:text-dark-text-secondary"
      >
        Loading projects...
      </div>

      <!-- Empty state -->
      <div v-else-if="projects.length === 0" class="p-6 text-center">
        <p class="text-gray-500 dark:text-dark-text-secondary text-sm">
          No projects yet
        </p>
        <button
          @click="emit('create-project')"
          class="mt-2 text-primary-600 dark:text-primary-400 text-sm hover:text-primary-700 dark:hover:text-primary-300"
        >
          Create your first project
        </button>
      </div>

      <!-- Project list -->
      <ul v-else class="divide-y divide-gray-200 dark:divide-dark-border">
        <li
          v-for="project in projects"
          :key="project.id"
          @click="emit('select-project', project)"
          :class="[
            'px-4 py-3 cursor-pointer transition-colors',
            selectedProjectId === project.id
              ? 'bg-primary-50 dark:bg-primary-900/20 border-l-4 border-primary-500'
              : 'hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary border-l-4 border-transparent',
          ]"
        >
          <div
            class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
          >
            {{ project.name }}
          </div>
          <div
            v-if="project.description"
            class="text-xs text-gray-500 dark:text-dark-text-secondary mt-1 truncate"
          >
            {{ project.description }}
          </div>
          <div class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-1">
            {{ project.seeds?.length || 0 }} seeds
          </div>
        </li>
      </ul>
    </div>
  </div>
</template>
