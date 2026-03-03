<script setup lang="ts">
interface Props {
  variant: 'text' | 'table-row' | 'card' | 'chart'
  rows?: number
}

const props = withDefaults(defineProps<Props>(), {
  rows: 1,
})
</script>

<template>
  <!-- Text skeleton -->
  <div v-if="props.variant === 'text'" class="space-y-3" role="status" aria-label="Loading content">
    <div
      v-for="i in props.rows"
      :key="i"
      class="h-4 bg-gray-200 dark:bg-gray-700 rounded animate-pulse"
      :class="i === props.rows ? 'w-3/4' : 'w-full'"
    />
    <span class="sr-only">Loading...</span>
  </div>

  <!-- Table row skeleton -->
  <div v-else-if="props.variant === 'table-row'" role="status" aria-label="Loading table data">
    <div
      v-for="i in props.rows"
      :key="i"
      class="flex items-center gap-4 px-6 py-4 border-b border-gray-100 dark:border-dark-border animate-pulse"
    >
      <div class="h-4 w-1/4 bg-gray-200 dark:bg-gray-700 rounded" />
      <div class="h-4 w-16 bg-gray-200 dark:bg-gray-700 rounded-full" />
      <div class="h-4 w-16 bg-gray-200 dark:bg-gray-700 rounded-full" />
      <div class="h-4 w-1/5 bg-gray-200 dark:bg-gray-700 rounded" />
      <div class="h-4 w-20 bg-gray-200 dark:bg-gray-700 rounded" />
      <div class="h-4 w-12 bg-gray-200 dark:bg-gray-700 rounded ml-auto" />
    </div>
    <span class="sr-only">Loading...</span>
  </div>

  <!-- Card skeleton (KPI) -->
  <div v-else-if="props.variant === 'card'" role="status" aria-label="Loading card data">
    <div
      v-for="i in props.rows"
      :key="i"
      class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border animate-pulse"
    >
      <div class="flex items-center justify-between">
        <div class="space-y-3 flex-1">
          <div class="h-3 w-24 bg-gray-200 dark:bg-gray-700 rounded" />
          <div class="h-8 w-16 bg-gray-200 dark:bg-gray-700 rounded" />
          <div class="h-3 w-32 bg-gray-200 dark:bg-gray-700 rounded" />
        </div>
        <div class="h-14 w-14 bg-gray-200 dark:bg-gray-700 rounded-lg" />
      </div>
    </div>
    <span class="sr-only">Loading...</span>
  </div>

  <!-- Chart skeleton -->
  <div v-else-if="props.variant === 'chart'" role="status" aria-label="Loading chart">
    <div class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border animate-pulse">
      <div class="h-4 w-40 bg-gray-200 dark:bg-gray-700 rounded mb-4" />
      <div class="h-48 bg-gray-200 dark:bg-gray-700 rounded" />
    </div>
    <span class="sr-only">Loading...</span>
  </div>
</template>
