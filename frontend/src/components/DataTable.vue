<script setup lang="ts">
import SkeletonLoader from './SkeletonLoader.vue'

export interface DataTableColumn {
  key: string
  label: string
  sortable?: boolean
  /** Extra CSS classes applied to each `<td>` in this column. */
  class?: string
  /** Extra CSS classes applied to the `<th>` header of this column. */
  headerClass?: string
}

interface Props {
  columns: DataTableColumn[]
  items: Record<string, unknown>[]
  loading?: boolean
  loadingRows?: number
  emptyMessage?: string
  emptyDescription?: string
  sortBy?: string
  sortOrder?: 'asc' | 'desc'
  /** Unique key on each item used for `:key` binding. Defaults to `'id'`. */
  rowKey?: string
}

const props = withDefaults(defineProps<Props>(), {
  loading: false,
  loadingRows: 10,
  emptyMessage: 'No data found',
  emptyDescription: '',
  sortBy: '',
  sortOrder: 'desc',
  rowKey: 'id',
})

const emit = defineEmits<{
  sort: [column: string]
  'row-click': [item: Record<string, unknown>, index: number]
}>()

function handleSort(col: DataTableColumn) {
  if (col.sortable) emit('sort', col.key)
}

function handleRowClick(item: Record<string, unknown>, index: number) {
  emit('row-click', item, index)
}

function getRowKey(item: Record<string, unknown>, index: number): string | number {
  const key = item[props.rowKey]
  if (key !== undefined && key !== null) return String(key)
  return index
}
</script>

<template>
  <div class="overflow-x-auto">
    <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
      <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
        <tr>
          <th
            v-for="col in columns"
            :key="col.key"
            scope="col"
            :class="[
              'px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider',
              col.headerClass,
              col.sortable ? 'cursor-pointer hover:text-gray-700 dark:hover:text-gray-200 select-none' : '',
            ]"
            :aria-sort="
              col.sortable && sortBy === col.key
                ? sortOrder === 'asc' ? 'ascending' : 'descending'
                : undefined
            "
            @click="handleSort(col)"
          >
            <div class="flex items-center gap-1">
              {{ col.label }}
              <template v-if="col.sortable && sortBy === col.key">
                <svg
                  v-if="sortOrder === 'asc'"
                  class="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 15l7-7 7 7" />
                </svg>
                <svg
                  v-else
                  class="w-4 h-4"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                  aria-hidden="true"
                >
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 9l-7 7-7-7" />
                </svg>
              </template>
            </div>
          </th>
        </tr>
      </thead>

      <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
        <!-- Loading skeleton -->
        <template v-if="loading">
          <tr>
            <td :colspan="columns.length" class="p-0">
              <SkeletonLoader variant="table-row" :rows="loadingRows" />
            </td>
          </tr>
        </template>

        <!-- Empty state -->
        <template v-else-if="items.length === 0">
          <tr>
            <td :colspan="columns.length" class="px-6 py-12 text-center">
              <slot name="empty">
                <p class="text-gray-500 dark:text-dark-text-secondary">{{ emptyMessage }}</p>
                <p
                  v-if="emptyDescription"
                  class="mt-1 text-sm text-gray-400 dark:text-dark-text-secondary"
                >
                  {{ emptyDescription }}
                </p>
              </slot>
            </td>
          </tr>
        </template>

        <!-- Data rows -->
        <template v-else>
          <tr
            v-for="(item, index) in items"
            :key="getRowKey(item, index)"
            class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
            @click="handleRowClick(item, index)"
          >
            <td
              v-for="col in columns"
              :key="col.key"
              :class="['px-6 py-4 whitespace-nowrap text-sm', col.class]"
            >
              <slot :name="col.key" :item="item" :value="item[col.key]" :index="index">
                {{ item[col.key] }}
              </slot>
            </td>
          </tr>
        </template>
      </tbody>
    </table>
  </div>
</template>
