<script setup lang="ts">
import { computed } from 'vue'
import {
  getSeverityBadgeClass,
  getFindingStatusBadgeClass,
  getIssueStatusBadgeClass,
  getPriorityBadgeClass,
  getAssetTypeBadgeClass,
} from '@/utils/severity'

type BadgeVariant = 'severity' | 'finding-status' | 'issue-status' | 'priority' | 'asset-type' | 'custom'

interface Props {
  label: string
  variant?: BadgeVariant
  /** Value used to resolve the badge class. Falls back to `label` when omitted. */
  value?: string
  /** Override all computed classes with a custom class string. */
  customClass?: string
}

const props = withDefaults(defineProps<Props>(), {
  variant: 'custom',
  value: '',
  customClass: '',
})

const DEFAULT_CLASS =
  'px-2 py-1 text-xs font-medium rounded-full bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200'

const badgeClass = computed(() => {
  if (props.customClass) return props.customClass

  const resolved = props.value || props.label

  switch (props.variant) {
    case 'severity':
      return getSeverityBadgeClass(resolved)
    case 'finding-status':
      return getFindingStatusBadgeClass(resolved)
    case 'issue-status':
      return getIssueStatusBadgeClass(resolved)
    case 'priority':
      return getPriorityBadgeClass(resolved)
    case 'asset-type':
      return getAssetTypeBadgeClass(resolved)
    default:
      return DEFAULT_CLASS
  }
})
</script>

<template>
  <span
    :class="[
      'px-2 inline-flex text-xs leading-5 font-semibold rounded-full',
      badgeClass,
    ]"
  >{{ label }}</span>
</template>
