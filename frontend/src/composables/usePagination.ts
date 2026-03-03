/**
 * Shared pagination composable with windowed page display.
 *
 * Replaces broken `v-for="page in Math.min(5, totalPages)"` pattern
 * that caps navigation at page 5 regardless of dataset size.
 */
import { computed, type Ref } from 'vue'

export interface PaginationPage {
  type: 'page' | 'ellipsis'
  value: number
}

/**
 * Generate a windowed page list: [1, ..., current-1, current, current+1, ..., last]
 *
 * @param currentPage - current page number (1-based)
 * @param totalPages - total number of pages
 * @param windowSize - pages to show on each side of current (default 2)
 */
export function useWindowedPagination(
  currentPage: Ref<number>,
  totalPages: Ref<number>,
  windowSize = 2,
) {
  const pages = computed((): PaginationPage[] => {
    const total = totalPages.value
    const current = currentPage.value

    if (total <= 0) return []
    if (total <= (windowSize * 2 + 3)) {
      // Few enough pages to show all
      return Array.from({ length: total }, (_, i) => ({
        type: 'page' as const,
        value: i + 1,
      }))
    }

    const result: PaginationPage[] = []

    // Always show page 1
    result.push({ type: 'page', value: 1 })

    const windowStart = Math.max(2, current - windowSize)
    const windowEnd = Math.min(total - 1, current + windowSize)

    // Left ellipsis
    if (windowStart > 2) {
      result.push({ type: 'ellipsis', value: -1 })
    }

    // Window pages
    for (let i = windowStart; i <= windowEnd; i++) {
      result.push({ type: 'page', value: i })
    }

    // Right ellipsis
    if (windowEnd < total - 1) {
      result.push({ type: 'ellipsis', value: -2 })
    }

    // Always show last page
    if (total > 1) {
      result.push({ type: 'page', value: total })
    }

    return result
  })

  const hasPrevious = computed(() => currentPage.value > 1)
  const hasNext = computed(() => currentPage.value < totalPages.value)

  return {
    pages,
    hasPrevious,
    hasNext,
  }
}
