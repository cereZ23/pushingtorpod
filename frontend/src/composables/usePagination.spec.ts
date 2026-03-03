import { describe, it, expect } from 'vitest'
import { ref } from 'vue'
import { useWindowedPagination, type PaginationPage } from './usePagination'

/** Helper: extract just the display values from pages (numbers for pages, '...' for ellipsis) */
function pageValues(pages: PaginationPage[]): (number | string)[] {
  return pages.map((p) => (p.type === 'ellipsis' ? '...' : p.value))
}

describe('useWindowedPagination', () => {
  // ---------- Basic cases ----------

  describe('basic cases', () => {
    it('returns empty array for 0 total pages', () => {
      const currentPage = ref(1)
      const totalPages = ref(0)
      const { pages, hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(pages.value).toEqual([])
      expect(hasPrevious.value).toBe(false)
      expect(hasNext.value).toBe(false)
    })

    it('returns single page for totalPages=1', () => {
      const currentPage = ref(1)
      const totalPages = ref(1)
      const { pages, hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(pages.value).toHaveLength(1)
      expect(pages.value[0]).toEqual({ type: 'page', value: 1 })
      expect(hasPrevious.value).toBe(false)
      expect(hasNext.value).toBe(false)
    })

    it('returns all pages when totalPages fits within window threshold', () => {
      const currentPage = ref(3)
      const totalPages = ref(5)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      // windowSize=2 default, threshold = 2*2+3 = 7, 5 <= 7 => show all
      expect(pageValues(pages.value)).toEqual([1, 2, 3, 4, 5])
    })

    it('returns all pages when totalPages equals threshold exactly', () => {
      const currentPage = ref(4)
      const totalPages = ref(7)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      // threshold = 2*2+3 = 7, 7 <= 7 => show all
      expect(pageValues(pages.value)).toEqual([1, 2, 3, 4, 5, 6, 7])
    })

    it('hasPrevious=false when currentPage=1', () => {
      const currentPage = ref(1)
      const totalPages = ref(5)
      const { hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(hasPrevious.value).toBe(false)
      expect(hasNext.value).toBe(true)
    })

    it('hasPrevious=true, hasNext=false when currentPage=last', () => {
      const currentPage = ref(5)
      const totalPages = ref(5)
      const { hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(hasPrevious.value).toBe(true)
      expect(hasNext.value).toBe(false)
    })

    it('hasPrevious=true, hasNext=true when currentPage is in the middle', () => {
      const currentPage = ref(3)
      const totalPages = ref(5)
      const { hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(hasPrevious.value).toBe(true)
      expect(hasNext.value).toBe(true)
    })
  })

  // ---------- Windowed pagination (many pages) ----------

  describe('windowed pagination', () => {
    it('20 pages, currentPage=1 shows [1, 2, 3, ..., 20]', () => {
      const currentPage = ref(1)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, 2, 3, '...', 20])
    })

    it('20 pages, currentPage=2 shows [1, 2, 3, 4, ..., 20]', () => {
      const currentPage = ref(2)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, 2, 3, 4, '...', 20])
    })

    it('20 pages, currentPage=10 shows [1, ..., 8, 9, 10, 11, 12, ..., 20]', () => {
      const currentPage = ref(10)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, '...', 8, 9, 10, 11, 12, '...', 20])
    })

    it('20 pages, currentPage=20 shows [1, ..., 18, 19, 20]', () => {
      const currentPage = ref(20)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, '...', 18, 19, 20])
    })

    it('20 pages, currentPage=19 shows [1, ..., 17, 18, 19, 20]', () => {
      const currentPage = ref(19)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, '...', 17, 18, 19, 20])
    })

    it('100 pages, currentPage=50 shows [1, ..., 48, 49, 50, 51, 52, ..., 100]', () => {
      const currentPage = ref(50)
      const totalPages = ref(100)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, '...', 48, 49, 50, 51, 52, '...', 100])
    })

    it('100 pages, currentPage=1 shows first few pages then ellipsis and last', () => {
      const currentPage = ref(1)
      const totalPages = ref(100)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, 2, 3, '...', 100])
    })

    it('100 pages, currentPage=100 shows first, ellipsis, then last few', () => {
      const currentPage = ref(100)
      const totalPages = ref(100)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, '...', 98, 99, 100])
    })
  })

  // ---------- Windowed pagination near boundaries ----------

  describe('near boundary behavior', () => {
    it('20 pages, currentPage=4 shows left pages without ellipsis', () => {
      const currentPage = ref(4)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      // windowStart = max(2, 4-2) = 2, so no left ellipsis (windowStart <= 2)
      expect(pageValues(pages.value)).toEqual([1, 2, 3, 4, 5, 6, '...', 20])
    })

    it('20 pages, currentPage=17 shows right pages without ellipsis', () => {
      const currentPage = ref(17)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      // windowEnd = min(19, 17+2) = 19, so no right ellipsis (windowEnd >= total-1)
      expect(pageValues(pages.value)).toEqual([1, '...', 15, 16, 17, 18, 19, 20])
    })
  })

  // ---------- Custom window size ----------

  describe('custom windowSize', () => {
    it('windowSize=1 shows narrower window', () => {
      const currentPage = ref(10)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages, 1)

      expect(pageValues(pages.value)).toEqual([1, '...', 9, 10, 11, '...', 20])
    })

    it('windowSize=3 shows wider window', () => {
      const currentPage = ref(10)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages, 3)

      expect(pageValues(pages.value)).toEqual([1, '...', 7, 8, 9, 10, 11, 12, 13, '...', 20])
    })
  })

  // ---------- Edge cases ----------

  describe('edge cases', () => {
    it('currentPage > totalPages: hasNext is false', () => {
      const currentPage = ref(25)
      const totalPages = ref(20)
      const { hasNext, hasPrevious } = useWindowedPagination(currentPage, totalPages)

      expect(hasNext.value).toBe(false)
      expect(hasPrevious.value).toBe(true)
    })

    it('currentPage=0: hasPrevious is false', () => {
      const currentPage = ref(0)
      const totalPages = ref(20)
      const { hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(hasPrevious.value).toBe(false)
      expect(hasNext.value).toBe(true)
    })

    it('negative currentPage: hasPrevious is false', () => {
      const currentPage = ref(-5)
      const totalPages = ref(20)
      const { hasPrevious } = useWindowedPagination(currentPage, totalPages)

      expect(hasPrevious.value).toBe(false)
    })

    it('negative totalPages: returns empty array', () => {
      const currentPage = ref(1)
      const totalPages = ref(-3)
      const { pages, hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(pages.value).toEqual([])
      expect(hasPrevious.value).toBe(false)
      expect(hasNext.value).toBe(false)
    })

    it('totalPages=2: shows both pages without ellipsis', () => {
      const currentPage = ref(1)
      const totalPages = ref(2)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pageValues(pages.value)).toEqual([1, 2])
    })
  })

  // ---------- Reactivity ----------

  describe('reactivity', () => {
    it('reacts to currentPage changes', () => {
      const currentPage = ref(1)
      const totalPages = ref(20)
      const { hasPrevious, hasNext } = useWindowedPagination(currentPage, totalPages)

      expect(hasPrevious.value).toBe(false)
      expect(hasNext.value).toBe(true)

      currentPage.value = 20
      expect(hasPrevious.value).toBe(true)
      expect(hasNext.value).toBe(false)
    })

    it('reacts to totalPages changes', () => {
      const currentPage = ref(1)
      const totalPages = ref(0)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      expect(pages.value).toEqual([])

      totalPages.value = 5
      expect(pageValues(pages.value)).toEqual([1, 2, 3, 4, 5])
    })
  })

  // ---------- Structural correctness ----------

  describe('structural correctness', () => {
    it('every page item has correct PaginationPage shape', () => {
      const currentPage = ref(10)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      for (const page of pages.value) {
        expect(page).toHaveProperty('type')
        expect(page).toHaveProperty('value')
        expect(['page', 'ellipsis']).toContain(page.type)
        expect(typeof page.value).toBe('number')
      }
    })

    it('ellipsis items have negative value markers', () => {
      const currentPage = ref(10)
      const totalPages = ref(20)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      const ellipses = pages.value.filter((p) => p.type === 'ellipsis')
      expect(ellipses.length).toBe(2)
      expect(ellipses[0].value).toBe(-1)
      expect(ellipses[1].value).toBe(-2)
    })

    it('first page is always 1 and last page is always totalPages', () => {
      const currentPage = ref(10)
      const totalPages = ref(50)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      const pageItems = pages.value.filter((p) => p.type === 'page')
      expect(pageItems[0].value).toBe(1)
      expect(pageItems[pageItems.length - 1].value).toBe(50)
    })

    it('page values are in ascending order', () => {
      const currentPage = ref(10)
      const totalPages = ref(50)
      const { pages } = useWindowedPagination(currentPage, totalPages)

      const pageItems = pages.value.filter((p) => p.type === 'page')
      for (let i = 1; i < pageItems.length; i++) {
        expect(pageItems[i].value).toBeGreaterThan(pageItems[i - 1].value)
      }
    })
  })
})
