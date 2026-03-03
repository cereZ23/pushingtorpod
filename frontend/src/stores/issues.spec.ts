import { vi, describe, it, expect, beforeEach } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'

// Mock the API client module
vi.mock('@/api/client', () => ({
  default: {
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
    delete: vi.fn(),
    defaults: { baseURL: 'http://test' },
    interceptors: {
      request: { use: vi.fn() },
      response: { use: vi.fn() },
    },
  },
}))

// Mock the tenant store dependency
vi.mock('./tenant', () => ({
  useTenantStore: vi.fn(() => ({
    currentTenantId: 1,
  })),
}))

// Mock axios.isAxiosError for error handling tests
vi.mock('axios', () => ({
  default: {
    isAxiosError: vi.fn((err: unknown) => {
      return (
        typeof err === 'object' &&
        err !== null &&
        'isAxiosError' in err &&
        (err as Record<string, unknown>).isAxiosError === true
      )
    }),
    create: vi.fn(),
  },
  isAxiosError: vi.fn((err: unknown) => {
    return (
      typeof err === 'object' &&
      err !== null &&
      'isAxiosError' in err &&
      (err as Record<string, unknown>).isAxiosError === true
    )
  }),
}))

import apiClient from '@/api/client'
import { useTenantStore } from './tenant'
import {
  useIssueStore,
  STATUS_TRANSITIONS,
  type Issue,
  type IssueDetail,
  type IssueComment,
  type IssueListResponse,
} from './issues'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeIssue(overrides: Partial<Issue> = {}): Issue {
  return {
    id: 1,
    tenant_id: 1,
    title: 'Critical SQL Injection',
    description: 'Found SQL injection in login form',
    severity: 'critical',
    status: 'open',
    affected_assets_count: 3,
    finding_count: 5,
    risk_score: 92,
    assigned_to: null,
    assigned_to_name: null,
    root_cause: null,
    sla_due_at: '2026-03-05T00:00:00Z',
    created_at: '2026-02-20T10:00:00Z',
    updated_at: '2026-02-20T10:00:00Z',
    ...overrides,
  }
}

function makeIssueDetail(overrides: Partial<IssueDetail> = {}): IssueDetail {
  return {
    ...makeIssue(),
    findings: [],
    comments: [],
    activity: [],
    ...overrides,
  }
}

function makeListResponse(
  issues: Issue[],
  meta: Partial<{ total: number; page: number; page_size: number; total_pages: number }> = {}
): { data: IssueListResponse } {
  return {
    data: {
      data: issues,
      meta: {
        total: meta.total ?? issues.length,
        page: meta.page ?? 1,
        page_size: meta.page_size ?? 25,
        total_pages: meta.total_pages ?? 1,
      },
    },
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('issues store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  // -----------------------------------------------------------------------
  // Initial state
  // -----------------------------------------------------------------------
  describe('initial state', () => {
    it('has empty issues list and null currentIssue', () => {
      const store = useIssueStore()
      expect(store.issues).toEqual([])
      expect(store.currentIssue).toBeNull()
      expect(store.isLoading).toBe(false)
      expect(store.isLoadingDetail).toBe(false)
      expect(store.error).toBe('')
      expect(store.totalItems).toBe(0)
      expect(store.totalPages).toBe(0)
      expect(store.currentPage).toBe(1)
      expect(store.pageSize).toBe(25)
    })
  })

  // -----------------------------------------------------------------------
  // STATUS_TRANSITIONS constant
  // -----------------------------------------------------------------------
  describe('STATUS_TRANSITIONS', () => {
    it('defines valid transitions for all statuses', () => {
      expect(STATUS_TRANSITIONS.open).toContain('triaged')
      expect(STATUS_TRANSITIONS.open).toContain('false_positive')
      expect(STATUS_TRANSITIONS.open).toContain('accepted_risk')
      expect(STATUS_TRANSITIONS.closed).toContain('open')
      expect(STATUS_TRANSITIONS.verified_fixed).toContain('closed')
    })

    it('does not allow arbitrary backward transitions', () => {
      expect(STATUS_TRANSITIONS.closed).not.toContain('triaged')
      expect(STATUS_TRANSITIONS.mitigated).not.toContain('open')
    })
  })

  // -----------------------------------------------------------------------
  // fetchIssues
  // -----------------------------------------------------------------------
  describe('fetchIssues', () => {
    it('sets loading state while fetching', async () => {
      const issues = [makeIssue({ id: 1 }), makeIssue({ id: 2, title: 'XSS' })]
      vi.mocked(apiClient.get).mockResolvedValueOnce(makeListResponse(issues, { total: 2 }))

      const store = useIssueStore()
      const promise = store.fetchIssues()

      // isLoading should be true while the request is in flight
      expect(store.isLoading).toBe(true)

      await promise

      expect(store.isLoading).toBe(false)
    })

    it('loads issues and sets pagination metadata', async () => {
      const issues = [
        makeIssue({ id: 1 }),
        makeIssue({ id: 2, title: 'XSS' }),
        makeIssue({ id: 3, title: 'Open Redirect' }),
      ]
      vi.mocked(apiClient.get).mockResolvedValueOnce(
        makeListResponse(issues, { total: 50, page: 2, page_size: 25, total_pages: 2 })
      )

      const store = useIssueStore()
      await store.fetchIssues({ page: 2 })

      expect(store.issues).toHaveLength(3)
      expect(store.totalItems).toBe(50)
      expect(store.currentPage).toBe(2)
      expect(store.pageSize).toBe(25)
      expect(store.totalPages).toBe(2)
    })

    it('calls API with correct URL and params', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce(makeListResponse([]))

      const store = useIssueStore()
      await store.fetchIssues({ severity: 'critical', status: 'open', page: 1, page_size: 10 })

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/issues',
        expect.objectContaining({
          params: { severity: 'critical', status: 'open', page: 1, page_size: 10 },
          signal: expect.any(AbortSignal),
        })
      )
    })

    it('clears error before fetching', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce(makeListResponse([]))

      const store = useIssueStore()
      store.error = 'Previous error'

      await store.fetchIssues()

      expect(store.error).toBe('')
    })

    it('sets error on API failure', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Network Error'))

      const store = useIssueStore()
      await store.fetchIssues()

      expect(store.error).toBe('Network Error')
      expect(store.isLoading).toBe(false)
    })

    it('uses fallback message for non-Error rejections', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce('string error')

      const store = useIssueStore()
      await store.fetchIssues()

      expect(store.error).toBe('Failed to fetch issues')
    })

    it('returns early with error when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useIssueStore()
      await store.fetchIssues()

      expect(store.error).toBe('No tenant selected')
      expect(apiClient.get).not.toHaveBeenCalled()
    })

    it('silently ignores CanceledError (aborted request)', async () => {
      const cancelError = new Error('canceled')
      cancelError.name = 'CanceledError'
      vi.mocked(apiClient.get).mockRejectedValueOnce(cancelError)

      const store = useIssueStore()
      await store.fetchIssues()

      expect(store.error).toBe('')
    })

    it('silently ignores AbortError', async () => {
      const abortError = new Error('The operation was aborted')
      abortError.name = 'AbortError'
      vi.mocked(apiClient.get).mockRejectedValueOnce(abortError)

      const store = useIssueStore()
      await store.fetchIssues()

      expect(store.error).toBe('')
    })
  })

  // -----------------------------------------------------------------------
  // AbortController behavior
  // -----------------------------------------------------------------------
  describe('AbortController', () => {
    it('aborts previous fetchIssues request when a new one starts', async () => {
      let firstSignal: AbortSignal | undefined
      let secondSignal: AbortSignal | undefined

      vi.mocked(apiClient.get)
        .mockImplementationOnce((_url, config) => {
          firstSignal = config?.signal as AbortSignal
          return new Promise(() => {
            // Never resolves to simulate in-flight request
          })
        })
        .mockImplementationOnce((_url, config) => {
          secondSignal = config?.signal as AbortSignal
          return Promise.resolve(makeListResponse([]))
        })

      const store = useIssueStore()

      // Start first fetch (will never resolve)
      void store.fetchIssues()

      // Start second fetch immediately -- this should abort the first
      const secondPromise = store.fetchIssues()

      await secondPromise

      expect(firstSignal?.aborted).toBe(true)
      expect(secondSignal?.aborted).toBe(false)
    })

    it('aborts previous fetchIssue request when a new one starts', async () => {
      let firstSignal: AbortSignal | undefined

      vi.mocked(apiClient.get)
        .mockImplementationOnce((_url, _config) => {
          firstSignal = _config?.signal as AbortSignal
          return new Promise(() => {})
        })
        .mockImplementationOnce((_url, _config) => {
          return Promise.resolve({ data: makeIssueDetail({ id: 2 }) })
        })

      const store = useIssueStore()

      store.fetchIssue(1)
      await store.fetchIssue(2)

      expect(firstSignal?.aborted).toBe(true)
      expect(store.currentIssue?.id).toBe(2)
    })
  })

  // -----------------------------------------------------------------------
  // fetchIssue
  // -----------------------------------------------------------------------
  describe('fetchIssue', () => {
    it('loads a single issue detail', async () => {
      const detail = makeIssueDetail({
        id: 42,
        findings: [
          {
            id: 1,
            asset_id: 10,
            source: 'nuclei',
            name: 'SQL Injection',
            severity: 'critical',
            first_seen: '2026-02-20T10:00:00Z',
            last_seen: '2026-02-20T10:00:00Z',
            status: 'open',
            occurrence_count: 3,
          },
        ],
        comments: [
          {
            id: 1,
            issue_id: 42,
            author_id: 1,
            author_name: 'admin',
            content: 'Investigating',
            created_at: '2026-02-20T10:00:00Z',
          },
        ],
      })
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: detail })

      const store = useIssueStore()
      await store.fetchIssue(42)

      expect(store.currentIssue).toEqual(detail)
      expect(store.isLoadingDetail).toBe(false)
      expect(store.error).toBe('')
    })

    it('sets loading state during fetch', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: makeIssueDetail() })

      const store = useIssueStore()
      const promise = store.fetchIssue(1)

      expect(store.isLoadingDetail).toBe(true)
      await promise
      expect(store.isLoadingDetail).toBe(false)
    })

    it('handles API error', async () => {
      vi.mocked(apiClient.get).mockRejectedValueOnce(new Error('Not Found'))

      const store = useIssueStore()
      await store.fetchIssue(999)

      expect(store.error).toBe('Not Found')
      expect(store.currentIssue).toBeNull()
      expect(store.isLoadingDetail).toBe(false)
    })

    it('returns early when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useIssueStore()
      await store.fetchIssue(1)

      expect(store.error).toBe('No tenant selected')
      expect(apiClient.get).not.toHaveBeenCalled()
    })

    it('calls correct URL', async () => {
      vi.mocked(apiClient.get).mockResolvedValueOnce({ data: makeIssueDetail({ id: 7 }) })

      const store = useIssueStore()
      await store.fetchIssue(7)

      expect(apiClient.get).toHaveBeenCalledWith(
        '/api/v1/tenants/1/issues/7',
        expect.objectContaining({ signal: expect.any(AbortSignal) })
      )
    })
  })

  // -----------------------------------------------------------------------
  // updateIssueStatus
  // -----------------------------------------------------------------------
  describe('updateIssueStatus', () => {
    it('calls PATCH with new status and returns true', async () => {
      const updatedIssue = makeIssue({ id: 1, status: 'triaged' })
      vi.mocked(apiClient.patch).mockResolvedValueOnce({ data: updatedIssue })

      const store = useIssueStore()
      store.issues = [makeIssue({ id: 1, status: 'open' })]

      const result = await store.updateIssueStatus(1, 'triaged')

      expect(result).toBe(true)
      expect(apiClient.patch).toHaveBeenCalledWith(
        '/api/v1/tenants/1/issues/1',
        { status: 'triaged' }
      )
    })

    it('includes comment when provided', async () => {
      vi.mocked(apiClient.patch).mockResolvedValueOnce({ data: makeIssue({ id: 1, status: 'false_positive' }) })

      const store = useIssueStore()
      await store.updateIssueStatus(1, 'false_positive', 'Not exploitable')

      expect(apiClient.patch).toHaveBeenCalledWith(
        '/api/v1/tenants/1/issues/1',
        { status: 'false_positive', comment: 'Not exploitable' }
      )
    })

    it('updates issue in list after successful status change', async () => {
      const updatedIssue = makeIssue({ id: 2, status: 'triaged' })
      vi.mocked(apiClient.patch).mockResolvedValueOnce({ data: updatedIssue })

      const store = useIssueStore()
      store.issues = [
        makeIssue({ id: 1 }),
        makeIssue({ id: 2, status: 'open' }),
        makeIssue({ id: 3 }),
      ]

      await store.updateIssueStatus(2, 'triaged')

      expect(store.issues[1].status).toBe('triaged')
      // Other issues should be untouched
      expect(store.issues[0].id).toBe(1)
      expect(store.issues[2].id).toBe(3)
    })

    it('updates currentIssue detail when it matches the updated issue', async () => {
      const updatedIssue = makeIssue({ id: 5, status: 'in_progress' })
      vi.mocked(apiClient.patch).mockResolvedValueOnce({ data: updatedIssue })

      const store = useIssueStore()
      store.currentIssue = makeIssueDetail({ id: 5, status: 'triaged' })

      await store.updateIssueStatus(5, 'in_progress')

      expect(store.currentIssue?.status).toBe('in_progress')
    })

    it('does not update currentIssue when ids differ', async () => {
      const updatedIssue = makeIssue({ id: 5, status: 'in_progress' })
      vi.mocked(apiClient.patch).mockResolvedValueOnce({ data: updatedIssue })

      const store = useIssueStore()
      store.currentIssue = makeIssueDetail({ id: 99, status: 'open' })

      await store.updateIssueStatus(5, 'in_progress')

      expect(store.currentIssue?.status).toBe('open')
    })

    it('returns false and sets error on API failure', async () => {
      vi.mocked(apiClient.patch).mockRejectedValueOnce(new Error('Forbidden'))

      const store = useIssueStore()
      const result = await store.updateIssueStatus(1, 'triaged')

      expect(result).toBe(false)
      expect(store.error).toBe('Forbidden')
    })

    it('extracts detail from Axios error response', async () => {
      const axiosError = {
        isAxiosError: true,
        response: { data: { detail: 'Invalid transition from open to closed' } },
        message: 'Request failed with status code 422',
      }
      vi.mocked(apiClient.patch).mockRejectedValueOnce(axiosError)

      const store = useIssueStore()
      const result = await store.updateIssueStatus(1, 'closed' as 'triaged')

      expect(result).toBe(false)
      expect(store.error).toBe('Invalid transition from open to closed')
    })

    it('returns false when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useIssueStore()
      const result = await store.updateIssueStatus(1, 'triaged')

      expect(result).toBe(false)
      expect(store.error).toBe('No tenant selected')
    })
  })

  // -----------------------------------------------------------------------
  // addComment
  // -----------------------------------------------------------------------
  describe('addComment', () => {
    it('posts comment and appends it to currentIssue.comments', async () => {
      const newComment: IssueComment = {
        id: 10,
        issue_id: 1,
        author_id: 1,
        author_name: 'admin',
        content: 'This needs attention',
        created_at: '2026-02-28T12:00:00Z',
      }
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: newComment })

      const store = useIssueStore()
      store.currentIssue = makeIssueDetail({ id: 1, comments: [] })

      const result = await store.addComment(1, 'This needs attention')

      expect(result).toEqual(newComment)
      expect(store.currentIssue?.comments).toHaveLength(1)
      expect(store.currentIssue?.comments[0].content).toBe('This needs attention')
      expect(apiClient.post).toHaveBeenCalledWith(
        '/api/v1/tenants/1/issues/1/comments',
        { content: 'This needs attention' }
      )
    })

    it('does not modify currentIssue when issue id does not match', async () => {
      const newComment: IssueComment = {
        id: 10,
        issue_id: 99,
        author_id: 1,
        author_name: 'admin',
        content: 'Comment on other issue',
        created_at: '2026-02-28T12:00:00Z',
      }
      vi.mocked(apiClient.post).mockResolvedValueOnce({ data: newComment })

      const store = useIssueStore()
      store.currentIssue = makeIssueDetail({ id: 1, comments: [] })

      await store.addComment(99, 'Comment on other issue')

      expect(store.currentIssue?.comments).toHaveLength(0)
    })

    it('returns null on error', async () => {
      vi.mocked(apiClient.post).mockRejectedValueOnce(new Error('Server Error'))

      const store = useIssueStore()
      const result = await store.addComment(1, 'test')

      expect(result).toBeNull()
      expect(store.error).toBe('Server Error')
    })

    it('returns null when no tenant selected', async () => {
      vi.mocked(useTenantStore).mockReturnValueOnce({ currentTenantId: undefined } as ReturnType<typeof useTenantStore>)

      const store = useIssueStore()
      const result = await store.addComment(1, 'test')

      expect(result).toBeNull()
      expect(store.error).toBe('No tenant selected')
    })
  })

  // -----------------------------------------------------------------------
  // assignIssue
  // -----------------------------------------------------------------------
  describe('assignIssue', () => {
    it('assigns a user and updates local state', async () => {
      const updatedIssue = makeIssue({ id: 3, assigned_to: 7, assigned_to_name: 'analyst1' })
      vi.mocked(apiClient.patch).mockResolvedValueOnce({ data: updatedIssue })

      const store = useIssueStore()
      store.issues = [makeIssue({ id: 3 })]

      const result = await store.assignIssue(3, 7)

      expect(result).toBe(true)
      expect(apiClient.patch).toHaveBeenCalledWith(
        '/api/v1/tenants/1/issues/3',
        { assigned_to: 7 }
      )
      expect(store.issues[0].assigned_to).toBe(7)
    })

    it('unassigns (null) and updates local state', async () => {
      const updatedIssue = makeIssue({ id: 3, assigned_to: null, assigned_to_name: null })
      vi.mocked(apiClient.patch).mockResolvedValueOnce({ data: updatedIssue })

      const store = useIssueStore()
      store.issues = [makeIssue({ id: 3, assigned_to: 7 })]

      const result = await store.assignIssue(3, null)

      expect(result).toBe(true)
      expect(apiClient.patch).toHaveBeenCalledWith(
        '/api/v1/tenants/1/issues/3',
        { assigned_to: null }
      )
    })

    it('returns false on error', async () => {
      vi.mocked(apiClient.patch).mockRejectedValueOnce(new Error('Not Found'))

      const store = useIssueStore()
      const result = await store.assignIssue(1, 5)

      expect(result).toBe(false)
      expect(store.error).toBe('Not Found')
    })
  })

  // -----------------------------------------------------------------------
  // clearError
  // -----------------------------------------------------------------------
  describe('clearError', () => {
    it('resets the error string', () => {
      const store = useIssueStore()
      store.error = 'some error'

      store.clearError()

      expect(store.error).toBe('')
    })
  })
})
