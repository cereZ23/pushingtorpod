import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import apiClient from '@/api/client'
import { useTenantStore } from './tenant'
import type { Finding } from '@/api/types'

export type IssueSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type IssueStatus = 'open' | 'triaged' | 'in_progress' | 'mitigated' | 'verifying' | 'verified_fixed' | 'closed' | 'false_positive' | 'accepted_risk'

export interface Issue {
  id: number
  tenant_id: number
  title: string
  description: string | null
  severity: IssueSeverity
  status: IssueStatus
  affected_assets_count: number
  finding_count: number
  risk_score: number
  assigned_to: number | null
  assigned_to_name: string | null
  root_cause: string | null
  sla_due_at: string | null
  created_at: string
  updated_at: string
}

export interface IssueComment {
  id: number
  issue_id: number
  author_id: number
  author_name: string
  content: string
  created_at: string
}

export interface IssueActivity {
  id: number
  issue_id: number
  actor_name: string
  action: string
  details: string | null
  created_at: string
}

export interface IssueDetail extends Issue {
  findings: Finding[]
  comments: IssueComment[]
  activity: IssueActivity[]
}

export interface IssueListParams {
  page?: number
  page_size?: number
  severity?: string
  status?: string
  search?: string
  assigned_to?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
}

export interface IssueListMeta {
  total: number
  page: number
  page_size: number
  total_pages: number
}

export interface IssueListResponse {
  data: Issue[]
  meta: IssueListMeta
}

/** Valid status transitions for issues (mirrors backend state machine) */
export const STATUS_TRANSITIONS: Record<IssueStatus, IssueStatus[]> = {
  open: ['triaged', 'false_positive', 'accepted_risk'],
  triaged: ['in_progress', 'false_positive', 'accepted_risk'],
  in_progress: ['mitigated', 'false_positive', 'accepted_risk'],
  mitigated: ['verifying'],
  verifying: ['verified_fixed', 'open'],
  verified_fixed: ['closed'],
  closed: ['open'],
  false_positive: ['closed'],
  accepted_risk: ['closed'],
}

export const useIssueStore = defineStore('issues', () => {
  const tenantStore = useTenantStore()

  const issues = ref<Issue[]>([])
  const currentIssue = ref<IssueDetail | null>(null)
  const isLoading = ref(false)
  const isLoadingDetail = ref(false)
  const error = ref('')
  const totalItems = ref(0)
  const totalPages = ref(0)
  const currentPage = ref(1)
  const pageSize = ref(25)

  const tenantId = computed(() => tenantStore.currentTenantId)

  async function fetchIssues(params?: IssueListParams): Promise<void> {
    if (!tenantId.value) {
      error.value = 'No tenant selected'
      return
    }

    isLoading.value = true
    error.value = ''

    try {
      const response = await apiClient.get<IssueListResponse>(
        `/api/v1/tenants/${tenantId.value}/issues`,
        { params }
      )
      issues.value = response.data.data
      totalItems.value = response.data.meta.total
      totalPages.value = response.data.meta.total_pages
      currentPage.value = response.data.meta.page
      pageSize.value = response.data.meta.page_size
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to fetch issues'
      error.value = message
    } finally {
      isLoading.value = false
    }
  }

  async function fetchIssue(issueId: number): Promise<void> {
    if (!tenantId.value) {
      error.value = 'No tenant selected'
      return
    }

    isLoadingDetail.value = true
    error.value = ''

    try {
      const response = await apiClient.get<IssueDetail>(
        `/api/v1/tenants/${tenantId.value}/issues/${issueId}`
      )
      currentIssue.value = response.data
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to fetch issue'
      error.value = message
    } finally {
      isLoadingDetail.value = false
    }
  }

  async function updateIssueStatus(issueId: number, newStatus: IssueStatus): Promise<boolean> {
    if (!tenantId.value) {
      error.value = 'No tenant selected'
      return false
    }

    error.value = ''

    try {
      const response = await apiClient.patch<Issue>(
        `/api/v1/tenants/${tenantId.value}/issues/${issueId}`,
        { status: newStatus }
      )

      // Update in list
      const index = issues.value.findIndex(i => i.id === issueId)
      if (index !== -1) {
        issues.value[index] = { ...issues.value[index], ...response.data }
      }

      // Update detail if current
      if (currentIssue.value && currentIssue.value.id === issueId) {
        currentIssue.value = { ...currentIssue.value, ...response.data }
      }

      return true
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to update issue status'
      error.value = message
      return false
    }
  }

  async function addComment(issueId: number, content: string): Promise<IssueComment | null> {
    if (!tenantId.value) {
      error.value = 'No tenant selected'
      return null
    }

    error.value = ''

    try {
      const response = await apiClient.post<IssueComment>(
        `/api/v1/tenants/${tenantId.value}/issues/${issueId}/comments`,
        { content }
      )

      if (currentIssue.value && currentIssue.value.id === issueId) {
        currentIssue.value.comments.push(response.data)
      }

      return response.data
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to add comment'
      error.value = message
      return null
    }
  }

  async function assignIssue(issueId: number, userId: number | null): Promise<boolean> {
    if (!tenantId.value) {
      error.value = 'No tenant selected'
      return false
    }

    error.value = ''

    try {
      const response = await apiClient.patch<Issue>(
        `/api/v1/tenants/${tenantId.value}/issues/${issueId}`,
        { assigned_to: userId }
      )

      const index = issues.value.findIndex(i => i.id === issueId)
      if (index !== -1) {
        issues.value[index] = { ...issues.value[index], ...response.data }
      }

      if (currentIssue.value && currentIssue.value.id === issueId) {
        currentIssue.value = { ...currentIssue.value, ...response.data }
      }

      return true
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Failed to assign issue'
      error.value = message
      return false
    }
  }

  function clearError(): void {
    error.value = ''
  }

  return {
    issues,
    currentIssue,
    isLoading,
    isLoadingDetail,
    error,
    totalItems,
    totalPages,
    currentPage,
    pageSize,
    fetchIssues,
    fetchIssue,
    updateIssueStatus,
    addComment,
    assignIssue,
    clearError,
  }
})
