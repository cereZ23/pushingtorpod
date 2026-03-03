<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { useIssueStore, STATUS_TRANSITIONS } from '@/stores/issues'
import type { IssueStatus, IssueActivity, IssueComment } from '@/stores/issues'
import type { Finding } from '@/api/types'
import { getSeverityBadgeClass, getIssueStatusBadgeClass, getIssueTransitionButtonClass, formatIssueStatusLabel } from '@/utils/severity'
import { formatDate } from '@/utils/formatters'
import apiClient from '@/api/client'
import AppDialog from '@/components/AppDialog.vue'

const route = useRoute()
const router = useRouter()
const tenantStore = useTenantStore()
const issueStore = useIssueStore()

const currentTenantId = computed(() => tenantStore.currentTenantId)
const issueId = computed(() => Number(route.params.id))

const commentText = ref('')
const isSubmittingComment = ref(false)
const isUpdatingStatus = ref(false)
const showTransitionModal = ref(false)
const pendingTransition = ref<IssueStatus | null>(null)
const transitionComment = ref('')

// Ticketing
const isCreatingTicket = ref(false)
const isSyncingTicket = ref(false)
const ticketInfo = ref<{ external_id: string; external_url: string; status: string } | null>(null)
const ticketError = ref('')

/** Statuses that require a justification comment */
const COMMENT_REQUIRED_STATUSES: IssueStatus[] = ['false_positive', 'accepted_risk']

onMounted(async () => {
  await loadIssue()
})

watch(currentTenantId, async () => {
  if (currentTenantId.value) {
    await loadIssue()
  }
})

async function loadIssue(): Promise<void> {
  if (!issueId.value) return
  await issueStore.fetchIssue(issueId.value)
}

function goBack(): void {
  router.push({ name: 'Issues' })
}

const availableTransitions = computed((): IssueStatus[] => {
  if (!issueStore.currentIssue) return []
  return STATUS_TRANSITIONS[issueStore.currentIssue.status] || []
})

async function handleStatusTransition(newStatus: IssueStatus): Promise<void> {
  if (!issueStore.currentIssue) return

  // If the target status requires a comment, show the modal
  if (COMMENT_REQUIRED_STATUSES.includes(newStatus)) {
    pendingTransition.value = newStatus
    transitionComment.value = ''
    showTransitionModal.value = true
    return
  }

  await executeTransition(newStatus)
}

async function confirmTransition(): Promise<void> {
  if (!pendingTransition.value || !transitionComment.value.trim()) return
  showTransitionModal.value = false
  await executeTransition(pendingTransition.value, transitionComment.value.trim())
  pendingTransition.value = null
  transitionComment.value = ''
}

function cancelTransition(): void {
  showTransitionModal.value = false
  pendingTransition.value = null
  transitionComment.value = ''
}

async function executeTransition(newStatus: IssueStatus, comment?: string): Promise<void> {
  if (!issueStore.currentIssue) return
  isUpdatingStatus.value = true
  const success = await issueStore.updateIssueStatus(issueStore.currentIssue.id, newStatus, comment)
  if (success) {
    // Only reload if the update succeeded
    await loadIssue()
  }
  isUpdatingStatus.value = false
}

async function handleSubmitComment(): Promise<void> {
  if (!issueStore.currentIssue || !commentText.value.trim()) return
  isSubmittingComment.value = true
  const result = await issueStore.addComment(issueStore.currentIssue.id, commentText.value.trim())
  if (result) {
    commentText.value = ''
    // Reload to get updated activity
    await loadIssue()
  }
  isSubmittingComment.value = false
}

function getSeverityColor(severity: string): string {
  return getSeverityBadgeClass(severity)
}

function getStatusColor(status: string): string {
  return getIssueStatusBadgeClass(status)
}

function getTransitionButtonClass(status: string): string {
  return getIssueTransitionButtonClass(status)
}

function getFindingSeverityColor(severity: string): string {
  return getSeverityBadgeClass(severity)
}

function formatStatusLabel(status: string): string {
  return formatIssueStatusLabel(status)
}

function isSlaOverdue(sla: string | null): boolean {
  if (!sla) return false
  return new Date(sla) < new Date()
}

function formatSla(sla: string | null): string {
  if (!sla) return 'Not set'
  const date = new Date(sla)
  const formatted = date.toLocaleDateString()
  if (isSlaOverdue(sla)) {
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
    return `${formatted} (${diffDays}d overdue)`
  }
  return formatted
}

function formatRelativeTime(dateString: string): string {
  return formatDate(dateString, 'relative')
}


/** Merge activity and comments into a single sorted timeline */
const timeline = computed((): Array<{ type: 'activity' | 'comment'; data: IssueActivity | IssueComment }> => {
  if (!issueStore.currentIssue) return []

  const items: Array<{ type: 'activity' | 'comment'; data: IssueActivity | IssueComment }> = []

  for (const activity of issueStore.currentIssue.activity) {
    items.push({ type: 'activity', data: activity })
  }

  for (const comment of issueStore.currentIssue.comments) {
    items.push({ type: 'comment', data: comment })
  }

  items.sort((a, b) => {
    const dateA = new Date(a.data.created_at).getTime()
    const dateB = new Date(b.data.created_at).getTime()
    return dateA - dateB
  })

  return items
})

async function handleCreateTicket(): Promise<void> {
  if (!issueStore.currentIssue || issueStore.currentIssue.findings.length === 0) return

  const firstFinding = issueStore.currentIssue.findings[0]
  isCreatingTicket.value = true
  ticketError.value = ''

  try {
    const response = await apiClient.post(
      `/api/v1/tenants/${currentTenantId.value}/findings/${firstFinding.id}/ticket`
    )
    ticketInfo.value = response.data
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    ticketError.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to create ticket'
  } finally {
    isCreatingTicket.value = false
  }
}

async function handleSyncTicket(): Promise<void> {
  if (!ticketInfo.value || !issueStore.currentIssue) return

  const firstFinding = issueStore.currentIssue.findings[0]
  if (!firstFinding) return

  isSyncingTicket.value = true
  ticketError.value = ''

  try {
    const response = await apiClient.post(
      `/api/v1/tenants/${currentTenantId.value}/findings/${firstFinding.id}/ticket/sync`
    )
    ticketInfo.value = response.data
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    ticketError.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to sync ticket'
  } finally {
    isSyncingTicket.value = false
  }
}

function viewFinding(finding: Finding): void {
  router.push({ name: 'FindingDetail', params: { id: finding.id } })
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header with Back Button -->
    <div class="flex items-center gap-4">
      <button
        @click="goBack"
        class="p-2 rounded-md text-gray-600 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
      >
        <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 19l-7-7 7-7" />
        </svg>
      </button>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Issue Detail</h2>
    </div>

    <!-- Error -->
    <div v-if="issueStore.error" role="alert" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200">{{ issueStore.error }}</p>
    </div>

    <!-- Loading -->
    <div v-if="issueStore.isLoadingDetail && !issueStore.currentIssue" role="status" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading issue...</div>
    </div>

    <template v-if="issueStore.currentIssue">
      <!-- Issue Header -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6">
        <div class="flex items-start justify-between">
          <div>
            <h3 class="text-xl font-semibold text-gray-900 dark:text-dark-text-primary">
              {{ issueStore.currentIssue.title }}
            </h3>
            <div class="flex items-center gap-3 mt-2">
              <span
                class="px-2.5 py-0.5 text-xs font-semibold rounded-full"
                :class="getSeverityColor(issueStore.currentIssue.severity)"
              >
                {{ issueStore.currentIssue.severity }}
              </span>
              <span
                class="px-2.5 py-0.5 text-xs font-semibold rounded-full"
                :class="getStatusColor(issueStore.currentIssue.status)"
              >
                {{ formatStatusLabel(issueStore.currentIssue.status) }}
              </span>
              <span class="text-sm text-gray-500 dark:text-dark-text-secondary">
                Created {{ formatDate(issueStore.currentIssue.created_at) }}
              </span>
            </div>
          </div>
        </div>

        <!-- Status Transition Actions -->
        <div v-if="availableTransitions.length > 0" class="mt-4 pt-4 border-t border-gray-200 dark:border-dark-border">
          <p class="text-sm font-medium text-gray-500 dark:text-dark-text-secondary mb-2">Move to:</p>
          <div class="flex flex-wrap gap-2">
            <button
              v-for="targetStatus in availableTransitions"
              :key="targetStatus"
              @click="handleStatusTransition(targetStatus)"
              :disabled="isUpdatingStatus"
              class="px-3 py-1.5 text-sm font-medium border rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              :class="getTransitionButtonClass(targetStatus)"
            >
              {{ formatStatusLabel(targetStatus) }}
            </button>
          </div>
        </div>

        <!-- Ticketing -->
        <div class="mt-4 pt-4 border-t border-gray-200 dark:border-dark-border">
          <div class="flex items-center gap-3">
            <template v-if="ticketInfo">
              <a
                :href="ticketInfo.external_url"
                target="_blank"
                rel="noopener noreferrer"
                class="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-primary-600 dark:text-primary-400 border border-primary-300 dark:border-primary-700 rounded-md hover:bg-primary-50 dark:hover:bg-primary-900/20"
              >
                <svg aria-hidden="true" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
                </svg>
                {{ ticketInfo.external_id }}
              </a>
              <span class="px-2 py-0.5 text-xs font-semibold rounded-full bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400">
                {{ ticketInfo.status }}
              </span>
              <button
                @click="handleSyncTicket"
                :disabled="isSyncingTicket"
                class="px-2 py-1 text-xs text-gray-600 dark:text-dark-text-secondary hover:text-gray-800 dark:hover:text-dark-text-primary border border-gray-300 dark:border-dark-border rounded transition-colors disabled:opacity-50"
              >
                {{ isSyncingTicket ? 'Syncing...' : 'Sync' }}
              </button>
            </template>
            <template v-else>
              <button
                @click="handleCreateTicket"
                :disabled="isCreatingTicket || !issueStore.currentIssue?.findings?.length"
                class="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium text-gray-700 dark:text-dark-text-secondary border border-gray-300 dark:border-dark-border rounded-md hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg aria-hidden="true" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 5v2m0 4v2m0 4v2M5 5a2 2 0 00-2 2v3a2 2 0 110 4v3a2 2 0 002 2h14a2 2 0 002-2v-3a2 2 0 110-4V7a2 2 0 00-2-2H5z" />
                </svg>
                {{ isCreatingTicket ? 'Creating...' : 'Create Ticket' }}
              </button>
            </template>
          </div>
          <p v-if="ticketError" class="mt-2 text-sm text-red-600 dark:text-red-400">{{ ticketError }}</p>
        </div>
      </div>

      <!-- Info Grid -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <!-- Details Card -->
        <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6">
          <h4 class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider mb-4">Details</h4>
          <dl class="space-y-3">
            <div class="flex justify-between">
              <dt class="text-sm text-gray-500 dark:text-dark-text-secondary">Risk Score</dt>
              <dd class="text-sm font-medium text-gray-900 dark:text-dark-text-primary flex items-center">
                {{ issueStore.currentIssue.risk_score }}
                <div class="ml-2 w-16 h-2 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden">
                  <div
                    class="h-full rounded-full"
                    :class="{
                      'bg-red-500': issueStore.currentIssue.risk_score >= 80,
                      'bg-orange-500': issueStore.currentIssue.risk_score >= 60 && issueStore.currentIssue.risk_score < 80,
                      'bg-yellow-500': issueStore.currentIssue.risk_score >= 40 && issueStore.currentIssue.risk_score < 60,
                      'bg-blue-500': issueStore.currentIssue.risk_score < 40,
                    }"
                    :style="{ width: `${Math.min(issueStore.currentIssue.risk_score, 100)}%` }"
                  />
                </div>
              </dd>
            </div>
            <div class="flex justify-between">
              <dt class="text-sm text-gray-500 dark:text-dark-text-secondary">Affected Assets</dt>
              <dd class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ issueStore.currentIssue.affected_assets_count }}</dd>
            </div>
            <div class="flex justify-between">
              <dt class="text-sm text-gray-500 dark:text-dark-text-secondary">Linked Findings</dt>
              <dd class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ issueStore.currentIssue.finding_count }}</dd>
            </div>
            <div class="flex justify-between">
              <dt class="text-sm text-gray-500 dark:text-dark-text-secondary">Assigned To</dt>
              <dd class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">
                {{ issueStore.currentIssue.assigned_to_name || 'Unassigned' }}
              </dd>
            </div>
            <div class="flex justify-between">
              <dt class="text-sm text-gray-500 dark:text-dark-text-secondary">SLA Due</dt>
              <dd
                class="text-sm font-medium"
                :class="isSlaOverdue(issueStore.currentIssue.sla_due_at)
                  ? 'text-red-600 dark:text-red-400'
                  : 'text-gray-900 dark:text-dark-text-primary'"
              >
                {{ formatSla(issueStore.currentIssue.sla_due_at) }}
              </dd>
            </div>
          </dl>
        </div>

        <!-- Root Cause Card -->
        <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-6">
          <h4 class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider mb-4">Root Cause</h4>
          <p
            v-if="issueStore.currentIssue.root_cause"
            class="text-sm text-gray-700 dark:text-dark-text-primary whitespace-pre-wrap"
          >
            {{ issueStore.currentIssue.root_cause }}
          </p>
          <p v-else class="text-sm text-gray-400 dark:text-dark-text-tertiary italic">
            No root cause analysis provided yet.
          </p>

          <div v-if="issueStore.currentIssue.description" class="mt-4 pt-4 border-t border-gray-200 dark:border-dark-border">
            <h4 class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider mb-2">Description</h4>
            <p class="text-sm text-gray-700 dark:text-dark-text-primary whitespace-pre-wrap">
              {{ issueStore.currentIssue.description }}
            </p>
          </div>
        </div>
      </div>

      <!-- Linked Findings -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
          <h4 class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider">
            Linked Findings ({{ issueStore.currentIssue.findings.length }})
          </h4>
        </div>

        <div v-if="issueStore.currentIssue.findings.length === 0" class="p-6 text-center">
          <p class="text-gray-500 dark:text-dark-text-secondary text-sm">No linked findings</p>
        </div>

        <div v-else class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
            <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Name</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Severity</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Status</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Asset</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
              <tr
                v-for="finding in issueStore.currentIssue.findings"
                :key="finding.id"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-6 py-3">
                  <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ finding.name }}</div>
                  <div v-if="finding.template_id" class="text-xs text-gray-500 dark:text-dark-text-secondary">{{ finding.template_id }}</div>
                </td>
                <td class="px-6 py-3 whitespace-nowrap">
                  <span
                    class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full"
                    :class="getFindingSeverityColor(finding.severity)"
                  >
                    {{ finding.severity }}
                  </span>
                </td>
                <td class="px-6 py-3 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary">
                  {{ finding.status }}
                </td>
                <td class="px-6 py-3 text-sm text-gray-500 dark:text-dark-text-secondary">
                  {{ finding.asset_identifier || '-' }}
                </td>
                <td class="px-6 py-3 whitespace-nowrap text-sm">
                  <button
                    @click="viewFinding(finding)"
                    class="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300"
                  >
                    View
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Activity Timeline and Comments -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
          <h4 class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider">Activity</h4>
        </div>

        <div class="p-6">
          <!-- Timeline -->
          <div v-if="timeline.length > 0" class="space-y-4 mb-6">
            <div
              v-for="(item, index) in timeline"
              :key="index"
              class="flex gap-3"
            >
              <!-- Activity Icon -->
              <div class="flex-shrink-0 mt-0.5">
                <!-- Comment icon -->
                <div
                  v-if="item.type === 'comment'"
                  class="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/20 flex items-center justify-center"
                >
                  <svg aria-hidden="true" class="w-4 h-4 text-blue-600 dark:text-blue-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z" />
                  </svg>
                </div>
                <!-- Activity icon -->
                <div
                  v-else
                  class="w-8 h-8 rounded-full bg-gray-100 dark:bg-gray-700/30 flex items-center justify-center"
                >
                  <svg aria-hidden="true" class="w-4 h-4 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
              </div>

              <!-- Content -->
              <div class="flex-1 min-w-0">
                <template v-if="item.type === 'comment'">
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">
                      {{ (item.data as IssueComment).author_name }}
                    </span>
                    <span class="text-xs text-gray-500 dark:text-dark-text-secondary">
                      {{ formatRelativeTime(item.data.created_at) }}
                    </span>
                  </div>
                  <div class="mt-1 p-3 bg-gray-50 dark:bg-dark-bg-tertiary rounded-md text-sm text-gray-700 dark:text-dark-text-primary whitespace-pre-wrap">
                    {{ (item.data as IssueComment).content }}
                  </div>
                </template>

                <template v-else>
                  <div class="flex items-center gap-2">
                    <span class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">
                      {{ (item.data as IssueActivity).actor_name }}
                    </span>
                    <span class="text-sm text-gray-600 dark:text-dark-text-secondary">
                      {{ (item.data as IssueActivity).action }}
                    </span>
                    <span class="text-xs text-gray-500 dark:text-dark-text-secondary">
                      {{ formatRelativeTime(item.data.created_at) }}
                    </span>
                  </div>
                  <div
                    v-if="(item.data as IssueActivity).details"
                    class="mt-1 text-sm text-gray-500 dark:text-dark-text-secondary"
                  >
                    {{ (item.data as IssueActivity).details }}
                  </div>
                </template>
              </div>
            </div>
          </div>

          <div v-else class="text-center py-4 mb-6 text-sm text-gray-500 dark:text-dark-text-secondary">
            No activity yet
          </div>

          <!-- Comment Input -->
          <div class="border-t border-gray-200 dark:border-dark-border pt-4">
            <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Add a comment</label>
            <textarea
              v-model="commentText"
              rows="3"
              placeholder="Write your comment..."
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
            />
            <div class="flex justify-end mt-2">
              <button
                @click="handleSubmitComment"
                :disabled="isSubmittingComment || !commentText.trim()"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
              >
                {{ isSubmittingComment ? 'Posting...' : 'Post Comment' }}
              </button>
            </div>
          </div>
        </div>
      </div>
      <!-- Transition Comment Modal -->
      <AppDialog
        :open="showTransitionModal"
        :title="`Confirm: ${pendingTransition ? formatStatusLabel(pendingTransition) : ''}`"
        description="A justification comment is required for this transition."
        @close="cancelTransition"
      >
        <textarea
          v-model="transitionComment"
          rows="3"
          placeholder="Provide a reason..."
          class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
        />
        <template #footer>
          <button
            @click="cancelTransition"
            class="px-4 py-2 text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary rounded-md transition-colors"
          >
            Cancel
          </button>
          <button
            @click="confirmTransition"
            :disabled="!transitionComment.trim()"
            class="px-4 py-2 text-sm bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            Confirm
          </button>
        </template>
      </AppDialog>
    </template>
  </div>
</template>
