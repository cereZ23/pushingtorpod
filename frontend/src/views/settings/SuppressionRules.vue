<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'
import { formatDate } from '@/utils/formatters'

// -- Types --

interface SuppressionRule {
  id: number
  tenant_id: number
  name: string
  pattern_type: 'template_id' | 'host' | 'severity' | 'cve_id' | 'regex'
  pattern: string
  reason: string | null
  is_active: boolean
  priority: number
  expires_at: string | null
  created_at: string
  updated_at: string
}

interface CreateSuppressionPayload {
  name: string
  pattern_type: string
  pattern: string
  reason: string | null
  is_active: boolean
  priority: number
  expires_at: string | null
}

// -- State --

const tenantStore = useTenantStore()
const currentTenantId = computed(() => tenantStore.currentTenantId)

const rules = ref<SuppressionRule[]>([])
const isLoading = ref(false)
const error = ref('')
const successMessage = ref('')

// Create dialog
const showCreateDialog = ref(false)
const isSaving = ref(false)
const newRule = ref<CreateSuppressionPayload>({
  name: '',
  pattern_type: 'template_id',
  pattern: '',
  reason: '',
  is_active: true,
  priority: 0,
  expires_at: null,
})

// Delete confirmation
const showDeleteConfirm = ref(false)
const ruleToDelete = ref<SuppressionRule | null>(null)
const isDeleting = ref(false)

// Pre-fill from finding
const showFromFinding = ref(false)
const findingTemplateId = ref('')

// -- Computed --

const patternTypes = [
  { value: 'template_id', label: 'Template ID', placeholder: 'e.g. CVE-2021-44228 or exposed-panels/phpmyadmin' },
  { value: 'host', label: 'Host', placeholder: 'e.g. *.staging.example.com' },
  { value: 'severity', label: 'Severity', placeholder: 'e.g. info or low' },
  { value: 'cve_id', label: 'CVE ID', placeholder: 'e.g. CVE-2023-*' },
  { value: 'regex', label: 'Regex', placeholder: 'e.g. ^test-.*\\.example\\.com$' },
]

const currentPlaceholder = computed(() => {
  const found = patternTypes.find(t => t.value === newRule.value.pattern_type)
  return found?.placeholder ?? 'Enter pattern'
})

const activeRules = computed(() => rules.value.filter(r => r.is_active))
const inactiveRules = computed(() => rules.value.filter(r => !r.is_active))

// -- API --

async function fetchRules(): Promise<void> {
  if (!currentTenantId.value) return
  isLoading.value = true
  error.value = ''

  try {
    const response = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/suppressions`
    )
    const data = response.data
    rules.value = Array.isArray(data) ? data : (data.items ?? [])
  } catch (err: unknown) {
    if (isNotFoundError(err)) {
      rules.value = []
    } else {
      const message = err instanceof Error ? err.message : 'Failed to load suppression rules'
      error.value = message
    }
  } finally {
    isLoading.value = false
  }
}

async function handleCreateRule(): Promise<void> {
  if (!currentTenantId.value) return
  if (!newRule.value.name.trim() || !newRule.value.pattern.trim()) return

  isSaving.value = true
  error.value = ''

  try {
    const payload = {
      ...newRule.value,
      reason: newRule.value.reason?.trim() || null,
      expires_at: newRule.value.expires_at || null,
    }
    const response = await apiClient.post(
      `/api/v1/tenants/${currentTenantId.value}/suppressions`,
      payload
    )
    rules.value.push(response.data)
    showCreateDialog.value = false
    resetForm()
    showSuccess('Suppression rule created')
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to create rule'
    error.value = message
  } finally {
    isSaving.value = false
  }
}

async function handleToggleActive(rule: SuppressionRule): Promise<void> {
  if (!currentTenantId.value) return

  const newState = !rule.is_active
  try {
    await apiClient.patch(
      `/api/v1/tenants/${currentTenantId.value}/suppressions/${rule.id}`,
      { is_active: newState }
    )
    rule.is_active = newState
    showSuccess(`Rule ${newState ? 'activated' : 'deactivated'}`)
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to update rule'
    error.value = message
  }
}

async function confirmDelete(rule: SuppressionRule): Promise<void> {
  ruleToDelete.value = rule
  showDeleteConfirm.value = true
}

async function handleDeleteRule(): Promise<void> {
  if (!currentTenantId.value || !ruleToDelete.value) return

  isDeleting.value = true
  error.value = ''

  try {
    await apiClient.delete(
      `/api/v1/tenants/${currentTenantId.value}/suppressions/${ruleToDelete.value.id}`
    )
    rules.value = rules.value.filter(r => r.id !== ruleToDelete.value!.id)
    showDeleteConfirm.value = false
    ruleToDelete.value = null
    showSuccess('Rule deleted')
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to delete rule'
    error.value = message
  } finally {
    isDeleting.value = false
  }
}

// -- Helpers --

function isNotFoundError(err: unknown): boolean {
  if (err && typeof err === 'object' && 'response' in err) {
    const axiosErr = err as { response?: { status?: number } }
    return axiosErr.response?.status === 404
  }
  return false
}

function resetForm(): void {
  newRule.value = {
    name: '',
    pattern_type: 'template_id',
    pattern: '',
    reason: '',
    is_active: true,
    priority: 0,
    expires_at: null,
  }
}

function openCreateDialog(): void {
  resetForm()
  showCreateDialog.value = true
}

function openCreateFromFinding(): void {
  showFromFinding.value = true
  findingTemplateId.value = ''
}

function prefillFromFinding(): void {
  if (!findingTemplateId.value.trim()) return
  resetForm()
  newRule.value.name = `Suppress ${findingTemplateId.value}`
  newRule.value.pattern_type = 'template_id'
  newRule.value.pattern = findingTemplateId.value.trim()
  newRule.value.reason = 'Created from finding template'
  showFromFinding.value = false
  showCreateDialog.value = true
}

function showSuccess(msg: string): void {
  successMessage.value = msg
  setTimeout(() => { successMessage.value = '' }, 3000)
}

function isExpired(rule: SuppressionRule): boolean {
  if (!rule.expires_at) return false
  return new Date(rule.expires_at) < new Date()
}

function getPatternTypeLabel(type: string): string {
  const found = patternTypes.find(t => t.value === type)
  return found?.label ?? type
}

// -- Lifecycle --

onMounted(async () => {
  await fetchRules()
})

watch(currentTenantId, () => {
  if (currentTenantId.value) {
    fetchRules()
  }
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <div>
        <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Suppression Rules</h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">Manage false positive rules and finding suppressions</p>
      </div>
      <div class="flex gap-2">
        <button
          @click="openCreateFromFinding"
          class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm"
        >
          Create from Finding
        </button>
        <button
          @click="openCreateDialog"
          class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm"
        >
          New Rule
        </button>
      </div>
    </div>

    <!-- Success Message -->
    <div
      v-if="successMessage"
      class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 rounded-md flex items-center gap-2"
    >
      <svg class="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
      </svg>
      <p class="text-green-800 dark:text-green-200 text-sm">{{ successMessage }}</p>
    </div>

    <!-- Error Banner -->
    <div v-if="error" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md flex items-center justify-between">
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
      <button @click="error = ''" class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 text-sm">Dismiss</button>
    </div>

    <!-- Loading -->
    <div v-if="isLoading" class="flex items-center justify-center h-64">
      <div class="flex flex-col items-center gap-3">
        <svg class="w-8 h-8 animate-spin text-primary-600" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span class="text-gray-600 dark:text-dark-text-secondary">Loading rules...</span>
      </div>
    </div>

    <!-- Rules Table -->
    <template v-if="!isLoading">
      <!-- Stats Cards -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border">
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">Total Rules</p>
          <p class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary mt-1">{{ rules.length }}</p>
        </div>
        <div class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border">
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">Active</p>
          <p class="text-2xl font-bold text-green-600 dark:text-green-400 mt-1">{{ activeRules.length }}</p>
        </div>
        <div class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border">
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">Inactive / Expired</p>
          <p class="text-2xl font-bold text-gray-500 dark:text-dark-text-tertiary mt-1">{{ inactiveRules.length }}</p>
        </div>
      </div>

      <!-- Empty state -->
      <div v-if="rules.length === 0" class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-12 text-center">
        <svg class="mx-auto h-12 w-12 text-gray-400 dark:text-dark-text-tertiary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636" />
        </svg>
        <p class="mt-4 text-gray-500 dark:text-dark-text-secondary">No suppression rules defined</p>
        <p class="text-sm text-gray-400 dark:text-dark-text-tertiary mt-1">Create rules to suppress false positives or noise from findings</p>
        <button
          @click="openCreateDialog"
          class="mt-4 px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm"
        >
          Create First Rule
        </button>
      </div>

      <!-- Rules table -->
      <div v-else class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
            <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
              <tr>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Name</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Type</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Pattern</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Reason</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Priority</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Expires</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Active</th>
                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
              <tr
                v-for="rule in rules"
                :key="rule.id"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
                :class="{ 'opacity-50': !rule.is_active || isExpired(rule) }"
              >
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ rule.name }}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class="px-2 py-0.5 text-xs font-medium rounded-full bg-purple-100 text-purple-700 dark:bg-purple-900/20 dark:text-purple-400">
                    {{ getPatternTypeLabel(rule.pattern_type) }}
                  </span>
                </td>
                <td class="px-6 py-4">
                  <span class="text-sm font-mono text-gray-700 dark:text-dark-text-secondary bg-gray-100 dark:bg-dark-bg-tertiary px-2 py-0.5 rounded break-all">
                    {{ rule.pattern }}
                  </span>
                </td>
                <td class="px-6 py-4">
                  <span class="text-sm text-gray-600 dark:text-dark-text-secondary max-w-[200px] truncate block">
                    {{ rule.reason || '-' }}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-dark-text-secondary text-center">
                  {{ rule.priority }}
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span v-if="rule.expires_at" class="text-sm" :class="isExpired(rule) ? 'text-red-600 dark:text-red-400' : 'text-gray-600 dark:text-dark-text-secondary'">
                    {{ formatDate(rule.expires_at, 'date') }}
                    <span v-if="isExpired(rule)" class="text-xs font-medium">(expired)</span>
                  </span>
                  <span v-else class="text-sm text-gray-400 dark:text-dark-text-tertiary">Never</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <button
                    @click="handleToggleActive(rule)"
                    class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-dark-bg-secondary"
                    :class="rule.is_active ? 'bg-primary-600' : 'bg-gray-300 dark:bg-gray-600'"
                  >
                    <span
                      class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform"
                      :class="rule.is_active ? 'translate-x-6' : 'translate-x-1'"
                    />
                  </button>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  <button
                    @click="confirmDelete(rule)"
                    class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300"
                    title="Delete rule"
                  >
                    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                    </svg>
                  </button>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- Create Rule Dialog -->
    <Teleport to="body">
      <div
        v-if="showCreateDialog"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div class="absolute inset-0 bg-black/50" @click="showCreateDialog = false" />
        <div class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-lg mx-4 border border-gray-200 dark:border-dark-border">
          <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Create Suppression Rule</h3>
            <button @click="showCreateDialog = false" class="text-gray-400 hover:text-gray-500">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <form @submit.prevent="handleCreateRule" class="p-6 space-y-4">
            <!-- Name -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Rule Name</label>
              <input
                v-model="newRule.name"
                type="text"
                required
                placeholder="e.g. Suppress phpMyAdmin on staging"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <!-- Pattern Type -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Pattern Type</label>
              <select
                v-model="newRule.pattern_type"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <option v-for="pt in patternTypes" :key="pt.value" :value="pt.value">{{ pt.label }}</option>
              </select>
            </div>

            <!-- Pattern -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Pattern</label>
              <input
                v-model="newRule.pattern"
                type="text"
                required
                :placeholder="currentPlaceholder"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 font-mono"
              />
            </div>

            <!-- Reason -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Reason</label>
              <textarea
                v-model="newRule.reason"
                rows="2"
                placeholder="Why this finding should be suppressed..."
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
              />
            </div>

            <!-- Priority & Expiry Row -->
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Priority</label>
                <input
                  v-model.number="newRule.priority"
                  type="number"
                  min="0"
                  max="100"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
                <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-1">Higher = evaluated first</p>
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                  Expires <span class="text-gray-400">(optional)</span>
                </label>
                <input
                  v-model="newRule.expires_at"
                  type="date"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
            </div>

            <!-- Active toggle -->
            <div class="flex items-center gap-3">
              <button
                type="button"
                @click="newRule.is_active = !newRule.is_active"
                class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500"
                :class="newRule.is_active ? 'bg-primary-600' : 'bg-gray-300 dark:bg-gray-600'"
              >
                <span
                  class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform"
                  :class="newRule.is_active ? 'translate-x-6' : 'translate-x-1'"
                />
              </button>
              <span class="text-sm text-gray-700 dark:text-dark-text-secondary">
                {{ newRule.is_active ? 'Active immediately' : 'Create as inactive' }}
              </span>
            </div>

            <!-- Actions -->
            <div class="flex justify-end gap-3 pt-2">
              <button
                type="button"
                @click="showCreateDialog = false"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="isSaving || !newRule.name.trim() || !newRule.pattern.trim()"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ isSaving ? 'Creating...' : 'Create Rule' }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <!-- Create from Finding Dialog -->
    <Teleport to="body">
      <div
        v-if="showFromFinding"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div class="absolute inset-0 bg-black/50" @click="showFromFinding = false" />
        <div class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-md mx-4 border border-gray-200 dark:border-dark-border">
          <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Create from Finding</h3>
            <button @click="showFromFinding = false" class="text-gray-400 hover:text-gray-500">
              <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>
          <div class="p-6 space-y-4">
            <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
              Enter a finding template ID to pre-fill a suppression rule. The rule will match all findings with this template.
            </p>
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Finding Template ID</label>
              <input
                v-model="findingTemplateId"
                type="text"
                placeholder="e.g. exposed-panels/phpmyadmin-panel"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 font-mono"
                @keyup.enter="prefillFromFinding"
              />
            </div>
            <div class="flex justify-end gap-3">
              <button
                type="button"
                @click="showFromFinding = false"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                @click="prefillFromFinding"
                :disabled="!findingTemplateId.trim()"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                Continue
              </button>
            </div>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Delete Confirmation Dialog -->
    <Teleport to="body">
      <div
        v-if="showDeleteConfirm"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div class="absolute inset-0 bg-black/50" @click="showDeleteConfirm = false" />
        <div class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-sm mx-4 border border-gray-200 dark:border-dark-border">
          <div class="p-6">
            <div class="flex items-center gap-3 mb-4">
              <div class="p-2 bg-red-100 dark:bg-red-900/20 rounded-full">
                <svg class="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Delete Rule</h3>
                <p class="text-sm text-gray-500 dark:text-dark-text-secondary">This action cannot be undone</p>
              </div>
            </div>
            <p class="text-sm text-gray-700 dark:text-dark-text-secondary mb-6">
              Are you sure you want to delete the suppression rule
              <strong class="text-gray-900 dark:text-dark-text-primary">"{{ ruleToDelete?.name }}"</strong>?
              Any findings previously suppressed by this rule will become visible again.
            </p>
            <div class="flex justify-end gap-3">
              <button
                @click="showDeleteConfirm = false"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                @click="handleDeleteRule"
                :disabled="isDeleting"
                class="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ isDeleting ? 'Deleting...' : 'Delete' }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
