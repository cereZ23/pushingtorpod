<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'

// --- Type definitions ---

type ChannelType = 'slack' | 'email' | 'webhook' | 'teams' | 'pagerduty'
type EventType = 'new_asset' | 'open_port' | 'new_cert' | 'new_path' | 'new_finding' | 'severity_change'

interface ChannelConfig {
  type: ChannelType
  config: Record<string, string>
}

interface AlertPolicy {
  id: number
  name: string
  event_types: EventType[]
  severity_condition: string | null
  channels: ChannelConfig[]
  cooldown_minutes: number
  digest_mode: boolean
  enabled: boolean
  created_at: string
  updated_at: string | null
}

interface AlertPolicyCreatePayload {
  name: string
  event_types: EventType[]
  severity_condition: string | null
  channels: ChannelConfig[]
  cooldown_minutes: number
  digest_mode: boolean
  enabled: boolean
}

// --- Store and state ---

const tenantStore = useTenantStore()
const currentTenantId = computed(() => tenantStore.currentTenantId)

const policies = ref<AlertPolicy[]>([])
const isLoading = ref(false)
const error = ref('')
const successMessage = ref('')

// Dialog state
const showDialog = ref(false)
const isEditing = ref(false)
const editingPolicyId = ref<number | null>(null)
const isSaving = ref(false)

// Form fields
const formName = ref('')
const formEventTypes = ref<EventType[]>([])
const formSeverityCondition = ref('')
const formChannels = ref<ChannelConfig[]>([])
const formCooldownMinutes = ref(30)
const formDigestMode = ref(false)
const formEnabled = ref(true)

// Testing state
const testingPolicyId = ref<number | null>(null)
const isSeedingDefaults = ref(false)

// Delete confirmation
const deletingPolicyId = ref<number | null>(null)

// --- Constants ---

const availableEventTypes: { value: EventType; label: string }[] = [
  { value: 'new_asset', label: 'New Asset Discovered' },
  { value: 'open_port', label: 'Open Port Detected' },
  { value: 'new_cert', label: 'New Certificate Found' },
  { value: 'new_path', label: 'New Path Crawled' },
  { value: 'new_finding', label: 'New Finding' },
  { value: 'severity_change', label: 'Severity Change' },
]

const availableChannelTypes: { value: ChannelType; label: string }[] = [
  { value: 'slack', label: 'Slack' },
  { value: 'email', label: 'Email' },
  { value: 'webhook', label: 'Webhook' },
  { value: 'teams', label: 'Microsoft Teams' },
  { value: 'pagerduty', label: 'PagerDuty' },
]

const channelConfigFields: Record<ChannelType, { key: string; label: string; placeholder: string }[]> = {
  slack: [
    { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://hooks.slack.com/services/...' },
    { key: 'channel', label: 'Channel', placeholder: '#security-alerts' },
  ],
  email: [
    { key: 'to', label: 'To', placeholder: 'security@example.com' },
    { key: 'subject_prefix', label: 'Subject Prefix', placeholder: '[EASM Alert]' },
  ],
  webhook: [
    { key: 'url', label: 'URL', placeholder: 'https://api.example.com/webhook' },
    { key: 'secret', label: 'Secret (optional)', placeholder: 'hmac-secret-key' },
  ],
  teams: [
    { key: 'webhook_url', label: 'Webhook URL', placeholder: 'https://outlook.office.com/webhook/...' },
  ],
  pagerduty: [
    { key: 'routing_key', label: 'Routing Key', placeholder: 'Events API v2 integration key' },
  ],
}

// --- Lifecycle ---

onMounted(async () => {
  await loadPolicies()
})

watch(currentTenantId, async () => {
  if (currentTenantId.value) {
    await loadPolicies()
  }
})

// --- API methods ---

async function loadPolicies(): Promise<void> {
  if (!currentTenantId.value) {
    error.value = 'No tenant selected'
    return
  }

  isLoading.value = true
  error.value = ''

  try {
    const response = await apiClient.get<AlertPolicy[]>(
      `/api/v1/tenants/${currentTenantId.value}/alert-policies`
    )
    policies.value = response.data
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to load alert policies'
    error.value = message
  } finally {
    isLoading.value = false
  }
}

async function savePolicy(): Promise<void> {
  if (!currentTenantId.value) return
  if (!formName.value.trim()) return

  isSaving.value = true
  error.value = ''

  const payload: AlertPolicyCreatePayload = {
    name: formName.value.trim(),
    event_types: formEventTypes.value,
    severity_condition: formSeverityCondition.value || null,
    channels: formChannels.value,
    cooldown_minutes: formCooldownMinutes.value,
    digest_mode: formDigestMode.value,
    enabled: formEnabled.value,
  }

  try {
    if (isEditing.value && editingPolicyId.value !== null) {
      await apiClient.patch(
        `/api/v1/tenants/${currentTenantId.value}/alert-policies/${editingPolicyId.value}`,
        payload
      )
      successMessage.value = 'Policy updated successfully'
    } else {
      await apiClient.post(
        `/api/v1/tenants/${currentTenantId.value}/alert-policies`,
        payload
      )
      successMessage.value = 'Policy created successfully'
    }
    closeDialog()
    await loadPolicies()
    clearSuccessAfterDelay()
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to save policy'
    error.value = message
  } finally {
    isSaving.value = false
  }
}

async function deletePolicy(policyId: number): Promise<void> {
  if (!currentTenantId.value) return

  error.value = ''

  try {
    await apiClient.delete(
      `/api/v1/tenants/${currentTenantId.value}/alert-policies/${policyId}`
    )
    deletingPolicyId.value = null
    successMessage.value = 'Policy deleted successfully'
    await loadPolicies()
    clearSuccessAfterDelay()
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to delete policy'
    error.value = message
    deletingPolicyId.value = null
  }
}

async function testPolicy(policyId: number): Promise<void> {
  if (!currentTenantId.value) return

  testingPolicyId.value = policyId
  error.value = ''

  try {
    await apiClient.post(
      `/api/v1/tenants/${currentTenantId.value}/alert-policies/${policyId}/test`
    )
    successMessage.value = 'Test notification sent successfully'
    clearSuccessAfterDelay()
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to send test notification'
    error.value = message
  } finally {
    testingPolicyId.value = null
  }
}

async function toggleEnabled(policy: AlertPolicy): Promise<void> {
  if (!currentTenantId.value) return

  error.value = ''

  try {
    await apiClient.patch(
      `/api/v1/tenants/${currentTenantId.value}/alert-policies/${policy.id}`,
      { enabled: !policy.enabled }
    )
    policy.enabled = !policy.enabled
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to toggle policy'
    error.value = message
  }
}

async function seedDefaults(): Promise<void> {
  if (!currentTenantId.value) return

  isSeedingDefaults.value = true
  error.value = ''

  try {
    await apiClient.post(
      `/api/v1/tenants/${currentTenantId.value}/alert-policies/seed-defaults`
    )
    successMessage.value = 'Default policies created successfully'
    await loadPolicies()
    clearSuccessAfterDelay()
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : 'Failed to seed default policies'
    error.value = message
  } finally {
    isSeedingDefaults.value = false
  }
}

// --- Dialog methods ---

function openCreateDialog(): void {
  isEditing.value = false
  editingPolicyId.value = null
  resetForm()
  showDialog.value = true
}

function openEditDialog(policy: AlertPolicy): void {
  isEditing.value = true
  editingPolicyId.value = policy.id
  formName.value = policy.name
  formEventTypes.value = [...policy.event_types]
  formSeverityCondition.value = policy.severity_condition || ''
  formChannels.value = policy.channels.map((ch) => ({
    type: ch.type,
    config: { ...ch.config },
  }))
  formCooldownMinutes.value = policy.cooldown_minutes
  formDigestMode.value = policy.digest_mode
  formEnabled.value = policy.enabled
  showDialog.value = true
}

function closeDialog(): void {
  showDialog.value = false
  resetForm()
}

function resetForm(): void {
  formName.value = ''
  formEventTypes.value = []
  formSeverityCondition.value = ''
  formChannels.value = []
  formCooldownMinutes.value = 30
  formDigestMode.value = false
  formEnabled.value = true
}

// --- Channel management ---

function addChannel(): void {
  formChannels.value.push({
    type: 'slack',
    config: {},
  })
}

function removeChannel(index: number): void {
  formChannels.value.splice(index, 1)
}

function onChannelTypeChange(index: number): void {
  formChannels.value[index].config = {}
}

// --- Event type multiselect ---

function toggleEventType(eventType: EventType): void {
  const idx = formEventTypes.value.indexOf(eventType)
  if (idx >= 0) {
    formEventTypes.value.splice(idx, 1)
  } else {
    formEventTypes.value.push(eventType)
  }
}

function isEventTypeSelected(eventType: EventType): boolean {
  return formEventTypes.value.includes(eventType)
}

// --- Utility methods ---

function clearSuccessAfterDelay(): void {
  setTimeout(() => {
    successMessage.value = ''
  }, 4000)
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Alert Policies</h2>
      <div class="flex items-center gap-3">
        <button
          @click="seedDefaults"
          :disabled="isSeedingDefaults"
          class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {{ isSeedingDefaults ? 'Seeding...' : 'Seed Defaults' }}
        </button>
        <button
          @click="openCreateDialog"
          class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
        >
          Create Policy
        </button>
      </div>
    </div>

    <!-- Success Message -->
    <div
      v-if="successMessage"
      class="bg-green-50 dark:bg-green-900/20 p-4 rounded-md flex items-center justify-between"
    >
      <p class="text-green-800 dark:text-green-200">{{ successMessage }}</p>
      <button
        @click="successMessage = ''"
        class="text-green-600 dark:text-green-400 hover:text-green-800 dark:hover:text-green-300 text-sm"
      >
        Dismiss
      </button>
    </div>

    <!-- Error State -->
    <div
      v-if="error"
      class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md flex items-center justify-between"
    >
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
      <button
        @click="error = ''"
        class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 text-sm"
      >
        Dismiss
      </button>
    </div>

    <!-- Loading State -->
    <div v-if="isLoading" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading alert policies...</div>
    </div>

    <!-- Policies Table -->
    <div
      v-else
      class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
    >
      <!-- Empty State -->
      <div v-if="policies.length === 0" class="p-12 text-center">
        <svg class="mx-auto h-12 w-12 text-gray-400 dark:text-dark-text-tertiary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        <p class="mt-4 text-gray-500 dark:text-dark-text-secondary">No alert policies configured</p>
        <div class="mt-4 flex justify-center gap-3">
          <button
            @click="seedDefaults"
            :disabled="isSeedingDefaults"
            class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 transition-colors"
          >
            Seed Defaults
          </button>
          <button
            @click="openCreateDialog"
            class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 transition-colors"
          >
            Create First Policy
          </button>
        </div>
      </div>

      <!-- Table -->
      <div v-else class="overflow-x-auto">
        <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
          <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
            <tr>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">
                Name
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">
                Event Types
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">
                Channels
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">
                Cooldown
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">
                Enabled
              </th>
              <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">
                Actions
              </th>
            </tr>
          </thead>
          <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
            <tr
              v-for="policy in policies"
              :key="policy.id"
              class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
            >
              <td class="px-6 py-4">
                <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">
                  {{ policy.name }}
                </div>
                <div v-if="policy.severity_condition" class="text-xs text-gray-500 dark:text-dark-text-secondary mt-0.5">
                  Severity: {{ policy.severity_condition }}
                </div>
              </td>
              <td class="px-6 py-4">
                <div class="flex flex-wrap gap-1">
                  <span
                    v-for="eventType in policy.event_types"
                    :key="eventType"
                    class="rounded-full px-2 py-1 text-xs bg-indigo-100 text-indigo-800 dark:bg-indigo-900/20 dark:text-indigo-400"
                  >
                    {{ eventType.replace(/_/g, ' ') }}
                  </span>
                </div>
              </td>
              <td class="px-6 py-4">
                <div class="flex flex-wrap gap-1">
                  <span
                    v-for="(channel, idx) in policy.channels"
                    :key="idx"
                    class="rounded-full px-2 py-1 text-xs bg-gray-100 text-gray-800 dark:bg-gray-700/30 dark:text-gray-300"
                  >
                    {{ channel.type }}
                  </span>
                </div>
              </td>
              <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary">
                {{ policy.cooldown_minutes }}m
                <span v-if="policy.digest_mode" class="ml-1 text-xs text-gray-500 dark:text-dark-text-tertiary">(digest)</span>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <button
                  @click="toggleEnabled(policy)"
                  :class="[
                    'relative inline-flex h-6 w-11 flex-shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 ease-in-out focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2',
                    policy.enabled
                      ? 'bg-indigo-600'
                      : 'bg-gray-200 dark:bg-dark-bg-tertiary'
                  ]"
                  role="switch"
                  :aria-checked="policy.enabled"
                >
                  <span
                    :class="[
                      'pointer-events-none inline-block h-5 w-5 transform rounded-full bg-white shadow ring-0 transition duration-200 ease-in-out',
                      policy.enabled ? 'translate-x-5' : 'translate-x-0'
                    ]"
                  />
                </button>
              </td>
              <td class="px-6 py-4 whitespace-nowrap">
                <div class="flex items-center gap-2">
                  <button
                    @click="testPolicy(policy.id)"
                    :disabled="testingPolicyId === policy.id"
                    class="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300 disabled:opacity-50"
                  >
                    {{ testingPolicyId === policy.id ? 'Testing...' : 'Test' }}
                  </button>
                  <span class="text-gray-300 dark:text-dark-border">|</span>
                  <button
                    @click="openEditDialog(policy)"
                    class="text-sm text-gray-600 dark:text-dark-text-secondary hover:text-gray-800 dark:hover:text-dark-text-primary"
                  >
                    Edit
                  </button>
                  <span class="text-gray-300 dark:text-dark-border">|</span>
                  <button
                    v-if="deletingPolicyId !== policy.id"
                    @click="deletingPolicyId = policy.id"
                    class="text-sm text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300"
                  >
                    Delete
                  </button>
                  <template v-else>
                    <button
                      @click="deletePolicy(policy.id)"
                      class="text-sm text-red-600 dark:text-red-400 font-medium hover:text-red-800 dark:hover:text-red-300"
                    >
                      Confirm
                    </button>
                    <button
                      @click="deletingPolicyId = null"
                      class="text-sm text-gray-500 dark:text-dark-text-secondary hover:text-gray-700 dark:hover:text-dark-text-primary"
                    >
                      Cancel
                    </button>
                  </template>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- Create/Edit Policy Dialog -->
    <Teleport to="body">
      <div
        v-if="showDialog"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <!-- Backdrop -->
        <div class="absolute inset-0 bg-black/50" @click="closeDialog" />

        <!-- Dialog -->
        <div class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-2xl mx-4 border border-gray-200 dark:border-dark-border max-h-[90vh] overflow-y-auto">
          <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">
              {{ isEditing ? 'Edit Policy' : 'Create Alert Policy' }}
            </h3>
          </div>

          <form @submit.prevent="savePolicy" class="p-6 space-y-5">
            <!-- Name -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                Policy Name
              </label>
              <input
                v-model="formName"
                type="text"
                required
                placeholder="e.g. Critical Finding Alert"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <!-- Event Types (Multiselect) -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">
                Event Types
              </label>
              <div class="flex flex-wrap gap-2">
                <button
                  v-for="et in availableEventTypes"
                  :key="et.value"
                  type="button"
                  @click="toggleEventType(et.value)"
                  :class="[
                    'px-3 py-1.5 text-sm rounded-md border transition-colors',
                    isEventTypeSelected(et.value)
                      ? 'bg-indigo-100 border-indigo-300 text-indigo-800 dark:bg-indigo-900/30 dark:border-indigo-600 dark:text-indigo-300'
                      : 'bg-white border-gray-300 text-gray-700 dark:bg-dark-bg-tertiary dark:border-dark-border dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary'
                  ]"
                >
                  {{ et.label }}
                </button>
              </div>
            </div>

            <!-- Severity Condition -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                Severity Condition (optional)
              </label>
              <select
                v-model="formSeverityCondition"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <option value="">No severity filter</option>
                <option value=">=critical">Critical or higher</option>
                <option value=">=high">High or higher</option>
                <option value=">=medium">Medium or higher</option>
                <option value=">=low">Low or higher</option>
              </select>
            </div>

            <!-- Channels -->
            <div>
              <div class="flex items-center justify-between mb-2">
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary">
                  Notification Channels
                </label>
                <button
                  type="button"
                  @click="addChannel"
                  class="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 dark:hover:text-indigo-300"
                >
                  + Add Channel
                </button>
              </div>
              <div v-if="formChannels.length === 0" class="text-sm text-gray-500 dark:text-dark-text-secondary p-3 border border-dashed border-gray-300 dark:border-dark-border rounded-md text-center">
                No channels configured. Add at least one channel.
              </div>
              <div v-else class="space-y-4">
                <div
                  v-for="(channel, index) in formChannels"
                  :key="index"
                  class="p-4 border border-gray-200 dark:border-dark-border rounded-md bg-gray-50 dark:bg-dark-bg-tertiary"
                >
                  <div class="flex items-center justify-between mb-3">
                    <select
                      v-model="channel.type"
                      @change="onChannelTypeChange(index)"
                      class="px-3 py-1.5 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-2 focus:ring-primary-500"
                    >
                      <option
                        v-for="ct in availableChannelTypes"
                        :key="ct.value"
                        :value="ct.value"
                      >
                        {{ ct.label }}
                      </option>
                    </select>
                    <button
                      type="button"
                      @click="removeChannel(index)"
                      class="text-gray-400 hover:text-red-500 transition-colors"
                    >
                      <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
                      </svg>
                    </button>
                  </div>
                  <div class="space-y-2">
                    <div
                      v-for="field in channelConfigFields[channel.type]"
                      :key="field.key"
                    >
                      <label class="block text-xs font-medium text-gray-600 dark:text-dark-text-secondary mb-1">
                        {{ field.label }}
                      </label>
                      <input
                        v-model="channel.config[field.key]"
                        type="text"
                        :placeholder="field.placeholder"
                        class="w-full px-3 py-1.5 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-2 focus:ring-primary-500"
                      />
                    </div>
                  </div>
                </div>
              </div>
            </div>

            <!-- Cooldown -->
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                  Cooldown (minutes)
                </label>
                <input
                  v-model.number="formCooldownMinutes"
                  type="number"
                  min="1"
                  max="1440"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <div class="flex items-end">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    v-model="formDigestMode"
                    type="checkbox"
                    class="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                  />
                  <span class="text-sm text-gray-700 dark:text-dark-text-secondary">
                    Digest mode (batch notifications)
                  </span>
                </label>
              </div>
            </div>

            <!-- Enabled toggle -->
            <div>
              <label class="flex items-center gap-2 cursor-pointer">
                <input
                  v-model="formEnabled"
                  type="checkbox"
                  class="h-4 w-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span class="text-sm text-gray-700 dark:text-dark-text-secondary">
                  Enable policy immediately
                </span>
              </label>
            </div>

            <!-- Actions -->
            <div class="flex justify-end gap-3 pt-2 border-t border-gray-200 dark:border-dark-border">
              <button
                type="button"
                @click="closeDialog"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="isSaving || !formName.trim() || formEventTypes.length === 0"
                class="px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ isSaving ? 'Saving...' : (isEditing ? 'Update Policy' : 'Create Policy') }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>
  </div>
</template>
