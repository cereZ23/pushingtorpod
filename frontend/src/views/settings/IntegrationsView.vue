<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'

interface TicketingConfig {
  id: number
  provider: string
  base_url: string | null
  project_key: string | null
  is_active: boolean
  auto_create_on_triage: boolean
  sync_status_back: boolean
}

const tenantStore = useTenantStore()
const tid = computed(() => tenantStore.currentTenantId)

const config = ref<TicketingConfig | null>(null)
const isLoading = ref(true)
const isSaving = ref(false)
const isTesting = ref(false)
const error = ref('')
const successMessage = ref('')
const testResult = ref<string | null>(null)

// Form state
const provider = ref<'jira' | 'servicenow'>('jira')
const baseUrl = ref('')
const projectKey = ref('')
const username = ref('')
const apiToken = ref('')
const autoCreateOnTriage = ref(false)
const syncStatusBack = ref(false)

async function fetchConfig() {
  if (!tid.value) return
  isLoading.value = true
  error.value = ''

  try {
    const response = await apiClient.get(`/api/v1/tenants/${tid.value}/integrations/ticketing`)
    config.value = response.data
    if (config.value) {
      provider.value = (config.value.provider as 'jira' | 'servicenow') || 'jira'
      baseUrl.value = config.value.base_url || ''
      projectKey.value = config.value.project_key || ''
      autoCreateOnTriage.value = config.value.auto_create_on_triage || false
      syncStatusBack.value = config.value.sync_status_back || false
    }
  } catch (err: unknown) {
    const axiosErr = err as { response?: { status?: number; data?: { detail?: string } }; message?: string }
    if (axiosErr.response?.status === 404) {
      config.value = null
    } else {
      error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to load configuration'
    }
  } finally {
    isLoading.value = false
  }
}

async function handleSave() {
  if (!tid.value) return
  isSaving.value = true
  error.value = ''

  try {
    const payload = {
      provider: provider.value,
      base_url: baseUrl.value.trim() || null,
      project_key: projectKey.value.trim() || null,
      username: username.value.trim() || null,
      api_token: apiToken.value.trim() || null,
      auto_create_on_triage: autoCreateOnTriage.value,
      sync_status_back: syncStatusBack.value,
      is_active: true,
    }

    if (config.value) {
      await apiClient.put(`/api/v1/tenants/${tid.value}/integrations/ticketing`, payload)
    } else {
      await apiClient.post(`/api/v1/tenants/${tid.value}/integrations/ticketing`, payload)
    }

    showSuccess('Configuration saved')
    await fetchConfig()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to save configuration'
  } finally {
    isSaving.value = false
  }
}

async function handleTestConnection() {
  if (!tid.value) return
  isTesting.value = true
  testResult.value = null
  error.value = ''

  try {
    const response = await apiClient.post(`/api/v1/tenants/${tid.value}/integrations/ticketing/test`)
    testResult.value = response.data?.message || 'Connection successful'
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    testResult.value = null
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Connection test failed'
  } finally {
    isTesting.value = false
  }
}

async function handleDeactivate() {
  if (!tid.value || !config.value) return

  try {
    await apiClient.delete(`/api/v1/tenants/${tid.value}/integrations/ticketing`)
    config.value = null
    baseUrl.value = ''
    projectKey.value = ''
    username.value = ''
    apiToken.value = ''
    showSuccess('Integration deactivated')
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to deactivate'
  }
}

function showSuccess(msg: string) {
  successMessage.value = msg
  setTimeout(() => { successMessage.value = '' }, 3000)
}

watch(tid, fetchConfig)
onMounted(fetchConfig)
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Integrations</h2>
      <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">Configure external integrations for ticketing and workflows</p>
    </div>

    <!-- Success / Error -->
    <div v-if="successMessage" class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 rounded-md">
      <p class="text-green-800 dark:text-green-200 text-sm">{{ successMessage }}</p>
    </div>
    <div v-if="error" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200 text-sm">{{ error }}</p>
    </div>

    <!-- Loading -->
    <div v-if="isLoading" class="flex items-center justify-center h-64">
      <div class="text-gray-600 dark:text-dark-text-secondary">Loading configuration...</div>
    </div>

    <template v-else>
      <!-- Ticketing Configuration -->
      <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
          <div>
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Ticketing Integration</h3>
            <p class="text-sm text-gray-500 dark:text-dark-text-secondary mt-1">Connect to Jira or ServiceNow for issue tracking</p>
          </div>
          <div v-if="config?.is_active" class="flex items-center gap-2">
            <span class="px-2.5 py-0.5 text-xs font-semibold rounded-full bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400">
              Active
            </span>
          </div>
        </div>

        <form @submit.prevent="handleSave" class="p-6 space-y-6">
          <!-- Provider Selection -->
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2">Provider</label>
            <div class="flex gap-4">
              <label
                v-for="p in ['jira', 'servicenow'] as const"
                :key="p"
                class="flex items-center gap-3 p-4 rounded-lg border-2 cursor-pointer transition-all flex-1"
                :class="provider === p
                  ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                  : 'border-gray-200 dark:border-dark-border hover:border-gray-300 dark:hover:border-gray-600'"
              >
                <input v-model="provider" :value="p" type="radio" name="provider" class="sr-only" />
                <div>
                  <span class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary">
                    {{ p === 'jira' ? 'Jira' : 'ServiceNow' }}
                  </span>
                  <p class="text-xs text-gray-500 dark:text-dark-text-secondary mt-0.5">
                    {{ p === 'jira' ? 'Atlassian Jira Cloud or Server' : 'ServiceNow ITSM' }}
                  </p>
                </div>
              </label>
            </div>
          </div>

          <!-- Jira Config -->
          <template v-if="provider === 'jira'">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Jira URL</label>
                <input
                  v-model="baseUrl"
                  type="url"
                  placeholder="https://your-org.atlassian.net"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Project Key</label>
                <input
                  v-model="projectKey"
                  type="text"
                  placeholder="EASM"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Email</label>
                <input
                  v-model="username"
                  type="email"
                  placeholder="admin@example.com"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">API Token</label>
                <input
                  v-model="apiToken"
                  type="password"
                  placeholder="Enter API token"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
            </div>
          </template>

          <!-- ServiceNow Config -->
          <template v-else>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div class="md:col-span-2">
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Instance URL</label>
                <input
                  v-model="baseUrl"
                  type="url"
                  placeholder="https://your-org.service-now.com"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Username</label>
                <input
                  v-model="username"
                  type="text"
                  placeholder="admin"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Password</label>
                <input
                  v-model="apiToken"
                  type="password"
                  placeholder="Enter password"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
            </div>
          </template>

          <!-- Options -->
          <div class="space-y-3 pt-2">
            <label class="flex items-center gap-3 cursor-pointer">
              <input v-model="autoCreateOnTriage" type="checkbox" class="rounded border-gray-300 text-primary-600 focus:ring-primary-500" />
              <span class="text-sm text-gray-700 dark:text-dark-text-secondary">Auto-create ticket when issue is triaged</span>
            </label>
            <label class="flex items-center gap-3 cursor-pointer">
              <input v-model="syncStatusBack" type="checkbox" class="rounded border-gray-300 text-primary-600 focus:ring-primary-500" />
              <span class="text-sm text-gray-700 dark:text-dark-text-secondary">Sync ticket status back to EASM issues</span>
            </label>
          </div>

          <!-- Test Result -->
          <div v-if="testResult" class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 rounded-md">
            <p class="text-green-800 dark:text-green-200 text-sm">{{ testResult }}</p>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-between pt-4 border-t border-gray-200 dark:border-dark-border">
            <div>
              <button
                v-if="config?.is_active"
                type="button"
                @click="handleDeactivate"
                class="px-4 py-2 text-sm text-red-600 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300 border border-red-300 dark:border-red-700 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
              >
                Deactivate
              </button>
            </div>
            <div class="flex gap-3">
              <button
                type="button"
                @click="handleTestConnection"
                :disabled="isTesting || !baseUrl.trim()"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {{ isTesting ? 'Testing...' : 'Test Connection' }}
              </button>
              <button
                type="submit"
                :disabled="isSaving"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
              >
                {{ isSaving ? 'Saving...' : 'Save Configuration' }}
              </button>
            </div>
          </div>
        </form>
      </div>
    </template>
  </div>
</template>
