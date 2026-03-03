<script setup lang="ts">
import { ref, onMounted, computed, watch } from 'vue'
import { useTenantStore } from '@/stores/tenant'
import apiClient from '@/api/client'
import { formatDate } from '@/utils/formatters'

// -- Types --

type ReportType = 'executive' | 'technical' | 'soc2' | 'iso27001'
type ReportFormat = 'pdf' | 'docx'
type ScheduleCadence = 'daily' | 'weekly' | 'monthly'

interface ReportSchedule {
  id: number
  tenant_id: number
  name: string
  report_type: ReportType
  format: ReportFormat
  schedule: ScheduleCadence
  recipients: string[]
  is_active: boolean
  last_sent_at: string | null
  created_at: string
}

interface ScheduleFormData {
  name: string
  report_type: ReportType
  format: ReportFormat
  schedule: ScheduleCadence
  recipientsText: string
}

// -- Constants --

const REPORT_TYPE_LABELS: Record<ReportType, string> = {
  executive: 'Executive',
  technical: 'Technical',
  soc2: 'SOC 2',
  iso27001: 'ISO 27001',
}

const FORMAT_LABELS: Record<ReportFormat, string> = {
  pdf: 'PDF',
  docx: 'DOCX',
}

const CADENCE_LABELS: Record<ScheduleCadence, string> = {
  daily: 'Daily',
  weekly: 'Weekly',
  monthly: 'Monthly',
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

// -- State --

const tenantStore = useTenantStore()
const currentTenantId = computed(() => tenantStore.currentTenantId)

const schedules = ref<ReportSchedule[]>([])
const isLoading = ref(false)
const error = ref('')
const successMessage = ref('')

// Form state
const showForm = ref(false)
const editingSchedule = ref<ReportSchedule | null>(null)
const isSaving = ref(false)
const formErrors = ref<string[]>([])

const form = ref<ScheduleFormData>({
  name: '',
  report_type: 'executive',
  format: 'pdf',
  schedule: 'weekly',
  recipientsText: '',
})

// Delete confirmation
const showDeleteConfirm = ref(false)
const scheduleToDelete = ref<ReportSchedule | null>(null)
const isDeleting = ref(false)

// -- Computed --

const isEditing = computed(() => editingSchedule.value !== null)

const formTitle = computed(() =>
  isEditing.value ? 'Edit Schedule' : 'Create Schedule'
)

const formSubmitLabel = computed(() => {
  if (isSaving.value) return isEditing.value ? 'Saving...' : 'Creating...'
  return isEditing.value ? 'Save Changes' : 'Create Schedule'
})

const parsedRecipients = computed((): string[] => {
  return form.value.recipientsText
    .split('\n')
    .map(line => line.trim())
    .filter(line => line.length > 0)
})

const invalidRecipients = computed((): string[] => {
  return parsedRecipients.value.filter(email => !EMAIL_REGEX.test(email))
})

const isFormValid = computed((): boolean => {
  return (
    form.value.name.trim().length > 0 &&
    parsedRecipients.value.length > 0 &&
    invalidRecipients.value.length === 0
  )
})

// -- API --

async function fetchSchedules(): Promise<void> {
  if (!currentTenantId.value) return
  isLoading.value = true
  error.value = ''

  try {
    const response = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/report-schedules`
    )
    const data = response.data
    schedules.value = Array.isArray(data) ? data : (data.items ?? data.data ?? [])
  } catch (err: unknown) {
    if (isNotFoundError(err)) {
      schedules.value = []
    } else {
      error.value = extractErrorMessage(err, 'Failed to load report schedules')
    }
  } finally {
    isLoading.value = false
  }
}

async function handleSubmit(): Promise<void> {
  if (!currentTenantId.value || !isFormValid.value) return

  formErrors.value = []
  if (invalidRecipients.value.length > 0) {
    formErrors.value = invalidRecipients.value.map(
      email => `Invalid email address: ${email}`
    )
    return
  }

  isSaving.value = true
  error.value = ''

  try {
    const payload = {
      name: form.value.name.trim(),
      report_type: form.value.report_type,
      format: form.value.format,
      schedule: form.value.schedule,
      recipients: parsedRecipients.value,
    }

    if (isEditing.value && editingSchedule.value) {
      const response = await apiClient.patch(
        `/api/v1/tenants/${currentTenantId.value}/report-schedules/${editingSchedule.value.id}`,
        payload
      )
      const idx = schedules.value.findIndex(s => s.id === editingSchedule.value!.id)
      if (idx !== -1) {
        schedules.value[idx] = response.data
      }
      showSuccess('Schedule updated')
    } else {
      const response = await apiClient.post(
        `/api/v1/tenants/${currentTenantId.value}/report-schedules`,
        payload
      )
      schedules.value.push(response.data)
      showSuccess('Schedule created')
    }

    closeForm()
  } catch (err: unknown) {
    error.value = extractErrorMessage(err, 'Failed to save schedule')
  } finally {
    isSaving.value = false
  }
}

async function handleToggleActive(schedule: ReportSchedule): Promise<void> {
  if (!currentTenantId.value) return

  const previousState = schedule.is_active
  // Optimistic update
  schedule.is_active = !previousState

  try {
    await apiClient.patch(
      `/api/v1/tenants/${currentTenantId.value}/report-schedules/${schedule.id}`,
      { is_active: schedule.is_active }
    )
    showSuccess(`Schedule ${schedule.is_active ? 'activated' : 'deactivated'}`)
  } catch (err: unknown) {
    // Revert on failure
    schedule.is_active = previousState
    error.value = extractErrorMessage(err, 'Failed to update schedule')
  }
}

async function handleDelete(): Promise<void> {
  if (!currentTenantId.value || !scheduleToDelete.value) return

  isDeleting.value = true
  error.value = ''

  try {
    await apiClient.delete(
      `/api/v1/tenants/${currentTenantId.value}/report-schedules/${scheduleToDelete.value.id}`
    )
    schedules.value = schedules.value.filter(s => s.id !== scheduleToDelete.value!.id)
    showDeleteConfirm.value = false
    scheduleToDelete.value = null
    showSuccess('Schedule deleted')
  } catch (err: unknown) {
    error.value = extractErrorMessage(err, 'Failed to delete schedule')
  } finally {
    isDeleting.value = false
  }
}

// -- Form helpers --

function openCreateForm(): void {
  editingSchedule.value = null
  formErrors.value = []
  form.value = {
    name: '',
    report_type: 'executive',
    format: 'pdf',
    schedule: 'weekly',
    recipientsText: '',
  }
  showForm.value = true
}

function openEditForm(schedule: ReportSchedule): void {
  editingSchedule.value = schedule
  formErrors.value = []
  form.value = {
    name: schedule.name,
    report_type: schedule.report_type,
    format: schedule.format,
    schedule: schedule.schedule,
    recipientsText: schedule.recipients.join('\n'),
  }
  showForm.value = true
}

function closeForm(): void {
  showForm.value = false
  editingSchedule.value = null
  formErrors.value = []
}

function confirmDelete(schedule: ReportSchedule): void {
  scheduleToDelete.value = schedule
  showDeleteConfirm.value = true
}

// -- Display helpers --

function formatRecipients(recipients: string[]): string {
  if (recipients.length === 0) return '--'
  const joined = recipients.join(', ')
  if (joined.length > 40) {
    return joined.substring(0, 37) + '...'
  }
  return joined
}

function getReportTypeLabel(type: ReportType): string {
  return REPORT_TYPE_LABELS[type] ?? type
}

function getFormatLabel(fmt: ReportFormat): string {
  return FORMAT_LABELS[fmt] ?? fmt.toUpperCase()
}

function getCadenceLabel(cadence: ScheduleCadence): string {
  return CADENCE_LABELS[cadence] ?? cadence
}

function getCadenceBadgeClass(cadence: ScheduleCadence): string {
  const classes: Record<ScheduleCadence, string> = {
    daily: 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400',
    weekly: 'bg-purple-100 text-purple-700 dark:bg-purple-900/20 dark:text-purple-400',
    monthly: 'bg-teal-100 text-teal-700 dark:bg-teal-900/20 dark:text-teal-400',
  }
  return classes[cadence] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/20 dark:text-gray-400'
}

function getFormatBadgeClass(fmt: ReportFormat): string {
  const classes: Record<ReportFormat, string> = {
    pdf: 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400',
    docx: 'bg-blue-100 text-blue-700 dark:bg-blue-900/20 dark:text-blue-400',
  }
  return classes[fmt] ?? 'bg-gray-100 text-gray-700 dark:bg-gray-900/20 dark:text-gray-400'
}

// -- Generic helpers --

function showSuccess(msg: string): void {
  successMessage.value = msg
  setTimeout(() => { successMessage.value = '' }, 3000)
}

function isNotFoundError(err: unknown): boolean {
  if (err && typeof err === 'object' && 'response' in err) {
    const axiosErr = err as { response?: { status?: number } }
    return axiosErr.response?.status === 404
  }
  return false
}

function extractErrorMessage(err: unknown, fallback: string): string {
  const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
  return axiosErr.response?.data?.detail || axiosErr.message || fallback
}

// -- Lifecycle --

onMounted(async () => {
  await fetchSchedules()
})

watch(currentTenantId, () => {
  if (currentTenantId.value) {
    fetchSchedules()
  }
})
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Scheduled Reports</h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">Automate PDF/DOCX report delivery via email</p>
      </div>
      <button
        @click="openCreateForm"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm"
      >
        Create Schedule
      </button>
    </div>

    <!-- Success Message -->
    <div
      v-if="successMessage"
      class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 rounded-md flex items-center gap-2"
    >
      <svg aria-hidden="true" class="w-5 h-5 text-green-600 dark:text-green-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
      </svg>
      <p class="text-green-800 dark:text-green-200 text-sm">{{ successMessage }}</p>
    </div>

    <!-- Error Banner -->
    <div v-if="error" role="alert" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md flex items-center justify-between">
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
      <button @click="error = ''" class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 text-sm">Dismiss</button>
    </div>

    <!-- Loading -->
    <div v-if="isLoading" role="status" class="flex items-center justify-center h-64">
      <div class="flex flex-col items-center gap-3">
        <svg class="w-8 h-8 animate-spin text-primary-600" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" />
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
        </svg>
        <span class="text-gray-600 dark:text-dark-text-secondary">Loading schedules...</span>
      </div>
    </div>

    <!-- Content -->
    <template v-if="!isLoading">
      <!-- Empty state -->
      <div v-if="schedules.length === 0 && !showForm" class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-12 text-center">
        <svg class="mx-auto h-12 w-12 text-gray-400 dark:text-dark-text-tertiary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        <p class="mt-4 text-gray-500 dark:text-dark-text-secondary">No scheduled reports configured.</p>
        <p class="text-sm text-gray-400 dark:text-dark-text-tertiary mt-1">Create one to automate report delivery.</p>
        <button
          @click="openCreateForm"
          class="mt-4 px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm"
        >
          Create First Schedule
        </button>
      </div>

      <!-- Schedules Table -->
      <div v-if="schedules.length > 0" class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
        <div class="overflow-x-auto">
          <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
            <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
              <tr>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Name</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Report Type</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Format</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Cadence</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Recipients</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Active</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Last Sent</th>
                <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border">
              <tr
                v-for="schedule in schedules"
                :key="schedule.id"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
                :class="{ 'opacity-50': !schedule.is_active }"
              >
                <td class="px-6 py-4 whitespace-nowrap">
                  <div class="text-sm font-medium text-gray-900 dark:text-dark-text-primary">{{ schedule.name }}</div>
                  <div class="text-xs text-gray-500 dark:text-dark-text-tertiary">Created {{ formatDate(schedule.created_at, 'date') }}</div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span class="text-sm text-gray-900 dark:text-dark-text-primary">{{ getReportTypeLabel(schedule.report_type) }}</span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span
                    class="px-2 py-0.5 text-xs font-medium rounded-full"
                    :class="getFormatBadgeClass(schedule.format)"
                  >
                    {{ getFormatLabel(schedule.format) }}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span
                    class="px-2 py-0.5 text-xs font-medium rounded-full"
                    :class="getCadenceBadgeClass(schedule.schedule)"
                  >
                    {{ getCadenceLabel(schedule.schedule) }}
                  </span>
                </td>
                <td class="px-6 py-4">
                  <span
                    class="text-sm text-gray-600 dark:text-dark-text-secondary max-w-[200px] truncate block"
                    :title="schedule.recipients.join(', ')"
                  >
                    {{ formatRecipients(schedule.recipients) }}
                  </span>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <button
                    @click="handleToggleActive(schedule)"
                    :aria-label="schedule.is_active ? 'Deactivate schedule' : 'Activate schedule'"
                    class="relative inline-flex h-6 w-11 items-center rounded-full transition-colors focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-dark-bg-secondary"
                    :class="schedule.is_active ? 'bg-primary-600' : 'bg-gray-300 dark:bg-gray-600'"
                  >
                    <span
                      class="inline-block h-4 w-4 transform rounded-full bg-white transition-transform"
                      :class="schedule.is_active ? 'translate-x-6' : 'translate-x-1'"
                    />
                  </button>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-600 dark:text-dark-text-secondary">
                  {{ formatDate(schedule.last_sent_at, 'relative') }}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm">
                  <div class="flex items-center gap-3">
                    <button
                      @click="openEditForm(schedule)"
                      class="text-primary-600 dark:text-primary-400 hover:text-primary-800 dark:hover:text-primary-300"
                      title="Edit schedule"
                    >
                      <svg aria-hidden="true" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                      </svg>
                    </button>
                    <button
                      @click="confirmDelete(schedule)"
                      class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300"
                      title="Delete schedule"
                    >
                      <svg aria-hidden="true" class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                      </svg>
                    </button>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- Create / Edit Dialog -->
    <Teleport to="body">
      <div
        v-if="showForm"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div class="absolute inset-0 bg-black/50" @click="closeForm" />
        <div class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-lg mx-4 border border-gray-200 dark:border-dark-border">
          <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">{{ formTitle }}</h3>
            <button @click="closeForm" class="text-gray-400 hover:text-gray-500 dark:hover:text-gray-300">
              <svg aria-hidden="true" class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <form @submit.prevent="handleSubmit" class="p-6 space-y-4">
            <!-- Form-level validation errors -->
            <div v-if="formErrors.length > 0" role="alert" class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-3 rounded-md">
              <ul class="list-disc list-inside text-sm text-red-700 dark:text-red-300 space-y-1">
                <li v-for="(fe, idx) in formErrors" :key="idx">{{ fe }}</li>
              </ul>
            </div>

            <!-- Name -->
            <div>
              <label for="schedule-name" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                Name <span class="text-red-500">*</span>
              </label>
              <input
                id="schedule-name"
                v-model="form.name"
                type="text"
                required
                placeholder="e.g. Weekly Executive Report"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <!-- Report Type & Format (side by side) -->
            <div class="grid grid-cols-2 gap-4">
              <div>
                <label for="schedule-report-type" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Report Type</label>
                <select
                  id="schedule-report-type"
                  v-model="form.report_type"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                >
                  <option value="executive">Executive</option>
                  <option value="technical">Technical</option>
                  <option value="soc2">SOC 2</option>
                  <option value="iso27001">ISO 27001</option>
                </select>
              </div>
              <div>
                <label for="schedule-format" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Format</label>
                <select
                  id="schedule-format"
                  v-model="form.format"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                >
                  <option value="pdf">PDF</option>
                  <option value="docx">DOCX</option>
                </select>
              </div>
            </div>

            <!-- Cadence -->
            <div>
              <label for="schedule-cadence" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Cadence</label>
              <select
                id="schedule-cadence"
                v-model="form.schedule"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <option value="daily">Daily</option>
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
              </select>
            </div>

            <!-- Recipients -->
            <div>
              <label for="schedule-recipients" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                Recipients <span class="text-red-500">*</span>
              </label>
              <textarea
                id="schedule-recipients"
                v-model="form.recipientsText"
                rows="4"
                required
                placeholder="One email address per line&#10;e.g.&#10;alice@example.com&#10;bob@example.com"
                class="w-full px-3 py-2 border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none font-mono text-sm"
                :class="invalidRecipients.length > 0 && parsedRecipients.length > 0
                  ? 'border-red-300 dark:border-red-700'
                  : 'border-gray-300 dark:border-dark-border'"
              />
              <div class="mt-1 flex items-center justify-between">
                <p v-if="invalidRecipients.length > 0 && parsedRecipients.length > 0" class="text-xs text-red-600 dark:text-red-400">
                  {{ invalidRecipients.length }} invalid email{{ invalidRecipients.length > 1 ? 's' : '' }}
                </p>
                <p v-else class="text-xs text-gray-500 dark:text-dark-text-tertiary">
                  One email per line
                </p>
                <p class="text-xs text-gray-400 dark:text-dark-text-tertiary">
                  {{ parsedRecipients.length }} recipient{{ parsedRecipients.length !== 1 ? 's' : '' }}
                </p>
              </div>
            </div>

            <!-- Actions -->
            <div class="flex justify-end gap-3 pt-2">
              <button
                type="button"
                @click="closeForm"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="isSaving || !isFormValid"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ formSubmitLabel }}
              </button>
            </div>
          </form>
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
                <svg aria-hidden="true" class="w-6 h-6 text-red-600 dark:text-red-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                </svg>
              </div>
              <div>
                <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Delete Schedule</h3>
                <p class="text-sm text-gray-500 dark:text-dark-text-secondary">This action cannot be undone</p>
              </div>
            </div>
            <p class="text-sm text-gray-700 dark:text-dark-text-secondary mb-6">
              Are you sure you want to delete the report schedule
              <strong class="text-gray-900 dark:text-dark-text-primary">"{{ scheduleToDelete?.name }}"</strong>?
              Automated report delivery will stop immediately.
            </p>
            <div class="flex justify-end gap-3">
              <button
                @click="showDeleteConfirm = false"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                @click="handleDelete"
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
