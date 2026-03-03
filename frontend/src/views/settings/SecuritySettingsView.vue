<script setup lang="ts">
import { ref, computed } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { authApi } from '@/api/auth'
import apiClient from '@/api/client'

const authStore = useAuthStore()

const mfaEnabled = computed(() => authStore.currentUser?.mfa_enabled ?? false)

// MFA setup state
const isSettingUp = ref(false)
const setupData = ref<{ secret: string; provisioning_uri: string; qr_code_base64?: string } | null>(null)
const verifyCode = ref('')
const isVerifying = ref(false)

// MFA disable state
const isDisabling = ref(false)
const disablePassword = ref('')
const showDisableConfirm = ref(false)

// Change password state
const currentPassword = ref('')
const newPassword = ref('')
const confirmPassword = ref('')
const isChangingPassword = ref(false)

const error = ref('')
const successMessage = ref('')

async function handleSetupMfa() {
  error.value = ''
  isSettingUp.value = true

  try {
    setupData.value = await authApi.setupMfa()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to start MFA setup'
  } finally {
    isSettingUp.value = false
  }
}

async function handleVerifySetup() {
  if (!verifyCode.value || verifyCode.value.length !== 6) return
  error.value = ''
  isVerifying.value = true

  try {
    await authApi.verifyMfaSetup(verifyCode.value)
    setupData.value = null
    verifyCode.value = ''
    showSuccess('MFA enabled successfully')
    await authStore.fetchCurrentUser()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Invalid verification code'
  } finally {
    isVerifying.value = false
  }
}

async function handleDisableMfa() {
  if (!disablePassword.value) return
  error.value = ''
  isDisabling.value = true

  try {
    await authApi.disableMfa(disablePassword.value)
    showDisableConfirm.value = false
    disablePassword.value = ''
    showSuccess('MFA disabled')
    await authStore.fetchCurrentUser()
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to disable MFA'
  } finally {
    isDisabling.value = false
  }
}

async function handleChangePassword() {
  error.value = ''

  if (newPassword.value !== confirmPassword.value) {
    error.value = 'Passwords do not match'
    return
  }

  if (newPassword.value.length < 8) {
    error.value = 'New password must be at least 8 characters'
    return
  }

  isChangingPassword.value = true

  try {
    await apiClient.post('/api/v1/auth/change-password', {
      current_password: currentPassword.value,
      new_password: newPassword.value,
    })
    currentPassword.value = ''
    newPassword.value = ''
    confirmPassword.value = ''
    showSuccess('Password changed successfully')
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to change password'
  } finally {
    isChangingPassword.value = false
  }
}

function cancelSetup() {
  setupData.value = null
  verifyCode.value = ''
}

function showSuccess(msg: string) {
  successMessage.value = msg
  setTimeout(() => { successMessage.value = '' }, 3000)
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div>
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">Security Settings</h2>
      <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">Manage your password and two-factor authentication</p>
    </div>

    <!-- Success / Error -->
    <div v-if="successMessage" class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 rounded-md">
      <p class="text-green-800 dark:text-green-200 text-sm">{{ successMessage }}</p>
    </div>
    <div v-if="error" class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md">
      <p class="text-red-800 dark:text-red-200 text-sm">{{ error }}</p>
    </div>

    <!-- MFA Section -->
    <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center">
        <div>
          <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Two-Factor Authentication</h3>
          <p class="text-sm text-gray-500 dark:text-dark-text-secondary mt-1">
            Add an extra layer of security using a TOTP authenticator app
          </p>
        </div>
        <span
          class="px-2.5 py-0.5 text-xs font-semibold rounded-full"
          :class="mfaEnabled
            ? 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
            : 'bg-gray-100 text-gray-500 dark:bg-gray-700/30 dark:text-gray-400'"
        >
          {{ mfaEnabled ? 'Enabled' : 'Disabled' }}
        </span>
      </div>

      <div class="p-6">
        <!-- MFA Setup Flow -->
        <template v-if="setupData">
          <div class="space-y-4">
            <p class="text-sm text-gray-700 dark:text-dark-text-secondary">
              Scan this QR code with your authenticator app (Google Authenticator, Authy, 1Password, etc.)
            </p>

            <!-- QR Code -->
            <div class="flex justify-center">
              <div v-if="setupData.qr_code_base64" class="bg-white p-4 rounded-lg inline-block">
                <img :src="`data:image/png;base64,${setupData.qr_code_base64}`" alt="MFA QR Code" class="w-48 h-48" />
              </div>
              <div v-else class="bg-gray-100 dark:bg-dark-bg-tertiary p-4 rounded-lg">
                <p class="text-sm text-gray-600 dark:text-dark-text-secondary">QR code unavailable. Enter the secret manually:</p>
              </div>
            </div>

            <!-- Manual Secret -->
            <div class="bg-gray-50 dark:bg-dark-bg-tertiary p-3 rounded-md">
              <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mb-1">Manual entry key:</p>
              <code class="text-sm font-mono text-gray-900 dark:text-dark-text-primary select-all">{{ setupData.secret }}</code>
            </div>

            <!-- Verification -->
            <div>
              <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                Enter the 6-digit code from your app
              </label>
              <div class="flex gap-3">
                <input
                  v-model="verifyCode"
                  type="text"
                  inputmode="numeric"
                  maxlength="6"
                  pattern="[0-9]{6}"
                  placeholder="000000"
                  class="w-40 px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 text-center font-mono text-lg tracking-widest"
                />
                <button
                  @click="handleVerifySetup"
                  :disabled="isVerifying || verifyCode.length !== 6"
                  class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
                >
                  {{ isVerifying ? 'Verifying...' : 'Verify & Enable' }}
                </button>
                <button
                  @click="cancelSetup"
                  class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </template>

        <!-- Enable/Disable Buttons -->
        <template v-else>
          <div v-if="!mfaEnabled">
            <p class="text-sm text-gray-600 dark:text-dark-text-secondary mb-4">
              Two-factor authentication is not enabled. We recommend enabling it for enhanced security.
            </p>
            <button
              @click="handleSetupMfa"
              :disabled="isSettingUp"
              class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
            >
              {{ isSettingUp ? 'Setting up...' : 'Enable Two-Factor Authentication' }}
            </button>
          </div>
          <div v-else>
            <p class="text-sm text-gray-600 dark:text-dark-text-secondary mb-4">
              Two-factor authentication is enabled. You'll need to enter a code from your authenticator app when logging in.
            </p>
            <button
              v-if="!showDisableConfirm"
              @click="showDisableConfirm = true"
              class="px-4 py-2 text-red-600 dark:text-red-400 border border-red-300 dark:border-red-700 rounded-md hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors text-sm"
            >
              Disable Two-Factor Authentication
            </button>
            <div v-else class="flex items-end gap-3">
              <div>
                <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
                  Confirm with your password
                </label>
                <input
                  v-model="disablePassword"
                  type="password"
                  placeholder="Current password"
                  class="w-64 px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                />
              </div>
              <button
                @click="handleDisableMfa"
                :disabled="isDisabling || !disablePassword"
                class="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
              >
                {{ isDisabling ? 'Disabling...' : 'Confirm Disable' }}
              </button>
              <button
                @click="showDisableConfirm = false; disablePassword = ''"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm"
              >
                Cancel
              </button>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- Change Password Section -->
    <div class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden">
      <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
        <h3 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Change Password</h3>
      </div>

      <form @submit.prevent="handleChangePassword" class="p-6 space-y-4 max-w-md">
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Current Password</label>
          <input
            v-model="currentPassword"
            type="password"
            required
            autocomplete="current-password"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">New Password</label>
          <input
            v-model="newPassword"
            type="password"
            required
            minlength="8"
            autocomplete="new-password"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
            placeholder="Min. 8 characters"
          />
        </div>
        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">Confirm New Password</label>
          <input
            v-model="confirmPassword"
            type="password"
            required
            autocomplete="new-password"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          />
        </div>
        <button
          type="submit"
          :disabled="isChangingPassword || !currentPassword || !newPassword || !confirmPassword"
          class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
        >
          {{ isChangingPassword ? 'Changing...' : 'Change Password' }}
        </button>
      </form>
    </div>
  </div>
</template>
