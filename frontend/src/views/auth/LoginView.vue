<script setup lang="ts">
import { ref } from 'vue'
import { useAuthStore } from '@/stores/auth'

const authStore = useAuthStore()

const email = ref('')
const password = ref('')
const mfaCode = ref('')
const isLoading = ref(false)
const error = ref('')

const apiBase = import.meta.env.VITE_API_BASE_URL || 'http://localhost:18000'
const ssoLoginUrl = `${apiBase}/api/v1/auth/saml/login`

async function handleLogin() {
  error.value = ''
  isLoading.value = true

  try {
    await authStore.login({
      email: email.value,
      password: password.value,
    })
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Login failed'
  } finally {
    isLoading.value = false
  }
}

async function handleMfaVerify() {
  error.value = ''
  isLoading.value = true

  try {
    await authStore.verifyMfa(mfaCode.value)
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Invalid MFA code'
  } finally {
    isLoading.value = false
  }
}

function cancelMfa() {
  authStore.mfaRequired = false
  authStore.mfaToken = null
  mfaCode.value = ''
  error.value = ''
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-dark-bg-primary py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-md w-full space-y-8">
      <div>
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-dark-text-primary">
          EASM Platform
        </h2>
        <p class="mt-2 text-center text-sm text-gray-600 dark:text-dark-text-secondary">
          External Attack Surface Management
        </p>
      </div>

      <!-- MFA Step -->
      <form v-if="authStore.mfaRequired" class="mt-8 space-y-6" @submit.prevent="handleMfaVerify">
        <div class="text-center mb-4">
          <svg class="mx-auto h-12 w-12 text-primary-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
          </svg>
          <p class="mt-2 text-sm text-gray-600 dark:text-dark-text-secondary">
            Enter the 6-digit code from your authenticator app
          </p>
        </div>

        <div>
          <label for="mfa-code" class="sr-only">MFA Code</label>
          <input
            id="mfa-code"
            v-model="mfaCode"
            type="text"
            inputmode="numeric"
            autocomplete="one-time-code"
            required
            maxlength="6"
            pattern="[0-9]{6}"
            class="appearance-none rounded-md relative block w-full px-3 py-3 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 text-center text-2xl tracking-widest font-mono"
            placeholder="000000"
          />
        </div>

        <div v-if="error" class="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
        </div>

        <div class="space-y-3">
          <button
            type="submit"
            :disabled="isLoading || mfaCode.length !== 6"
            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {{ isLoading ? 'Verifying...' : 'Verify' }}
          </button>
          <button
            type="button"
            @click="cancelMfa"
            class="w-full text-center text-sm text-gray-600 dark:text-dark-text-secondary hover:text-gray-800 dark:hover:text-dark-text-primary"
          >
            Back to login
          </button>
        </div>
      </form>

      <!-- Login Step -->
      <form v-else class="mt-8 space-y-6" @submit.prevent="handleLogin">
        <div class="rounded-md shadow-sm -space-y-px">
          <div>
            <label for="email" class="sr-only">Email address</label>
            <input
              id="email"
              v-model="email"
              name="email"
              type="email"
              autocomplete="email"
              required
              class="appearance-none rounded-t-md relative block w-full px-3 py-2 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 focus:z-10 sm:text-sm"
              placeholder="Email address"
            />
          </div>
          <div>
            <label for="password" class="sr-only">Password</label>
            <input
              id="password"
              v-model="password"
              name="password"
              type="password"
              autocomplete="current-password"
              required
              class="appearance-none rounded-b-md relative block w-full px-3 py-2 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 focus:z-10 sm:text-sm"
              placeholder="Password"
            />
          </div>
        </div>

        <div class="flex items-center justify-end">
          <router-link
            to="/forgot-password"
            class="text-sm font-medium text-primary-600 hover:text-primary-500"
          >
            Forgot your password?
          </router-link>
        </div>

        <div v-if="error" class="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
        </div>

        <div>
          <button
            type="submit"
            :disabled="isLoading"
            class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <span v-if="isLoading">Signing in...</span>
            <span v-else>Sign in</span>
          </button>
        </div>
        <div class="relative">
          <div class="absolute inset-0 flex items-center">
            <div class="w-full border-t border-gray-300 dark:border-dark-border"></div>
          </div>
          <div class="relative flex justify-center text-sm">
            <span class="px-2 bg-gray-50 dark:bg-dark-bg-primary text-gray-500 dark:text-dark-text-secondary">
              Or
            </span>
          </div>
        </div>

        <div>
          <a
            :href="ssoLoginUrl"
            class="group relative w-full flex justify-center py-2 px-4 border border-gray-300 dark:border-dark-border text-sm font-medium rounded-md text-gray-700 dark:text-dark-text-primary bg-white dark:bg-dark-bg-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500"
          >
            <svg class="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
            Sign in with SSO
          </a>
        </div>

        <p class="text-center text-sm text-gray-600 dark:text-dark-text-secondary">
          New organization?
          <router-link to="/onboarding" class="font-medium text-primary-600 hover:text-primary-500">
            Get started
          </router-link>
        </p>
      </form>
    </div>
  </div>
</template>
