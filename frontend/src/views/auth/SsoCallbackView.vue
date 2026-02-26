<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { useRouter } from 'vue-router'

const authStore = useAuthStore()
const router = useRouter()
const error = ref('')

onMounted(() => {
  // Parse tokens from URL fragment (set by SAML ACS redirect)
  const hash = window.location.hash.substring(1)
  const params = new URLSearchParams(hash)

  const accessToken = params.get('access_token')
  const refreshToken = params.get('refresh_token')

  if (!accessToken || !refreshToken) {
    error.value = 'SSO authentication failed. No tokens received.'
    return
  }

  // Store tokens and redirect to dashboard
  authStore.setTokens(accessToken, refreshToken)

  // Clear the hash from URL to avoid token leakage in browser history
  window.history.replaceState(null, '', '/auth/sso-callback')

  router.push('/')
})
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-dark-bg-primary">
    <div class="max-w-md w-full text-center space-y-4">
      <div v-if="error" class="rounded-md bg-red-50 dark:bg-red-900/20 p-6">
        <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
        <router-link
          to="/login"
          class="mt-4 inline-block text-sm font-medium text-primary-600 hover:text-primary-500"
        >
          Back to login
        </router-link>
      </div>
      <div v-else class="p-6">
        <svg class="animate-spin h-8 w-8 text-primary-600 mx-auto" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
          <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"></circle>
          <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"></path>
        </svg>
        <p class="mt-4 text-sm text-gray-600 dark:text-dark-text-secondary">
          Completing SSO login...
        </p>
      </div>
    </div>
  </div>
</template>
