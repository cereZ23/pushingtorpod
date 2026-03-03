<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { authApi } from '@/api/auth'

const route = useRoute()
const router = useRouter()

const token = ref((route.query.token as string) || '')
const username = ref('')
const password = ref('')
const confirmPassword = ref('')
const fullName = ref('')
const isSubmitting = ref(false)
const error = ref('')
const success = ref(false)

async function handleSubmit() {
  error.value = ''

  if (!token.value) {
    error.value = 'Invalid invitation link.'
    return
  }

  if (password.value !== confirmPassword.value) {
    error.value = 'Passwords do not match'
    return
  }

  if (password.value.length < 8) {
    error.value = 'Password must be at least 8 characters'
    return
  }

  isSubmitting.value = true

  try {
    await authApi.acceptInvite(
      token.value,
      username.value,
      password.value,
      fullName.value || undefined,
    )
    success.value = true
    setTimeout(() => router.push('/login'), 3000)
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Failed to accept invitation'
  } finally {
    isSubmitting.value = false
  }
}
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-dark-bg-primary py-12 px-4 sm:px-6 lg:px-8">
    <div class="max-w-md w-full space-y-8">
      <div>
        <h2 class="mt-6 text-center text-3xl font-extrabold text-gray-900 dark:text-dark-text-primary">
          Accept Invitation
        </h2>
        <p class="mt-2 text-center text-sm text-gray-600 dark:text-dark-text-secondary">
          Create your account to join the team
        </p>
      </div>

      <!-- Success -->
      <div v-if="success" class="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg text-center">
        <svg class="mx-auto h-12 w-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
        </svg>
        <p class="mt-4 text-green-800 dark:text-green-200 font-medium">Account created successfully</p>
        <p class="mt-2 text-sm text-green-600 dark:text-green-300">Redirecting to login...</p>
      </div>

      <!-- Form -->
      <form v-else class="mt-8 space-y-6" @submit.prevent="handleSubmit">
        <div class="space-y-4">
          <div>
            <label for="full-name" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
              Full Name
            </label>
            <input
              id="full-name"
              v-model="fullName"
              type="text"
              autocomplete="name"
              class="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
              placeholder="John Doe"
            />
          </div>
          <div>
            <label for="username" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
              Username
            </label>
            <input
              id="username"
              v-model="username"
              type="text"
              autocomplete="username"
              required
              minlength="3"
              class="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
              placeholder="johndoe"
            />
          </div>
          <div>
            <label for="password" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
              Password
            </label>
            <input
              id="password"
              v-model="password"
              type="password"
              autocomplete="new-password"
              required
              minlength="8"
              class="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
              placeholder="Min. 8 characters"
            />
          </div>
          <div>
            <label for="confirm-password" class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1">
              Confirm Password
            </label>
            <input
              id="confirm-password"
              v-model="confirmPassword"
              type="password"
              autocomplete="new-password"
              required
              class="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
              placeholder="Repeat password"
            />
          </div>
        </div>

        <div v-if="error" class="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
        </div>

        <button
          type="submit"
          :disabled="isSubmitting"
          class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {{ isSubmitting ? 'Creating account...' : 'Create Account' }}
        </button>

        <p class="text-center text-sm text-gray-600 dark:text-dark-text-secondary">
          Already have an account?
          <router-link to="/login" class="font-medium text-primary-600 hover:text-primary-500">
            Sign in
          </router-link>
        </p>
      </form>
    </div>
  </div>
</template>
