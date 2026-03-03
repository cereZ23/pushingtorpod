<script setup lang="ts">
import { ref } from 'vue'
import { authApi } from '@/api/auth'

const email = ref('')
const isSubmitting = ref(false)
const submitted = ref(false)
const error = ref('')

async function handleSubmit() {
  error.value = ''
  isSubmitting.value = true

  try {
    await authApi.forgotPassword(email.value)
    submitted.value = true
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    error.value = axiosErr.response?.data?.detail || axiosErr.message || 'Something went wrong'
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
          Reset Password
        </h2>
        <p class="mt-2 text-center text-sm text-gray-600 dark:text-dark-text-secondary">
          Enter your email to receive a password reset link
        </p>
      </div>

      <!-- Success State -->
      <div v-if="submitted" class="bg-green-50 dark:bg-green-900/20 p-6 rounded-lg text-center">
        <svg class="mx-auto h-12 w-12 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
        </svg>
        <p class="mt-4 text-green-800 dark:text-green-200 font-medium">Check your email</p>
        <p class="mt-2 text-sm text-green-600 dark:text-green-300">
          If an account exists for {{ email }}, you'll receive a password reset link.
        </p>
        <router-link to="/login" class="inline-block mt-4 text-sm font-medium text-primary-600 hover:text-primary-500">
          Back to login
        </router-link>
      </div>

      <!-- Form -->
      <form v-else class="mt-8 space-y-6" @submit.prevent="handleSubmit">
        <div>
          <label for="email" class="sr-only">Email address</label>
          <input
            id="email"
            v-model="email"
            type="email"
            autocomplete="email"
            required
            class="appearance-none rounded-md relative block w-full px-3 py-2 border border-gray-300 dark:border-dark-border placeholder-gray-500 dark:placeholder-gray-400 text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-secondary focus:outline-none focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
            placeholder="Email address"
          />
        </div>

        <div v-if="error" class="rounded-md bg-red-50 dark:bg-red-900/20 p-4">
          <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
        </div>

        <button
          type="submit"
          :disabled="isSubmitting"
          class="group relative w-full flex justify-center py-2 px-4 border border-transparent text-sm font-medium rounded-md text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {{ isSubmitting ? 'Sending...' : 'Send Reset Link' }}
        </button>

        <p class="text-center text-sm text-gray-600 dark:text-dark-text-secondary">
          <router-link to="/login" class="font-medium text-primary-600 hover:text-primary-500">
            Back to login
          </router-link>
        </p>
      </form>
    </div>
  </div>
</template>
