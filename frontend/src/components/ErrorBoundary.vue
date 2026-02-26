<script setup lang="ts">
import { ref, onErrorCaptured } from 'vue'
import { useRouter } from 'vue-router'

const router = useRouter()

const hasError = ref(false)
const errorMessage = ref('')

onErrorCaptured((err: Error, instance, info: string) => {
  hasError.value = true
  errorMessage.value = err?.message || 'An unexpected error occurred'

  console.error('[ErrorBoundary] Captured error:', {
    error: err,
    component: instance?.$options?.name || instance?.$options?.__name || 'Unknown',
    info,
  })

  // Prevent the error from propagating further
  return false
})

function handleRetry() {
  hasError.value = false
  errorMessage.value = ''
}

function handleGoToDashboard() {
  hasError.value = false
  errorMessage.value = ''
  router.push('/')
}

/**
 * Sanitize error message to avoid leaking sensitive internals.
 * Keeps the message to a reasonable length and strips stack-like content.
 */
function sanitizedMessage(msg: string): string {
  const cleaned = msg.split('\n')[0].trim()
  if (cleaned.length > 200) {
    return cleaned.slice(0, 200) + '...'
  }
  return cleaned || 'An unexpected error occurred'
}
</script>

<template>
  <div v-if="hasError" class="flex items-center justify-center min-h-[400px] px-4">
    <div class="w-full max-w-md rounded-lg border border-red-200 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-6 text-center shadow-sm">
      <!-- Warning Icon -->
      <div class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-red-100 dark:bg-red-900/40">
        <svg
          class="h-6 w-6 text-red-600 dark:text-red-400"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
          aria-hidden="true"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
      </div>

      <!-- Title -->
      <h2 class="mb-2 text-lg font-semibold text-red-800 dark:text-red-300">
        Something went wrong
      </h2>

      <!-- Error Message -->
      <p class="mb-6 text-sm text-red-700 dark:text-red-400">
        {{ sanitizedMessage(errorMessage) }}
      </p>

      <!-- Actions -->
      <div class="flex items-center justify-center gap-3">
        <button
          @click="handleRetry"
          class="inline-flex items-center rounded-md bg-red-600 px-4 py-2 text-sm font-medium text-white shadow-sm hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900 transition-colors"
        >
          Try Again
        </button>

        <button
          @click="handleGoToDashboard"
          class="inline-flex items-center rounded-md border border-red-300 dark:border-red-700 bg-white dark:bg-transparent px-4 py-2 text-sm font-medium text-red-700 dark:text-red-400 shadow-sm hover:bg-red-50 dark:hover:bg-red-900/30 focus:outline-none focus:ring-2 focus:ring-red-500 focus:ring-offset-2 dark:focus:ring-offset-gray-900 transition-colors"
        >
          Go to Dashboard
        </button>
      </div>
    </div>
  </div>

  <slot v-else />
</template>
