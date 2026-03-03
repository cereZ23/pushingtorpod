<script setup lang="ts">
import { useRouter } from 'vue-router'

const router = useRouter()
</script>

<template>
  <div class="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-dark-bg-primary px-4">
    <div class="text-center max-w-md">
      <p class="text-6xl font-bold text-primary-600 mb-4">404</p>
      <h1 class="text-2xl font-semibold text-gray-900 dark:text-dark-text-primary mb-2">
        Page not found
      </h1>
      <p class="text-gray-500 dark:text-dark-text-secondary mb-8">
        The page you're looking for doesn't exist or has been moved.
      </p>
      <div class="flex justify-center gap-4">
        <button
          @click="router.back()"
          class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-sm text-gray-700 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
        >
          Go Back
        </button>
        <router-link
          to="/"
          class="px-4 py-2 bg-primary-600 text-white rounded-md text-sm hover:bg-primary-700"
        >
          Dashboard
        </router-link>
      </div>
    </div>
  </div>
</template>
