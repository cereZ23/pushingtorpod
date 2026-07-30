<script setup lang="ts">
import { computed } from "vue";
import { useAuthStore } from "@/stores/auth";

const authStore = useAuthStore();
const isSuperuser = computed(() => !!authStore.currentUser?.is_superuser);
</script>

<template>
  <div
    class="flex flex-col items-center justify-center text-center px-6 py-16 min-h-[24rem]"
  >
    <div class="max-w-md">
      <div
        class="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-gray-100 dark:bg-dark-bg-tertiary"
      >
        <svg
          class="h-6 w-6 text-gray-400 dark:text-dark-text-secondary"
          fill="none"
          viewBox="0 0 24 24"
          stroke-width="1.5"
          stroke="currentColor"
          aria-hidden="true"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            d="M3.75 21h16.5M4.5 3h15M5.25 3v18m13.5-18v18M9 6.75h1.5m-1.5 3h1.5m-1.5 3h1.5m3-6H15m-1.5 3H15m-1.5 3H15M9 21v-3.375c0-.621.504-1.125 1.125-1.125h3.75c.621 0 1.125.504 1.125 1.125V21"
          />
        </svg>
      </div>
      <h2
        class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
      >
        No workspace available
      </h2>
      <p
        class="mt-2 text-sm text-gray-500 dark:text-dark-text-secondary"
      >
        <template v-if="isSuperuser">
          There are no tenants yet. Create the first organization to start
          discovering and scanning its attack surface.
        </template>
        <template v-else>
          Your account isn't a member of any workspace yet. Ask your
          administrator to add you to a tenant.
        </template>
      </p>
      <router-link
        v-if="isSuperuser"
        to="/admin/onboard-customer"
        class="mt-6 inline-flex items-center px-4 py-2 rounded-md text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-dark-bg-primary"
      >
        + Create tenant
      </router-link>
    </div>
  </div>
</template>
