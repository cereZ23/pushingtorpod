<script setup lang="ts">
import { ref, onMounted } from "vue";
import { useRouter } from "vue-router";
import apiClient from "@/api/client";
import { useTenantStore } from "@/stores/tenant";
import { useToastStore } from "@/stores/toast";

interface TenantOverview {
  id: number;
  name: string;
  slug: string;
  is_active: boolean;
  owner_email: string | null;
  user_count: number;
  asset_count: number;
}

const router = useRouter();
const tenantStore = useTenantStore();
const toast = useToastStore();

const tenants = ref<TenantOverview[]>([]);
const isLoading = ref(true);
const error = ref("");

async function loadTenants() {
  isLoading.value = true;
  error.value = "";
  try {
    const res = await apiClient.get<TenantOverview[]>(
      "/api/v1/tenants/overview",
    );
    tenants.value = res.data;
  } catch (err: unknown) {
    const axiosErr = err as {
      response?: { data?: { detail?: string } };
      message?: string;
    };
    error.value =
      axiosErr.response?.data?.detail ||
      axiosErr.message ||
      "Failed to load tenants";
  } finally {
    isLoading.value = false;
  }
}

// Switch into the tenant and open its user management.
function manageUsers(t: TenantOverview) {
  tenantStore.selectTenant(t.id);
  toast.success(`Managing ${t.name}`);
  router.push("/settings/users");
}

onMounted(loadTenants);
</script>

<template>
  <div>
    <div class="mb-6 flex items-start justify-between">
      <div>
        <h1
          class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary"
        >
          Tenants
        </h1>
        <p
          class="mt-1 text-sm text-gray-500 dark:text-dark-text-secondary"
        >
          All customer workspaces. Open one to manage its users, or create a new
          one.
        </p>
      </div>
      <router-link
        to="/admin/onboard-customer"
        class="inline-flex items-center px-4 py-2 rounded-md text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:ring-offset-2 dark:focus:ring-offset-dark-bg-primary"
      >
        + New tenant
      </router-link>
    </div>

    <div
      v-if="isLoading"
      role="status"
      class="flex items-center justify-center h-48 text-gray-600 dark:text-dark-text-secondary"
    >
      Loading...
    </div>

    <div
      v-else-if="error"
      class="rounded-md bg-red-50 dark:bg-red-900/20 p-4 text-sm text-red-800 dark:text-red-200"
    >
      {{ error }}
    </div>

    <div
      v-else
      class="bg-white dark:bg-dark-bg-secondary shadow rounded-lg overflow-hidden"
    >
      <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
        <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
          <tr>
            <th
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Tenant
            </th>
            <th
              class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Owner
            </th>
            <th
              class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Users
            </th>
            <th
              class="px-6 py-3 text-right text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Assets
            </th>
            <th class="px-6 py-3"></th>
          </tr>
        </thead>
        <tbody
          class="divide-y divide-gray-200 dark:divide-dark-border"
        >
          <tr v-if="tenants.length === 0">
            <td
              colspan="5"
              class="px-6 py-8 text-center text-sm text-gray-500 dark:text-dark-text-secondary"
            >
              No tenants yet.
            </td>
          </tr>
          <tr
            v-for="t in tenants"
            :key="t.id"
            class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
          >
            <td class="px-6 py-4 whitespace-nowrap">
              <div
                class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
              >
                {{ t.name }}
                <span
                  v-if="!t.is_active"
                  class="ml-2 text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400"
                  >inactive</span
                >
              </div>
              <div class="text-xs text-gray-500 dark:text-dark-text-secondary">
                {{ t.slug }}
              </div>
            </td>
            <td
              class="px-6 py-4 whitespace-nowrap text-sm text-gray-700 dark:text-dark-text-secondary"
            >
              {{ t.owner_email || "—" }}
            </td>
            <td
              class="px-6 py-4 whitespace-nowrap text-right text-sm text-gray-700 dark:text-dark-text-secondary"
            >
              {{ t.user_count }}
            </td>
            <td
              class="px-6 py-4 whitespace-nowrap text-right text-sm text-gray-700 dark:text-dark-text-secondary"
            >
              {{ t.asset_count }}
            </td>
            <td class="px-6 py-4 whitespace-nowrap text-right">
              <button
                type="button"
                class="text-sm font-medium text-primary-600 dark:text-primary-400 hover:underline"
                @click="manageUsers(t)"
              >
                Manage
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  </div>
</template>
