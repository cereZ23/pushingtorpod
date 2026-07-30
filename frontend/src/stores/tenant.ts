import { defineStore } from "pinia";
import { ref, computed } from "vue";
import type { Tenant } from "@/api/types";
import { tenantApi } from "@/api/tenants";
import { useScanStore } from "./scans";
import { useIssueStore } from "./issues";
import { useGraphStore } from "./graph";

export const useTenantStore = defineStore("tenant", () => {
  const currentTenant = ref<Tenant | null>(null);
  const tenants = ref<Tenant[]>([]);

  const currentTenantId = computed(() => currentTenant.value?.id);

  // Single mutation point for the active tenant: keeps currentTenant and
  // localStorage in sync so a refresh (and the auth store's RBAC computed,
  // which reads this store) always agree on which tenant is active.
  function _applyTenant(tenant: Tenant) {
    currentTenant.value = tenant;
    localStorage.setItem("currentTenantId", String(tenant.id));
  }

  async function fetchTenants() {
    tenants.value = await tenantApi.list();

    // If the current tenant is stale (not in the new list), reset it
    if (
      currentTenant.value &&
      !tenants.value.find((t) => t.id === currentTenant.value!.id)
    ) {
      currentTenant.value = null;
    }

    // Auto-select tenant if none selected (or was just reset)
    if (!currentTenant.value && tenants.value.length > 0) {
      const storedId = localStorage.getItem("currentTenantId");
      const stored = storedId
        ? tenants.value.find((t) => t.id === parseInt(storedId))
        : undefined;
      _applyTenant(stored ?? tenants.value[0]);
    }
  }

  function $reset() {
    currentTenant.value = null;
    tenants.value = [];
  }

  function selectTenant(tenantId: number) {
    const tenant = tenants.value.find((t) => t.id === tenantId);
    if (tenant) {
      _applyTenant(tenant);
      // Clear tenant-scoped data from dependent stores.
      // NOTE: this is a hand-maintained allowlist — any NEW store that caches
      // tenant-scoped data must be reset here too, or it will leak the previous
      // tenant's data after a switch. View-local lists clear themselves in their
      // currentTenantId watcher (clear-before-refetch).
      useScanStore().$reset();
      useIssueStore().$reset();
      useGraphStore().$reset();
    }
  }

  return {
    currentTenant,
    tenants,
    currentTenantId,
    fetchTenants,
    selectTenant,
    $reset,
  };
});
