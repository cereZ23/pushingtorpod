import { defineStore } from "pinia";
import { ref, computed } from "vue";
import apiClient from "@/api/client";
import { useTenantStore } from "./tenant";

export interface ScopeEntry {
  type: "domain" | "ip" | "cidr";
  value: string;
}

export interface ScanAuthorization {
  id: number;
  tenant_id: number;
  name: string;
  scope_entries: ScopeEntry[];
  authorized_by: string | null;
  authorization_ref: string | null;
  valid_from: string | null;
  valid_until: string | null;
  is_active: boolean;
  created_at: string;
}

export interface ScanAuthorizationCreate {
  name: string;
  scope_entries: ScopeEntry[];
  authorized_by?: string;
  authorization_ref?: string;
  valid_from?: string;
  valid_until?: string;
}

/**
 * Scan authorizations gate active DAST fuzzing (Tier 3). `activeAuthorization`
 * mirrors the backend gate exactly: is_active AND within the validity window,
 * so the "DAST ready" badge can't promise something the server won't run.
 */
export const useAuthorizationStore = defineStore("authorizations", () => {
  const tenantStore = useTenantStore();
  const authorizations = ref<ScanAuthorization[]>([]);
  const isLoading = ref(false);
  const error = ref("");

  const activeAuthorization = computed<ScanAuthorization | null>(() => {
    const now = Date.now();
    return (
      authorizations.value.find(
        (a) =>
          a.is_active &&
          (!a.valid_from || Date.parse(a.valid_from) <= now) &&
          (!a.valid_until || Date.parse(a.valid_until) >= now),
      ) ?? null
    );
  });

  async function fetchAuthorizations() {
    const tid = tenantStore.currentTenantId;
    if (!tid) return;
    isLoading.value = true;
    error.value = "";
    try {
      const res = await apiClient.get<ScanAuthorization[]>(
        `/api/v1/tenants/${tid}/scan-authorizations`,
      );
      authorizations.value = res.data;
    } catch (err: unknown) {
      const e = err as { response?: { data?: { detail?: string } }; message?: string };
      error.value = e.response?.data?.detail || e.message || "Failed to load authorizations";
    } finally {
      isLoading.value = false;
    }
  }

  async function createAuthorization(body: ScanAuthorizationCreate) {
    const tid = tenantStore.currentTenantId;
    if (!tid) throw new Error("No tenant selected");
    const res = await apiClient.post(`/api/v1/tenants/${tid}/scan-authorizations`, body);
    await fetchAuthorizations();
    return res.data;
  }

  async function revokeAuthorization(id: number) {
    const tid = tenantStore.currentTenantId;
    if (!tid) return;
    await apiClient.delete(`/api/v1/tenants/${tid}/scan-authorizations/${id}`);
    await fetchAuthorizations();
  }

  function $reset() {
    authorizations.value = [];
    error.value = "";
  }

  return {
    authorizations,
    isLoading,
    error,
    activeAuthorization,
    fetchAuthorizations,
    createAuthorization,
    revokeAuthorization,
    $reset,
  };
});
