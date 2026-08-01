<script setup lang="ts">
import { ref, computed, onMounted, watch } from "vue";
import { useTenantStore } from "@/stores/tenant";
import { useAuthStore } from "@/stores/auth";
import { useToastStore } from "@/stores/toast";
import {
  useAuthorizationStore,
  type ScopeEntry,
  type ScanAuthorizationCreate,
} from "@/stores/authorizations";
import AppDialog from "@/components/AppDialog.vue";

const tenantStore = useTenantStore();
const authStore = useAuthStore();
const toast = useToastStore();
const store = useAuthorizationStore();

const tid = computed(() => tenantStore.currentTenantId);
const isSuperuser = computed(() => !!authStore.currentUser?.is_superuser);
const currentTenantName = computed(() => tenantStore.currentTenant?.name ?? "");
function switchTenant(event: Event) {
  const id = parseInt((event.target as HTMLSelectElement).value, 10);
  if (!isNaN(id)) tenantStore.selectTenant(id);
}

const showCreate = ref(false);
const isSaving = ref(false);
const form = ref<ScanAuthorizationCreate>({
  name: "",
  scope_entries: [{ type: "domain", value: "" }],
  authorized_by: "",
  authorization_ref: "",
  valid_from: "",
  valid_until: "",
});

function resetForm() {
  form.value = {
    name: "",
    scope_entries: [{ type: "domain", value: "" }],
    authorized_by: "",
    authorization_ref: "",
    valid_from: "",
    valid_until: "",
  };
}
function addScope() {
  form.value.scope_entries.push({ type: "domain", value: "" });
}
function removeScope(i: number) {
  form.value.scope_entries.splice(i, 1);
}

async function submit() {
  const scopes = form.value.scope_entries.filter((s) => s.value.trim());
  if (!form.value.name.trim() || scopes.length === 0) {
    toast.error("Name and at least one scope entry are required.");
    return;
  }
  isSaving.value = true;
  try {
    await store.createAuthorization({
      name: form.value.name.trim(),
      scope_entries: scopes as ScopeEntry[],
      authorized_by: form.value.authorized_by || undefined,
      authorization_ref: form.value.authorization_ref || undefined,
      valid_from: form.value.valid_from || undefined,
      valid_until: form.value.valid_until || undefined,
    });
    toast.success("Scan authorization created — Tier 3 active DAST is now permitted for this scope.");
    showCreate.value = false;
    resetForm();
  } catch (err: unknown) {
    const e = err as { response?: { data?: { detail?: string } }; message?: string };
    toast.error(e.response?.data?.detail || e.message || "Failed to create authorization");
  } finally {
    isSaving.value = false;
  }
}

async function revoke(id: number, name: string) {
  try {
    await store.revokeAuthorization(id);
    toast.success(`Revoked "${name}" — active DAST no longer permitted by it.`);
  } catch (err: unknown) {
    const e = err as { response?: { data?: { detail?: string } }; message?: string };
    toast.error(e.response?.data?.detail || e.message || "Failed to revoke");
  }
}

function fmt(d: string | null): string {
  return d ? new Date(d).toLocaleDateString() : "";
}
function isExpired(a: { valid_until: string | null }): boolean {
  return !!a.valid_until && Date.parse(a.valid_until) < Date.now();
}

onMounted(() => store.fetchAuthorizations());
watch(tid, () => {
  if (tid.value) store.fetchAuthorizations();
});
</script>

<template>
  <div class="space-y-6">
    <div class="flex justify-between items-center">
      <div>
        <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
          Scan Authorizations
        </h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">
          Legal sign-off that active DAST fuzzing (SQLi / XSS / SSRF payload injection) may run
          against a target. Tier 3 DAST stays off until one exists.
        </p>
      </div>
      <button
        @click="showCreate = true"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 text-sm font-medium"
      >
        New Authorization
      </button>
    </div>

    <!-- Which tenant -->
    <div
      class="flex items-center gap-2 text-sm rounded-md border border-gray-200 dark:border-dark-border bg-gray-50 dark:bg-dark-bg-tertiary px-3 py-2"
    >
      <span class="text-gray-500 dark:text-dark-text-secondary">Authorizations for:</span>
      <span v-if="!isSuperuser" class="font-medium text-gray-900 dark:text-dark-text-primary">{{
        currentTenantName
      }}</span>
      <select
        v-else
        :value="tid"
        @change="switchTenant"
        aria-label="Select tenant"
        class="font-medium text-gray-900 dark:text-dark-text-primary bg-transparent border border-gray-300 dark:border-dark-border rounded-md px-2 py-1 text-sm"
      >
        <option v-for="t in tenantStore.tenants" :key="t.id" :value="t.id">{{ t.name }}</option>
      </select>
    </div>

    <div v-if="store.isLoading" class="text-gray-600 dark:text-dark-text-secondary py-8 text-center">
      Loading...
    </div>

    <div
      v-else-if="store.authorizations.length === 0"
      class="text-center py-10 border border-dashed border-gray-300 dark:border-dark-border rounded-lg"
    >
      <p class="text-sm text-gray-500 dark:text-dark-text-secondary">
        No scan authorizations yet. Active DAST fuzzing stays off for Tier 3 scans until you add one.
      </p>
      <button
        @click="showCreate = true"
        class="mt-4 px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 text-sm font-medium"
      >
        New Authorization
      </button>
    </div>

    <div
      v-else
      class="bg-white dark:bg-dark-bg-secondary shadow rounded-lg overflow-hidden"
    >
      <table class="min-w-full divide-y divide-gray-200 dark:divide-dark-border">
        <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
          <tr>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Name</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Scope</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">
              Authorized
            </th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Valid</th>
            <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase">Status</th>
            <th class="px-6 py-3"></th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-200 dark:divide-dark-border">
          <tr v-for="a in store.authorizations" :key="a.id">
            <td class="px-6 py-4 text-sm font-medium text-gray-900 dark:text-dark-text-primary">
              {{ a.name }}
            </td>
            <td class="px-6 py-4">
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="(s, i) in a.scope_entries.slice(0, 3)"
                  :key="i"
                  class="text-xs px-1.5 py-0.5 rounded bg-gray-100 text-gray-700 dark:bg-gray-700/40 dark:text-gray-300"
                  >{{ s.type }}: {{ s.value }}</span
                >
                <span
                  v-if="a.scope_entries.length > 3"
                  class="text-xs text-gray-500"
                  >+{{ a.scope_entries.length - 3 }}</span
                >
              </div>
            </td>
            <td class="px-6 py-4 text-sm text-gray-700 dark:text-dark-text-secondary">
              <div>{{ a.authorized_by || "—" }}</div>
              <div class="text-xs text-gray-500">{{ a.authorization_ref || "—" }}</div>
            </td>
            <td
              class="px-6 py-4 text-sm"
              :class="isExpired(a) ? 'text-red-600 dark:text-red-400' : 'text-gray-700 dark:text-dark-text-secondary'"
            >
              {{ a.valid_until ? `${fmt(a.valid_from) || "now"} → ${fmt(a.valid_until)}` : "Open-ended" }}
            </td>
            <td class="px-6 py-4">
              <span
                v-if="a.is_active && !isExpired(a)"
                class="text-xs px-2 py-0.5 rounded-full bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                >Active</span
              >
              <span
                v-else
                class="text-xs px-2 py-0.5 rounded-full bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400"
                >{{ a.is_active ? "Expired" : "Revoked" }}</span
              >
            </td>
            <td class="px-6 py-4 text-right">
              <button
                v-if="a.is_active"
                @click="revoke(a.id, a.name)"
                class="text-sm font-medium text-red-600 dark:text-red-400 hover:underline"
              >
                Revoke
              </button>
            </td>
          </tr>
        </tbody>
      </table>
    </div>

    <!-- Create modal -->
    <AppDialog :open="showCreate" title="New Scan Authorization" @close="showCreate = false">
      <div class="space-y-4">
        <div
          class="text-xs rounded-md bg-amber-50 dark:bg-amber-900/20 text-amber-800 dark:text-amber-300 p-3"
        >
          This does not launch a scan. It permits Tier 3 active DAST fuzzing (payload injection)
          against the listed scope on future scans. Only list targets you are contractually
          authorized to actively attack.
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >Name</label
          >
          <input
            v-model="form.name"
            type="text"
            placeholder="e.g. Acme pentest engagement"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md dark:bg-dark-bg-tertiary dark:text-dark-text-primary text-sm"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
            >Authorized scope</label
          >
          <div v-for="(s, i) in form.scope_entries" :key="i" class="flex gap-2 mb-2">
            <select
              v-model="s.type"
              class="px-2 py-2 border border-gray-300 dark:border-dark-border rounded-md dark:bg-dark-bg-tertiary dark:text-dark-text-primary text-sm"
            >
              <option value="domain">domain</option>
              <option value="ip">ip</option>
              <option value="cidr">cidr</option>
            </select>
            <input
              v-model="s.value"
              type="text"
              placeholder="acme.com / 1.2.3.4 / 10.0.0.0/24"
              class="flex-1 px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md dark:bg-dark-bg-tertiary dark:text-dark-text-primary text-sm"
            />
            <button
              v-if="form.scope_entries.length > 1"
              @click="removeScope(i)"
              class="px-2 text-gray-400 hover:text-red-600"
              type="button"
            >
              ✕
            </button>
          </div>
          <button
            @click="addScope"
            type="button"
            class="text-sm text-primary-600 dark:text-primary-400 hover:underline"
          >
            + Add scope entry
          </button>
        </div>

        <div class="grid grid-cols-2 gap-3">
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >Authorized by</label
            >
            <input
              v-model="form.authorized_by"
              type="text"
              placeholder="Name / email"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md dark:bg-dark-bg-tertiary dark:text-dark-text-primary text-sm"
            />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >Reference</label
            >
            <input
              v-model="form.authorization_ref"
              type="text"
              placeholder="Ticket / signed doc"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md dark:bg-dark-bg-tertiary dark:text-dark-text-primary text-sm"
            />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >Valid from</label
            >
            <input
              v-model="form.valid_from"
              type="datetime-local"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md dark:bg-dark-bg-tertiary dark:text-dark-text-primary text-sm"
            />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >Valid until</label
            >
            <input
              v-model="form.valid_until"
              type="datetime-local"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md dark:bg-dark-bg-tertiary dark:text-dark-text-primary text-sm"
            />
          </div>
        </div>

        <div class="flex justify-end gap-2 pt-2">
          <button
            @click="showCreate = false"
            type="button"
            class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-sm"
          >
            Cancel
          </button>
          <button
            @click="submit"
            :disabled="isSaving"
            class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 text-sm font-medium disabled:opacity-50"
          >
            {{ isSaving ? "Creating…" : "Create Authorization" }}
          </button>
        </div>
      </div>
    </AppDialog>
  </div>
</template>
