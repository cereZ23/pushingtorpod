<script setup lang="ts">
import { ref, onMounted, computed, watch } from "vue";
import { useTenantStore } from "@/stores/tenant";
import { useScanStore } from "@/stores/scans";
import apiClient from "@/api/client";
import type { Project } from "@/stores/scans";

// -- Types --

interface ScanProfile {
  id: number;
  project_id: number;
  name: string;
  scan_tier: number;
  port_scan_mode: string;
  max_rate_pps: number;
  timeout_minutes: number;
  nuclei_tags: string[] | null;
  schedule_cron: string | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

interface ScopeRule {
  id: number;
  project_id: number;
  rule_type: "include" | "exclude";
  match_type: "domain" | "ip" | "cidr" | "regex";
  pattern: string;
  description: string | null;
  created_at: string;
}

// -- State --

const tenantStore = useTenantStore();
const scanStore = useScanStore();
const currentTenantId = computed(() => tenantStore.currentTenantId);

const isLoadingProfiles = ref(false);
const isLoadingScopes = ref(false);
const error = ref("");
const successMessage = ref("");

// Projects & selection
const selectedProjectId = ref<number | null>(null);
const selectedProject = computed(
  () =>
    scanStore.projects.find((p) => p.id === selectedProjectId.value) ?? null,
);

// Profiles
const profiles = ref<ScanProfile[]>([]);
const showCreateProfile = ref(false);
const isSavingProfile = ref(false);

const newProfile = ref({
  name: "",
  scan_tier: 1,
  port_scan_mode: "top-100",
  max_rate_pps: 10,
  timeout_minutes: 120,
  schedule_cron: "",
});

// Scopes
const scopes = ref<ScopeRule[]>([]);
const showAddScope = ref(false);
const isSavingScope = ref(false);

const newScope = ref({
  rule_type: "include" as "include" | "exclude",
  match_type: "domain" as "domain" | "ip" | "cidr" | "regex",
  pattern: "",
  description: "",
});

// Schedule presets
const schedulePresets = [
  { label: "Daily at 2 AM", value: "0 2 * * *" },
  { label: "Weekly (Mon 2 AM)", value: "0 2 * * 1" },
  { label: "Every 12 hours", value: "0 */12 * * *" },
  { label: "Every 6 hours", value: "0 */6 * * *" },
  { label: "Custom", value: "__custom__" },
  { label: "Manual only", value: "" },
];

const selectedPreset = ref("0 2 * * *");
const customCron = ref("");
const isCustomSchedule = computed(() => selectedPreset.value === "__custom__");

function getScheduleCron(): string {
  if (selectedPreset.value === "__custom__") return customCron.value.trim();
  return selectedPreset.value;
}

function getPresetLabel(cron: string | null): string {
  if (!cron) return "Manual only";
  const found = schedulePresets.find((p) => p.value === cron);
  return found ? found.label : cron;
}

// Inline schedule editing
const editingScheduleId = ref<number | null>(null);
const editPreset = ref("");
const editCustomCron = ref("");

function startEditSchedule(profile: ScanProfile) {
  editingScheduleId.value = profile.id;
  const match = schedulePresets.find((p) => p.value === profile.schedule_cron);
  if (match) {
    editPreset.value = match.value;
    editCustomCron.value = "";
  } else if (profile.schedule_cron) {
    editPreset.value = "__custom__";
    editCustomCron.value = profile.schedule_cron;
  } else {
    editPreset.value = "";
    editCustomCron.value = "";
  }
}

async function saveEditSchedule(profile: ScanProfile) {
  const cron =
    editPreset.value === "__custom__"
      ? editCustomCron.value.trim() || null
      : editPreset.value || null;
  await handleUpdateSchedule(profile, cron);
  editingScheduleId.value = null;
}

function cancelEditSchedule() {
  editingScheduleId.value = null;
}

// -- Computed --

const portScanModes = [
  { value: "top-100", label: "Top 100 Ports" },
  { value: "top-1000", label: "Top 1000 Ports" },
  { value: "full", label: "Full (65535)" },
  { value: "custom", label: "Custom" },
];

function getTierBadgeClass(tier: number): string {
  if (tier === 1)
    return "bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400";
  if (tier === 2)
    return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400";
  return "bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400";
}

function getTierLabel(tier: number): string {
  if (tier === 1) return "Safe";
  if (tier === 2) return "Moderate";
  return "Aggressive";
}

// -- API --

async function fetchProfiles(): Promise<void> {
  if (!currentTenantId.value || !selectedProjectId.value) return;
  isLoadingProfiles.value = true;
  error.value = "";

  try {
    const response = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/projects/${selectedProjectId.value}/profiles`,
    );
    const data = response.data;
    profiles.value = Array.isArray(data) ? data : (data.items ?? []);
  } catch (err: unknown) {
    if (isNotFoundError(err)) {
      profiles.value = [];
    } else {
      const message =
        err instanceof Error ? err.message : "Failed to load profiles";
      error.value = message;
    }
  } finally {
    isLoadingProfiles.value = false;
  }
}

async function fetchScopes(): Promise<void> {
  if (!currentTenantId.value || !selectedProjectId.value) return;
  isLoadingScopes.value = true;

  try {
    const response = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/projects/${selectedProjectId.value}/scopes`,
    );
    const data = response.data;
    scopes.value = Array.isArray(data) ? data : (data.items ?? []);
  } catch (err: unknown) {
    if (isNotFoundError(err)) {
      scopes.value = [];
    } else {
      const message =
        err instanceof Error ? err.message : "Failed to load scopes";
      error.value = message;
    }
  } finally {
    isLoadingScopes.value = false;
  }
}

async function handleCreateProfile(): Promise<void> {
  if (!currentTenantId.value || !selectedProjectId.value) return;
  if (!newProfile.value.name.trim()) return;

  isSavingProfile.value = true;
  error.value = "";

  try {
    const payload = {
      ...newProfile.value,
      schedule_cron: getScheduleCron() || null,
    };
    const response = await apiClient.post(
      `/api/v1/tenants/${currentTenantId.value}/projects/${selectedProjectId.value}/profiles`,
      payload,
    );
    profiles.value.push(response.data);
    showCreateProfile.value = false;
    resetProfileForm();
    showSuccess("Profile created successfully");
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to create profile";
    error.value = message;
  } finally {
    isSavingProfile.value = false;
  }
}

async function handleDeleteProfile(profile: ScanProfile): Promise<void> {
  if (!currentTenantId.value || !selectedProjectId.value) return;
  if (!confirm(`Delete profile "${profile.name}"?`)) return;

  try {
    await apiClient.delete(
      `/api/v1/tenants/${currentTenantId.value}/projects/${selectedProjectId.value}/profiles/${profile.id}`,
    );
    profiles.value = profiles.value.filter((p) => p.id !== profile.id);
    showSuccess("Profile deleted");
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to delete profile";
    error.value = message;
  }
}

async function handleUpdateSchedule(
  profile: ScanProfile,
  cron: string | null,
): Promise<void> {
  if (!currentTenantId.value || !selectedProjectId.value) return;

  try {
    await apiClient.patch(
      `/api/v1/tenants/${currentTenantId.value}/projects/${selectedProjectId.value}/profiles/${profile.id}/schedule`,
      { schedule_cron: cron },
    );
    profile.schedule_cron = cron;
    showSuccess("Schedule updated");
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to update schedule";
    error.value = message;
  }
}

async function handleAddScope(): Promise<void> {
  if (!currentTenantId.value || !selectedProjectId.value) return;
  if (!newScope.value.pattern.trim()) return;

  isSavingScope.value = true;
  error.value = "";

  try {
    const payload = {
      ...newScope.value,
      description: newScope.value.description.trim() || null,
    };
    const response = await apiClient.post(
      `/api/v1/tenants/${currentTenantId.value}/projects/${selectedProjectId.value}/scopes`,
      payload,
    );
    scopes.value.push(response.data);
    showAddScope.value = false;
    resetScopeForm();
    showSuccess("Scope rule added");
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to add scope rule";
    error.value = message;
  } finally {
    isSavingScope.value = false;
  }
}

async function handleRemoveScope(scope: ScopeRule): Promise<void> {
  if (!currentTenantId.value || !selectedProjectId.value) return;

  try {
    await apiClient.delete(
      `/api/v1/tenants/${currentTenantId.value}/projects/${selectedProjectId.value}/scopes/${scope.id}`,
    );
    scopes.value = scopes.value.filter((s) => s.id !== scope.id);
    showSuccess("Scope rule removed");
  } catch (err: unknown) {
    if (!isNotFoundError(err)) {
      const message =
        err instanceof Error ? err.message : "Failed to remove scope rule";
      error.value = message;
    }
  }
}

// -- Helpers --

function isNotFoundError(err: unknown): boolean {
  if (err && typeof err === "object" && "response" in err) {
    const axiosErr = err as { response?: { status?: number } };
    return axiosErr.response?.status === 404;
  }
  return false;
}

function resetProfileForm(): void {
  newProfile.value = {
    name: "",
    scan_tier: 1,
    port_scan_mode: "top-100",
    max_rate_pps: 10,
    timeout_minutes: 120,
    schedule_cron: "",
  };
  selectedPreset.value = "0 2 * * *";
  customCron.value = "";
}

function resetScopeForm(): void {
  newScope.value = {
    rule_type: "include",
    match_type: "domain",
    pattern: "",
    description: "",
  };
}

function showSuccess(msg: string): void {
  successMessage.value = msg;
  setTimeout(() => {
    successMessage.value = "";
  }, 3000);
}

function selectProject(project: Project): void {
  selectedProjectId.value = project.id;
}

// -- Watchers --

watch(selectedProjectId, async () => {
  if (selectedProjectId.value) {
    await Promise.all([fetchProfiles(), fetchScopes()]);
  }
});

watch(currentTenantId, async () => {
  if (currentTenantId.value) {
    await scanStore.fetchProjects();
    if (scanStore.projects.length > 0) {
      selectedProjectId.value = scanStore.projects[0].id;
    }
  }
});

// -- Lifecycle --

onMounted(async () => {
  await scanStore.fetchProjects();
  if (scanStore.projects.length > 0) {
    selectedProjectId.value = scanStore.projects[0].id;
  }
});
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <div>
        <h2
          class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary"
        >
          Scan Policies
        </h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">
          Configure scan profiles, scheduling, and scope rules
        </p>
      </div>
    </div>

    <!-- Success Message -->
    <div
      v-if="successMessage"
      class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-3 rounded-md flex items-center gap-2"
    >
      <svg
        class="w-5 h-5 text-green-600 dark:text-green-400"
        fill="none"
        stroke="currentColor"
        viewBox="0 0 24 24"
      >
        <path
          stroke-linecap="round"
          stroke-linejoin="round"
          stroke-width="2"
          d="M5 13l4 4L19 7"
        />
      </svg>
      <p class="text-green-800 dark:text-green-200 text-sm">
        {{ successMessage }}
      </p>
    </div>

    <!-- Error Banner -->
    <div
      v-if="error"
      class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md flex items-center justify-between"
    >
      <p class="text-red-800 dark:text-red-200">{{ error }}</p>
      <button
        @click="error = ''"
        class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 text-sm"
      >
        Dismiss
      </button>
    </div>

    <!-- Main Layout -->
    <div class="flex gap-6">
      <!-- Project Selector Sidebar -->
      <div class="w-[260px] shrink-0">
        <div
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
        >
          <div
            class="px-4 py-3 border-b border-gray-200 dark:border-dark-border"
          >
            <h3
              class="text-sm font-semibold text-gray-700 dark:text-dark-text-secondary uppercase tracking-wider"
            >
              Projects
            </h3>
          </div>

          <div
            v-if="scanStore.isLoadingProjects"
            class="p-4 text-center text-gray-500 dark:text-dark-text-secondary text-sm"
          >
            Loading projects...
          </div>

          <div
            v-else-if="scanStore.projects.length === 0"
            class="p-6 text-center"
          >
            <p class="text-gray-500 dark:text-dark-text-secondary text-sm">
              No projects found
            </p>
            <p class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-1">
              Create a project in Scan Management first
            </p>
          </div>

          <ul v-else class="divide-y divide-gray-200 dark:divide-dark-border">
            <li
              v-for="project in scanStore.projects"
              :key="project.id"
              @click="selectProject(project)"
              :class="[
                'px-4 py-3 cursor-pointer transition-colors',
                selectedProjectId === project.id
                  ? 'bg-primary-50 dark:bg-primary-900/20 border-l-4 border-primary-500'
                  : 'hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary border-l-4 border-transparent',
              ]"
            >
              <div
                class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
              >
                {{ project.name }}
              </div>
              <div
                v-if="project.description"
                class="text-xs text-gray-500 dark:text-dark-text-secondary mt-1 truncate"
              >
                {{ project.description }}
              </div>
            </li>
          </ul>
        </div>
      </div>

      <!-- Content Panel -->
      <div class="flex-1 min-w-0 space-y-6">
        <!-- No project selected -->
        <div
          v-if="!selectedProject"
          class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-12 text-center"
        >
          <svg
            class="mx-auto h-12 w-12 text-gray-400 dark:text-dark-text-tertiary"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"
            />
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"
            />
          </svg>
          <p class="mt-4 text-gray-500 dark:text-dark-text-secondary">
            Select a project to configure scan policies
          </p>
        </div>

        <template v-else>
          <!-- Active Scan Profiles -->
          <div
            class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
          >
            <div
              class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center"
            >
              <h3
                class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
              >
                Scan Profiles
              </h3>
              <button
                @click="showCreateProfile = true"
                class="px-3 py-1.5 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm"
              >
                Create Profile
              </button>
            </div>

            <div
              v-if="isLoadingProfiles"
              class="p-6 text-center text-gray-500 dark:text-dark-text-secondary"
            >
              Loading profiles...
            </div>

            <div v-else-if="profiles.length === 0" class="p-6 text-center">
              <p class="text-gray-500 dark:text-dark-text-secondary text-sm">
                No scan profiles configured
              </p>
              <button
                @click="showCreateProfile = true"
                class="mt-2 text-primary-600 dark:text-primary-400 text-sm hover:text-primary-700 dark:hover:text-primary-300"
              >
                Create your first profile
              </button>
            </div>

            <div v-else class="overflow-x-auto">
              <table
                class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
              >
                <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
                  <tr>
                    <th
                      class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Name
                    </th>
                    <th
                      class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Tier
                    </th>
                    <th
                      class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Ports
                    </th>
                    <th
                      class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Rate
                    </th>
                    <th
                      class="px-3 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Schedule
                    </th>
                    <th
                      class="px-3 py-3 text-right text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody
                  class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border"
                >
                  <tr
                    v-for="profile in profiles"
                    :key="profile.id"
                    class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
                  >
                    <td class="px-3 py-3 whitespace-nowrap">
                      <div
                        class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
                      >
                        {{ profile.name }}
                      </div>
                    </td>
                    <td class="px-3 py-3 whitespace-nowrap">
                      <span
                        class="px-2 py-0.5 text-xs font-semibold rounded-full"
                        :class="getTierBadgeClass(profile.scan_tier)"
                      >
                        T{{ profile.scan_tier }}
                        {{ getTierLabel(profile.scan_tier) }}
                      </span>
                    </td>
                    <td
                      class="px-3 py-3 whitespace-nowrap text-sm text-gray-600 dark:text-dark-text-secondary"
                    >
                      {{ profile.port_scan_mode }}
                    </td>
                    <td
                      class="px-3 py-3 whitespace-nowrap text-sm text-gray-600 dark:text-dark-text-secondary"
                    >
                      {{ profile.max_rate_pps }} req/s
                    </td>
                    <td class="px-3 py-3">
                      <template v-if="editingScheduleId === profile.id">
                        <div class="flex items-center gap-2">
                          <select
                            v-model="editPreset"
                            class="px-2 py-1 border border-gray-300 dark:border-dark-border rounded text-sm text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:ring-1 focus:ring-primary-500"
                          >
                            <option
                              v-for="preset in schedulePresets"
                              :key="preset.value"
                              :value="preset.value"
                            >
                              {{ preset.label }}
                            </option>
                          </select>
                          <input
                            v-if="editPreset === '__custom__'"
                            v-model="editCustomCron"
                            type="text"
                            placeholder="cron"
                            class="w-32 px-2 py-1 border border-gray-300 dark:border-dark-border rounded text-sm font-mono text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary"
                          />
                          <button
                            @click="saveEditSchedule(profile)"
                            class="text-primary-600 dark:text-primary-400 hover:text-primary-700 text-sm"
                          >
                            Save
                          </button>
                          <button
                            @click="cancelEditSchedule"
                            class="text-gray-500 dark:text-dark-text-tertiary hover:text-gray-700 text-sm"
                          >
                            Cancel
                          </button>
                        </div>
                      </template>
                      <template v-else>
                        <span
                          class="text-sm text-gray-700 dark:text-dark-text-secondary"
                        >
                          {{ getPresetLabel(profile.schedule_cron) }}
                        </span>
                        <span
                          v-if="
                            profile.schedule_cron &&
                            !schedulePresets.find(
                              (p) => p.value === profile.schedule_cron,
                            )
                          "
                          class="ml-1 text-xs font-mono text-gray-500 dark:text-dark-text-tertiary"
                        >
                          ({{ profile.schedule_cron }})
                        </span>
                      </template>
                    </td>
                    <td
                      class="px-3 py-3 whitespace-nowrap text-sm text-right space-x-2"
                    >
                      <button
                        @click="startEditSchedule(profile)"
                        class="text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300"
                      >
                        Schedule
                      </button>
                      <button
                        @click="handleDeleteProfile(profile)"
                        class="text-red-500 dark:text-red-400 hover:text-red-700 dark:hover:text-red-300"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <!-- Scope Rules -->
          <div
            class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
          >
            <div
              class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center"
            >
              <h3
                class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
              >
                Scope Rules
              </h3>
              <button
                @click="showAddScope = true"
                class="px-3 py-1.5 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors text-sm"
              >
                Add Rule
              </button>
            </div>

            <div
              v-if="isLoadingScopes"
              class="p-6 text-center text-gray-500 dark:text-dark-text-secondary"
            >
              Loading scope rules...
            </div>

            <div v-else-if="scopes.length === 0" class="p-6 text-center">
              <p class="text-gray-500 dark:text-dark-text-secondary text-sm">
                No scope rules defined. All discovered assets will be in scope.
              </p>
            </div>

            <div
              v-else
              class="divide-y divide-gray-200 dark:divide-dark-border"
            >
              <div
                v-for="scope in scopes"
                :key="scope.id"
                class="px-6 py-3 flex items-center justify-between hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <div class="flex items-center gap-3">
                  <span
                    class="px-2 py-0.5 text-xs font-semibold rounded-full"
                    :class="
                      scope.rule_type === 'include'
                        ? 'bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400'
                        : 'bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400'
                    "
                  >
                    {{ scope.rule_type }}
                  </span>
                  <span
                    class="px-1.5 py-0.5 text-xs font-medium rounded bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary"
                    >{{ scope.match_type }}</span
                  >
                  <span
                    class="text-sm font-mono text-gray-900 dark:text-dark-text-primary"
                    >{{ scope.pattern }}</span
                  >
                  <span
                    v-if="scope.description"
                    class="text-xs text-gray-500 dark:text-dark-text-tertiary"
                  >
                    -- {{ scope.description }}
                  </span>
                </div>
                <button
                  @click="handleRemoveScope(scope)"
                  class="text-red-500 hover:text-red-700 dark:text-red-400 dark:hover:text-red-300 p-1"
                  title="Remove rule"
                >
                  <svg
                    class="w-4 h-4"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                    />
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </template>
      </div>
    </div>

    <!-- Create Profile Dialog -->
    <Teleport to="body">
      <div
        v-if="showCreateProfile"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div
          class="absolute inset-0 bg-black/50"
          @click="showCreateProfile = false"
        />
        <div
          class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-lg mx-4 border border-gray-200 dark:border-dark-border"
        >
          <div
            class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center"
          >
            <h3
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Create Scan Profile
            </h3>
            <button
              @click="showCreateProfile = false"
              class="text-gray-400 hover:text-gray-500"
            >
              <svg
                class="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>

          <form @submit.prevent="handleCreateProfile" class="p-6 space-y-4">
            <!-- Name -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
                >Profile Name</label
              >
              <input
                v-model="newProfile.name"
                type="text"
                required
                placeholder="e.g. Daily Quick Scan"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <!-- Tier -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
                >Scan Tier</label
              >
              <div class="grid grid-cols-3 gap-3">
                <label
                  v-for="tier in [1, 2, 3]"
                  :key="tier"
                  class="relative flex flex-col items-center p-3 rounded-lg border-2 cursor-pointer transition-all"
                  :class="
                    newProfile.scan_tier === tier
                      ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20'
                      : 'border-gray-200 dark:border-dark-border hover:border-gray-300 dark:hover:border-gray-600'
                  "
                >
                  <input
                    v-model="newProfile.scan_tier"
                    :value="tier"
                    type="radio"
                    name="tier"
                    class="sr-only"
                  />
                  <span
                    class="px-2 py-0.5 text-xs font-bold rounded-full mb-1"
                    :class="getTierBadgeClass(tier)"
                  >
                    Tier {{ tier }}
                  </span>
                  <span
                    class="text-xs text-gray-600 dark:text-dark-text-secondary"
                    >{{ getTierLabel(tier) }}</span
                  >
                </label>
              </div>
            </div>

            <!-- Port Scan Mode -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
                >Port Scan Mode</label
              >
              <select
                v-model="newProfile.port_scan_mode"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <option
                  v-for="mode in portScanModes"
                  :key="mode.value"
                  :value="mode.value"
                >
                  {{ mode.label }}
                </option>
              </select>
            </div>

            <!-- Max Rate -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Max Rate (req/s):
                <span
                  class="font-bold text-primary-600 dark:text-primary-400"
                  >{{ newProfile.max_rate_pps }}</span
                >
              </label>
              <input
                v-model.number="newProfile.max_rate_pps"
                type="range"
                min="1"
                max="300"
                step="1"
                class="w-full h-2 bg-gray-200 dark:bg-dark-bg-tertiary rounded-lg appearance-none cursor-pointer accent-primary-600"
              />
              <div
                class="flex justify-between text-xs text-gray-500 dark:text-dark-text-tertiary mt-1"
              >
                <span>1</span>
                <span>150</span>
                <span>300</span>
              </div>
            </div>

            <!-- Timeout -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
                >Timeout (minutes)</label
              >
              <input
                v-model.number="newProfile.timeout_minutes"
                type="number"
                min="5"
                max="480"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <!-- Schedule Preset Picker -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
                >Schedule</label
              >
              <div class="grid grid-cols-2 gap-2">
                <label
                  v-for="preset in schedulePresets"
                  :key="preset.value"
                  class="flex items-center gap-2 px-3 py-2 rounded-md border cursor-pointer transition-all text-sm"
                  :class="
                    selectedPreset === preset.value
                      ? 'border-primary-500 bg-primary-50 dark:bg-primary-900/20 text-primary-700 dark:text-primary-300'
                      : 'border-gray-200 dark:border-dark-border text-gray-700 dark:text-dark-text-secondary hover:border-gray-300 dark:hover:border-gray-600'
                  "
                >
                  <input
                    v-model="selectedPreset"
                    :value="preset.value"
                    type="radio"
                    name="schedule-preset"
                    class="sr-only"
                  />
                  {{ preset.label }}
                </label>
              </div>
              <div v-if="isCustomSchedule" class="mt-2">
                <input
                  v-model="customCron"
                  type="text"
                  placeholder="e.g. 0 3 * * 1,4 (Mon & Thu at 3 AM)"
                  class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 text-sm"
                />
                <p
                  class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-1"
                >
                  Standard 5-field cron expression
                </p>
              </div>
            </div>

            <!-- Actions -->
            <div class="flex justify-end gap-3 pt-2">
              <button
                type="button"
                @click="showCreateProfile = false"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="isSavingProfile || !newProfile.name.trim()"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ isSavingProfile ? "Creating..." : "Create Profile" }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <!-- Add Scope Dialog -->
    <Teleport to="body">
      <div
        v-if="showAddScope"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div
          class="absolute inset-0 bg-black/50"
          @click="showAddScope = false"
        />
        <div
          class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-md mx-4 border border-gray-200 dark:border-dark-border"
        >
          <div
            class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center"
          >
            <h3
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Add Scope Rule
            </h3>
            <button
              @click="showAddScope = false"
              class="text-gray-400 hover:text-gray-500"
            >
              <svg
                class="w-5 h-5"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </button>
          </div>

          <form @submit.prevent="handleAddScope" class="p-6 space-y-4">
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
                >Rule Type</label
              >
              <div class="flex gap-4">
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    v-model="newScope.rule_type"
                    type="radio"
                    value="include"
                    class="text-primary-600 focus:ring-primary-500"
                  />
                  <span
                    class="text-sm text-gray-700 dark:text-dark-text-secondary"
                    >Include</span
                  >
                </label>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input
                    v-model="newScope.rule_type"
                    type="radio"
                    value="exclude"
                    class="text-primary-600 focus:ring-primary-500"
                  />
                  <span
                    class="text-sm text-gray-700 dark:text-dark-text-secondary"
                    >Exclude</span
                  >
                </label>
              </div>
            </div>

            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
                >Match Type</label
              >
              <select
                v-model="newScope.match_type"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              >
                <option value="domain">Domain</option>
                <option value="ip">IP Address</option>
                <option value="cidr">CIDR Range</option>
                <option value="regex">Regex</option>
              </select>
            </div>

            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
                >Pattern</label
              >
              <input
                v-model="newScope.pattern"
                type="text"
                required
                placeholder="e.g. *.example.com or 10.0.0.0/24"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Description <span class="text-gray-400">(optional)</span>
              </label>
              <input
                v-model="newScope.description"
                type="text"
                placeholder="Reason for this rule"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div class="flex justify-end gap-3 pt-2">
              <button
                type="button"
                @click="showAddScope = false"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="isSavingScope || !newScope.pattern.trim()"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ isSavingScope ? "Adding..." : "Add Rule" }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>
  </div>
</template>
