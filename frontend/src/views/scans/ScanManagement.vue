<script setup lang="ts">
import { ref, onMounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { useTenantStore } from "@/stores/tenant";
import { useScanStore } from "@/stores/scans";
import { SCAN_TIERS } from "@/stores/scans";
import type {
  Project,
  ScanRun,
  ProjectSeed,
  ScanRunStatus,
} from "@/stores/scans";
import { formatDate } from "@/utils/formatters";

const router = useRouter();
const tenantStore = useTenantStore();
const scanStore = useScanStore();

const currentTenantId = computed(() => tenantStore.currentTenantId);

// Create project dialog
const showCreateDialog = ref(false);
const newProjectName = ref("");
const newProjectDescription = ref("");
const newProjectSeeds = ref<ProjectSeed[]>([{ type: "domain", value: "" }]);
const isCreating = ref(false);

// Trigger scan dialog
const showTierDialog = ref(false);
const isTriggering = ref(false);

// Edit project dialog
const showEditDialog = ref(false);
const editProjectName = ref("");
const editProjectDescription = ref("");
const editProjectSeeds = ref<ProjectSeed[]>([{ type: "domain", value: "" }]);
const isUpdating = ref(false);

// Delete scan dialog
const showDeleteDialog = ref(false);
const scanToDelete = ref<ScanRun | null>(null);
const isDeleting = ref(false);

onMounted(async () => {
  await scanStore.fetchProjects();
  if (scanStore.projects.length > 0 && !scanStore.selectedProject) {
    selectProject(scanStore.projects[0]);
  }
});

watch(currentTenantId, async () => {
  if (currentTenantId.value) {
    await scanStore.fetchProjects();
    if (scanStore.projects.length > 0) {
      selectProject(scanStore.projects[0]);
    }
  }
});

async function selectProject(project: Project): Promise<void> {
  scanStore.selectProject(project);
  await scanStore.fetchScanRuns(project.id);
}

function openCreateDialog(): void {
  newProjectName.value = "";
  newProjectDescription.value = "";
  newProjectSeeds.value = [{ type: "domain", value: "" }];
  showCreateDialog.value = true;
}

function closeCreateDialog(): void {
  showCreateDialog.value = false;
}

function addSeedRow(): void {
  newProjectSeeds.value.push({ type: "domain", value: "" });
}

function removeSeedRow(index: number): void {
  if (newProjectSeeds.value.length > 1) {
    newProjectSeeds.value.splice(index, 1);
  }
}

async function handleCreateProject(): Promise<void> {
  if (!newProjectName.value.trim()) return;

  isCreating.value = true;
  const seeds = newProjectSeeds.value.filter((s) => s.value.trim() !== "");

  const project = await scanStore.createProject({
    name: newProjectName.value.trim(),
    description: newProjectDescription.value.trim(),
    seeds,
  });

  isCreating.value = false;

  if (project) {
    closeCreateDialog();
    selectProject(project);
  }
}

function openTierDialog(): void {
  showTierDialog.value = true;
}

function closeTierDialog(): void {
  showTierDialog.value = false;
}

async function handleTriggerScan(tier: number): Promise<void> {
  if (!scanStore.selectedProject) return;
  isTriggering.value = true;
  closeTierDialog();
  const run = await scanStore.triggerScan(scanStore.selectedProject.id, tier);
  isTriggering.value = false;
  if (run) {
    router.push({ name: "ScanDetail", params: { runId: run.id } });
  }
}

function viewScanDetail(run: ScanRun): void {
  router.push({ name: "ScanDetail", params: { runId: run.id } });
}

function canDelete(run: ScanRun): boolean {
  return (
    run.status === "completed" ||
    run.status === "failed" ||
    run.status === "cancelled"
  );
}

function confirmDelete(run: ScanRun): void {
  scanToDelete.value = run;
  showDeleteDialog.value = true;
}

async function handleDeleteScan(): Promise<void> {
  if (!scanToDelete.value) return;
  isDeleting.value = true;
  const success = await scanStore.deleteScanRun(scanToDelete.value.id);
  isDeleting.value = false;
  if (success) {
    showDeleteDialog.value = false;
    scanToDelete.value = null;
  }
}

function getStatusBadgeClass(status: ScanRunStatus): string {
  const classes: Record<ScanRunStatus, string> = {
    pending: "bg-gray-100 text-gray-800 dark:bg-gray-700/30 dark:text-gray-300",
    running: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
    completed:
      "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400",
    failed: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
    cancelled:
      "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
  };
  return classes[status] || classes.pending;
}

function getTierBadgeClass(tier: number): string {
  if (tier === 1)
    return "bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400";
  if (tier === 2)
    return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400";
  return "bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400";
}

function getTierIconClass(tier: number): string {
  if (tier === 1) return "text-green-500";
  if (tier === 2) return "text-yellow-500";
  return "text-red-500";
}

function openEditDialog(): void {
  if (!scanStore.selectedProject) return;
  editProjectName.value = scanStore.selectedProject.name;
  editProjectDescription.value = scanStore.selectedProject.description || "";
  editProjectSeeds.value = scanStore.selectedProject.seeds?.length
    ? scanStore.selectedProject.seeds.map((s) => ({ ...s }))
    : [{ type: "domain", value: "" }];
  showEditDialog.value = true;
}

function closeEditDialog(): void {
  showEditDialog.value = false;
}

function addEditSeedRow(): void {
  editProjectSeeds.value.push({ type: "domain", value: "" });
}

function removeEditSeedRow(index: number): void {
  if (editProjectSeeds.value.length > 1) {
    editProjectSeeds.value.splice(index, 1);
  }
}

async function handleUpdateProject(): Promise<void> {
  if (!scanStore.selectedProject || !editProjectName.value.trim()) return;

  isUpdating.value = true;
  const seeds = editProjectSeeds.value.filter((s) => s.value.trim() !== "");

  await scanStore.updateProject(scanStore.selectedProject.id, {
    name: editProjectName.value.trim(),
    description: editProjectDescription.value.trim(),
    seeds,
  });

  isUpdating.value = false;
  closeEditDialog();
}

function formatDuration(run: ScanRun): string {
  if (!run.started_at) return "-";
  const start = new Date(run.started_at).getTime();
  const end = run.completed_at
    ? new Date(run.completed_at).getTime()
    : Date.now();
  const seconds = Math.floor((end - start) / 1000);

  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${minutes}m`;
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
        Scan Management
      </h2>
      <button
        @click="openCreateDialog"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 transition-colors"
      >
        New Project
      </button>
    </div>

    <!-- Error Banner -->
    <div
      v-if="scanStore.error"
      role="alert"
      class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md flex items-center justify-between"
    >
      <p class="text-red-800 dark:text-red-200">{{ scanStore.error }}</p>
      <button
        @click="scanStore.clearError"
        class="text-red-600 dark:text-red-400 hover:text-red-800 dark:hover:text-red-300 text-sm"
      >
        Dismiss
      </button>
    </div>

    <!-- Main Layout -->
    <div class="flex gap-6">
      <!-- Project List Sidebar -->
      <div class="w-[300px] shrink-0">
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

          <!-- Loading state -->
          <div
            v-if="scanStore.isLoadingProjects"
            role="status"
            class="p-4 text-center text-gray-500 dark:text-dark-text-secondary"
          >
            Loading projects...
          </div>

          <!-- Empty state -->
          <div
            v-else-if="scanStore.projects.length === 0"
            class="p-6 text-center"
          >
            <p class="text-gray-500 dark:text-dark-text-secondary text-sm">
              No projects yet
            </p>
            <button
              @click="openCreateDialog"
              class="mt-2 text-primary-600 dark:text-primary-400 text-sm hover:text-primary-700 dark:hover:text-primary-300"
            >
              Create your first project
            </button>
          </div>

          <!-- Project list -->
          <ul v-else class="divide-y divide-gray-200 dark:divide-dark-border">
            <li
              v-for="project in scanStore.projects"
              :key="project.id"
              @click="selectProject(project)"
              :class="[
                'px-4 py-3 cursor-pointer transition-colors',
                scanStore.selectedProject?.id === project.id
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
              <div
                class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-1"
              >
                {{ project.seeds?.length || 0 }} seeds
              </div>
            </li>
          </ul>
        </div>
      </div>

      <!-- Scan Runs Panel -->
      <div class="flex-1 min-w-0">
        <div
          v-if="!scanStore.selectedProject"
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
              d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2"
            />
          </svg>
          <p class="mt-4 text-gray-500 dark:text-dark-text-secondary">
            Select a project to view scan runs
          </p>
        </div>

        <div v-else class="space-y-4">
          <!-- Project Header -->
          <div
            class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border p-4"
          >
            <div class="flex justify-between items-start">
              <div>
                <h3
                  class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
                >
                  {{ scanStore.selectedProject.name }}
                </h3>
                <p
                  v-if="scanStore.selectedProject.description"
                  class="text-sm text-gray-500 dark:text-dark-text-secondary mt-1"
                >
                  {{ scanStore.selectedProject.description }}
                </p>
                <div class="flex gap-2 mt-2">
                  <span
                    v-for="seed in scanStore.selectedProject.seeds || []"
                    :key="seed.value"
                    class="inline-flex items-center px-2 py-0.5 text-xs font-medium rounded bg-gray-100 text-gray-700 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary"
                  >
                    {{ seed.type }}: {{ seed.value }}
                  </span>
                </div>
              </div>
              <div class="flex gap-2">
                <button
                  @click="openEditDialog"
                  class="px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors text-sm"
                >
                  Edit
                </button>
                <button
                  @click="openTierDialog"
                  :disabled="isTriggering"
                  class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors text-sm"
                >
                  {{ isTriggering ? "Triggering..." : "Trigger Scan" }}
                </button>
              </div>
            </div>
          </div>

          <!-- Scan Runs Table -->
          <div
            class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
          >
            <!-- Loading -->
            <div
              v-if="scanStore.isLoadingRuns"
              role="status"
              class="p-8 text-center text-gray-500 dark:text-dark-text-secondary"
            >
              Loading scan runs...
            </div>

            <!-- Empty -->
            <div
              v-else-if="scanStore.scanRuns.length === 0"
              class="p-8 text-center"
            >
              <p class="text-gray-500 dark:text-dark-text-secondary">
                No scan runs yet for this project
              </p>
              <button
                @click="openTierDialog"
                class="mt-2 text-primary-600 dark:text-primary-400 text-sm hover:text-primary-700 dark:hover:text-primary-300"
              >
                Run your first scan
              </button>
            </div>

            <!-- Table -->
            <div v-else class="overflow-x-auto">
              <table
                class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
              >
                <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
                  <tr>
                    <th
                      scope="col"
                      class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      ID
                    </th>
                    <th
                      scope="col"
                      class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Status
                    </th>
                    <th
                      scope="col"
                      class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Triggered By
                    </th>
                    <th
                      scope="col"
                      class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Started
                    </th>
                    <th
                      scope="col"
                      class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Duration
                    </th>
                    <th
                      scope="col"
                      class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-secondary uppercase tracking-wider"
                    >
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody
                  class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border"
                >
                  <tr
                    v-for="run in scanStore.scanRuns"
                    :key="run.id"
                    class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary cursor-pointer"
                    @click="viewScanDetail(run)"
                  >
                    <td
                      class="px-6 py-4 whitespace-nowrap text-sm font-mono text-gray-900 dark:text-dark-text-primary"
                    >
                      #{{ run.id }}
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap">
                      <span
                        class="px-2 inline-flex items-center text-xs leading-5 font-semibold rounded-full"
                        :class="getStatusBadgeClass(run.status)"
                      >
                        <span
                          v-if="run.status === 'running'"
                          class="w-2 h-2 mr-1.5 rounded-full bg-blue-500 animate-pulse"
                        />
                        {{ run.status }}
                      </span>
                    </td>
                    <td
                      class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary"
                    >
                      {{ run.triggered_by }}
                    </td>
                    <td
                      class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary"
                    >
                      {{ formatDate(run.started_at) }}
                    </td>
                    <td
                      class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary"
                    >
                      {{ formatDuration(run) }}
                    </td>
                    <td
                      class="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-3"
                    >
                      <button
                        @click.stop="viewScanDetail(run)"
                        class="text-primary-600 hover:text-primary-900 dark:text-primary-400 dark:hover:text-primary-300"
                      >
                        View
                      </button>
                      <button
                        v-if="canDelete(run)"
                        @click.stop="confirmDelete(run)"
                        class="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300"
                      >
                        Delete
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Create Project Dialog -->
    <Teleport to="body">
      <div
        v-if="showCreateDialog"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <!-- Backdrop -->
        <div class="absolute inset-0 bg-black/50" @click="closeCreateDialog" />

        <!-- Dialog -->
        <div
          class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-lg mx-4 border border-gray-200 dark:border-dark-border"
        >
          <div
            class="px-6 py-4 border-b border-gray-200 dark:border-dark-border"
          >
            <h3
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Create New Project
            </h3>
          </div>

          <form @submit.prevent="handleCreateProject" class="p-6 space-y-4">
            <!-- Name -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Project Name
              </label>
              <input
                v-model="newProjectName"
                type="text"
                required
                placeholder="e.g. ACME Corp External Scan"
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <!-- Description -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Description
              </label>
              <textarea
                v-model="newProjectDescription"
                rows="2"
                placeholder="Optional project description..."
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
              />
            </div>

            <!-- Seeds -->
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Seeds
              </label>
              <div class="space-y-2">
                <div
                  v-for="(seed, index) in newProjectSeeds"
                  :key="index"
                  class="flex gap-2"
                >
                  <select
                    v-model="seed.type"
                    class="w-32 px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                  >
                    <option value="domain">Domain</option>
                    <option value="ip">IP</option>
                    <option value="cidr">CIDR</option>
                    <option value="asn">ASN</option>
                  </select>
                  <input
                    v-model="seed.value"
                    type="text"
                    placeholder="e.g. example.com"
                    class="flex-1 px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                  />
                  <button
                    type="button"
                    @click="removeSeedRow(index)"
                    :disabled="newProjectSeeds.length <= 1"
                    class="px-2 py-2 text-gray-400 hover:text-red-500 disabled:opacity-30 disabled:cursor-not-allowed"
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
              </div>
              <button
                type="button"
                @click="addSeedRow"
                class="mt-2 text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300"
              >
                + Add seed
              </button>
            </div>

            <!-- Actions -->
            <div class="flex justify-end gap-3 pt-2">
              <button
                type="button"
                @click="closeCreateDialog"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="isCreating || !newProjectName.trim()"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ isCreating ? "Creating..." : "Create Project" }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <!-- Delete Confirmation Dialog -->
    <Teleport to="body">
      <div
        v-if="showDeleteDialog"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div
          class="absolute inset-0 bg-black/50"
          @click="showDeleteDialog = false"
        />
        <div
          class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-md mx-4 border border-gray-200 dark:border-dark-border"
        >
          <div
            class="px-6 py-4 border-b border-gray-200 dark:border-dark-border"
          >
            <h3
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Delete Scan Run
            </h3>
          </div>
          <div class="p-6">
            <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
              Are you sure you want to delete scan run
              <span class="font-mono font-semibold"
                >#{{ scanToDelete?.id }}</span
              >? This will permanently remove all phase results and
              observations. This action cannot be undone.
            </p>
          </div>
          <div
            class="px-6 py-4 border-t border-gray-200 dark:border-dark-border flex justify-end gap-3"
          >
            <button
              @click="showDeleteDialog = false"
              class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
            >
              Cancel
            </button>
            <button
              @click="handleDeleteScan"
              :disabled="isDeleting"
              class="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {{ isDeleting ? "Deleting..." : "Delete" }}
            </button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Scan Tier Selection Dialog -->
    <Teleport to="body">
      <div
        v-if="showTierDialog"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <!-- Backdrop -->
        <div class="absolute inset-0 bg-black/50" @click="closeTierDialog" />

        <!-- Dialog -->
        <div
          class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-2xl mx-4 border border-gray-200 dark:border-dark-border"
        >
          <div
            class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center"
          >
            <h3
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Select Scan Type
            </h3>
            <button
              @click="closeTierDialog"
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

          <div class="p-6">
            <div class="grid grid-cols-3 gap-4">
              <button
                v-for="tier in SCAN_TIERS"
                :key="tier.tier"
                @click="handleTriggerScan(tier.tier)"
                class="flex flex-col items-center p-5 rounded-lg border-2 transition-all hover:shadow-md"
                :class="{
                  'border-green-300 dark:border-green-700 hover:border-green-500 hover:bg-green-50 dark:hover:bg-green-900/10':
                    tier.tier === 1,
                  'border-yellow-300 dark:border-yellow-700 hover:border-yellow-500 hover:bg-yellow-50 dark:hover:bg-yellow-900/10':
                    tier.tier === 2,
                  'border-red-300 dark:border-red-700 hover:border-red-500 hover:bg-red-50 dark:hover:bg-red-900/10':
                    tier.tier === 3,
                }"
              >
                <!-- Icon -->
                <div class="mb-3">
                  <!-- Shield for Safe -->
                  <svg
                    v-if="tier.tier === 1"
                    class="w-10 h-10"
                    :class="getTierIconClass(tier.tier)"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                    />
                  </svg>
                  <!-- Bolt for Moderate -->
                  <svg
                    v-else-if="tier.tier === 2"
                    class="w-10 h-10"
                    :class="getTierIconClass(tier.tier)"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M13 10V3L4 14h7v7l9-11h-7z"
                    />
                  </svg>
                  <!-- Fire for Aggressive -->
                  <svg
                    v-else
                    class="w-10 h-10"
                    :class="getTierIconClass(tier.tier)"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"
                    />
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z"
                    />
                  </svg>
                </div>

                <!-- Tier badge -->
                <span
                  class="px-2.5 py-0.5 text-xs font-bold rounded-full mb-2"
                  :class="getTierBadgeClass(tier.tier)"
                >
                  Tier {{ tier.tier }}
                </span>

                <!-- Name -->
                <h4
                  class="text-base font-semibold text-gray-900 dark:text-dark-text-primary mb-2"
                >
                  {{ tier.name }}
                </h4>

                <!-- Description -->
                <p
                  class="text-xs text-gray-500 dark:text-dark-text-secondary text-center mb-3"
                >
                  {{ tier.description }}
                </p>

                <!-- Stats -->
                <div
                  class="flex gap-3 text-xs text-gray-600 dark:text-dark-text-secondary"
                >
                  <span class="flex items-center gap-1">
                    <svg
                      class="w-3.5 h-3.5"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M5 12h14M12 5l7 7-7 7"
                      />
                    </svg>
                    {{ tier.ports }}
                  </span>
                  <span class="flex items-center gap-1">
                    <svg
                      class="w-3.5 h-3.5"
                      fill="none"
                      stroke="currentColor"
                      viewBox="0 0 24 24"
                    >
                      <path
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        d="M13 10V3L4 14h7v7l9-11h-7z"
                      />
                    </svg>
                    {{ tier.rate }}
                  </span>
                </div>
              </button>
            </div>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Edit Project Dialog -->
    <Teleport to="body">
      <div
        v-if="showEditDialog"
        class="fixed inset-0 z-50 flex items-center justify-center"
      >
        <div class="absolute inset-0 bg-black/50" @click="closeEditDialog" />
        <div
          class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-lg mx-4 border border-gray-200 dark:border-dark-border"
        >
          <div
            class="px-6 py-4 border-b border-gray-200 dark:border-dark-border"
          >
            <h3
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Edit Project
            </h3>
          </div>

          <form @submit.prevent="handleUpdateProject" class="p-6 space-y-4">
            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Project Name
              </label>
              <input
                v-model="editProjectName"
                type="text"
                required
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
              />
            </div>

            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Description
              </label>
              <textarea
                v-model="editProjectDescription"
                rows="2"
                placeholder="Optional project description..."
                class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500 resize-none"
              />
            </div>

            <div>
              <label
                class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-1"
              >
                Seeds
              </label>
              <div class="space-y-2">
                <div
                  v-for="(seed, index) in editProjectSeeds"
                  :key="index"
                  class="flex gap-2"
                >
                  <select
                    v-model="seed.type"
                    class="w-32 px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                  >
                    <option value="domain">Domain</option>
                    <option value="ip">IP</option>
                    <option value="cidr">CIDR</option>
                    <option value="asn">ASN</option>
                  </select>
                  <input
                    v-model="seed.value"
                    type="text"
                    placeholder="e.g. example.com"
                    class="flex-1 px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
                  />
                  <button
                    type="button"
                    @click="removeEditSeedRow(index)"
                    :disabled="editProjectSeeds.length <= 1"
                    class="px-2 py-2 text-gray-400 hover:text-red-500 disabled:opacity-30 disabled:cursor-not-allowed"
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
              </div>
              <button
                type="button"
                @click="addEditSeedRow"
                class="mt-2 text-sm text-primary-600 dark:text-primary-400 hover:text-primary-700 dark:hover:text-primary-300"
              >
                + Add seed
              </button>
            </div>

            <div class="flex justify-end gap-3 pt-2">
              <button
                type="button"
                @click="closeEditDialog"
                class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                :disabled="isUpdating || !editProjectName.trim()"
                class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                {{ isUpdating ? "Saving..." : "Save Changes" }}
              </button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>
  </div>
</template>
