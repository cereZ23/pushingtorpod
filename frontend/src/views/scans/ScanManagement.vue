<script setup lang="ts">
import { ref, onMounted, computed, watch } from "vue";
import { useRouter } from "vue-router";
import { useTenantStore } from "@/stores/tenant";
import { useScanStore } from "@/stores/scans";
import type { Project, ScanRun, ProjectSeed } from "@/stores/scans";

import ProjectSidebar from "@/components/scans/ProjectSidebar.vue";
import ProjectHeader from "@/components/scans/ProjectHeader.vue";
import ScanRunsTable from "@/components/scans/ScanRunsTable.vue";
import TierSelectionDialog from "@/components/scans/TierSelectionDialog.vue";
import ConfirmDeleteDialog from "@/components/scans/ConfirmDeleteDialog.vue";

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

// Delete project dialog
const showDeleteProjectDialog = ref(false);
const isDeletingProject = ref(false);

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

// --- Create project ---

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

// --- Trigger scan ---

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

// --- View / Compare ---

function viewScanDetail(run: ScanRun): void {
  router.push({ name: "ScanDetail", params: { runId: run.id } });
}

const completedRunsCount = computed(
  () => scanStore.scanRuns.filter((r) => r.status === "completed").length,
);

function goToCompare(): void {
  if (!scanStore.selectedProject) return;
  router.push({
    name: "ScanDiff",
    params: { projectId: scanStore.selectedProject.id },
  });
}

// --- Delete scan run ---

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

const deleteScanMessage =
  "Are you sure you want to delete this scan run? This will permanently remove all phase results and observations. This action cannot be undone.";
const deleteScanEntityName = computed(() =>
  scanToDelete.value ? `#${scanToDelete.value.id}` : "",
);

// --- Edit project ---

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

// --- Delete project ---

function confirmDeleteProject(): void {
  showDeleteProjectDialog.value = true;
}

async function handleDeleteProject(): Promise<void> {
  if (!scanStore.selectedProject) return;
  isDeletingProject.value = true;
  const success = await scanStore.deleteProject(scanStore.selectedProject.id);
  isDeletingProject.value = false;
  if (success) {
    showDeleteProjectDialog.value = false;
    if (scanStore.selectedProject) {
      await scanStore.fetchScanRuns(scanStore.selectedProject.id);
    }
  }
}

const deleteProjectMessage =
  "Are you sure you want to delete project? This will permanently remove all scan runs, profiles, and scope rules. This action cannot be undone.";
const deleteProjectEntityName = computed(
  () => scanStore.selectedProject?.name ?? "",
);
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
      <ProjectSidebar
        :projects="scanStore.projects"
        :selected-project-id="scanStore.selectedProject?.id ?? null"
        :is-loading="scanStore.isLoadingProjects"
        @select-project="selectProject"
        @create-project="openCreateDialog"
      />

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
          <ProjectHeader
            :project="scanStore.selectedProject"
            :completed-runs-count="completedRunsCount"
            :is-triggering="isTriggering"
            @edit="openEditDialog"
            @delete="confirmDeleteProject"
            @trigger-scan="openTierDialog"
            @compare="goToCompare"
          />

          <!-- Scan Runs Table -->
          <ScanRunsTable
            :runs="scanStore.scanRuns"
            :is-loading="scanStore.isLoadingRuns"
            @view-detail="viewScanDetail"
            @delete-run="confirmDelete"
            @trigger-scan="openTierDialog"
          />
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
            <!-- Inline error (visible inside dialog) -->
            <div
              v-if="scanStore.error"
              class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-md p-3"
            >
              <p class="text-sm text-red-800 dark:text-red-200">
                {{ scanStore.error }}
              </p>
            </div>

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

    <!-- Delete Scan Run Dialog -->
    <ConfirmDeleteDialog
      :open="showDeleteDialog"
      title="Delete Scan Run"
      :message="deleteScanMessage"
      :entity-name="deleteScanEntityName"
      :is-loading="isDeleting"
      @close="showDeleteDialog = false"
      @confirm="handleDeleteScan"
    />

    <!-- Tier Selection Dialog -->
    <TierSelectionDialog
      :open="showTierDialog"
      :is-loading="isTriggering"
      @close="closeTierDialog"
      @submit="handleTriggerScan"
    />

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

    <!-- Delete Project Dialog -->
    <ConfirmDeleteDialog
      :open="showDeleteProjectDialog"
      title="Delete Project"
      :message="deleteProjectMessage"
      :entity-name="deleteProjectEntityName"
      :is-loading="isDeletingProject"
      confirm-label="Delete Project"
      @close="showDeleteProjectDialog = false"
      @confirm="handleDeleteProject"
    />
  </div>
</template>
