import { defineStore } from "pinia";
import { ref, computed } from "vue";
import apiClient from "@/api/client";
import { useTenantStore } from "./tenant";

export interface ProjectSeed {
  type: string;
  value: string;
}

export interface Project {
  id: number;
  tenant_id: number;
  name: string;
  description: string | null;
  seeds: ProjectSeed[] | null;
  settings: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export type ScanRunStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

export interface ScanRun {
  id: number;
  project_id: number;
  profile_id: number | null;
  tenant_id: number;
  status: ScanRunStatus;
  triggered_by: string;
  started_at: string | null;
  completed_at: string | null;
  stats: Record<string, unknown> | null;
  error_message: string | null;
  celery_task_id: string | null;
  created_at: string;
  duration_seconds: number | null;
}

export type PhaseStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "skipped";

export interface PhaseProgress {
  id: number;
  scan_run_id: number;
  phase: string;
  status: PhaseStatus;
  started_at: string | null;
  completed_at: string | null;
  stats: Record<string, unknown> | null;
  error_message: string | null;
  duration_seconds: number | null;
}

export interface CreateProjectPayload {
  name: string;
  description: string;
  seeds: ProjectSeed[];
}

export interface TaskResponse {
  task_id: string;
  status: string;
  message: string;
  data: { scan_run_id: number } | null;
}

export interface ScanTier {
  tier: number;
  name: string;
  description: string;
  ports: string;
  rate: string;
}

export const SCAN_TIERS: ScanTier[] = [
  {
    tier: 1,
    name: "Safe",
    description:
      "Non-intrusive recon. Top 100 ports, CDN/WAF detection, safe Nuclei templates, 10 req/s.",
    ports: "Top 100",
    rate: "10 req/s",
  },
  {
    tier: 2,
    name: "Moderate",
    description:
      "Standard scan. DNS permutation (alterx+puredns), cloud enum, service fingerprinting, top 1000 ports, medium Nuclei templates, 50 req/s.",
    ports: "Top 1000",
    rate: "50 req/s",
  },
  {
    tier: 3,
    name: "Aggressive",
    description:
      "Full scan. All tier 2 tools + interactsh OOB callbacks, all ports, all Nuclei templates, 100 req/s. Use with caution.",
    ports: "Full (65535)",
    rate: "100 req/s",
  },
];

export const useScanStore = defineStore("scans", () => {
  const tenantStore = useTenantStore();

  const projects = ref<Project[]>([]);
  const selectedProject = ref<Project | null>(null);
  const scanRuns = ref<ScanRun[]>([]);
  const currentScanRun = ref<ScanRun | null>(null);
  const phaseProgress = ref<PhaseProgress[]>([]);
  const isLoadingProjects = ref(false);
  const isLoadingRuns = ref(false);
  const isLoadingProgress = ref(false);
  const error = ref("");

  // AbortControllers for cancelling stale in-flight requests
  let fetchProjectsAbort: AbortController | null = null;
  let fetchScanRunsAbort: AbortController | null = null;

  const tenantId = computed(() => tenantStore.currentTenantId);

  async function fetchProjects(): Promise<void> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return;
    }

    fetchProjectsAbort?.abort();
    fetchProjectsAbort = new AbortController();

    isLoadingProjects.value = true;
    error.value = "";

    try {
      const response = await apiClient.get(
        `/api/v1/tenants/${tenantId.value}/projects`,
        { signal: fetchProjectsAbort.signal },
      );
      const data = response.data;
      projects.value = Array.isArray(data) ? data : (data.items ?? []);
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        (err.name === "CanceledError" || err.name === "AbortError")
      )
        return;
      const message =
        err instanceof Error ? err.message : "Failed to fetch projects";
      error.value = message;
    } finally {
      isLoadingProjects.value = false;
    }
  }

  async function createProject(
    payload: CreateProjectPayload,
  ): Promise<Project | null> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return null;
    }

    error.value = "";

    try {
      const response = await apiClient.post<Project>(
        `/api/v1/tenants/${tenantId.value}/projects`,
        payload,
      );
      const newProject = response.data;
      projects.value.push(newProject);
      return newProject;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to create project";
      error.value = message;
      return null;
    }
  }

  async function fetchScanRuns(projectId: number): Promise<void> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return;
    }

    fetchScanRunsAbort?.abort();
    fetchScanRunsAbort = new AbortController();

    isLoadingRuns.value = true;
    error.value = "";

    try {
      const response = await apiClient.get(
        `/api/v1/tenants/${tenantId.value}/projects/${projectId}/scans`,
        { signal: fetchScanRunsAbort.signal },
      );
      const data = response.data;
      scanRuns.value = Array.isArray(data) ? data : (data.items ?? []);
    } catch (err: unknown) {
      if (
        err instanceof Error &&
        (err.name === "CanceledError" || err.name === "AbortError")
      )
        return;
      const message =
        err instanceof Error ? err.message : "Failed to fetch scan runs";
      error.value = message;
    } finally {
      isLoadingRuns.value = false;
    }
  }

  async function fetchScanRun(runId: number): Promise<void> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return;
    }

    error.value = "";

    try {
      const response = await apiClient.get<ScanRun>(
        `/api/v1/tenants/${tenantId.value}/scans/${runId}`,
      );
      currentScanRun.value = response.data;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch scan run";
      error.value = message;
    }
  }

  async function triggerScan(
    projectId: number,
    scanTier: number = 1,
  ): Promise<ScanRun | null> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return null;
    }

    error.value = "";

    try {
      const response = await apiClient.post<TaskResponse>(
        `/api/v1/tenants/${tenantId.value}/projects/${projectId}/scans`,
        { triggered_by: "manual", scan_tier: scanTier },
      );
      const taskResp = response.data;
      const scanRunId = taskResp.data?.scan_run_id;

      if (scanRunId) {
        // Fetch the actual scan run from the API
        const runResponse = await apiClient.get<ScanRun>(
          `/api/v1/tenants/${tenantId.value}/scans/${scanRunId}`,
        );
        const newRun = runResponse.data;
        scanRuns.value.unshift(newRun);
        return newRun;
      }

      // Fallback: refresh the scan runs list
      await fetchScanRuns(projectId);
      return scanRuns.value[0] ?? null;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to trigger scan";
      error.value = message;
      return null;
    }
  }

  async function fetchProgress(runId: number): Promise<void> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return;
    }

    isLoadingProgress.value = true;
    error.value = "";

    try {
      const response = await apiClient.get<{
        scan_run: ScanRun;
        phases: PhaseProgress[];
      }>(`/api/v1/tenants/${tenantId.value}/scans/${runId}/progress`);
      currentScanRun.value = response.data.scan_run;
      phaseProgress.value = response.data.phases;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to fetch progress";
      error.value = message;
    } finally {
      isLoadingProgress.value = false;
    }
  }

  async function cancelScan(runId: number): Promise<boolean> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return false;
    }

    error.value = "";

    try {
      await apiClient.post(
        `/api/v1/tenants/${tenantId.value}/scans/${runId}/cancel`,
      );

      if (currentScanRun.value && currentScanRun.value.id === runId) {
        currentScanRun.value.status = "cancelled";
      }

      const runIndex = scanRuns.value.findIndex((r) => r.id === runId);
      if (runIndex !== -1) {
        scanRuns.value[runIndex].status = "cancelled";
      }

      return true;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to cancel scan";
      error.value = message;
      return false;
    }
  }

  async function deleteScanRun(runId: number): Promise<boolean> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return false;
    }

    error.value = "";

    try {
      await apiClient.delete(
        `/api/v1/tenants/${tenantId.value}/scans/${runId}`,
      );

      scanRuns.value = scanRuns.value.filter((r) => r.id !== runId);

      if (currentScanRun.value && currentScanRun.value.id === runId) {
        currentScanRun.value = null;
      }

      return true;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to delete scan run";
      error.value = message;
      return false;
    }
  }

  async function updateProject(
    projectId: number,
    payload: Partial<CreateProjectPayload>,
  ): Promise<Project | null> {
    if (!tenantId.value) {
      error.value = "No tenant selected";
      return null;
    }

    error.value = "";

    try {
      const response = await apiClient.put<Project>(
        `/api/v1/tenants/${tenantId.value}/projects/${projectId}`,
        payload,
      );
      const updated = response.data;
      const idx = projects.value.findIndex((p) => p.id === projectId);
      if (idx !== -1) {
        projects.value[idx] = updated;
      }
      if (selectedProject.value?.id === projectId) {
        selectedProject.value = updated;
      }
      return updated;
    } catch (err: unknown) {
      const message =
        err instanceof Error ? err.message : "Failed to update project";
      error.value = message;
      return null;
    }
  }

  function selectProject(project: Project): void {
    selectedProject.value = project;
  }

  function clearError(): void {
    error.value = "";
  }

  return {
    projects,
    selectedProject,
    scanRuns,
    currentScanRun,
    phaseProgress,
    isLoadingProjects,
    isLoadingRuns,
    isLoadingProgress,
    error,
    fetchProjects,
    createProject,
    fetchScanRuns,
    fetchScanRun,
    triggerScan,
    fetchProgress,
    cancelScan,
    deleteScanRun,
    updateProject,
    selectProject,
    clearError,
  };
});
