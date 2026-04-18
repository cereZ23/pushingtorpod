<script setup lang="ts">
import { ref, computed, watch } from "vue";
import { useTenantStore } from "@/stores/tenant";
import apiClient from "@/api/client";
import { formatDate } from "@/utils/formatters";

// --- Type definitions ---

type ReportType = "executive" | "technical" | "soc2" | "iso27001";
type SeverityLevel = "critical" | "high" | "medium" | "low" | "info";

interface TopIssue {
  finding_id: number;
  name: string;
  severity: SeverityLevel;
  cvss_score: number | null;
  cve_id?: string | null;
  template_id?: string | null;
  asset_identifier: string;
  first_seen: string;
}

interface Recommendation {
  priority: number;
  title: string;
  description: string;
  affected_count: number;
}

interface ExecutiveReport {
  risk_score: number;
  risk_grade: string;
  total_assets: number;
  total_findings: number;
  open_findings: number;
  finding_counts_by_severity: Record<SeverityLevel, number>;
  finding_counts_by_status: Record<string, number>;
  asset_counts: Record<string, number>;
  score_trend: Array<{ date: string; score: number; grade: string }>;
  top_issues: TopIssue[];
  recommendations: Recommendation[];
  generated_at: string;
}

interface TechnicalFinding {
  id: number;
  name: string;
  severity: SeverityLevel;
  cvss_score: number | null;
  cve_id: string | null;
  template_id: string | null;
  asset_identifier: string;
  asset_type: string;
  evidence: Record<string, unknown> | null;
  status: "open" | "suppressed" | "fixed";
  first_seen: string;
  last_seen: string;
  host: string | null;
  matched_at: string | null;
}

interface TechnicalReport {
  total: number;
  severity_filter: string | null;
  findings: TechnicalFinding[];
  generated_at: string;
}

// --- Store and state ---

const tenantStore = useTenantStore();
const currentTenantId = computed(() => tenantStore.currentTenantId);

const selectedReportType = ref<ReportType>("executive");
const isLoading = ref(false);
const error = ref("");
const isExporting = ref(false);
const isDownloading = ref<"pdf" | "docx" | null>(null);

// Executive report state
const executiveReport = ref<ExecutiveReport | null>(null);

// Technical report state
const technicalReport = ref<TechnicalReport | null>(null);
const severityFilter = ref<SeverityLevel | "">("");
const technicalLimit = ref(100);

// Technical report inline filters
const tableSearchQuery = ref("");
const tableStatusFilter = ref<string>("");

// --- Computed properties ---

const filteredFindings = computed<TechnicalFinding[]>(() => {
  if (!technicalReport.value) return [];

  let results = technicalReport.value.findings;

  if (tableSearchQuery.value) {
    const query = tableSearchQuery.value.toLowerCase();
    results = results.filter(
      (f) =>
        f.name.toLowerCase().includes(query) ||
        f.asset_identifier.toLowerCase().includes(query) ||
        (f.cve_id && f.cve_id.toLowerCase().includes(query)) ||
        (f.template_id && f.template_id.toLowerCase().includes(query)),
    );
  }

  if (tableStatusFilter.value) {
    results = results.filter((f) => f.status === tableStatusFilter.value);
  }

  return results;
});

const gradeColorClass = computed<string>(() => {
  if (!executiveReport.value) return "text-gray-500";
  const grade = (executiveReport.value.risk_grade || "").toUpperCase();
  if (grade.startsWith("A")) return "text-green-600 dark:text-green-400";
  if (grade.startsWith("B")) return "text-blue-600 dark:text-blue-400";
  if (grade.startsWith("C")) return "text-yellow-600 dark:text-yellow-400";
  if (grade.startsWith("D")) return "text-orange-600 dark:text-orange-400";
  return "text-red-600 dark:text-red-400";
});

const riskScoreColorClass = computed<string>(() => {
  if (!executiveReport.value) return "bg-gray-500";
  const score = executiveReport.value.risk_score;
  if (score >= 80) return "bg-red-500";
  if (score >= 60) return "bg-orange-500";
  if (score >= 40) return "bg-yellow-500";
  if (score >= 20) return "bg-blue-500";
  return "bg-green-500";
});

// --- Reset on tenant change ---

watch(currentTenantId, () => {
  executiveReport.value = null;
  technicalReport.value = null;
  error.value = "";
});

// --- API methods ---

const isComplianceType = computed(
  () =>
    selectedReportType.value === "soc2" ||
    selectedReportType.value === "iso27001",
);

async function generateReport(): Promise<void> {
  if (!currentTenantId.value) {
    error.value = "No tenant selected";
    return;
  }

  // Compliance reports go directly to PDF download (no JSON preview)
  if (isComplianceType.value) {
    await downloadReport("pdf");
    return;
  }

  isLoading.value = true;
  error.value = "";
  executiveReport.value = null;
  technicalReport.value = null;

  try {
    if (selectedReportType.value === "executive") {
      const response = await apiClient.get<ExecutiveReport>(
        `/api/v1/tenants/${currentTenantId.value}/reports/executive`,
      );
      executiveReport.value = response.data;
    } else {
      const params: Record<string, string | number> = {
        limit: technicalLimit.value,
      };
      if (severityFilter.value) {
        params.severity = severityFilter.value;
      }
      const response = await apiClient.get<TechnicalReport>(
        `/api/v1/tenants/${currentTenantId.value}/reports/technical`,
        { params },
      );
      technicalReport.value = response.data;
    }
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to generate report";
    error.value = message;
  } finally {
    isLoading.value = false;
  }
}

async function exportReport(format: "json" | "csv"): Promise<void> {
  if (!currentTenantId.value) {
    error.value = "No tenant selected";
    return;
  }

  isExporting.value = true;
  error.value = "";

  try {
    const response = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/reports/export/${format}`,
      { responseType: "blob" },
    );

    const blob = new Blob([response.data as BlobPart]);
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `easm-report-${currentTenantId.value}.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  } catch (err: unknown) {
    const message =
      err instanceof Error
        ? err.message
        : `Failed to export ${format.toUpperCase()}`;
    error.value = message;
  } finally {
    isExporting.value = false;
  }
}

async function downloadReport(format: "pdf" | "docx"): Promise<void> {
  if (!currentTenantId.value) {
    error.value = "No tenant selected";
    return;
  }

  isDownloading.value = format;
  error.value = "";

  try {
    const params: Record<string, string | number> = {
      report_type: selectedReportType.value,
    };
    if (selectedReportType.value === "technical") {
      if (severityFilter.value) params.severity = severityFilter.value;
      params.limit = technicalLimit.value;
    }

    const response = await apiClient.get(
      `/api/v1/tenants/${currentTenantId.value}/reports/export/${format}`,
      { params, responseType: "blob", timeout: 120000 },
    );

    const mimeTypes: Record<string, string> = {
      pdf: "application/pdf",
      docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    };
    const blob = new Blob([response.data as BlobPart], {
      type: mimeTypes[format],
    });
    const url = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `easm-${selectedReportType.value}-report.${format}`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    window.URL.revokeObjectURL(url);
  } catch (err: unknown) {
    const message =
      err instanceof Error
        ? err.message
        : `Failed to download ${format.toUpperCase()}`;
    error.value = message;
  } finally {
    isDownloading.value = null;
  }
}

// --- Utility methods ---

function getSeverityBadgeClass(severity: SeverityLevel): string {
  const colors: Record<SeverityLevel, string> = {
    critical: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
    high: "bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400",
    medium:
      "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400",
    low: "bg-blue-100 text-blue-800 dark:bg-blue-900/20 dark:text-blue-400",
    info: "bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400",
  };
  return colors[severity] || colors.info;
}

function getStatusBadgeClass(status: string): string {
  const colors: Record<string, string> = {
    open: "bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400",
    suppressed:
      "bg-gray-100 text-gray-600 dark:bg-gray-700/30 dark:text-gray-400",
    fixed:
      "bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400",
  };
  return (
    colors[status] ||
    "bg-gray-100 text-gray-800 dark:bg-gray-900/20 dark:text-gray-400"
  );
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex justify-between items-center">
      <h2 class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">
        Reports
      </h2>
      <div class="flex items-center gap-3">
        <button
          @click="downloadReport('pdf')"
          :disabled="isDownloading !== null"
          class="px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
        >
          <svg
            aria-hidden="true"
            class="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          {{ isDownloading === "pdf" ? "Generating..." : "Download PDF" }}
        </button>
        <button
          @click="downloadReport('docx')"
          :disabled="isDownloading !== null"
          class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors flex items-center gap-2"
        >
          <svg
            aria-hidden="true"
            class="w-4 h-4"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          {{ isDownloading === "docx" ? "Generating..." : "Download DOCX" }}
        </button>
        <button
          @click="exportReport('json')"
          :disabled="isExporting"
          class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {{ isExporting ? "Exporting..." : "Export JSON" }}
        </button>
        <button
          @click="exportReport('csv')"
          :disabled="isExporting"
          class="px-4 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
        >
          {{ isExporting ? "Exporting..." : "Export CSV" }}
        </button>
      </div>
    </div>

    <!-- Report Configuration -->
    <div
      class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
    >
      <h3
        class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4"
      >
        Generate Report
      </h3>
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <!-- Report Type -->
        <div>
          <label
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
          >
            Report Type
          </label>
          <select
            v-model="selectedReportType"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="executive">Executive Summary</option>
            <option value="technical">Technical Report</option>
            <option value="soc2">SOC 2 Compliance</option>
            <option value="iso27001">ISO 27001 Compliance</option>
          </select>
        </div>

        <!-- Severity Filter (technical only) -->
        <div v-if="selectedReportType === 'technical'">
          <label
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
          >
            Severity Filter
          </label>
          <select
            v-model="severityFilter"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>

        <!-- Limit (technical only) -->
        <div v-if="selectedReportType === 'technical'">
          <label
            class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
          >
            Max Results
          </label>
          <select
            v-model="technicalLimit"
            class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
          >
            <option :value="50">50</option>
            <option :value="100">100</option>
            <option :value="250">250</option>
            <option :value="500">500</option>
          </select>
        </div>

        <!-- Generate Button -->
        <div class="flex items-end">
          <button
            @click="generateReport"
            :disabled="isLoading"
            class="w-full px-4 py-2 bg-indigo-600 text-white rounded-md hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            {{
              isLoading || isDownloading
                ? "Generating..."
                : isComplianceType
                  ? "Download PDF"
                  : "Generate"
            }}
          </button>
        </div>
      </div>

      <!-- Compliance Beta Disclaimer -->
      <div
        v-if="isComplianceType"
        class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 p-4 rounded-md"
      >
        <div class="flex items-start gap-3">
          <svg
            class="w-5 h-5 text-amber-600 dark:text-amber-400 mt-0.5 shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              stroke-linecap="round"
              stroke-linejoin="round"
              stroke-width="2"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z"
            />
          </svg>
          <div>
            <p class="text-sm font-medium text-amber-800 dark:text-amber-200">
              Beta — Partial coverage
            </p>
            <p class="text-sm text-amber-700 dark:text-amber-300 mt-1">
              Compliance mapping currently covers ~20 of 93 ISO 27001 Annex A
              controls. Use this report as a starting point, not as audit
              evidence. Full coverage is on our roadmap.
            </p>
          </div>
        </div>
      </div>
    </div>

    <!-- Error State -->
    <div
      v-if="error"
      role="alert"
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

    <!-- Loading State -->
    <div
      v-if="isLoading"
      role="status"
      class="flex items-center justify-center h-64"
    >
      <div class="text-gray-600 dark:text-dark-text-secondary">
        Generating report...
      </div>
    </div>

    <!-- ============================================ -->
    <!-- Executive Report Display                     -->
    <!-- ============================================ -->
    <template v-if="executiveReport && !isLoading">
      <!-- Risk Score and Grade -->
      <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
        <!-- Risk Score Card -->
        <div
          class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
        >
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
            Overall Risk Score
          </p>
          <div class="flex items-center mt-2">
            <p
              class="text-4xl font-bold text-gray-900 dark:text-dark-text-primary"
            >
              {{ executiveReport.risk_score }}
            </p>
            <span
              class="text-sm text-gray-500 dark:text-dark-text-tertiary ml-1"
              >/ 100</span
            >
          </div>
          <div
            class="mt-3 w-full h-3 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden"
          >
            <div
              class="h-full rounded-full transition-all"
              :class="riskScoreColorClass"
              :style="{
                width: `${Math.min(executiveReport.risk_score, 100)}%`,
              }"
            />
          </div>
        </div>

        <!-- Grade Card -->
        <div
          class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
        >
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
            Security Grade
          </p>
          <p class="text-5xl font-bold mt-2" :class="gradeColorClass">
            {{ executiveReport.risk_grade }}
          </p>
        </div>

        <!-- Summary Stats Card -->
        <div
          class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
        >
          <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
            Summary
          </p>
          <div class="mt-2 space-y-2">
            <div class="flex justify-between">
              <span class="text-sm text-gray-500 dark:text-dark-text-tertiary"
                >Total Assets</span
              >
              <span
                class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
              >
                {{ executiveReport.total_assets.toLocaleString() }}
              </span>
            </div>
            <div class="flex justify-between">
              <span class="text-sm text-gray-500 dark:text-dark-text-tertiary"
                >Total Findings</span
              >
              <span
                class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
              >
                {{ executiveReport.total_findings.toLocaleString() }}
              </span>
            </div>
            <div class="flex justify-between">
              <span class="text-sm text-gray-500 dark:text-dark-text-tertiary"
                >Generated</span
              >
              <span
                class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
              >
                {{ formatDate(executiveReport.generated_at) }}
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- Findings by Severity -->
      <div
        class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
      >
        <h3
          class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary mb-4"
        >
          Findings by Severity
        </h3>
        <div class="grid grid-cols-2 md:grid-cols-5 gap-4">
          <div
            v-for="(
              count, severity
            ) in executiveReport.finding_counts_by_severity"
            :key="severity"
            class="text-center p-4 rounded-lg"
            :class="getSeverityBadgeClass(severity as SeverityLevel)"
          >
            <p class="text-2xl font-bold">{{ count }}</p>
            <p class="text-sm capitalize mt-1">{{ severity }}</p>
          </div>
        </div>
      </div>

      <!-- Top Issues -->
      <div
        class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
      >
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
          <h3
            class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
          >
            Top Issues
          </h3>
        </div>
        <div
          v-if="executiveReport.top_issues.length === 0"
          class="p-8 text-center"
        >
          <p class="text-gray-500 dark:text-dark-text-secondary">
            No issues found
          </p>
        </div>
        <div v-else class="overflow-x-auto">
          <table
            class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
          >
            <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
              <tr>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Issue
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Severity
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Asset
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  First Seen
                </th>
              </tr>
            </thead>
            <tbody
              class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border"
            >
              <tr
                v-for="(issue, index) in executiveReport.top_issues"
                :key="index"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td
                  class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary"
                >
                  {{ issue.name }}
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span
                    class="rounded-full px-2 py-1 text-xs font-semibold"
                    :class="getSeverityBadgeClass(issue.severity)"
                  >
                    {{ issue.severity }}
                  </span>
                </td>
                <td
                  class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary"
                >
                  {{ issue.asset_identifier }}
                </td>
                <td
                  class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary"
                >
                  {{ formatDate(issue.first_seen) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- Recommendations -->
      <div
        class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
      >
        <div class="px-6 py-4 border-b border-gray-200 dark:border-dark-border">
          <h3
            class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
          >
            Recommendations
          </h3>
        </div>
        <div
          v-if="executiveReport.recommendations.length === 0"
          class="p-8 text-center"
        >
          <p class="text-gray-500 dark:text-dark-text-secondary">
            No recommendations at this time
          </p>
        </div>
        <ul v-else class="divide-y divide-gray-200 dark:divide-dark-border">
          <li
            v-for="rec in executiveReport.recommendations"
            :key="rec.priority"
            class="px-6 py-4 flex items-start gap-4"
          >
            <div
              class="flex-shrink-0 w-8 h-8 rounded-full bg-indigo-100 dark:bg-indigo-900/20 flex items-center justify-center"
            >
              <span
                class="text-sm font-bold text-indigo-600 dark:text-indigo-400"
                >{{ rec.priority }}</span
              >
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex items-center gap-2">
                <p
                  class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
                >
                  {{ rec.title }}
                </p>
                <span
                  v-if="rec.affected_count"
                  class="rounded-full px-2 py-1 text-xs font-semibold bg-gray-100 text-gray-700 dark:bg-gray-700/30 dark:text-gray-300"
                >
                  {{ rec.affected_count }} affected
                </span>
              </div>
              <p
                class="mt-1 text-sm text-gray-500 dark:text-dark-text-secondary"
              >
                {{ rec.description }}
              </p>
            </div>
          </li>
        </ul>
      </div>
    </template>

    <!-- ============================================ -->
    <!-- Technical Report Display                     -->
    <!-- ============================================ -->
    <template v-if="technicalReport && !isLoading">
      <!-- Summary Bar -->
      <div
        class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border"
      >
        <div class="flex items-center justify-between">
          <div class="flex items-center gap-6">
            <div>
              <span class="text-sm text-gray-500 dark:text-dark-text-tertiary"
                >Total Findings</span
              >
              <span
                class="ml-2 text-lg font-bold text-gray-900 dark:text-dark-text-primary"
              >
                {{ technicalReport.total }}
              </span>
            </div>
            <div v-if="technicalReport.severity_filter">
              <span class="text-sm text-gray-500 dark:text-dark-text-tertiary"
                >Filtered by</span
              >
              <span
                class="ml-2 rounded-full px-2 py-1 text-xs font-semibold"
                :class="
                  getSeverityBadgeClass(
                    technicalReport.severity_filter as SeverityLevel,
                  )
                "
              >
                {{ technicalReport.severity_filter }}
              </span>
            </div>
          </div>
          <span class="text-sm text-gray-500 dark:text-dark-text-tertiary">
            Generated {{ formatDate(technicalReport.generated_at) }}
          </span>
        </div>
      </div>

      <!-- Inline Filters for Technical Table -->
      <div
        class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border"
      >
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
            >
              Search Findings
            </label>
            <input
              v-model="tableSearchQuery"
              type="text"
              placeholder="Search by name, asset, CVE, template..."
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
            />
          </div>
          <div>
            <label
              class="block text-sm font-medium text-gray-700 dark:text-dark-text-secondary mb-2"
            >
              Status
            </label>
            <select
              v-model="tableStatusFilter"
              class="w-full px-3 py-2 border border-gray-300 dark:border-dark-border rounded-md text-gray-900 dark:text-dark-text-primary dark:bg-dark-bg-tertiary focus:outline-none focus:ring-2 focus:ring-primary-500"
            >
              <option value="">All Statuses</option>
              <option value="open">Open</option>
              <option value="suppressed">Suppressed</option>
              <option value="fixed">Fixed</option>
            </select>
          </div>
          <div class="flex items-end">
            <p class="text-sm text-gray-500 dark:text-dark-text-tertiary">
              Showing {{ filteredFindings.length }} of
              {{ technicalReport.findings.length }} findings
            </p>
          </div>
        </div>
      </div>

      <!-- Findings Table -->
      <div
        class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
      >
        <div v-if="filteredFindings.length === 0" class="p-8 text-center">
          <p class="text-gray-500 dark:text-dark-text-secondary">
            No findings match current filters
          </p>
        </div>
        <div v-else class="overflow-x-auto">
          <table
            class="min-w-full divide-y divide-gray-200 dark:divide-dark-border"
          >
            <thead class="bg-gray-50 dark:bg-dark-bg-tertiary">
              <tr>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Finding
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Severity
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  CVSS
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Asset
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Status
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  First Seen
                </th>
                <th
                  class="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Evidence
                </th>
              </tr>
            </thead>
            <tbody
              class="bg-white dark:bg-dark-bg-secondary divide-y divide-gray-200 dark:divide-dark-border"
            >
              <tr
                v-for="finding in filteredFindings"
                :key="finding.id"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary"
              >
                <td class="px-6 py-4">
                  <div
                    class="text-sm font-medium text-gray-900 dark:text-dark-text-primary"
                  >
                    {{ finding.name }}
                  </div>
                  <div
                    class="text-xs text-gray-500 dark:text-dark-text-secondary mt-0.5"
                  >
                    <span v-if="finding.cve_id" class="font-mono">{{
                      finding.cve_id
                    }}</span>
                    <span v-if="finding.cve_id && finding.template_id">
                      |
                    </span>
                    <span v-if="finding.template_id" class="font-mono">{{
                      finding.template_id
                    }}</span>
                  </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span
                    class="rounded-full px-2 py-1 text-xs font-semibold"
                    :class="getSeverityBadgeClass(finding.severity)"
                  >
                    {{ finding.severity }}
                  </span>
                </td>
                <td
                  class="px-6 py-4 whitespace-nowrap text-sm text-gray-900 dark:text-dark-text-primary"
                >
                  {{
                    finding.cvss_score !== null
                      ? finding.cvss_score.toFixed(1)
                      : "-"
                  }}
                </td>
                <td class="px-6 py-4">
                  <div
                    class="text-sm text-gray-900 dark:text-dark-text-primary"
                  >
                    {{ finding.asset_identifier }}
                  </div>
                  <div
                    class="text-xs text-gray-500 dark:text-dark-text-secondary capitalize"
                  >
                    {{ finding.asset_type }}
                  </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap">
                  <span
                    class="rounded-full px-2 py-1 text-xs font-semibold"
                    :class="getStatusBadgeClass(finding.status)"
                  >
                    {{ finding.status }}
                  </span>
                </td>
                <td
                  class="px-6 py-4 whitespace-nowrap text-sm text-gray-500 dark:text-dark-text-secondary"
                >
                  {{ formatDate(finding.first_seen) }}
                </td>
                <td class="px-6 py-4">
                  <div
                    v-if="
                      finding.evidence &&
                      Object.keys(finding.evidence).length > 0
                    "
                  >
                    <details class="text-xs">
                      <summary
                        class="cursor-pointer text-indigo-600 dark:text-indigo-400 hover:text-indigo-800 dark:hover:text-indigo-300"
                      >
                        View evidence
                      </summary>
                      <pre
                        class="mt-2 p-2 bg-gray-50 dark:bg-dark-bg-tertiary rounded text-xs text-gray-700 dark:text-dark-text-secondary overflow-auto max-w-xs max-h-32"
                        >{{ JSON.stringify(finding.evidence, null, 2) }}</pre
                      >
                    </details>
                  </div>
                  <span
                    v-else
                    class="text-sm text-gray-400 dark:text-dark-text-tertiary"
                    >-</span
                  >
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </template>

    <!-- Empty State (no report generated yet) -->
    <div
      v-if="!isLoading && !executiveReport && !technicalReport && !error"
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
          d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
        />
      </svg>
      <p class="mt-4 text-gray-500 dark:text-dark-text-secondary">
        Select a report type and click Generate to view your report
      </p>
    </div>
  </div>
</template>
