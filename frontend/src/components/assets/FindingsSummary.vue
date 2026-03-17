<script setup lang="ts">
import { useRouter } from "vue-router";
import {
  getSeverityBadgeClass,
  getFindingStatusBadgeClass,
} from "@/utils/severity";
import { formatDate } from "@/utils/formatters";
import type { Finding } from "@/api/types";
import { ShieldExclamationIcon } from "@heroicons/vue/24/outline";

interface Props {
  findings: Finding[];
  severityBreakdown: Record<string, number>;
}

defineProps<Props>();

const router = useRouter();

const getSeverityColor = getSeverityBadgeClass;
const getStatusBadge = getFindingStatusBadgeClass;

function getSeverityDot(severity: string): string {
  const colors: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
    info: "bg-gray-400",
  };
  return colors[severity.toLowerCase()] || "bg-gray-400";
}

function formatRelativeDate(dateString: string | undefined | null): string {
  return formatDate(dateString, "relative");
}
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
  >
    <div class="flex items-center gap-2 mb-5">
      <ShieldExclamationIcon
        class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
      />
      <h2
        class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
      >
        Findings
      </h2>
      <span
        class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
      >
        {{ findings.length }}
      </span>
    </div>

    <!-- Severity breakdown bar -->
    <div v-if="findings.length > 0" class="mb-5">
      <div
        class="flex h-2 rounded-full overflow-hidden bg-gray-100 dark:bg-dark-bg-tertiary"
      >
        <div
          v-if="severityBreakdown.critical"
          class="bg-red-500 transition-all duration-500"
          :style="{
            width: (severityBreakdown.critical / findings.length) * 100 + '%',
          }"
          :title="`Critical: ${severityBreakdown.critical}`"
        />
        <div
          v-if="severityBreakdown.high"
          class="bg-orange-500 transition-all duration-500"
          :style="{
            width: (severityBreakdown.high / findings.length) * 100 + '%',
          }"
          :title="`High: ${severityBreakdown.high}`"
        />
        <div
          v-if="severityBreakdown.medium"
          class="bg-yellow-500 transition-all duration-500"
          :style="{
            width: (severityBreakdown.medium / findings.length) * 100 + '%',
          }"
          :title="`Medium: ${severityBreakdown.medium}`"
        />
        <div
          v-if="severityBreakdown.low"
          class="bg-blue-500 transition-all duration-500"
          :style="{
            width: (severityBreakdown.low / findings.length) * 100 + '%',
          }"
          :title="`Low: ${severityBreakdown.low}`"
        />
        <div
          v-if="severityBreakdown.info"
          class="bg-gray-400 transition-all duration-500"
          :style="{
            width: (severityBreakdown.info / findings.length) * 100 + '%',
          }"
          :title="`Info: ${severityBreakdown.info}`"
        />
      </div>
      <div class="flex items-center gap-4 mt-2">
        <span
          v-for="(count, sev) in severityBreakdown"
          :key="sev"
          v-show="count > 0"
          class="inline-flex items-center gap-1.5 text-xs text-gray-600 dark:text-dark-text-secondary"
        >
          <span
            class="w-2 h-2 rounded-full"
            :class="getSeverityDot(String(sev))"
          />
          <span class="capitalize">{{ sev }}</span>
          <span class="font-semibold">{{ count }}</span>
        </span>
      </div>
    </div>

    <!-- Findings table -->
    <div v-if="findings.length > 0" class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-gray-200 dark:border-dark-border">
            <th
              class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-24"
            >
              Severity
            </th>
            <th
              class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              Name
            </th>
            <th
              class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              CVE
            </th>
            <th
              class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              CVSS
            </th>
            <th
              class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              Status
            </th>
            <th
              class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              Source
            </th>
            <th
              class="pb-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              Last Seen
            </th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-dark-border/50">
          <tr
            v-for="finding in findings"
            :key="finding.id"
            @click="router.push(`/findings/${finding.id}`)"
            class="cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 group"
          >
            <td class="py-3 pr-4">
              <span
                :class="[
                  'inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase',
                  getSeverityColor(finding.severity),
                ]"
              >
                {{ finding.severity }}
              </span>
            </td>
            <td class="py-3 pr-4">
              <span
                class="text-gray-900 dark:text-dark-text-primary font-medium group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors"
              >
                {{ finding.name }}
              </span>
            </td>
            <td class="py-3 pr-4">
              <span
                v-if="finding.cve_id"
                class="font-mono text-xs text-gray-600 dark:text-dark-text-secondary"
                >{{ finding.cve_id }}</span
              >
              <span v-else class="text-gray-400 dark:text-dark-text-tertiary"
                >--</span
              >
            </td>
            <td class="py-3 pr-4">
              <span
                v-if="finding.cvss_score"
                class="font-mono font-medium"
                :class="
                  finding.cvss_score >= 9
                    ? 'text-red-600 dark:text-red-400'
                    : finding.cvss_score >= 7
                      ? 'text-orange-600 dark:text-orange-400'
                      : 'text-gray-700 dark:text-dark-text-secondary'
                "
              >
                {{ finding.cvss_score.toFixed(1) }}
              </span>
              <span v-else class="text-gray-400 dark:text-dark-text-tertiary"
                >--</span
              >
            </td>
            <td class="py-3 pr-4">
              <span
                :class="[
                  'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize',
                  getStatusBadge(finding.status),
                ]"
              >
                {{ finding.status }}
              </span>
            </td>
            <td
              class="py-3 pr-4 text-gray-500 dark:text-dark-text-tertiary text-xs"
            >
              {{ finding.source }}
            </td>
            <td class="py-3 text-gray-500 dark:text-dark-text-tertiary text-xs">
              {{ formatRelativeDate(finding.last_seen) }}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
    <div v-else class="text-center py-8">
      <ShieldExclamationIcon
        class="h-10 w-10 text-gray-300 dark:text-gray-600 mx-auto mb-2"
      />
      <p class="text-sm text-gray-500 dark:text-dark-text-secondary">
        No findings reported
      </p>
    </div>
  </div>
</template>
