<script setup lang="ts">
import { computed } from "vue";
import { useRouter } from "vue-router";
import { getRiskScoreClasses } from "@/utils/severity";
import { formatDate } from "@/utils/formatters";
import { useRiskGauge } from "@/composables/useRiskGauge";
import type { Asset } from "@/api/types";
import {
  ArrowLeftIcon,
  ArrowPathIcon,
  CloudIcon,
  ClockIcon,
  ShieldCheckIcon,
  ServerStackIcon,
} from "@heroicons/vue/24/outline";

interface Props {
  asset: Asset;
  isRescanning: boolean;
  rescanMessage: string;
  parentAsset: Asset["parent_asset"] | null;
}

const props = defineProps<Props>();
const emit = defineEmits<{
  rescan: [];
}>();

const router = useRouter();

const riskScore = computed(() => props.asset.risk_score ?? 0);
const riskScoreColor = computed(() => getRiskScoreClasses(riskScore.value));
const { arc: riskGaugeArc } = useRiskGauge(riskScore, 38);

const assetTypeBadge = computed(() => {
  const t = props.asset.type || "unknown";
  const map: Record<string, { label: string; cls: string }> = {
    domain: {
      label: "Domain",
      cls: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    },
    subdomain: {
      label: "Subdomain",
      cls: "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400",
    },
    ip: {
      label: "IP Address",
      cls: "bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400",
    },
    url: {
      label: "URL",
      cls: "bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400",
    },
    service: {
      label: "Service",
      cls: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    },
  };
  return (
    map[t] || {
      label: t,
      cls: "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300",
    }
  );
});

const cloudProviderInfo = computed(() => {
  const provider = props.asset.cloud_provider;
  if (!provider) return null;
  const map: Record<string, { color: string }> = {
    AWS: {
      color:
        "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
    },
    GCP: {
      color: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    },
    Azure: {
      color: "bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400",
    },
    Cloudflare: {
      color:
        "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    },
    DigitalOcean: {
      color: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    },
  };
  return {
    name: provider,
    ...(map[provider] || {
      color: "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300",
    }),
  };
});

function formatRelativeDate(dateString: string | undefined | null): string {
  return formatDate(dateString, "relative");
}
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
  >
    <div
      class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4"
    >
      <!-- Left: back + title + badges -->
      <div class="flex items-start gap-4 min-w-0">
        <button
          @click="router.push('/assets')"
          class="mt-1 p-2 rounded-md text-gray-400 hover:text-gray-600 dark:hover:text-dark-text-primary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary transition-colors flex-shrink-0"
          title="Back to Assets"
        >
          <ArrowLeftIcon class="h-5 w-5" />
        </button>
        <div class="min-w-0">
          <h1
            class="text-2xl lg:text-3xl font-bold text-gray-900 dark:text-dark-text-primary truncate font-mono"
          >
            {{ asset.identifier }}
          </h1>
          <div class="mt-2 flex flex-wrap items-center gap-2">
            <!-- Asset type badge -->
            <span
              :class="[
                'inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold',
                assetTypeBadge.cls,
              ]"
            >
              {{ assetTypeBadge.label }}
            </span>
            <!-- Status badge -->
            <span
              v-if="asset.is_active"
              class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
            >
              <span
                class="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse-slow"
              />
              Active
            </span>
            <span
              v-else
              class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-400"
            >
              <span class="w-1.5 h-1.5 rounded-full bg-gray-400" />
              Inactive
            </span>
            <!-- Cloud provider badge -->
            <span
              v-if="cloudProviderInfo"
              :class="[
                'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold',
                cloudProviderInfo.color,
              ]"
            >
              <CloudIcon class="h-3.5 w-3.5" />
              {{ cloudProviderInfo.name }}
            </span>
            <!-- CDN badge -->
            <span
              v-if="asset.cdn_name"
              class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400"
            >
              <ShieldCheckIcon class="h-3.5 w-3.5" />
              CDN: {{ asset.cdn_name }}
            </span>
            <!-- WAF badge -->
            <span
              v-if="asset.waf_name"
              class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold bg-teal-100 text-teal-700 dark:bg-teal-900/30 dark:text-teal-400"
            >
              <ShieldCheckIcon class="h-3.5 w-3.5" />
              WAF: {{ asset.waf_name }}
            </span>
            <!-- Priority -->
            <span
              v-if="asset.priority"
              class="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary capitalize"
            >
              Priority: {{ asset.priority }}
            </span>
          </div>
          <!-- Timestamps row -->
          <div
            class="mt-3 flex flex-wrap items-center gap-4 text-xs text-gray-500 dark:text-dark-text-tertiary"
          >
            <span class="inline-flex items-center gap-1">
              <ClockIcon class="h-3.5 w-3.5" />
              First seen {{ formatRelativeDate(asset.first_seen) }}
            </span>
            <span class="inline-flex items-center gap-1">
              <ClockIcon class="h-3.5 w-3.5" />
              Last seen {{ formatRelativeDate(asset.last_seen) }}
            </span>
            <span
              v-if="asset.last_enriched_at"
              class="inline-flex items-center gap-1"
            >
              <ArrowPathIcon class="h-3.5 w-3.5" />
              Scanned {{ formatRelativeDate(asset.last_enriched_at) }}
            </span>
          </div>
        </div>
      </div>
      <!-- Right: Risk gauge + actions -->
      <div class="flex items-center gap-6 flex-shrink-0">
        <!-- Risk score gauge -->
        <div class="flex flex-col items-center">
          <svg viewBox="0 0 100 100" class="w-20 h-20">
            <!-- Background arc -->
            <circle
              cx="50"
              cy="50"
              r="38"
              fill="none"
              stroke="currentColor"
              stroke-width="7"
              stroke-dasharray="204 68"
              stroke-dashoffset="-34"
              stroke-linecap="round"
              class="text-gray-200 dark:text-gray-700"
            />
            <!-- Score arc -->
            <path
              v-if="riskGaugeArc"
              :d="riskGaugeArc"
              fill="none"
              :stroke="riskScoreColor.fill"
              stroke-width="7"
              stroke-linecap="round"
            />
            <!-- Score text -->
            <text
              x="50"
              y="46"
              text-anchor="middle"
              dominant-baseline="middle"
              :fill="riskScoreColor.fill"
              font-size="18"
              font-weight="bold"
            >
              {{ riskScore }}
            </text>
            <text
              x="50"
              y="62"
              text-anchor="middle"
              dominant-baseline="middle"
              fill="currentColor"
              font-size="8"
              class="text-gray-400 dark:text-gray-500"
            >
              RISK
            </text>
          </svg>
        </div>
        <!-- Action buttons -->
        <div class="flex flex-col gap-2">
          <button
            @click="emit('rescan')"
            :disabled="isRescanning"
            class="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 disabled:opacity-50 rounded-lg transition-colors"
          >
            <ArrowPathIcon
              class="h-4 w-4"
              :class="{ 'animate-spin': isRescanning }"
            />
            Rescan
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Rescan feedback -->
  <div
    v-if="rescanMessage"
    class="rounded-lg border p-4"
    :class="
      rescanMessage.includes('Failed')
        ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-800 dark:text-red-200'
        : 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-200'
    "
  >
    <p class="text-sm">{{ rescanMessage }}</p>
  </div>

  <!-- Parent asset banner (for SERVICE-type assets) -->
  <div
    v-if="parentAsset"
    class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 flex items-center justify-between"
  >
    <div class="flex items-center gap-3">
      <ServerStackIcon
        class="h-5 w-5 text-amber-600 dark:text-amber-400 flex-shrink-0"
      />
      <div>
        <p class="text-sm font-medium text-amber-800 dark:text-amber-200">
          This is a service-level asset. Data shown is inherited from the parent
          host.
        </p>
        <p class="text-xs text-amber-600 dark:text-amber-400 mt-0.5">
          Parent: <strong>{{ parentAsset.identifier }}</strong> ({{
            parentAsset.type
          }})
        </p>
      </div>
    </div>
    <button
      @click="router.push(`/assets/${parentAsset.id}`)"
      class="ml-4 px-3 py-1.5 text-xs font-medium rounded-md bg-amber-100 dark:bg-amber-800/40 text-amber-800 dark:text-amber-200 hover:bg-amber-200 dark:hover:bg-amber-800/60 transition-colors flex-shrink-0"
    >
      View Parent
    </button>
  </div>
</template>
