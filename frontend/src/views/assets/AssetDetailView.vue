<script setup lang="ts">
import { ref, onMounted, computed, watch } from "vue";
import { useRoute } from "vue-router";
import { useTenantStore } from "@/stores/tenant";
import { getRiskScoreClasses } from "@/utils/severity";
import { formatDate } from "@/utils/formatters";
import { assetApi } from "@/api/assets";
import type {
  Asset,
  Service,
  Finding,
  Certificate,
  AssetEvent,
  AssetSummary,
  AssetDnsInfo,
  AssetHttpInfo,
  AssetEndpoint,
} from "@/api/types";
import {
  GlobeAltIcon,
  ServerStackIcon,
  ShieldExclamationIcon,
  LockClosedIcon,
  LinkIcon,
  ClockIcon,
  ChevronDownIcon,
  ChevronUpIcon,
  ExclamationTriangleIcon,
  SignalIcon,
  CpuChipIcon,
  CommandLineIcon,
  CheckCircleIcon,
  FunnelIcon,
} from "@heroicons/vue/24/outline";

// Sub-components
import AssetHeaderCard from "@/components/assets/AssetHeaderCard.vue";
import DnsInfoPanel from "@/components/assets/DnsInfoPanel.vue";
import FindingsSummary from "@/components/assets/FindingsSummary.vue";
import CertificateGrid from "@/components/assets/CertificateGrid.vue";
import ScreenshotViewer from "@/components/assets/ScreenshotViewer.vue";

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const route = useRoute();
const tenantStore = useTenantStore();

const assetId = computed(() => parseInt(route.params.id as string));
const asset = ref<Asset | null>(null);
const services = ref<Service[]>([]);
const findings = ref<Finding[]>([]);
const certificates = ref<Certificate[]>([]);
const events = ref<AssetEvent[]>([]);
const endpoints = ref<AssetEndpoint[]>([]);
const summary = ref<AssetSummary | null>(null);
const dnsInfo = ref<AssetDnsInfo | null>(null);
const techStack = ref<string[]>([]);
const httpInfo = ref<AssetHttpInfo[]>([]);
const parentAsset = ref<Asset["parent_asset"] | null>(null);

interface Screenshot {
  full: string;
  thumb: string;
  service_id: number;
  captured_at: string;
  http_status: number;
}

const isLoading = ref(true);
const isRescanning = ref(false);
const error = ref("");
const screenshots = ref<Screenshot[]>([]);
const screenshotViewerRef = ref<InstanceType<typeof ScreenshotViewer> | null>(
  null,
);

// Collapsible section states
const showEndpoints = ref(false);
const showEvents = ref(false);

// Endpoint filter
const endpointTypeFilter = ref("all");

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

async function loadAssetDetails() {
  try {
    isLoading.value = true;
    error.value = "";

    if (!tenantStore.currentTenantId) {
      await tenantStore.fetchTenants();
    }

    if (!tenantStore.currentTenantId) {
      error.value = "No tenant available";
      return;
    }

    const assetDetails = await assetApi.get(
      tenantStore.currentTenantId,
      assetId.value,
    );

    if (!assetDetails) {
      error.value = "Asset not found";
      return;
    }

    asset.value = assetDetails;
    services.value = assetDetails.services || [];
    findings.value = assetDetails.findings || [];
    certificates.value = assetDetails.certificates || [];
    events.value = assetDetails.events || [];
    endpoints.value = assetDetails.endpoints || [];
    summary.value = assetDetails.summary || null;
    dnsInfo.value = assetDetails.dns_info || null;
    techStack.value = assetDetails.tech_stack || [];
    httpInfo.value = assetDetails.http_info || [];
    parentAsset.value = assetDetails.parent_asset || null;

    // Load screenshots
    try {
      const { default: apiClient } = await import("@/api/client");
      const screenshotResp = await apiClient.get(
        `/api/v1/tenants/${tenantStore.currentTenantId}/assets/${assetId.value}/screenshots`,
      );
      screenshots.value = screenshotResp.data.screenshots || [];
    } catch {
      screenshots.value = [];
    }
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } } };
    error.value =
      axiosErr.response?.data?.detail || "Failed to load asset details";
  } finally {
    isLoading.value = false;
  }
}

const rescanMessage = ref("");

async function handleRescan() {
  if (!tenantStore.currentTenantId || !asset.value) return;
  isRescanning.value = true;
  rescanMessage.value = "";
  try {
    const { default: apiClient } = await import("@/api/client");
    await apiClient.post(
      `/api/v1/tenants/${tenantStore.currentTenantId}/assets/${asset.value.id}/rescan`,
    );
    rescanMessage.value = "Rescan queued. Results will appear shortly.";
    // Reload after a delay to pick up new data
    setTimeout(() => {
      loadAssetDetails();
      rescanMessage.value = "";
    }, 10000);
  } catch (err: unknown) {
    const axiosErr = err as {
      response?: { data?: { detail?: string } };
      message?: string;
    };
    rescanMessage.value =
      axiosErr.response?.data?.detail || "Failed to trigger rescan";
  } finally {
    isRescanning.value = false;
  }
}

// ---------------------------------------------------------------------------
// Computed helpers
// ---------------------------------------------------------------------------

const riskScore = computed(() => asset.value?.risk_score ?? 0);

const riskScoreColor = computed(() => getRiskScoreClasses(riskScore.value));

const openFindings = computed(() =>
  findings.value.filter((f: Finding) => f.status === "open"),
);

const severityBreakdown = computed(() => {
  if (summary.value?.severity_breakdown)
    return summary.value.severity_breakdown;
  const breakdown: Record<string, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };
  for (const f of openFindings.value) {
    const sev = f.severity?.toLowerCase();
    if (sev && sev in breakdown) {
      breakdown[sev]++;
    }
  }
  return breakdown;
});

const expiringCerts = computed(() =>
  certificates.value.filter(
    (c: Certificate) =>
      !c.is_expired &&
      c.days_until_expiry !== undefined &&
      c.days_until_expiry <= 30,
  ),
);

const cloudProviderInfo = computed(() => {
  const provider = asset.value?.cloud_provider || dnsInfo.value?.cloud_provider;
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

// Group tech by approximate category
const groupedTech = computed(() => {
  if (techStack.value.length === 0) return {};
  const webServers = [
    "nginx",
    "apache",
    "iis",
    "caddy",
    "litespeed",
    "lighttpd",
    "openresty",
  ];
  const frameworks = [
    "react",
    "vue",
    "angular",
    "next.js",
    "nuxt",
    "svelte",
    "django",
    "flask",
    "rails",
    "laravel",
    "express",
    "spring",
    "asp.net",
  ];
  const cms = [
    "wordpress",
    "drupal",
    "joomla",
    "ghost",
    "strapi",
    "contentful",
    "shopify",
    "magento",
    "woocommerce",
  ];
  const jsLibs = [
    "jquery",
    "bootstrap",
    "tailwind",
    "lodash",
    "moment.js",
    "axios",
    "three.js",
    "d3.js",
  ];
  const cdns = [
    "cloudflare",
    "akamai",
    "fastly",
    "cloudfront",
    "stackpath",
    "bunnycdn",
  ];
  const languages = [
    "php",
    "python",
    "java",
    "ruby",
    "node.js",
    "go",
    ".net",
    "perl",
  ];

  const groups: Record<string, string[]> = {};
  for (const tech of techStack.value) {
    const lower = tech.toLowerCase();
    let category = "Other";
    if (webServers.some((ws) => lower.includes(ws))) category = "Web Server";
    else if (frameworks.some((fw) => lower.includes(fw)))
      category = "Framework";
    else if (cms.some((c) => lower.includes(c))) category = "CMS";
    else if (jsLibs.some((lib) => lower.includes(lib))) category = "JS Library";
    else if (cdns.some((cdn) => lower.includes(cdn))) category = "CDN";
    else if (languages.some((lang) => lower.includes(lang)))
      category = "Language";

    if (!groups[category]) groups[category] = [];
    groups[category].push(tech);
  }
  return groups;
});

const filteredEndpoints = computed(() => {
  if (endpointTypeFilter.value === "all") return endpoints.value;
  return endpoints.value.filter(
    (e: AssetEndpoint) => e.endpoint_type === endpointTypeFilter.value,
  );
});

const endpointTypes = computed(() => {
  const types = new Set(
    endpoints.value.map((e: AssetEndpoint) => e.endpoint_type).filter(Boolean),
  );
  return ["all", ...Array.from(types)];
});

const openPortsList = computed((): number[] => {
  if (summary.value?.open_ports?.length) return summary.value.open_ports;
  const ports: number[] = services.value
    .map((s: Service) => s.port)
    .filter(
      (p: number | undefined): p is number => p !== undefined && p !== null,
    );
  return Array.from(new Set<number>(ports)).sort(
    (a: number, b: number) => a - b,
  );
});

const servicesWithTlsCount = computed(
  () => services.value.filter((s: Service) => s.has_tls).length,
);
const apiEndpointsCount = computed(
  () => endpoints.value.filter((e: AssetEndpoint) => e.is_api).length,
);

// ---------------------------------------------------------------------------
// Well-known port to service name mapping
// ---------------------------------------------------------------------------

const WELL_KNOWN_PORTS: Record<number, { name: string; proto: string }> = {
  21: { name: "FTP", proto: "ftp" },
  22: { name: "SSH", proto: "ssh" },
  23: { name: "Telnet", proto: "telnet" },
  25: { name: "SMTP", proto: "smtp" },
  53: { name: "DNS", proto: "dns" },
  80: { name: "HTTP", proto: "http" },
  110: { name: "POP3", proto: "pop3" },
  143: { name: "IMAP", proto: "imap" },
  443: { name: "HTTPS", proto: "https" },
  445: { name: "SMB", proto: "smb" },
  465: { name: "SMTPS", proto: "smtps" },
  587: { name: "SMTP Submission", proto: "submission" },
  993: { name: "IMAPS", proto: "imaps" },
  995: { name: "POP3S", proto: "pop3s" },
  1433: { name: "MSSQL", proto: "mssql" },
  1521: { name: "Oracle DB", proto: "oracle" },
  3306: { name: "MySQL", proto: "mysql" },
  3389: { name: "RDP", proto: "rdp" },
  4443: { name: "HTTPS Alt", proto: "https" },
  5222: { name: "XMPP Client", proto: "xmpp" },
  5269: { name: "XMPP Server", proto: "xmpp-s2s" },
  5280: { name: "XMPP HTTP", proto: "xmpp-bosh" },
  5432: { name: "PostgreSQL", proto: "postgres" },
  5672: { name: "AMQP", proto: "amqp" },
  6379: { name: "Redis", proto: "redis" },
  8080: { name: "HTTP Proxy", proto: "http-proxy" },
  8443: { name: "HTTPS Alt", proto: "https-alt" },
  8888: { name: "HTTP Alt", proto: "http-alt" },
  9090: { name: "HTTP Admin", proto: "http-admin" },
  9200: { name: "Elasticsearch", proto: "elasticsearch" },
  9999: { name: "HTTP Admin", proto: "http-admin" },
  27017: { name: "MongoDB", proto: "mongodb" },
};

function getServiceName(service: Service): string {
  if (
    service.protocol &&
    service.protocol !== "tcp" &&
    service.protocol !== "udp"
  )
    return service.protocol.toUpperCase();
  if (service.port && WELL_KNOWN_PORTS[service.port])
    return WELL_KNOWN_PORTS[service.port].name;
  return "Unknown";
}

/** Parse version field which may contain "product/version" or just "product" */
function parseProductVersion(service: Service): {
  product: string;
  version: string;
} {
  const ver = service.version || "";
  if (ver.includes("/")) {
    const [prod, ...rest] = ver.split("/");
    return { product: prod, version: rest.join("/") };
  }
  if (ver && !/^\d/.test(ver)) {
    return { product: ver, version: "" };
  }
  return { product: "", version: ver };
}

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

function getMethodBadge(method: string): string {
  const colors: Record<string, string> = {
    GET: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    POST: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    PUT: "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    PATCH:
      "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    DELETE: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
  };
  return (
    colors[method?.toUpperCase()] ||
    "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300"
  );
}

function getEventKindBadge(kind: string): string {
  const colors: Record<string, string> = {
    new_asset:
      "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    open_port:
      "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
    new_cert:
      "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    new_path:
      "bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400",
    finding: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
  };
  return (
    colors[kind.toLowerCase()] ||
    "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300"
  );
}

function formatRelativeDate(dateString: string | undefined | null): string {
  return formatDate(dateString, "relative");
}

function httpStatusClass(code: number): string {
  if (code >= 200 && code < 300) return "text-green-600 dark:text-green-400";
  if (code >= 300 && code < 400) return "text-blue-600 dark:text-blue-400";
  if (code >= 400 && code < 500) return "text-orange-600 dark:text-orange-400";
  if (code >= 500) return "text-red-600 dark:text-red-400";
  return "text-gray-600 dark:text-gray-400";
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

onMounted(() => {
  loadAssetDetails();
});

// Reload when navigating between assets (e.g. View Parent)
watch(assetId, () => {
  loadAssetDetails();
});
</script>

<template>
  <div class="max-w-7xl mx-auto">
    <!-- ================================================================== -->
    <!-- ERROR STATE                                                        -->
    <!-- ================================================================== -->
    <div
      v-if="error"
      role="alert"
      class="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 mb-6"
    >
      <div class="flex items-center gap-3">
        <ExclamationTriangleIcon
          class="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0"
        />
        <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
      </div>
    </div>

    <!-- ================================================================== -->
    <!-- LOADING STATE                                                      -->
    <!-- ================================================================== -->
    <div v-if="isLoading" role="status" class="space-y-6">
      <!-- Skeleton header -->
      <div
        class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
      >
        <div class="animate-pulse space-y-4">
          <div class="flex items-center gap-4">
            <div class="h-5 w-5 bg-gray-200 dark:bg-gray-700 rounded" />
            <div class="h-8 bg-gray-200 dark:bg-gray-700 rounded w-80" />
          </div>
          <div class="flex gap-3">
            <div class="h-6 bg-gray-200 dark:bg-gray-700 rounded w-20" />
            <div class="h-6 bg-gray-200 dark:bg-gray-700 rounded w-16" />
            <div class="h-6 bg-gray-200 dark:bg-gray-700 rounded w-24" />
          </div>
        </div>
      </div>
      <!-- Skeleton KPI row -->
      <div class="grid grid-cols-2 lg:grid-cols-6 gap-4">
        <div
          v-for="n in 6"
          :key="n"
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4"
        >
          <div class="animate-pulse space-y-2">
            <div class="h-3 bg-gray-200 dark:bg-gray-700 rounded w-16" />
            <div class="h-7 bg-gray-200 dark:bg-gray-700 rounded w-10" />
          </div>
        </div>
      </div>
      <!-- Skeleton cards -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div
          v-for="n in 4"
          :key="n"
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
        >
          <div class="animate-pulse space-y-3">
            <div class="h-5 bg-gray-200 dark:bg-gray-700 rounded w-40" />
            <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-full" />
            <div class="h-4 bg-gray-200 dark:bg-gray-700 rounded w-3/4" />
          </div>
        </div>
      </div>
    </div>

    <!-- ================================================================== -->
    <!-- MAIN CONTENT                                                       -->
    <!-- ================================================================== -->
    <div v-else-if="asset" class="space-y-6">
      <!-- ================================================================ -->
      <!-- 1. HEADER SECTION (extracted)                                    -->
      <!-- ================================================================ -->
      <AssetHeaderCard
        :asset="asset"
        :is-rescanning="isRescanning"
        :rescan-message="rescanMessage"
        :parent-asset="parentAsset"
        @rescan="handleRescan"
      />

      <!-- ================================================================ -->
      <!-- 2. SUMMARY KPI CARDS                                             -->
      <!-- ================================================================ -->
      <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <!-- Open Ports -->
        <div
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4"
        >
          <div class="flex items-center gap-2 mb-2">
            <SignalIcon
              class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary"
            />
            <span
              class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
              >Open Ports</span
            >
          </div>
          <p
            class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary"
          >
            {{ openPortsList.length }}
          </p>
          <p
            v-if="openPortsList.length > 0"
            class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary truncate"
            :title="openPortsList.join(', ')"
          >
            {{ openPortsList.slice(0, 5).join(", ")
            }}<span v-if="openPortsList.length > 5">...</span>
          </p>
          <p
            v-else
            class="mt-1 text-xs text-gray-400 dark:text-dark-text-tertiary"
          >
            None detected
          </p>
        </div>

        <!-- Open Findings -->
        <div
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4"
        >
          <div class="flex items-center gap-2 mb-2">
            <ShieldExclamationIcon
              class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary"
            />
            <span
              class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
              >Findings</span
            >
          </div>
          <p
            class="text-2xl font-bold"
            :class="
              openFindings.length > 0
                ? 'text-red-600 dark:text-red-400'
                : 'text-gray-900 dark:text-dark-text-primary'
            "
          >
            {{ summary?.open_findings ?? openFindings.length }}
          </p>
          <div class="mt-1 flex items-center gap-1 flex-wrap">
            <span
              v-if="severityBreakdown.critical"
              class="inline-flex items-center text-[10px] font-bold px-1 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
              >{{ severityBreakdown.critical }}C</span
            >
            <span
              v-if="severityBreakdown.high"
              class="inline-flex items-center text-[10px] font-bold px-1 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400"
              >{{ severityBreakdown.high }}H</span
            >
            <span
              v-if="severityBreakdown.medium"
              class="inline-flex items-center text-[10px] font-bold px-1 py-0.5 rounded bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400"
              >{{ severityBreakdown.medium }}M</span
            >
          </div>
        </div>

        <!-- Services -->
        <div
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4"
        >
          <div class="flex items-center gap-2 mb-2">
            <ServerStackIcon
              class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary"
            />
            <span
              class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
              >Services</span
            >
          </div>
          <p
            class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary"
          >
            {{ summary?.total_services ?? services.length }}
          </p>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary">
            {{ servicesWithTlsCount }} with TLS
          </p>
        </div>

        <!-- Certificates -->
        <div
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4"
        >
          <div class="flex items-center gap-2 mb-2">
            <LockClosedIcon
              class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary"
            />
            <span
              class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
              >Certificates</span
            >
          </div>
          <p
            class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary"
          >
            {{ summary?.total_certificates ?? certificates.length }}
          </p>
          <p
            v-if="expiringCerts.length > 0"
            class="mt-1 text-xs text-orange-600 dark:text-orange-400 font-medium"
          >
            {{ expiringCerts.length }} expiring soon
          </p>
          <p v-else class="mt-1 text-xs text-green-600 dark:text-green-400">
            All valid
          </p>
        </div>

        <!-- Endpoints -->
        <div
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4"
        >
          <div class="flex items-center gap-2 mb-2">
            <LinkIcon
              class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary"
            />
            <span
              class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
              >Endpoints</span
            >
          </div>
          <p
            class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary"
          >
            {{ summary?.total_endpoints ?? endpoints.length }}
          </p>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary">
            {{ apiEndpointsCount }} API
          </p>
        </div>

        <!-- Risk Score mini -->
        <div
          class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4"
        >
          <div class="flex items-center gap-2 mb-2">
            <ExclamationTriangleIcon
              class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary"
            />
            <span
              class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
              >Risk</span
            >
          </div>
          <p class="text-2xl font-bold" :class="riskScoreColor.text">
            {{ riskScore
            }}<span
              class="text-sm font-normal text-gray-400 dark:text-dark-text-tertiary"
              >/100</span
            >
          </p>
          <div
            class="mt-1.5 w-full h-1.5 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden"
          >
            <div
              class="h-full rounded-full transition-all duration-500"
              :class="riskScoreColor.bg"
              :style="{ width: riskScore + '%' }"
            />
          </div>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 3. DNS & NETWORK INTELLIGENCE (extracted)                        -->
      <!-- ================================================================ -->
      <DnsInfoPanel
        v-if="dnsInfo"
        :dns-info="dnsInfo"
        :cloud-provider="cloudProviderInfo"
      />

      <!-- ================================================================ -->
      <!-- 4. TECHNOLOGY STACK                                              -->
      <!-- ================================================================ -->
      <div
        v-if="techStack.length > 0"
        class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
      >
        <div class="flex items-center gap-2 mb-5">
          <CpuChipIcon
            class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
          />
          <h2
            class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
          >
            Technology Stack
          </h2>
          <span
            class="ml-auto text-xs text-gray-400 dark:text-dark-text-tertiary"
            >{{ techStack.length }} technologies detected</span
          >
        </div>
        <!-- If grouped -->
        <div v-if="Object.keys(groupedTech).length > 1" class="space-y-4">
          <div v-for="(techs, category) in groupedTech" :key="category">
            <h3
              class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
            >
              {{ category }}
            </h3>
            <div class="flex flex-wrap gap-2">
              <span
                v-for="tech in techs"
                :key="tech"
                class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-gray-50 text-gray-700 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary border border-gray-200 dark:border-dark-border"
              >
                <CommandLineIcon class="h-3.5 w-3.5 text-gray-400" />
                {{ tech }}
              </span>
            </div>
          </div>
        </div>
        <!-- If single group or ungrouped -->
        <div v-else class="flex flex-wrap gap-2">
          <span
            v-for="tech in techStack"
            :key="tech"
            class="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium bg-gray-50 text-gray-700 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary border border-gray-200 dark:border-dark-border"
          >
            <CommandLineIcon class="h-3.5 w-3.5 text-gray-400" />
            {{ tech }}
          </span>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 5. HTTP SERVICES                                                 -->
      <!-- ================================================================ -->
      <div
        v-if="httpInfo.length > 0"
        class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
      >
        <div class="flex items-center gap-2 mb-5">
          <GlobeAltIcon
            class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
          />
          <h2
            class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
          >
            HTTP Services
          </h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 dark:border-dark-border">
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Port
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Status
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Title
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Web Server
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  TLS
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Response
                </th>
                <th
                  class="pb-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Technologies
                </th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-border/50">
              <tr
                v-for="http in httpInfo"
                :key="http.port"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50"
              >
                <td
                  class="py-3 pr-4 font-mono font-medium text-gray-900 dark:text-dark-text-primary"
                >
                  {{ http.port }}
                </td>
                <td class="py-3 pr-4">
                  <span
                    class="font-mono font-medium"
                    :class="httpStatusClass(http.status_code)"
                    >{{ http.status_code }}</span
                  >
                </td>
                <td
                  class="py-3 pr-4 text-gray-700 dark:text-dark-text-secondary max-w-xs truncate"
                  :title="http.title"
                >
                  {{ http.title || "--" }}
                </td>
                <td
                  class="py-3 pr-4 text-gray-700 dark:text-dark-text-secondary"
                >
                  {{ http.web_server || "--" }}
                </td>
                <td class="py-3 pr-4">
                  <span
                    v-if="http.has_tls"
                    class="inline-flex items-center gap-1 text-green-600 dark:text-green-400"
                  >
                    <LockClosedIcon class="h-3.5 w-3.5" />
                    {{ http.tls_version || "Yes" }}
                  </span>
                  <span
                    v-else
                    class="text-gray-400 dark:text-dark-text-tertiary"
                    >--</span
                  >
                </td>
                <td
                  class="py-3 pr-4 text-gray-700 dark:text-dark-text-secondary"
                >
                  <span
                    v-if="http.response_time_ms"
                    :class="
                      http.response_time_ms > 2000
                        ? 'text-orange-600 dark:text-orange-400'
                        : ''
                    "
                  >
                    {{ http.response_time_ms }}ms
                  </span>
                  <span v-else>--</span>
                </td>
                <td class="py-3">
                  <div class="flex flex-wrap gap-1 max-w-xs">
                    <span
                      v-for="tech in (http.technologies || []).slice(0, 4)"
                      :key="tech"
                      class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
                    >
                      {{ tech }}
                    </span>
                    <span
                      v-if="(http.technologies || []).length > 4"
                      class="text-[10px] text-gray-400"
                    >
                      +{{ http.technologies.length - 4 }}
                    </span>
                  </div>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 6. OPEN PORTS & SERVICES TABLE                                   -->
      <!-- ================================================================ -->
      <div
        class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
      >
        <div class="flex items-center gap-2 mb-5">
          <ServerStackIcon
            class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
          />
          <h2
            class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
          >
            Services
          </h2>
          <span
            class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
          >
            {{ services.length }}
          </span>
        </div>
        <div v-if="services.length > 0" class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 dark:border-dark-border">
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Port
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Service
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Product / Version
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  TLS
                </th>
                <th
                  class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                >
                  Fingerprint
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
                v-for="service in services"
                :key="service.id"
                class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50"
              >
                <td class="py-3 pr-4">
                  <span
                    class="font-mono font-semibold text-gray-900 dark:text-dark-text-primary"
                    >{{ service.port ?? "--" }}</span
                  >
                  <span
                    class="text-gray-400 dark:text-dark-text-tertiary text-xs"
                    >/{{ service.protocol || "tcp" }}</span
                  >
                </td>
                <td class="py-3 pr-4">
                  <span
                    class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300"
                  >
                    {{ getServiceName(service) }}
                  </span>
                  <p
                    v-if="service.http_title"
                    class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-1 truncate max-w-[200px]"
                  >
                    {{ service.http_title }}
                  </p>
                  <p
                    v-if="service.web_server"
                    class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-0.5"
                  >
                    {{ service.web_server }}
                  </p>
                </td>
                <td class="py-3 pr-4">
                  <template
                    v-if="
                      service.version ||
                      (service.product &&
                        service.product !== service.protocol?.toUpperCase())
                    "
                  >
                    <span
                      v-if="parseProductVersion(service).product"
                      class="text-gray-900 dark:text-dark-text-primary font-medium"
                      >{{ parseProductVersion(service).product }}</span
                    >
                    <span
                      v-if="parseProductVersion(service).version"
                      class="ml-1 font-mono text-xs text-gray-500 dark:text-dark-text-tertiary"
                      >{{ parseProductVersion(service).version }}</span
                    >
                  </template>
                  <span
                    v-else
                    class="text-gray-400 dark:text-dark-text-tertiary"
                    >--</span
                  >
                  <div v-if="service.http_status" class="mt-0.5">
                    <span
                      class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono"
                      :class="
                        service.http_status < 300
                          ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300'
                          : service.http_status < 400
                            ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300'
                            : 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                      "
                    >
                      HTTP {{ service.http_status }}
                    </span>
                  </div>
                </td>
                <td class="py-3 pr-4">
                  <span
                    v-if="service.has_tls"
                    class="inline-flex items-center gap-1 text-green-600 dark:text-green-400 text-xs font-medium"
                  >
                    <LockClosedIcon class="h-3.5 w-3.5" />
                    {{ service.tls_version || "Yes" }}
                  </span>
                  <span
                    v-else
                    class="text-gray-400 dark:text-dark-text-tertiary text-xs"
                    >--</span
                  >
                </td>
                <td class="py-3 pr-4">
                  <span
                    v-if="service.tls_fingerprint"
                    class="font-mono text-xs text-gray-500 dark:text-dark-text-tertiary truncate max-w-[120px] block"
                    :title="service.tls_fingerprint"
                  >
                    {{ service.tls_fingerprint.substring(0, 16) }}...
                  </span>
                  <span
                    v-else
                    class="text-gray-400 dark:text-dark-text-tertiary text-xs"
                    >--</span
                  >
                </td>
                <td class="py-3 pr-4">
                  <span
                    v-if="service.enrichment_source"
                    class="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
                  >
                    {{ service.enrichment_source }}
                  </span>
                  <span
                    v-else
                    class="text-gray-400 dark:text-dark-text-tertiary text-xs"
                    >--</span
                  >
                </td>
                <td
                  class="py-3 text-gray-500 dark:text-dark-text-tertiary text-xs"
                >
                  {{ formatRelativeDate(service.last_seen) }}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="text-center py-8">
          <ServerStackIcon
            class="h-10 w-10 text-gray-300 dark:text-gray-600 mx-auto mb-2"
          />
          <p class="text-sm text-gray-500 dark:text-dark-text-secondary">
            No services discovered
          </p>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 7. FINDINGS (extracted)                                          -->
      <!-- ================================================================ -->
      <FindingsSummary
        :findings="findings"
        :severity-breakdown="severityBreakdown"
      />

      <!-- ================================================================ -->
      <!-- 8. TLS CERTIFICATES (extracted)                                  -->
      <!-- ================================================================ -->
      <CertificateGrid
        v-if="certificates.length > 0"
        :certificates="certificates"
      />

      <!-- ================================================================ -->
      <!-- 9. DISCOVERED ENDPOINTS (collapsible)                            -->
      <!-- ================================================================ -->
      <div
        v-if="endpoints.length > 0"
        class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg"
      >
        <!-- Toggle header -->
        <button
          @click="showEndpoints = !showEndpoints"
          class="w-full flex items-center justify-between p-6 text-left hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 transition-colors rounded-lg"
        >
          <div class="flex items-center gap-2">
            <LinkIcon
              class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
            />
            <h2
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Discovered Endpoints
            </h2>
            <span
              class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
            >
              {{ endpoints.length }}
            </span>
          </div>
          <ChevronDownIcon
            v-if="!showEndpoints"
            class="h-5 w-5 text-gray-400"
          />
          <ChevronUpIcon v-else class="h-5 w-5 text-gray-400" />
        </button>

        <!-- Content -->
        <div v-if="showEndpoints" class="px-6 pb-6">
          <!-- Filter -->
          <div class="flex items-center gap-2 mb-4">
            <FunnelIcon class="h-4 w-4 text-gray-400" />
            <select
              v-model="endpointTypeFilter"
              class="text-xs border border-gray-300 dark:border-dark-border bg-white dark:bg-dark-bg-tertiary text-gray-700 dark:text-dark-text-secondary rounded-md px-2 py-1 focus:outline-none focus:ring-1 focus:ring-primary-500"
            >
              <option v-for="t in endpointTypes" :key="t" :value="t">
                {{ t === "all" ? "All Types" : t }}
              </option>
            </select>
            <span class="text-xs text-gray-500 dark:text-dark-text-tertiary"
              >{{ filteredEndpoints.length }} results</span
            >
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-gray-200 dark:border-dark-border">
                  <th
                    class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-20"
                  >
                    Method
                  </th>
                  <th
                    class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                  >
                    Path
                  </th>
                  <th
                    class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-16"
                  >
                    Status
                  </th>
                  <th
                    class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
                  >
                    Type
                  </th>
                  <th
                    class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-12"
                  >
                    API
                  </th>
                  <th
                    class="pb-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-16"
                  >
                    Depth
                  </th>
                </tr>
              </thead>
              <tbody
                class="divide-y divide-gray-100 dark:divide-dark-border/50"
              >
                <tr
                  v-for="ep in filteredEndpoints.slice(0, 50)"
                  :key="ep.id"
                  class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50"
                >
                  <td class="py-2.5 pr-4">
                    <span
                      :class="[
                        'inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold',
                        getMethodBadge(ep.method),
                      ]"
                    >
                      {{ ep.method }}
                    </span>
                  </td>
                  <td
                    class="py-2.5 pr-4 font-mono text-xs text-gray-700 dark:text-dark-text-secondary truncate max-w-sm"
                    :title="ep.path"
                  >
                    {{ ep.path }}
                  </td>
                  <td
                    class="py-2.5 pr-4 font-mono text-xs"
                    :class="httpStatusClass(ep.status_code)"
                  >
                    {{ ep.status_code }}
                  </td>
                  <td
                    class="py-2.5 pr-4 text-xs text-gray-500 dark:text-dark-text-tertiary capitalize"
                  >
                    {{ ep.endpoint_type || "--" }}
                  </td>
                  <td class="py-2.5 pr-4">
                    <CheckCircleIcon
                      v-if="ep.is_api"
                      class="h-4 w-4 text-green-500"
                    />
                    <span v-else class="text-gray-300 dark:text-gray-600"
                      >--</span
                    >
                  </td>
                  <td
                    class="py-2.5 text-xs text-gray-500 dark:text-dark-text-tertiary"
                  >
                    {{ ep.depth }}
                  </td>
                </tr>
              </tbody>
            </table>
            <p
              v-if="filteredEndpoints.length > 50"
              class="mt-3 text-xs text-gray-500 dark:text-dark-text-tertiary text-center"
            >
              Showing 50 of {{ filteredEndpoints.length }} endpoints
            </p>
          </div>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- SCREENSHOTS (extracted)                                          -->
      <!-- ================================================================ -->
      <ScreenshotViewer
        v-if="screenshots.length > 0"
        ref="screenshotViewerRef"
        :screenshots="screenshots"
        :asset-id="assetId"
      />

      <!-- ================================================================ -->
      <!-- 10. TIMELINE / EVENTS (collapsible)                              -->
      <!-- ================================================================ -->
      <div
        v-if="events.length > 0"
        class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg"
      >
        <!-- Toggle header -->
        <button
          @click="showEvents = !showEvents"
          class="w-full flex items-center justify-between p-6 text-left hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 transition-colors rounded-lg"
        >
          <div class="flex items-center gap-2">
            <ClockIcon
              class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
            />
            <h2
              class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
            >
              Timeline
            </h2>
            <span
              class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
            >
              {{ events.length }}
            </span>
          </div>
          <ChevronDownIcon v-if="!showEvents" class="h-5 w-5 text-gray-400" />
          <ChevronUpIcon v-else class="h-5 w-5 text-gray-400" />
        </button>

        <!-- Content -->
        <div v-if="showEvents" class="px-6 pb-6">
          <div class="relative">
            <!-- Timeline line -->
            <div
              class="absolute left-3 top-0 bottom-0 w-px bg-gray-200 dark:bg-dark-border"
            />
            <div class="space-y-4">
              <div
                v-for="event in events.slice(0, 30)"
                :key="event.id"
                class="relative flex items-start gap-4 pl-8"
              >
                <!-- Dot -->
                <div
                  class="absolute left-1.5 top-1.5 w-3 h-3 rounded-full border-2 border-white dark:border-dark-bg-secondary bg-gray-400 dark:bg-gray-500"
                />
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span
                      :class="[
                        'inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase',
                        getEventKindBadge(event.kind),
                      ]"
                    >
                      {{ event.kind.replace(/_/g, " ") }}
                    </span>
                    <span
                      class="text-xs text-gray-500 dark:text-dark-text-tertiary"
                      >{{ formatRelativeDate(event.created_at) }}</span
                    >
                  </div>
                  <p
                    v-if="event.payload"
                    class="mt-1 text-xs text-gray-600 dark:text-dark-text-secondary"
                  >
                    {{
                      typeof event.payload === "string"
                        ? event.payload
                        : JSON.stringify(event.payload).slice(0, 120)
                    }}
                  </p>
                </div>
              </div>
            </div>
            <p
              v-if="events.length > 30"
              class="mt-4 text-xs text-gray-500 dark:text-dark-text-tertiary text-center pl-8"
            >
              Showing 30 of {{ events.length }} events
            </p>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
