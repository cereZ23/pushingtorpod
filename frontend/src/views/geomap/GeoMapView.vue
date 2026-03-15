<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch, nextTick } from "vue";
import { useTenantStore } from "@/stores/tenant";
import apiClient from "@/api/client";
import L from "leaflet";
import "leaflet/dist/leaflet.css";

// -- Types --

interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface GeoFeatureProperties {
  id: number;
  identifier: string;
  type: string;
  risk_score: number;
  ip: string | null;
  country: string | null;
  country_code: string | null;
  city: string | null;
  region: string | null;
  asn: number | null;
  asn_org: string | null;
  isp: string | null;
  cdn: string | null;
  waf: string | null;
  cloud_provider: string | null;
  findings: FindingCounts;
  total_findings: number;
}

interface GeoFeature {
  type: "Feature";
  geometry: {
    type: "Point";
    coordinates: [number, number]; // [lng, lat]
  };
  properties: GeoFeatureProperties;
}

interface GeoFeatureCollection {
  type: "FeatureCollection";
  features: GeoFeature[];
}

interface CountrySummary {
  country_code: string;
  country: string;
  count: number;
  avg_risk: number;
}

interface ProviderEntry {
  name: string;
  count: number;
}

interface GeoSummary {
  total_geolocated: number;
  total_assets: number;
  countries: CountrySummary[];
  cloud_providers: ProviderEntry[];
  cdn_providers: ProviderEntry[];
  waf_providers: ProviderEntry[];
}

// -- State --

const tenantStore = useTenantStore();
const currentTenantId = computed(() => tenantStore.currentTenantId);

const isLoading = ref(true);
const error = ref("");
const mapContainerRef = ref<HTMLDivElement | null>(null);
let mapInstance: L.Map | null = null;
let markersLayer: L.LayerGroup | null = null;

const features = ref<GeoFeature[]>([]);
const summaryData = ref<GeoSummary>({
  total_geolocated: 0,
  total_assets: 0,
  countries: [],
  cloud_providers: [],
  cdn_providers: [],
  waf_providers: [],
});

// Filters
const filterType = ref<string>("all");
const filterMinRisk = ref<number>(0);

// -- Computed --

const filteredFeatures = computed(() => {
  return features.value.filter((f) => {
    if (filterType.value !== "all" && f.properties.type !== filterType.value) {
      return false;
    }
    if (f.properties.risk_score < filterMinRisk.value) {
      return false;
    }
    return true;
  });
});

const geolocatedPct = computed(() => {
  if (summaryData.value.total_assets === 0) return 0;
  return Math.round(
    (summaryData.value.total_geolocated / summaryData.value.total_assets) * 100,
  );
});

const topCountries = computed(() => {
  return summaryData.value.countries.slice(0, 5);
});

const riskDistribution = computed(() => {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of filteredFeatures.value) {
    const score = f.properties.risk_score;
    if (score >= 80) counts.critical++;
    else if (score >= 60) counts.high++;
    else if (score >= 40) counts.medium++;
    else counts.low++;
  }
  return counts;
});

const riskTotal = computed(() => {
  const d = riskDistribution.value;
  return d.critical + d.high + d.medium + d.low;
});

const maxProviderCount = computed(() => {
  const all = [
    ...summaryData.value.cloud_providers,
    ...summaryData.value.cdn_providers,
    ...summaryData.value.waf_providers,
  ];
  if (all.length === 0) return 1;
  return Math.max(...all.map((p) => p.count), 1);
});

// -- Helpers --

function countryCodeToFlag(code: string | null): string {
  if (!code || code.length !== 2) return "";
  const codePoints = code
    .toUpperCase()
    .split("")
    .map((char) => 0x1f1e6 + char.charCodeAt(0) - 65);
  return String.fromCodePoint(...codePoints);
}

function getRiskColor(score: number): string {
  if (score >= 80) return "#EF4444";
  if (score >= 60) return "#F97316";
  if (score >= 40) return "#EAB308";
  return "#22C55E";
}

function getRiskLabel(score: number): string {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

function getRiskBadgeClass(score: number): string {
  if (score >= 80)
    return "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400";
  if (score >= 60)
    return "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400";
  if (score >= 40)
    return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400";
  return "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400";
}

// -- Map Setup --

function initializeMap(): void {
  if (!mapContainerRef.value || mapInstance) return;

  mapInstance = L.map(mapContainerRef.value, {
    center: [30, 0],
    zoom: 2,
    minZoom: 2,
    maxZoom: 18,
    zoomControl: true,
    attributionControl: true,
  });

  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution:
      '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    maxZoom: 19,
  }).addTo(mapInstance);

  markersLayer = L.layerGroup().addTo(mapInstance);
}

function updateMarkers(): void {
  if (!markersLayer || !mapInstance) return;

  markersLayer.clearLayers();

  const filtered = filteredFeatures.value;
  if (filtered.length === 0) return;

  const bounds = L.latLngBounds([]);

  for (const feature of filtered) {
    const [lng, lat] = feature.geometry.coordinates;
    const props = feature.properties;
    const color = getRiskColor(props.risk_score);
    const riskLabel = getRiskLabel(props.risk_score);

    const marker = L.circleMarker([lat, lng], {
      radius: 8,
      fillColor: color,
      color: "#fff",
      weight: 2,
      opacity: 1,
      fillOpacity: 0.85,
    });

    // Build popup content
    const locationParts = [props.city, props.region, props.country].filter(
      Boolean,
    );
    const location =
      locationParts.length > 0 ? locationParts.join(", ") : "Unknown";

    let popupHtml = `
      <div style="font-family: system-ui, -apple-system, sans-serif; min-width: 220px; font-size: 13px;">
        <div style="font-weight: 700; font-size: 14px; margin-bottom: 6px; color: #111827; word-break: break-all;">
          ${props.identifier}
        </div>
        <div style="display: grid; grid-template-columns: auto 1fr; gap: 3px 10px; color: #374151;">
          <span style="color: #6b7280;">Type:</span>
          <span style="text-transform: capitalize;">${props.type}</span>
    `;

    if (props.ip) {
      popupHtml += `
          <span style="color: #6b7280;">IP:</span>
          <span style="font-family: monospace; font-size: 12px;">${props.ip}</span>
      `;
    }

    popupHtml += `
          <span style="color: #6b7280;">Location:</span>
          <span>${props.country_code ? countryCodeToFlag(props.country_code) + " " : ""}${location}</span>
          <span style="color: #6b7280;">Risk:</span>
          <span>
            <span style="display: inline-block; padding: 1px 8px; border-radius: 9999px; font-size: 11px; font-weight: 600; color: #fff; background: ${color};">
              ${props.risk_score} - ${riskLabel}
            </span>
          </span>
    `;

    if (props.asn_org) {
      popupHtml += `
          <span style="color: #6b7280;">ASN:</span>
          <span>${props.asn ? "AS" + props.asn + " " : ""}${props.asn_org}</span>
      `;
    }

    if (props.cdn) {
      popupHtml += `
          <span style="color: #6b7280;">CDN:</span>
          <span>${props.cdn}</span>
      `;
    }

    if (props.waf) {
      popupHtml += `
          <span style="color: #6b7280;">WAF:</span>
          <span>${props.waf}</span>
      `;
    }

    if (props.cloud_provider) {
      popupHtml += `
          <span style="color: #6b7280;">Cloud:</span>
          <span>${props.cloud_provider}</span>
      `;
    }

    popupHtml += `</div>`;

    // Findings summary
    const findings = props.findings;
    if (props.total_findings > 0) {
      popupHtml += `
        <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid #e5e7eb;">
          <span style="font-weight: 600; color: #111827; font-size: 12px;">Findings (${props.total_findings}):</span>
          <div style="display: flex; gap: 6px; margin-top: 4px; flex-wrap: wrap;">
      `;
      if (findings.critical > 0) {
        popupHtml += `<span style="padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #fef2f2; color: #b91c1c;">${findings.critical}C</span>`;
      }
      if (findings.high > 0) {
        popupHtml += `<span style="padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #fff7ed; color: #c2410c;">${findings.high}H</span>`;
      }
      if (findings.medium > 0) {
        popupHtml += `<span style="padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #fefce8; color: #a16207;">${findings.medium}M</span>`;
      }
      if (findings.low > 0) {
        popupHtml += `<span style="padding: 1px 6px; border-radius: 4px; font-size: 11px; font-weight: 600; background: #eff6ff; color: #1d4ed8;">${findings.low}L</span>`;
      }
      popupHtml += `</div></div>`;
    }

    popupHtml += `</div>`;

    marker.bindPopup(popupHtml, { maxWidth: 320 });
    markersLayer!.addLayer(marker);
    bounds.extend([lat, lng]);
  }

  if (filtered.length > 0 && bounds.isValid()) {
    mapInstance.fitBounds(bounds, { padding: [40, 40], maxZoom: 10 });
  }
}

// -- Data Fetching --

async function loadGeoData(): Promise<void> {
  if (!currentTenantId.value) {
    error.value = "No tenant selected";
    isLoading.value = false;
    return;
  }

  isLoading.value = true;
  error.value = "";

  try {
    const [assetsResp, summaryResp] = await Promise.allSettled([
      apiClient.get<GeoFeatureCollection>(
        `/api/v1/tenants/${currentTenantId.value}/geomap/assets`,
      ),
      apiClient.get<GeoSummary>(
        `/api/v1/tenants/${currentTenantId.value}/geomap/summary`,
      ),
    ]);

    if (assetsResp.status === "fulfilled") {
      features.value = assetsResp.value.data.features || [];
    } else {
      console.error("Failed to load geo assets:", assetsResp.reason);
      features.value = [];
    }

    if (summaryResp.status === "fulfilled") {
      summaryData.value = summaryResp.value.data;
    } else {
      console.error("Failed to load geo summary:", summaryResp.reason);
    }

    updateMarkers();
  } catch (err: unknown) {
    const message =
      err instanceof Error ? err.message : "Failed to load geographic data";
    error.value = message;
    console.error("GeoMap load error:", message);
  } finally {
    isLoading.value = false;
    // Leaflet needs invalidateSize AFTER the container becomes visible.
    // v-show="!isLoading" makes the container visible only after isLoading=false,
    // so we must wait for the DOM to update before telling Leaflet to recalculate.
    await nextTick();
    if (mapInstance) {
      mapInstance.invalidateSize();
    }
  }
}

function handleRefresh(): void {
  loadGeoData();
}

// Watch filters to update markers reactively
watch([filterType, filterMinRisk], () => {
  updateMarkers();
});

// -- Lifecycle --

onMounted(async () => {
  await nextTick();
  initializeMap();
  await loadGeoData();
});

watch(currentTenantId, () => {
  if (currentTenantId.value) {
    loadGeoData();
  }
});

onUnmounted(() => {
  if (mapInstance) {
    mapInstance.remove();
    mapInstance = null;
    markersLayer = null;
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
          Geographic Map
        </h2>
        <p class="text-sm text-gray-500 dark:text-dark-text-tertiary mt-1">
          Asset geolocation and geographic distribution
        </p>
      </div>
      <button
        @click="handleRefresh"
        :disabled="isLoading"
        class="px-4 py-2 bg-primary-600 text-white rounded-md hover:bg-primary-700 disabled:opacity-50 transition-colors flex items-center gap-2"
      >
        <svg
          class="w-4 h-4"
          :class="{ 'animate-spin': isLoading }"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"
          />
        </svg>
        Refresh
      </button>
    </div>

    <!-- Error State -->
    <div
      v-if="error && !isLoading"
      class="bg-red-50 dark:bg-red-900/20 p-4 rounded-md"
    >
      <div class="flex items-center gap-2">
        <svg
          class="w-5 h-5 text-red-600 dark:text-red-400 flex-shrink-0"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
          />
        </svg>
        <p class="text-red-800 dark:text-red-200">{{ error }}</p>
      </div>
    </div>

    <!-- Filter Toolbar -->
    <div
      class="bg-white dark:bg-dark-bg-secondary p-4 rounded-lg border border-gray-200 dark:border-dark-border"
    >
      <div class="flex flex-wrap items-center gap-4">
        <!-- Asset Type Filter -->
        <div class="flex items-center gap-2">
          <label
            for="filter-type"
            class="text-sm font-medium text-gray-700 dark:text-dark-text-secondary"
          >
            Asset Type
          </label>
          <select
            id="filter-type"
            v-model="filterType"
            class="block rounded-md border border-gray-300 dark:border-dark-border bg-white dark:bg-dark-bg-tertiary text-gray-900 dark:text-dark-text-primary text-sm px-3 py-1.5 focus:ring-primary-500 focus:border-primary-500"
          >
            <option value="all">All</option>
            <option value="domain">Domain</option>
            <option value="subdomain">Subdomain</option>
            <option value="ip">IP</option>
            <option value="url">URL</option>
            <option value="service">Service</option>
          </select>
        </div>

        <!-- Min Risk Score Filter -->
        <div class="flex items-center gap-2">
          <label
            for="filter-risk"
            class="text-sm font-medium text-gray-700 dark:text-dark-text-secondary"
          >
            Min Risk Score
          </label>
          <input
            id="filter-risk"
            v-model.number="filterMinRisk"
            type="number"
            min="0"
            max="100"
            class="block w-20 rounded-md border border-gray-300 dark:border-dark-border bg-white dark:bg-dark-bg-tertiary text-gray-900 dark:text-dark-text-primary text-sm px-3 py-1.5 focus:ring-primary-500 focus:border-primary-500"
          />
        </div>

        <!-- Results Count -->
        <div class="ml-auto text-sm text-gray-500 dark:text-dark-text-tertiary">
          Showing {{ filteredFeatures.length }} of
          {{ features.length }} geolocated assets
        </div>

        <!-- Legend -->
        <div
          class="flex items-center gap-3 text-xs text-gray-600 dark:text-dark-text-secondary"
        >
          <div class="flex items-center gap-1">
            <span class="w-3 h-3 rounded-full bg-red-500 inline-block"></span>
            Critical (&ge;80)
          </div>
          <div class="flex items-center gap-1">
            <span
              class="w-3 h-3 rounded-full bg-orange-500 inline-block"
            ></span>
            High (60-79)
          </div>
          <div class="flex items-center gap-1">
            <span
              class="w-3 h-3 rounded-full bg-yellow-500 inline-block"
            ></span>
            Medium (40-59)
          </div>
          <div class="flex items-center gap-1">
            <span class="w-3 h-3 rounded-full bg-green-500 inline-block"></span>
            Low (&lt;40)
          </div>
        </div>
      </div>
    </div>

    <!-- Loading State -->
    <div v-if="isLoading" class="flex items-center justify-center h-64">
      <div class="flex flex-col items-center gap-3">
        <svg
          class="w-8 h-8 animate-spin text-primary-600"
          fill="none"
          viewBox="0 0 24 24"
        >
          <circle
            class="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            stroke-width="4"
          />
          <path
            class="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
        <span class="text-gray-600 dark:text-dark-text-secondary"
          >Loading geographic data...</span
        >
      </div>
    </div>

    <!-- Map Container -->
    <div
      v-show="!isLoading"
      class="bg-white dark:bg-dark-bg-secondary rounded-lg border border-gray-200 dark:border-dark-border overflow-hidden"
    >
      <div
        ref="mapContainerRef"
        class="w-full"
        style="height: 65vh; min-height: 400px"
      ></div>
    </div>

    <!-- Summary Panel -->
    <template v-if="!isLoading">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <!-- Card 1: Geolocated Assets -->
        <div
          class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
        >
          <div class="flex items-center justify-between">
            <div>
              <p class="text-sm text-gray-600 dark:text-dark-text-secondary">
                Geolocated Assets
              </p>
              <p
                class="text-3xl font-bold text-gray-900 dark:text-dark-text-primary mt-2"
              >
                {{ summaryData.total_geolocated.toLocaleString() }}
              </p>
              <div class="flex items-center mt-2">
                <span
                  class="text-sm text-gray-500 dark:text-dark-text-tertiary"
                >
                  of {{ summaryData.total_assets.toLocaleString() }} total
                </span>
              </div>
              <div class="mt-2">
                <div
                  class="w-full h-2 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden"
                >
                  <div
                    class="h-full bg-primary-600 rounded-full transition-all duration-500"
                    :style="{ width: geolocatedPct + '%' }"
                  ></div>
                </div>
                <p
                  class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-1"
                >
                  {{ geolocatedPct }}% geolocated
                </p>
              </div>
            </div>
            <div class="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
              <svg
                class="w-8 h-8 text-blue-600 dark:text-blue-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"
                />
                <path
                  stroke-linecap="round"
                  stroke-linejoin="round"
                  stroke-width="2"
                  d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"
                />
              </svg>
            </div>
          </div>
        </div>

        <!-- Card 2: Top Countries -->
        <div
          class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
        >
          <h3
            class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary mb-3"
          >
            Top Countries
          </h3>
          <div v-if="topCountries.length > 0" class="space-y-2">
            <div
              v-for="country in topCountries"
              :key="country.country_code"
              class="flex items-center justify-between text-sm"
            >
              <div class="flex items-center gap-2">
                <span class="text-base leading-none">{{
                  countryCodeToFlag(country.country_code)
                }}</span>
                <span class="text-gray-700 dark:text-dark-text-secondary">{{
                  country.country_code
                }}</span>
              </div>
              <div class="flex items-center gap-3">
                <span
                  class="font-semibold text-gray-900 dark:text-dark-text-primary"
                  >{{ country.count }}</span
                >
                <span
                  class="text-xs font-medium px-1.5 py-0.5 rounded"
                  :class="getRiskBadgeClass(country.avg_risk)"
                >
                  {{ Math.round(country.avg_risk) }}
                </span>
              </div>
            </div>
          </div>
          <p v-else class="text-sm text-gray-500 dark:text-dark-text-tertiary">
            No country data available
          </p>
        </div>

        <!-- Card 3: Cloud / CDN / WAF -->
        <div
          class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
        >
          <h3
            class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary mb-3"
          >
            Infrastructure
          </h3>
          <div class="space-y-3">
            <!-- Cloud Providers -->
            <div v-if="summaryData.cloud_providers.length > 0">
              <p
                class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-1"
              >
                Cloud
              </p>
              <div
                v-for="provider in summaryData.cloud_providers.slice(0, 3)"
                :key="'cloud-' + provider.name"
                class="flex items-center gap-2 text-sm mb-1"
              >
                <span
                  class="text-gray-700 dark:text-dark-text-secondary flex-1 truncate"
                  >{{ provider.name }}</span
                >
                <div
                  class="w-20 h-1.5 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden"
                >
                  <div
                    class="h-full bg-cyan-500 rounded-full"
                    :style="{
                      width: (provider.count / maxProviderCount) * 100 + '%',
                    }"
                  ></div>
                </div>
                <span
                  class="text-xs font-semibold text-gray-900 dark:text-dark-text-primary w-6 text-right"
                  >{{ provider.count }}</span
                >
              </div>
            </div>
            <!-- CDN Providers -->
            <div v-if="summaryData.cdn_providers.length > 0">
              <p
                class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-1"
              >
                CDN
              </p>
              <div
                v-for="provider in summaryData.cdn_providers.slice(0, 3)"
                :key="'cdn-' + provider.name"
                class="flex items-center gap-2 text-sm mb-1"
              >
                <span
                  class="text-gray-700 dark:text-dark-text-secondary flex-1 truncate"
                  >{{ provider.name }}</span
                >
                <div
                  class="w-20 h-1.5 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden"
                >
                  <div
                    class="h-full bg-violet-500 rounded-full"
                    :style="{
                      width: (provider.count / maxProviderCount) * 100 + '%',
                    }"
                  ></div>
                </div>
                <span
                  class="text-xs font-semibold text-gray-900 dark:text-dark-text-primary w-6 text-right"
                  >{{ provider.count }}</span
                >
              </div>
            </div>
            <!-- WAF Providers -->
            <div v-if="summaryData.waf_providers.length > 0">
              <p
                class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-1"
              >
                WAF
              </p>
              <div
                v-for="provider in summaryData.waf_providers.slice(0, 3)"
                :key="'waf-' + provider.name"
                class="flex items-center gap-2 text-sm mb-1"
              >
                <span
                  class="text-gray-700 dark:text-dark-text-secondary flex-1 truncate"
                  >{{ provider.name }}</span
                >
                <div
                  class="w-20 h-1.5 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden"
                >
                  <div
                    class="h-full bg-amber-500 rounded-full"
                    :style="{
                      width: (provider.count / maxProviderCount) * 100 + '%',
                    }"
                  ></div>
                </div>
                <span
                  class="text-xs font-semibold text-gray-900 dark:text-dark-text-primary w-6 text-right"
                  >{{ provider.count }}</span
                >
              </div>
            </div>
            <!-- Empty state -->
            <p
              v-if="
                summaryData.cloud_providers.length === 0 &&
                summaryData.cdn_providers.length === 0 &&
                summaryData.waf_providers.length === 0
              "
              class="text-sm text-gray-500 dark:text-dark-text-tertiary"
            >
              No infrastructure data available
            </p>
          </div>
        </div>

        <!-- Card 4: Risk Distribution -->
        <div
          class="bg-white dark:bg-dark-bg-secondary p-6 rounded-lg border border-gray-200 dark:border-dark-border"
        >
          <h3
            class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary mb-3"
          >
            Risk Distribution
          </h3>
          <div class="space-y-3">
            <!-- Critical -->
            <div class="flex items-center gap-3">
              <span
                class="w-16 text-sm text-gray-600 dark:text-dark-text-secondary text-right"
                >Critical</span
              >
              <div
                class="flex-1 h-5 bg-gray-100 dark:bg-dark-bg-tertiary rounded-md overflow-hidden relative"
              >
                <div
                  class="h-full rounded-md transition-all duration-700 ease-out bg-red-500"
                  :style="{
                    width:
                      riskTotal > 0
                        ? (riskDistribution.critical / riskTotal) * 100 + '%'
                        : '0%',
                  }"
                ></div>
              </div>
              <span
                class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary w-8 text-right"
              >
                {{ riskDistribution.critical }}
              </span>
            </div>
            <!-- High -->
            <div class="flex items-center gap-3">
              <span
                class="w-16 text-sm text-gray-600 dark:text-dark-text-secondary text-right"
                >High</span
              >
              <div
                class="flex-1 h-5 bg-gray-100 dark:bg-dark-bg-tertiary rounded-md overflow-hidden relative"
              >
                <div
                  class="h-full rounded-md transition-all duration-700 ease-out bg-orange-500"
                  :style="{
                    width:
                      riskTotal > 0
                        ? (riskDistribution.high / riskTotal) * 100 + '%'
                        : '0%',
                  }"
                ></div>
              </div>
              <span
                class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary w-8 text-right"
              >
                {{ riskDistribution.high }}
              </span>
            </div>
            <!-- Medium -->
            <div class="flex items-center gap-3">
              <span
                class="w-16 text-sm text-gray-600 dark:text-dark-text-secondary text-right"
                >Medium</span
              >
              <div
                class="flex-1 h-5 bg-gray-100 dark:bg-dark-bg-tertiary rounded-md overflow-hidden relative"
              >
                <div
                  class="h-full rounded-md transition-all duration-700 ease-out bg-yellow-500"
                  :style="{
                    width:
                      riskTotal > 0
                        ? (riskDistribution.medium / riskTotal) * 100 + '%'
                        : '0%',
                  }"
                ></div>
              </div>
              <span
                class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary w-8 text-right"
              >
                {{ riskDistribution.medium }}
              </span>
            </div>
            <!-- Low -->
            <div class="flex items-center gap-3">
              <span
                class="w-16 text-sm text-gray-600 dark:text-dark-text-secondary text-right"
                >Low</span
              >
              <div
                class="flex-1 h-5 bg-gray-100 dark:bg-dark-bg-tertiary rounded-md overflow-hidden relative"
              >
                <div
                  class="h-full rounded-md transition-all duration-700 ease-out bg-green-500"
                  :style="{
                    width:
                      riskTotal > 0
                        ? (riskDistribution.low / riskTotal) * 100 + '%'
                        : '0%',
                  }"
                ></div>
              </div>
              <span
                class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary w-8 text-right"
              >
                {{ riskDistribution.low }}
              </span>
            </div>
          </div>
          <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-3">
            {{ riskTotal }} assets on map
          </p>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
/* Fix Leaflet z-index conflicts with Tailwind */
:deep(.leaflet-pane) {
  z-index: 1;
}

:deep(.leaflet-top),
:deep(.leaflet-bottom) {
  z-index: 2;
}

:deep(.leaflet-popup) {
  z-index: 3;
}

/* Style the popup for dark mode compatibility */
:deep(.leaflet-popup-content-wrapper) {
  border-radius: 8px;
  box-shadow:
    0 4px 6px -1px rgb(0 0 0 / 0.1),
    0 2px 4px -2px rgb(0 0 0 / 0.1);
}

:deep(.leaflet-popup-content) {
  margin: 10px 12px;
}
</style>
