<script setup lang="ts">
import type { AssetDnsInfo } from "@/api/types";
import { GlobeAltIcon, CloudIcon } from "@heroicons/vue/24/outline";

interface CloudProviderDisplay {
  name: string;
  color: string;
}

interface DnsDiscoveryRecord {
  name: string;
  matched_at?: string;
  severity?: string;
}

interface Props {
  dnsInfo: AssetDnsInfo;
  cloudProvider: CloudProviderDisplay | null;
  dnsDiscovery?: Record<string, DnsDiscoveryRecord>;
}

const props = defineProps<Props>();

// Security posture checks (present/absent)
const securityRecords = [
  { key: "spf-record-detect", label: "SPF", category: "email" },
  { key: "dkim-record-detect", label: "DKIM", category: "email" },
  { key: "dmarc-record-detect", label: "DMARC", category: "email" },
  { key: "dnssec-detect", label: "DNSSEC", category: "dns" },
  { key: "caa-fingerprint", label: "CAA", category: "dns" },
];

function hasRecord(key: string): boolean {
  return !!props.dnsDiscovery?.[key];
}

// Group remaining records by category
const recordCategories = [
  {
    label: "Mail",
    keys: ["mx-record-detect", "bimi-record-detect", "email-service-detect"],
  },
  {
    label: "DNS Infrastructure",
    keys: ["ns-record-detect", "soa-record-detect", "dns-wildcard-detect"],
  },
  {
    label: "Records",
    keys: [
      "aaaa-record-detect",
      "txt-record-detect",
      "srv-record-detect",
      "ptr-record-detect",
      "tlsa-record-detect",
    ],
  },
  {
    label: "SaaS Detection",
    keys: ["dns-saas-service-detection"],
  },
];
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
  >
    <div class="flex items-center gap-2 mb-5">
      <GlobeAltIcon
        class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
      />
      <h2
        class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
      >
        DNS & Network Intelligence
      </h2>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
      <!-- Resolved IPs -->
      <div v-if="dnsInfo.resolved_ips?.length">
        <h3
          class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
        >
          Resolved IPs
        </h3>
        <div class="flex flex-wrap gap-1.5">
          <span
            v-for="ip in dnsInfo.resolved_ips"
            :key="ip"
            class="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono font-medium bg-gray-100 text-gray-700 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary"
          >
            {{ ip }}
          </span>
        </div>
      </div>

      <!-- Reverse DNS -->
      <div v-if="dnsInfo.reverse_dns">
        <h3
          class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
        >
          Reverse DNS
        </h3>
        <p class="text-sm font-mono text-gray-900 dark:text-dark-text-primary">
          {{ dnsInfo.reverse_dns }}
        </p>
      </div>

      <!-- Cloud Provider -->
      <div v-if="dnsInfo.cloud_provider">
        <h3
          class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
        >
          Cloud Provider
        </h3>
        <span
          v-if="cloudProvider"
          :class="[
            'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-semibold',
            cloudProvider.color,
          ]"
        >
          <CloudIcon class="h-4 w-4" />
          {{ cloudProvider.name }}
        </span>
      </div>

      <!-- WHOIS -->
      <div v-if="dnsInfo.whois_summary">
        <h3
          class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
        >
          WHOIS Information
        </h3>
        <dl class="space-y-1.5">
          <div v-if="dnsInfo.whois_summary.registrar" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Registrar
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.whois_summary.registrar }}
            </dd>
          </div>
          <div v-if="dnsInfo.whois_summary.org" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Organization
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.whois_summary.org }}
            </dd>
          </div>
          <div v-if="dnsInfo.whois_summary.country" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Country
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.whois_summary.country }}
            </dd>
          </div>
          <div v-if="dnsInfo.whois_summary.created" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Created
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.whois_summary.created }}
            </dd>
          </div>
          <div v-if="dnsInfo.whois_summary.expires" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Expires
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.whois_summary.expires }}
            </dd>
          </div>
        </dl>
      </div>

      <!-- ASN -->
      <div v-if="dnsInfo.asn_info">
        <h3
          class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
        >
          ASN Information
        </h3>
        <dl class="space-y-1.5">
          <div v-if="dnsInfo.asn_info.asn" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              ASN
            </dt>
            <dd
              class="text-xs font-mono text-gray-900 dark:text-dark-text-primary"
            >
              AS{{ dnsInfo.asn_info.asn }}
            </dd>
          </div>
          <div v-if="dnsInfo.asn_info.org" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Organization
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.asn_info.org }}
            </dd>
          </div>
          <div v-if="dnsInfo.asn_info.country" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Country
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.asn_info.country }}
            </dd>
          </div>
        </dl>
      </div>

      <!-- GeoIP Location -->
      <div v-if="dnsInfo.geo_info">
        <h3
          class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
        >
          Geolocation
        </h3>
        <dl class="space-y-1.5">
          <div v-if="dnsInfo.geo_info.country" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Country
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.geo_info.country }}
              <span
                v-if="dnsInfo.geo_info.country_code"
                class="text-gray-400 dark:text-dark-text-tertiary ml-1"
                >({{ dnsInfo.geo_info.country_code }})</span
              >
            </dd>
          </div>
          <div v-if="dnsInfo.geo_info.region" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Region
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.geo_info.region }}
            </dd>
          </div>
          <div v-if="dnsInfo.geo_info.city" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              City
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.geo_info.city }}
            </dd>
          </div>
          <div
            v-if="dnsInfo.geo_info.lat && dnsInfo.geo_info.lon"
            class="flex gap-2"
          >
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              Coordinates
            </dt>
            <dd
              class="text-xs font-mono text-gray-900 dark:text-dark-text-primary"
            >
              {{ dnsInfo.geo_info.lat.toFixed(4) }},
              {{ dnsInfo.geo_info.lon.toFixed(4) }}
            </dd>
          </div>
          <div v-if="dnsInfo.geo_info.isp" class="flex gap-2">
            <dt
              class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0"
            >
              ISP
            </dt>
            <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
              {{ dnsInfo.geo_info.isp }}
            </dd>
          </div>
        </dl>
      </div>

      <!-- Nameservers -->
      <div v-if="dnsInfo.nameservers?.length">
        <h3
          class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2"
        >
          Nameservers
        </h3>
        <div class="flex flex-wrap gap-1.5">
          <span
            v-for="ns in dnsInfo.nameservers"
            :key="ns"
            class="inline-flex items-center px-2.5 py-1 rounded-md text-xs font-mono bg-gray-100 text-gray-700 dark:bg-dark-bg-tertiary dark:text-dark-text-secondary"
          >
            {{ ns }}
          </span>
        </div>
      </div>
    </div>

    <!-- DNS Security Posture (only shown when discovery data exists) -->
    <div
      v-if="dnsDiscovery && Object.keys(dnsDiscovery).length > 0"
      class="mt-6 pt-6 border-t border-gray-200 dark:border-dark-border"
    >
      <h3
        class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-3"
      >
        DNS Security Posture
      </h3>
      <div class="flex flex-wrap gap-3 mb-5">
        <div
          v-for="rec in securityRecords"
          :key="rec.key"
          class="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium"
          :class="
            hasRecord(rec.key)
              ? 'bg-green-50 text-green-700 dark:bg-green-900/20 dark:text-green-400'
              : 'bg-amber-50 text-amber-700 dark:bg-amber-900/20 dark:text-amber-400'
          "
        >
          <svg
            v-if="hasRecord(rec.key)"
            class="w-3.5 h-3.5"
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
          <svg
            v-else
            class="w-3.5 h-3.5"
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
          {{ rec.label }}
        </div>
      </div>

      <!-- Discovery Records Grid -->
      <h3
        class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-3"
      >
        Discovery Records
      </h3>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
        <template v-for="cat in recordCategories" :key="cat.label">
          <div
            v-for="rkey in cat.keys.filter((k) => dnsDiscovery?.[k])"
            :key="rkey"
            class="bg-gray-50 dark:bg-dark-bg-tertiary rounded-md p-3"
          >
            <p class="text-xs text-gray-500 dark:text-dark-text-tertiary">
              {{ cat.label }}
            </p>
            <p
              class="text-sm font-medium text-gray-900 dark:text-dark-text-primary mt-0.5"
            >
              {{ dnsDiscovery![rkey].name }}
            </p>
            <p
              v-if="dnsDiscovery![rkey].matched_at"
              class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-1 font-mono truncate"
            >
              {{ dnsDiscovery![rkey].matched_at }}
            </p>
          </div>
        </template>
      </div>
    </div>
  </div>
</template>
