<script setup lang="ts">
import type { AssetDnsInfo } from "@/api/types";
import { GlobeAltIcon, CloudIcon } from "@heroicons/vue/24/outline";

interface CloudProviderDisplay {
  name: string;
  color: string;
}

interface Props {
  dnsInfo: AssetDnsInfo;
  cloudProvider: CloudProviderDisplay | null;
}

defineProps<Props>();
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
  </div>
</template>
