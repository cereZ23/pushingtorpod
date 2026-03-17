<script setup lang="ts">
import { useRouter } from "vue-router";
import type { Certificate } from "@/api/types";
import { LockClosedIcon } from "@heroicons/vue/24/outline";

interface Props {
  certificates: Certificate[];
}

defineProps<Props>();

const router = useRouter();

function certExpiryText(cert: Certificate): string {
  if (cert.is_expired) return "Expired";
  if (cert.days_until_expiry === undefined || cert.days_until_expiry === null)
    return "Unknown";
  if (cert.days_until_expiry <= 0) return "Expired";
  if (cert.days_until_expiry <= 7)
    return `${cert.days_until_expiry}d (critical)`;
  if (cert.days_until_expiry <= 30)
    return `${cert.days_until_expiry}d (warning)`;
  return `${cert.days_until_expiry} days`;
}

function certExpiryClass(cert: Certificate): string {
  if (
    cert.is_expired ||
    (cert.days_until_expiry !== undefined && cert.days_until_expiry <= 0)
  ) {
    return "text-red-600 dark:text-red-400";
  }
  if (cert.days_until_expiry !== undefined && cert.days_until_expiry <= 30) {
    return "text-orange-600 dark:text-orange-400";
  }
  return "text-green-600 dark:text-green-400";
}
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6"
  >
    <div class="flex items-center gap-2 mb-5">
      <LockClosedIcon
        class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
      />
      <h2
        class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
      >
        TLS Certificates
      </h2>
      <span
        class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
      >
        {{ certificates.length }}
      </span>
    </div>
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <div
        v-for="cert in certificates"
        :key="cert.id"
        @click="router.push(`/certificates/${cert.id}`)"
        class="border border-gray-200 dark:border-dark-border rounded-lg p-5 cursor-pointer hover:border-primary-300 dark:hover:border-primary-700 hover:shadow-sm transition-all"
      >
        <!-- Header row -->
        <div class="flex items-start justify-between gap-3">
          <div class="min-w-0">
            <h3
              class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary truncate font-mono"
            >
              {{ cert.subject_cn || "Unknown CN" }}
            </h3>
            <p
              class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-0.5"
            >
              Issued by {{ cert.issuer || "Unknown" }}
            </p>
          </div>
          <!-- Expiry indicator -->
          <span
            :class="[
              'text-xs font-semibold flex-shrink-0',
              certExpiryClass(cert),
            ]"
          >
            {{ certExpiryText(cert) }}
          </span>
        </div>

        <!-- Validity dates -->
        <div class="mt-3 grid grid-cols-2 gap-3">
          <div>
            <p
              class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              Valid From
            </p>
            <p
              class="text-xs text-gray-700 dark:text-dark-text-secondary mt-0.5"
            >
              {{
                cert.not_before
                  ? new Date(cert.not_before).toLocaleDateString()
                  : "--"
              }}
            </p>
          </div>
          <div>
            <p
              class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider"
            >
              Valid Until
            </p>
            <p class="text-xs mt-0.5" :class="certExpiryClass(cert)">
              {{
                cert.not_after
                  ? new Date(cert.not_after).toLocaleDateString()
                  : "--"
              }}
            </p>
          </div>
        </div>

        <!-- Key info row -->
        <div
          v-if="
            cert.public_key_algorithm ||
            cert.public_key_bits ||
            cert.signature_algorithm
          "
          class="mt-3"
        >
          <p
            class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-1"
          >
            Key Information
          </p>
          <p class="text-xs text-gray-700 dark:text-dark-text-secondary">
            <span v-if="cert.public_key_algorithm">{{
              cert.public_key_algorithm
            }}</span>
            <span v-if="cert.public_key_bits">
              {{ cert.public_key_bits }}-bit</span
            >
            <span v-if="cert.signature_algorithm">
              / {{ cert.signature_algorithm }}</span
            >
          </p>
        </div>

        <!-- SANs -->
        <div v-if="cert.san_domains?.length" class="mt-3">
          <p
            class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-1"
          >
            Subject Alternative Names
          </p>
          <div class="flex flex-wrap gap-1">
            <span
              v-for="san in cert.san_domains.slice(0, 6)"
              :key="san"
              class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
            >
              {{ san }}
            </span>
            <span
              v-if="cert.san_domains.length > 6"
              class="text-[10px] text-gray-400 dark:text-dark-text-tertiary self-center"
            >
              +{{ cert.san_domains.length - 6 }} more
            </span>
          </div>
        </div>

        <!-- Security indicators -->
        <div class="mt-3 flex flex-wrap gap-1.5">
          <span
            v-if="cert.is_expired"
            class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
          >
            EXPIRED
          </span>
          <span
            v-if="cert.is_self_signed"
            class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400"
          >
            SELF-SIGNED
          </span>
          <span
            v-if="cert.is_wildcard"
            class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400"
          >
            WILDCARD
          </span>
          <span
            v-if="cert.has_weak_signature"
            class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400"
          >
            WEAK SIGNATURE
          </span>
        </div>
      </div>
    </div>
  </div>
</template>
