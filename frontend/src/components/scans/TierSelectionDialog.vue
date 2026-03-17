<script setup lang="ts">
import { SCAN_TIERS } from "@/stores/scans";

interface Props {
  open: boolean;
  isLoading: boolean;
}

defineProps<Props>();

const emit = defineEmits<{
  close: [];
  submit: [tier: number];
}>();

function getTierBadgeClass(tier: number): string {
  if (tier === 1)
    return "bg-green-100 text-green-700 dark:bg-green-900/20 dark:text-green-400";
  if (tier === 2)
    return "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/20 dark:text-yellow-400";
  return "bg-red-100 text-red-700 dark:bg-red-900/20 dark:text-red-400";
}

function getTierIconClass(tier: number): string {
  if (tier === 1) return "text-green-500";
  if (tier === 2) return "text-yellow-500";
  return "text-red-500";
}
</script>

<template>
  <Teleport to="body">
    <div
      v-if="open"
      class="fixed inset-0 z-50 flex items-center justify-center"
    >
      <!-- Backdrop -->
      <div class="absolute inset-0 bg-black/50" @click="emit('close')" />

      <!-- Dialog -->
      <div
        class="relative bg-white dark:bg-dark-bg-secondary rounded-lg shadow-xl w-full max-w-2xl mx-4 border border-gray-200 dark:border-dark-border"
      >
        <div
          class="px-6 py-4 border-b border-gray-200 dark:border-dark-border flex justify-between items-center"
        >
          <h3
            class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
          >
            Select Scan Type
          </h3>
          <button
            @click="emit('close')"
            class="text-gray-400 hover:text-gray-500"
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

        <div class="p-6">
          <div class="grid grid-cols-3 gap-4">
            <button
              v-for="tier in SCAN_TIERS"
              :key="tier.tier"
              @click="emit('submit', tier.tier)"
              class="flex flex-col items-center p-5 rounded-lg border-2 transition-all hover:shadow-md"
              :class="{
                'border-green-300 dark:border-green-700 hover:border-green-500 hover:bg-green-50 dark:hover:bg-green-900/10':
                  tier.tier === 1,
                'border-yellow-300 dark:border-yellow-700 hover:border-yellow-500 hover:bg-yellow-50 dark:hover:bg-yellow-900/10':
                  tier.tier === 2,
                'border-red-300 dark:border-red-700 hover:border-red-500 hover:bg-red-50 dark:hover:bg-red-900/10':
                  tier.tier === 3,
              }"
            >
              <!-- Icon -->
              <div class="mb-3">
                <!-- Shield for Safe -->
                <svg
                  v-if="tier.tier === 1"
                  class="w-10 h-10"
                  :class="getTierIconClass(tier.tier)"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                  />
                </svg>
                <!-- Bolt for Moderate -->
                <svg
                  v-else-if="tier.tier === 2"
                  class="w-10 h-10"
                  :class="getTierIconClass(tier.tier)"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M13 10V3L4 14h7v7l9-11h-7z"
                  />
                </svg>
                <!-- Fire for Aggressive -->
                <svg
                  v-else
                  class="w-10 h-10"
                  :class="getTierIconClass(tier.tier)"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M17.657 18.657A8 8 0 016.343 7.343S7 9 9 10c0-2 .5-5 2.986-7C14 5 16.09 5.777 17.656 7.343A7.975 7.975 0 0120 13a7.975 7.975 0 01-2.343 5.657z"
                  />
                  <path
                    stroke-linecap="round"
                    stroke-linejoin="round"
                    stroke-width="2"
                    d="M9.879 16.121A3 3 0 1012.015 11L11 14H9c0 .768.293 1.536.879 2.121z"
                  />
                </svg>
              </div>

              <!-- Tier badge -->
              <span
                class="px-2.5 py-0.5 text-xs font-bold rounded-full mb-2"
                :class="getTierBadgeClass(tier.tier)"
              >
                Tier {{ tier.tier }}
              </span>

              <!-- Name -->
              <h4
                class="text-base font-semibold text-gray-900 dark:text-dark-text-primary mb-2"
              >
                {{ tier.name }}
              </h4>

              <!-- Description -->
              <p
                class="text-xs text-gray-500 dark:text-dark-text-secondary text-center mb-3"
              >
                {{ tier.description }}
              </p>

              <!-- Stats -->
              <div
                class="flex gap-3 text-xs text-gray-600 dark:text-dark-text-secondary"
              >
                <span class="flex items-center gap-1">
                  <svg
                    class="w-3.5 h-3.5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M5 12h14M12 5l7 7-7 7"
                    />
                  </svg>
                  {{ tier.ports }}
                </span>
                <span class="flex items-center gap-1">
                  <svg
                    class="w-3.5 h-3.5"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      stroke-linecap="round"
                      stroke-linejoin="round"
                      stroke-width="2"
                      d="M13 10V3L4 14h7v7l9-11h-7z"
                    />
                  </svg>
                  {{ tier.rate }}
                </span>
              </div>
            </button>
          </div>
        </div>
      </div>
    </div>
  </Teleport>
</template>
