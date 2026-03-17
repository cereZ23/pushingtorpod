<script setup lang="ts">
import { ref, onUnmounted } from "vue";
import { useTenantStore } from "@/stores/tenant";
import { ChevronDownIcon, ChevronUpIcon } from "@heroicons/vue/24/outline";

interface Screenshot {
  full: string;
  thumb: string;
  service_id: number;
  captured_at: string;
  http_status: number;
}

interface Props {
  screenshots: Screenshot[];
  assetId: number;
}

const props = defineProps<Props>();

const tenantStore = useTenantStore();

const showScreenshots = ref(true);
const selectedScreenshot = ref<Screenshot | null>(null);
/** Maps screenshot path to object URL for auth-aware image loading */
const screenshotBlobs = ref<Record<string, string>>({});

function screenshotProxyPath(
  screenshot: Screenshot,
  type: "full" | "thumb",
): string {
  const filename = (type === "thumb" ? screenshot.thumb : screenshot.full)
    .split("/")
    .pop();
  return `/api/v1/tenants/${tenantStore.currentTenantId}/assets/${props.assetId}/screenshots/${type}/${filename}`;
}

function screenshotUrl(screenshot: Screenshot, type: "full" | "thumb"): string {
  const path = screenshotProxyPath(screenshot, type);
  return screenshotBlobs.value[path] || "";
}

/** Load screenshot image as blob via authenticated API client */
async function loadScreenshotBlob(
  screenshot: Screenshot,
  type: "full" | "thumb",
): Promise<void> {
  const path = screenshotProxyPath(screenshot, type);
  if (screenshotBlobs.value[path]) return; // already loaded
  try {
    const { default: apiClient } = await import("@/api/client");
    const resp = await apiClient.get(path, { responseType: "blob" });
    const url = URL.createObjectURL(resp.data);
    screenshotBlobs.value[path] = url;
  } catch {
    // silently fail -- the image just won't show
  }
}

/** Pre-load all thumbnail blobs */
async function loadAllThumbnails(): Promise<void> {
  await Promise.all(
    props.screenshots.map((ss) => loadScreenshotBlob(ss, "thumb")),
  );
}

/** Clean up blob URLs and reload thumbnails when screenshots change externally */
function resetAndLoad(): void {
  for (const url of Object.values(screenshotBlobs.value)) {
    URL.revokeObjectURL(url);
  }
  screenshotBlobs.value = {};
  selectedScreenshot.value = null;
  if (props.screenshots.length > 0) {
    loadAllThumbnails();
  }
}

// Load thumbnails on mount
resetAndLoad();

onUnmounted(() => {
  for (const url of Object.values(screenshotBlobs.value)) {
    URL.revokeObjectURL(url);
  }
});

defineExpose({ resetAndLoad });
</script>

<template>
  <div
    class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg"
  >
    <button
      @click="showScreenshots = !showScreenshots"
      class="w-full flex items-center justify-between p-6 text-left hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 transition-colors rounded-lg"
    >
      <div class="flex items-center gap-2">
        <svg
          class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z"
          />
          <path
            stroke-linecap="round"
            stroke-linejoin="round"
            stroke-width="2"
            d="M15 13a3 3 0 11-6 0 3 3 0 016 0z"
          />
        </svg>
        <h2
          class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary"
        >
          Screenshots
        </h2>
        <span
          class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
        >
          {{ screenshots.length }}
        </span>
      </div>
      <ChevronDownIcon v-if="!showScreenshots" class="h-5 w-5 text-gray-400" />
      <ChevronUpIcon v-else class="h-5 w-5 text-gray-400" />
    </button>

    <div v-if="showScreenshots" class="px-6 pb-6">
      <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-4">
        <div
          v-for="(ss, idx) in screenshots"
          :key="idx"
          class="group cursor-pointer"
          @click="
            selectedScreenshot = ss;
            loadScreenshotBlob(ss, 'full');
          "
        >
          <div
            class="relative overflow-hidden rounded-lg border border-gray-200 dark:border-dark-border aspect-video bg-gray-100 dark:bg-dark-bg-tertiary"
          >
            <img
              v-if="screenshotUrl(ss, 'thumb')"
              :src="screenshotUrl(ss, 'thumb')"
              :alt="`Screenshot port ${ss.full.match(/\d+/)?.[0] || ''}`"
              class="w-full h-full object-cover group-hover:opacity-80 transition-opacity"
            />
            <div
              v-else
              class="flex items-center justify-center h-full text-gray-400 dark:text-dark-text-tertiary text-xs"
            >
              Loading...
            </div>
          </div>
          <p
            class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary truncate"
          >
            Port {{ ss.full.match(/(\d+)_/)?.[1] || "?" }} &middot;
            {{ new Date(ss.captured_at).toLocaleDateString() }}
          </p>
        </div>
      </div>
    </div>

    <!-- Lightbox -->
    <div
      v-if="selectedScreenshot"
      class="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4"
      @click.self="selectedScreenshot = null"
    >
      <div class="relative max-w-5xl w-full">
        <button
          @click="selectedScreenshot = null"
          class="absolute -top-10 right-0 text-white hover:text-gray-300 text-sm"
        >
          Close (Esc)
        </button>
        <img
          v-if="screenshotUrl(selectedScreenshot, 'full')"
          :src="screenshotUrl(selectedScreenshot, 'full')"
          alt="Full screenshot"
          class="w-full rounded-lg shadow-2xl"
        />
        <div
          v-else
          class="flex items-center justify-center h-64 text-white text-sm"
        >
          Loading full image...
        </div>
      </div>
    </div>
  </div>
</template>
