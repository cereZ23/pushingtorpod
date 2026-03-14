<script setup lang="ts">
import { ref, computed, onMounted, watch } from "vue";
import { MagnifyingGlassIcon } from "@heroicons/vue/24/outline";
import { useTenantStore } from "@/stores/tenant";
import axios from "axios";

interface TechnologyItem {
  name: string;
  category: string;
  category_label: string;
  description: string;
  icon: string;
  service_count: number;
  versions: Record<string, number>;
}

interface CategoryInfo {
  slug: string;
  label: string;
  count: number;
}

const tenantStore = useTenantStore();
const tenantId = computed(() => tenantStore.currentTenantId);

const technologies = ref<TechnologyItem[]>([]);
const loading = ref(true);
const error = ref("");
const searchQuery = ref("");
const selectedCategory = ref("");

const ICON_BASE = "https://cdn.jsdelivr.net/npm/simple-icons@v11/icons";

function iconUrl(slug: string): string {
  if (!slug) return "";
  return `${ICON_BASE}/${slug}.svg`;
}

const availableCategories = computed<CategoryInfo[]>(() => {
  const cats: Record<string, { label: string; count: number }> = {};
  for (const tech of technologies.value) {
    if (!cats[tech.category]) {
      cats[tech.category] = { label: tech.category_label, count: 0 };
    }
    cats[tech.category].count++;
  }
  return Object.entries(cats)
    .map(([slug, info]) => ({ slug, label: info.label, count: info.count }))
    .sort((a, b) => b.count - a.count);
});

const filteredTechnologies = computed(() => {
  let result = technologies.value;

  if (selectedCategory.value) {
    result = result.filter((t) => t.category === selectedCategory.value);
  }

  if (searchQuery.value) {
    const q = searchQuery.value.toLowerCase();
    result = result.filter(
      (t) =>
        t.name.toLowerCase().includes(q) ||
        t.category_label.toLowerCase().includes(q),
    );
  }

  return result;
});

async function fetchTechnologies() {
  if (!tenantId.value) return;
  loading.value = true;
  error.value = "";
  try {
    const response = await axios.get<TechnologyItem[]>(
      `/api/v1/tenants/${tenantId.value}/services/technologies`,
    );
    technologies.value = response.data;
  } catch (err) {
    error.value = "Failed to load technologies";
    console.error("Failed to fetch technologies:", err);
  } finally {
    loading.value = false;
  }
}

onMounted(fetchTechnologies);
watch(tenantId, fetchTechnologies);

function versionCount(versions: Record<string, number>): number {
  return Object.keys(versions).length;
}

function topVersions(
  versions: Record<string, number>,
  max = 3,
): Array<{ version: string; count: number }> {
  return Object.entries(versions)
    .map(([version, count]) => ({ version, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, max);
}
</script>

<template>
  <div class="space-y-6">
    <!-- Header -->
    <div class="flex items-center justify-between">
      <div>
        <h1 class="text-2xl font-bold text-gray-900 dark:text-white">
          Technologies
        </h1>
        <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
          Discovered technologies across your attack surface
        </p>
      </div>
      <span
        v-if="!loading"
        class="text-sm font-medium text-gray-500 dark:text-gray-400"
      >
        {{ filteredTechnologies.length }} technologies
      </span>
    </div>

    <!-- Search + Filters -->
    <div class="space-y-4">
      <!-- Search bar -->
      <div class="relative max-w-md">
        <MagnifyingGlassIcon
          class="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400"
        />
        <input
          v-model="searchQuery"
          type="text"
          placeholder="Search technologies..."
          class="w-full pl-9 pr-4 py-2 text-sm border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-gray-900 dark:text-white placeholder-gray-400 focus:ring-2 focus:ring-blue-500 focus:border-transparent"
        />
      </div>

      <!-- Category pills -->
      <div class="flex flex-wrap gap-2">
        <button
          @click="selectedCategory = ''"
          :class="[
            !selectedCategory
              ? 'bg-blue-600 text-white'
              : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600',
          ]"
          class="px-3 py-1.5 rounded-full text-sm font-medium transition-colors"
        >
          All ({{ technologies.length }})
        </button>
        <button
          v-for="cat in availableCategories"
          :key="cat.slug"
          @click="selectedCategory = cat.slug"
          :class="[
            selectedCategory === cat.slug
              ? 'bg-blue-600 text-white'
              : 'bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600',
          ]"
          class="px-3 py-1.5 rounded-full text-sm font-medium transition-colors"
        >
          {{ cat.label }} ({{ cat.count }})
        </button>
      </div>
    </div>

    <!-- Loading skeleton -->
    <div
      v-if="loading"
      class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4"
    >
      <div
        v-for="i in 12"
        :key="i"
        class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 animate-pulse"
      >
        <div class="flex items-start justify-between mb-3">
          <div class="flex items-center gap-3">
            <div class="w-8 h-8 bg-gray-200 dark:bg-gray-700 rounded"></div>
            <div>
              <div class="h-4 w-28 bg-gray-200 dark:bg-gray-700 rounded"></div>
              <div
                class="h-3 w-16 bg-gray-200 dark:bg-gray-700 rounded mt-2"
              ></div>
            </div>
          </div>
          <div class="h-5 w-20 bg-gray-200 dark:bg-gray-700 rounded-full"></div>
        </div>
        <div class="h-3 w-full bg-gray-200 dark:bg-gray-700 rounded mt-3"></div>
        <div class="h-3 w-2/3 bg-gray-200 dark:bg-gray-700 rounded mt-2"></div>
      </div>
    </div>

    <!-- Error -->
    <div
      v-else-if="error"
      class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4"
    >
      <p class="text-sm text-red-600 dark:text-red-400">{{ error }}</p>
    </div>

    <!-- Empty state -->
    <div
      v-else-if="filteredTechnologies.length === 0"
      class="text-center py-12"
    >
      <p class="text-gray-500 dark:text-gray-400">
        {{
          searchQuery || selectedCategory
            ? "No technologies match your filters"
            : "No technologies detected yet. Run a scan to discover technologies."
        }}
      </p>
    </div>

    <!-- Technology grid -->
    <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      <div
        v-for="tech in filteredTechnologies"
        :key="tech.name"
        class="bg-white dark:bg-gray-800 rounded-lg border border-gray-200 dark:border-gray-700 p-4 hover:shadow-md hover:border-gray-300 dark:hover:border-gray-600 transition-all"
      >
        <div class="flex items-start justify-between mb-2">
          <div class="flex items-center gap-3 min-w-0">
            <!-- Tech icon -->
            <div
              class="flex-shrink-0 w-8 h-8 rounded bg-gray-100 dark:bg-gray-700 flex items-center justify-center"
            >
              <img
                v-if="tech.icon"
                :src="iconUrl(tech.icon)"
                :alt="tech.name"
                class="w-5 h-5 dark:invert dark:brightness-200"
                loading="lazy"
                @error="
                  ($event.target as HTMLImageElement).style.display = 'none'
                "
              />
              <span v-else class="text-xs font-bold text-gray-400">
                {{ tech.name.charAt(0) }}
              </span>
            </div>
            <div class="min-w-0">
              <h3
                class="font-semibold text-gray-900 dark:text-white truncate"
                :title="tech.name"
              >
                {{ tech.name }}
                <span
                  v-if="versionCount(tech.versions) === 1"
                  class="text-gray-400 font-normal"
                >
                  ({{ Object.keys(tech.versions)[0] }})
                </span>
              </h3>
              <div class="flex items-center gap-2 mt-0.5">
                <span
                  class="text-sm font-medium text-blue-600 dark:text-blue-400"
                >
                  {{ tech.service_count }}
                  {{ tech.service_count === 1 ? "Service" : "Services" }}
                </span>
              </div>
            </div>
          </div>
          <span
            class="flex-shrink-0 text-xs px-2 py-1 rounded-full bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300"
          >
            {{ tech.category_label }}
          </span>
        </div>

        <p
          v-if="tech.description"
          class="text-sm text-gray-500 dark:text-gray-400 line-clamp-2 mt-2"
        >
          {{ tech.description }}
        </p>

        <!-- Version badges (when multiple) -->
        <div
          v-if="versionCount(tech.versions) > 1"
          class="flex flex-wrap gap-1 mt-3"
        >
          <span
            v-for="v in topVersions(tech.versions)"
            :key="v.version"
            class="text-xs px-1.5 py-0.5 rounded bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300"
          >
            v{{ v.version }}
          </span>
          <span
            v-if="versionCount(tech.versions) > 3"
            class="text-xs px-1.5 py-0.5 text-gray-400"
          >
            +{{ versionCount(tech.versions) - 3 }} more
          </span>
        </div>
      </div>
    </div>
  </div>
</template>
