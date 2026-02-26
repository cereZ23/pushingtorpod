<script setup lang="ts">
import { ref, reactive, onMounted, computed, watch } from 'vue'
import { RouterView, useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useTenantStore } from '@/stores/tenant'
import { useThemeStore } from '@/stores/theme'
import {
  MagnifyingGlassIcon,
  ShieldExclamationIcon,
  CogIcon,
  AdjustmentsHorizontalIcon,
  ChevronRightIcon,
} from '@heroicons/vue/24/outline'
import ErrorBoundary from '@/components/ErrorBoundary.vue'

// --- Types ---

interface NavItem {
  label: string
  to: string
  /** Match against $route.name (string equality) */
  activeNames?: string[]
  /** Match against $route.path (startsWith) */
  activePaths?: string[]
  /** Only visible to superusers */
  adminOnly?: boolean
}

interface NavGroup {
  key: string
  label: string
  icon: typeof MagnifyingGlassIcon
  items: NavItem[]
  /** Only visible to superusers */
  adminOnly?: boolean
}

// --- Stores & Router ---

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const tenantStore = useTenantStore()
const themeStore = useThemeStore()

const isLoading = ref(true)
const isSidebarOpen = ref(true)

// --- Navigation groups definition ---

const navGroups: NavGroup[] = [
  {
    key: 'discovery',
    label: 'Discovery',
    icon: MagnifyingGlassIcon,
    items: [
      {
        label: 'Assets',
        to: '/assets',
        activePaths: ['/assets'],
      },
      {
        label: 'Services',
        to: '/services',
        activeNames: ['ServiceList'],
      },
      {
        label: 'Certificates',
        to: '/certificates',
        activePaths: ['/certificates'],
      },
      {
        label: 'Surface Map',
        to: '/graph',
        activeNames: ['SurfaceMap'],
      },
    ],
  },
  {
    key: 'vulnerabilities',
    label: 'Vulnerabilities',
    icon: ShieldExclamationIcon,
    items: [
      {
        label: 'Findings',
        to: '/findings',
        activePaths: ['/findings'],
      },
      {
        label: 'Issues',
        to: '/issues',
        activeNames: ['Issues', 'IssueDetail'],
      },
    ],
  },
  {
    key: 'operations',
    label: 'Operations',
    icon: CogIcon,
    items: [
      {
        label: 'Scans',
        to: '/scans',
        activeNames: ['Scans', 'ScanDetail'],
      },
      {
        label: 'Reports',
        to: '/reports',
        activeNames: ['Reports'],
      },
      {
        label: 'Alert Policies',
        to: '/alerts',
        activeNames: ['AlertPolicies'],
      },
    ],
  },
  {
    key: 'configuration',
    label: 'Configuration',
    icon: AdjustmentsHorizontalIcon,
    items: [
      {
        label: 'Scan Policies',
        to: '/settings/scan-policies',
        activeNames: ['ScanPolicies'],
      },
      {
        label: 'Suppression Rules',
        to: '/settings/suppressions',
        activeNames: ['SuppressionRules'],
      },
      {
        label: 'Onboard Customer',
        to: '/admin/onboard-customer',
        activeNames: ['OnboardCustomer'],
        adminOnly: true,
      },
    ],
  },
]

// --- Collapsed state with localStorage persistence ---

const STORAGE_KEY = 'easm-sidebar-collapsed'

function loadCollapsedState(): Record<string, boolean> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw) {
      return JSON.parse(raw) as Record<string, boolean>
    }
  } catch {
    // Ignore parse errors
  }
  // Default: all expanded (none collapsed)
  return {}
}

function saveCollapsedState(state: Record<string, boolean>) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
  } catch {
    // Ignore storage errors
  }
}

const collapsedGroups = reactive<Record<string, boolean>>(loadCollapsedState())

function toggleGroup(key: string) {
  collapsedGroups[key] = !collapsedGroups[key]
  saveCollapsedState({ ...collapsedGroups })
}

function isGroupCollapsed(key: string): boolean {
  return !!collapsedGroups[key]
}

// --- Active route helpers ---

function isItemActive(item: NavItem): boolean {
  const currentName = route.name as string | undefined
  const currentPath = route.path

  if (item.activeNames && currentName) {
    if (item.activeNames.includes(currentName)) return true
  }

  if (item.activePaths) {
    for (const p of item.activePaths) {
      if (currentPath.startsWith(p)) return true
    }
  }

  return false
}

function findActiveGroupKey(): string | null {
  for (const group of navGroups) {
    for (const item of group.items) {
      if (isItemActive(item)) {
        return group.key
      }
    }
  }
  return null
}

// Auto-expand the group containing the active route
watch(
  () => route.fullPath,
  () => {
    const activeKey = findActiveGroupKey()
    if (activeKey && collapsedGroups[activeKey]) {
      collapsedGroups[activeKey] = false
      saveCollapsedState({ ...collapsedGroups })
    }
  },
  { immediate: true }
)

// --- Visible items (respects adminOnly) ---

function visibleItems(group: NavGroup): NavItem[] {
  return group.items.filter(item => {
    if (item.adminOnly && !authStore.currentUser?.is_superuser) return false
    return true
  })
}

function isGroupVisible(group: NavGroup): boolean {
  if (group.adminOnly && !authStore.currentUser?.is_superuser) return false
  return visibleItems(group).length > 0
}

// --- SVG icon paths for nav items (preserved from original) ---

const itemIcons: Record<string, string[]> = {
  '/assets': [
    'M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9',
  ],
  '/services': [
    'M5 12h14M5 12a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v4a2 2 0 01-2 2M5 12a2 2 0 00-2 2v4a2 2 0 002 2h14a2 2 0 002-2v-4a2 2 0 00-2-2m-2-4h.01M17 16h.01',
  ],
  '/certificates': [
    'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  ],
  '/graph': [
    'M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1',
  ],
  '/findings': [
    'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
  ],
  '/issues': [
    'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01',
  ],
  '/scans': [
    'M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15',
  ],
  '/reports': [
    'M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  ],
  '/alerts': [
    'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9',
  ],
  '/settings/scan-policies': [
    'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z',
    'M15 12a3 3 0 11-6 0 3 3 0 016 0z',
  ],
  '/settings/suppressions': [
    'M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636',
  ],
  '/admin/onboard-customer': [
    'M18 9v3m0 0v3m0-3h3m-3 0h-3m-2-5a4 4 0 11-8 0 4 4 0 018 0zM3 20a6 6 0 0112 0v1H3v-1z',
  ],
}

// --- Init ---

onMounted(async () => {
  themeStore.initTheme()

  try {
    // Check if we have a token first
    if (!authStore.accessToken) {
      router.push('/login')
      return
    }

    await authStore.fetchCurrentUser()
    await tenantStore.fetchTenants()
    isLoading.value = false
  } catch (err: unknown) {
    isLoading.value = false

    // If unauthorized, clear tokens and redirect to login
    const axiosErr = err as { response?: { status?: number }; message?: string }
    if (axiosErr?.response?.status === 401 || axiosErr?.message?.includes('401')) {
      authStore.clearTokens()
      router.push('/login')
    }
  }
})

const currentTenant = computed(() => tenantStore.currentTenant)

function handleLogout() {
  authStore.logout()
}

function toggleSidebar() {
  isSidebarOpen.value = !isSidebarOpen.value
}
</script>

<template>
  <div class="min-h-screen bg-gray-50 dark:bg-dark-bg-primary">
    <!-- Top Navigation -->
    <nav class="bg-white dark:bg-dark-bg-secondary border-b border-gray-200 dark:border-dark-border">
      <div class="px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between h-16">
          <div class="flex items-center">
            <button
              @click="toggleSidebar"
              class="mr-4 p-2 rounded-md text-gray-600 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
            >
              <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <h1 class="text-xl font-bold text-gray-900 dark:text-dark-text-primary">EASM Platform</h1>
          </div>

          <div class="flex items-center space-x-4">
            <!-- Tenant Selector -->
            <div v-if="currentTenant" class="text-sm">
              <span class="text-gray-600 dark:text-dark-text-secondary">Tenant:</span>
              <span class="ml-2 font-medium text-gray-900 dark:text-dark-text-primary">{{ currentTenant.name }}</span>
            </div>

            <!-- Theme Toggle -->
            <button
              @click="themeStore.toggleTheme"
              class="p-2 rounded-md text-gray-600 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
            >
              <svg v-if="themeStore.isDark" class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" />
              </svg>
              <svg v-else class="w-5 h-5" fill="currentColor" viewBox="0 0 20 20">
                <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
              </svg>
            </button>

            <!-- User Menu -->
            <div class="flex items-center space-x-3">
              <span class="text-sm text-gray-700 dark:text-dark-text-secondary">
                {{ authStore.currentUser?.email }}
              </span>
              <button
                @click="handleLogout"
                class="px-3 py-2 text-sm font-medium text-gray-700 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary rounded-md"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </div>
    </nav>

    <div class="flex">
      <!-- Sidebar -->
      <aside
        v-show="isSidebarOpen"
        class="w-64 bg-white dark:bg-dark-bg-secondary border-r border-gray-200 dark:border-dark-border min-h-screen"
      >
        <nav class="p-4 space-y-1">
          <!-- Dashboard (always top-level) -->
          <router-link
            to="/"
            class="flex items-center px-3 py-2 text-sm font-medium rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
            :class="{ 'bg-gray-100 dark:bg-dark-bg-tertiary': $route.name === 'Dashboard' }"
          >
            <svg class="w-5 h-5 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
            </svg>
            Dashboard
          </router-link>

          <!-- Collapsible Navigation Groups -->
          <template v-for="group in navGroups" :key="group.key">
            <div v-if="isGroupVisible(group)" class="pt-3">
              <!-- Group Header (clickable) -->
              <button
                @click="toggleGroup(group.key)"
                class="flex items-center w-full px-3 py-2 text-xs font-semibold uppercase tracking-wider rounded-md text-gray-500 dark:text-dark-text-tertiary hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary transition-colors"
              >
                <component
                  :is="group.icon"
                  class="w-4 h-4 mr-2 flex-shrink-0"
                />
                <span class="flex-1 text-left">{{ group.label }}</span>
                <ChevronRightIcon
                  class="w-4 h-4 flex-shrink-0 transition-transform duration-200"
                  :class="{ 'rotate-90': !isGroupCollapsed(group.key) }"
                />
              </button>

              <!-- Group Items (collapsible) -->
              <div
                v-show="!isGroupCollapsed(group.key)"
                class="mt-1 space-y-0.5"
              >
                <template v-for="item in visibleItems(group)" :key="item.to">
                  <router-link
                    :to="item.to"
                    class="flex items-center pl-5 pr-3 py-2 text-sm font-medium rounded-md text-gray-700 dark:text-dark-text-secondary hover:bg-gray-100 dark:hover:bg-dark-bg-tertiary"
                    :class="{ 'bg-gray-100 dark:bg-dark-bg-tertiary': isItemActive(item) }"
                  >
                    <svg class="w-5 h-5 mr-3 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path
                        v-for="(d, idx) in (itemIcons[item.to] || [])"
                        :key="idx"
                        stroke-linecap="round"
                        stroke-linejoin="round"
                        stroke-width="2"
                        :d="d"
                      />
                    </svg>
                    {{ item.label }}
                  </router-link>
                </template>
              </div>
            </div>
          </template>
        </nav>
      </aside>

      <!-- Main Content -->
      <main class="flex-1 p-6">
        <div v-if="isLoading" class="flex items-center justify-center h-64">
          <div class="text-gray-600 dark:text-dark-text-secondary">Loading...</div>
        </div>
        <ErrorBoundary v-else>
          <RouterView />
        </ErrorBoundary>
      </main>
    </div>
  </div>
</template>
