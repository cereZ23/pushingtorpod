<script setup lang="ts">
import { ref, onMounted, onUnmounted, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useTenantStore } from '@/stores/tenant'
import { getRiskScoreClasses, getSeverityBadgeClass, getFindingStatusBadgeClass } from '@/utils/severity'
import { formatDate } from '@/utils/formatters'
import { useRiskGauge } from '@/composables/useRiskGauge'
import { assetApi } from '@/api/assets'
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
} from '@/api/types'
import {
  ArrowLeftIcon,
  ArrowPathIcon,
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
  CloudIcon,
  CheckCircleIcon,
  FunnelIcon,
  ShieldCheckIcon,
} from '@heroicons/vue/24/outline'

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const route = useRoute()
const router = useRouter()
const tenantStore = useTenantStore()

const assetId = computed(() => parseInt(route.params.id as string))
const asset = ref<Asset | null>(null)
const services = ref<Service[]>([])
const findings = ref<Finding[]>([])
const certificates = ref<Certificate[]>([])
const events = ref<AssetEvent[]>([])
const endpoints = ref<AssetEndpoint[]>([])
const summary = ref<AssetSummary | null>(null)
const dnsInfo = ref<AssetDnsInfo | null>(null)
const techStack = ref<string[]>([])
const httpInfo = ref<AssetHttpInfo[]>([])
const parentAsset = ref<Asset['parent_asset'] | null>(null)

interface Screenshot {
  full: string
  thumb: string
  service_id: number
  captured_at: string
  http_status: number
}

const isLoading = ref(true)
const isRescanning = ref(false)
const error = ref('')
const screenshots = ref<Screenshot[]>([])
const showScreenshots = ref(true)
const selectedScreenshot = ref<Screenshot | null>(null)
/** Maps screenshot path → object URL for auth-aware image loading */
const screenshotBlobs = ref<Record<string, string>>({})

// Collapsible section states
const showEndpoints = ref(false)
const showEvents = ref(false)

// Endpoint filter
const endpointTypeFilter = ref('all')

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

async function loadAssetDetails() {
  try {
    isLoading.value = true
    error.value = ''

    // Clean up old screenshot blob URLs
    for (const url of Object.values(screenshotBlobs.value)) {
      URL.revokeObjectURL(url)
    }
    screenshotBlobs.value = {}
    selectedScreenshot.value = null

    if (!tenantStore.currentTenantId) {
      await tenantStore.fetchTenants()
    }

    if (!tenantStore.currentTenantId) {
      error.value = 'No tenant available'
      return
    }

    const assetDetails = await assetApi.get(tenantStore.currentTenantId, assetId.value)

    if (!assetDetails) {
      error.value = 'Asset not found'
      return
    }

    asset.value = assetDetails
    services.value = assetDetails.services || []
    findings.value = assetDetails.findings || []
    certificates.value = assetDetails.certificates || []
    events.value = assetDetails.events || []
    endpoints.value = assetDetails.endpoints || []
    summary.value = assetDetails.summary || null
    dnsInfo.value = assetDetails.dns_info || null
    techStack.value = assetDetails.tech_stack || []
    httpInfo.value = assetDetails.http_info || []
    parentAsset.value = assetDetails.parent_asset || null

    // Load screenshots
    try {
      const { default: apiClient } = await import('@/api/client')
      const screenshotResp = await apiClient.get(
        `/api/v1/tenants/${tenantStore.currentTenantId}/assets/${assetId.value}/screenshots`
      )
      screenshots.value = screenshotResp.data.screenshots || []
      // Pre-load thumbnail blobs via authenticated client
      if (screenshots.value.length > 0) {
        loadAllThumbnails()
      }
    } catch {
      screenshots.value = []
    }
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } } }
    error.value = axiosErr.response?.data?.detail || 'Failed to load asset details'
  } finally {
    isLoading.value = false
  }
}

const rescanMessage = ref('')

async function handleRescan() {
  if (!tenantStore.currentTenantId || !asset.value) return
  isRescanning.value = true
  rescanMessage.value = ''
  try {
    const { default: apiClient } = await import('@/api/client')
    await apiClient.post(
      `/api/v1/tenants/${tenantStore.currentTenantId}/assets/${asset.value.id}/rescan`
    )
    rescanMessage.value = 'Rescan queued. Results will appear shortly.'
    // Reload after a delay to pick up new data
    setTimeout(() => {
      loadAssetDetails()
      rescanMessage.value = ''
    }, 10000)
  } catch (err: unknown) {
    const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string }
    rescanMessage.value = axiosErr.response?.data?.detail || 'Failed to trigger rescan'
  } finally {
    isRescanning.value = false
  }
}

// ---------------------------------------------------------------------------
// Computed helpers
// ---------------------------------------------------------------------------

const riskScore = computed(() => asset.value?.risk_score ?? 0)

const riskScoreColor = computed(() => getRiskScoreClasses(riskScore.value))

const { arc: riskGaugeArc } = useRiskGauge(riskScore, 38)

const assetTypeBadge = computed(() => {
  const t = asset.value?.type || 'unknown'
  const map: Record<string, { label: string; cls: string }> = {
    domain: { label: 'Domain', cls: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' },
    subdomain: { label: 'Subdomain', cls: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400' },
    ip: { label: 'IP Address', cls: 'bg-cyan-100 text-cyan-700 dark:bg-cyan-900/30 dark:text-cyan-400' },
    url: { label: 'URL', cls: 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-400' },
    service: { label: 'Service', cls: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' },
  }
  return map[t] || { label: t, cls: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300' }
})

const openFindings = computed(() => findings.value.filter((f: Finding) => f.status === 'open'))

const severityBreakdown = computed(() => {
  if (summary.value?.severity_breakdown) return summary.value.severity_breakdown
  const breakdown: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of openFindings.value) {
    const sev = f.severity?.toLowerCase()
    if (sev && sev in breakdown) {
      breakdown[sev]++
    }
  }
  return breakdown
})

const expiringCerts = computed(() =>
  certificates.value.filter((c: Certificate) => !c.is_expired && c.days_until_expiry !== undefined && c.days_until_expiry <= 30)
)

const cloudProviderInfo = computed(() => {
  const provider = asset.value?.cloud_provider || dnsInfo.value?.cloud_provider
  if (!provider) return null
  const map: Record<string, { color: string }> = {
    AWS: { color: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400' },
    GCP: { color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' },
    Azure: { color: 'bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400' },
    Cloudflare: { color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' },
    DigitalOcean: { color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400' },
  }
  return { name: provider, ...(map[provider] || { color: 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300' }) }
})

// Group tech by approximate category
const groupedTech = computed(() => {
  if (techStack.value.length === 0) return {}
  const webServers = ['nginx', 'apache', 'iis', 'caddy', 'litespeed', 'lighttpd', 'openresty']
  const frameworks = ['react', 'vue', 'angular', 'next.js', 'nuxt', 'svelte', 'django', 'flask', 'rails', 'laravel', 'express', 'spring', 'asp.net']
  const cms = ['wordpress', 'drupal', 'joomla', 'ghost', 'strapi', 'contentful', 'shopify', 'magento', 'woocommerce']
  const jsLibs = ['jquery', 'bootstrap', 'tailwind', 'lodash', 'moment.js', 'axios', 'three.js', 'd3.js']
  const cdns = ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'stackpath', 'bunnycdn']
  const languages = ['php', 'python', 'java', 'ruby', 'node.js', 'go', '.net', 'perl']

  const groups: Record<string, string[]> = {}
  for (const tech of techStack.value) {
    const lower = tech.toLowerCase()
    let category = 'Other'
    if (webServers.some(ws => lower.includes(ws))) category = 'Web Server'
    else if (frameworks.some(fw => lower.includes(fw))) category = 'Framework'
    else if (cms.some(c => lower.includes(c))) category = 'CMS'
    else if (jsLibs.some(lib => lower.includes(lib))) category = 'JS Library'
    else if (cdns.some(cdn => lower.includes(cdn))) category = 'CDN'
    else if (languages.some(lang => lower.includes(lang))) category = 'Language'

    if (!groups[category]) groups[category] = []
    groups[category].push(tech)
  }
  return groups
})

function screenshotProxyPath(screenshot: Screenshot, type: 'full' | 'thumb'): string {
  const filename = (type === 'thumb' ? screenshot.thumb : screenshot.full).split('/').pop()
  return `/api/v1/tenants/${tenantStore.currentTenantId}/assets/${assetId.value}/screenshots/${type}/${filename}`
}

function screenshotUrl(screenshot: Screenshot, type: 'full' | 'thumb'): string {
  const path = screenshotProxyPath(screenshot, type)
  return screenshotBlobs.value[path] || ''
}

/** Load screenshot image as blob via authenticated API client */
async function loadScreenshotBlob(screenshot: Screenshot, type: 'full' | 'thumb'): Promise<void> {
  const path = screenshotProxyPath(screenshot, type)
  if (screenshotBlobs.value[path]) return // already loaded
  try {
    const { default: apiClient } = await import('@/api/client')
    const resp = await apiClient.get(path, { responseType: 'blob' })
    const url = URL.createObjectURL(resp.data)
    screenshotBlobs.value[path] = url
  } catch {
    // silently fail — the image just won't show
  }
}

/** Pre-load all thumbnail blobs after screenshots metadata is fetched */
async function loadAllThumbnails(): Promise<void> {
  await Promise.all(screenshots.value.map(ss => loadScreenshotBlob(ss, 'thumb')))
}

const filteredEndpoints = computed(() => {
  if (endpointTypeFilter.value === 'all') return endpoints.value
  return endpoints.value.filter((e: AssetEndpoint) => e.endpoint_type === endpointTypeFilter.value)
})

const endpointTypes = computed(() => {
  const types = new Set(endpoints.value.map((e: AssetEndpoint) => e.endpoint_type).filter(Boolean))
  return ['all', ...Array.from(types)]
})

const openPortsList = computed((): number[] => {
  if (summary.value?.open_ports?.length) return summary.value.open_ports
  const ports: number[] = services.value
    .map((s: Service) => s.port)
    .filter((p: number | undefined): p is number => p !== undefined && p !== null)
  return Array.from(new Set<number>(ports)).sort((a: number, b: number) => a - b)
})

const servicesWithTlsCount = computed(() => services.value.filter((s: Service) => s.has_tls).length)
const apiEndpointsCount = computed(() => endpoints.value.filter((e: AssetEndpoint) => e.is_api).length)

// ---------------------------------------------------------------------------
// Well-known port to service name mapping
// ---------------------------------------------------------------------------

const WELL_KNOWN_PORTS: Record<number, { name: string; proto: string }> = {
  21: { name: 'FTP', proto: 'ftp' },
  22: { name: 'SSH', proto: 'ssh' },
  23: { name: 'Telnet', proto: 'telnet' },
  25: { name: 'SMTP', proto: 'smtp' },
  53: { name: 'DNS', proto: 'dns' },
  80: { name: 'HTTP', proto: 'http' },
  110: { name: 'POP3', proto: 'pop3' },
  143: { name: 'IMAP', proto: 'imap' },
  443: { name: 'HTTPS', proto: 'https' },
  445: { name: 'SMB', proto: 'smb' },
  465: { name: 'SMTPS', proto: 'smtps' },
  587: { name: 'SMTP Submission', proto: 'submission' },
  993: { name: 'IMAPS', proto: 'imaps' },
  995: { name: 'POP3S', proto: 'pop3s' },
  1433: { name: 'MSSQL', proto: 'mssql' },
  1521: { name: 'Oracle DB', proto: 'oracle' },
  3306: { name: 'MySQL', proto: 'mysql' },
  3389: { name: 'RDP', proto: 'rdp' },
  4443: { name: 'HTTPS Alt', proto: 'https' },
  5222: { name: 'XMPP Client', proto: 'xmpp' },
  5269: { name: 'XMPP Server', proto: 'xmpp-s2s' },
  5280: { name: 'XMPP HTTP', proto: 'xmpp-bosh' },
  5432: { name: 'PostgreSQL', proto: 'postgres' },
  5672: { name: 'AMQP', proto: 'amqp' },
  6379: { name: 'Redis', proto: 'redis' },
  8080: { name: 'HTTP Proxy', proto: 'http-proxy' },
  8443: { name: 'HTTPS Alt', proto: 'https-alt' },
  8888: { name: 'HTTP Alt', proto: 'http-alt' },
  9090: { name: 'HTTP Admin', proto: 'http-admin' },
  9200: { name: 'Elasticsearch', proto: 'elasticsearch' },
  9999: { name: 'HTTP Admin', proto: 'http-admin' },
  27017: { name: 'MongoDB', proto: 'mongodb' },
}

function getServiceName(service: Service): string {
  // Use fingerprintx-detected protocol over generic port mapping
  if (service.protocol && service.protocol !== 'tcp' && service.protocol !== 'udp') return service.protocol.toUpperCase()
  if (service.port && WELL_KNOWN_PORTS[service.port]) return WELL_KNOWN_PORTS[service.port].name
  return 'Unknown'
}

/** Parse version field which may contain "product/version" or just "product" */
function parseProductVersion(service: Service): { product: string; version: string } {
  const ver = service.version || ''
  // "nginx/1.26.3" → product=nginx, version=1.26.3
  if (ver.includes('/')) {
    const [prod, ...rest] = ver.split('/')
    return { product: prod, version: rest.join('/') }
  }
  // "nginx" (no digits = product name, not version)
  if (ver && !/^\d/.test(ver)) {
    return { product: ver, version: '' }
  }
  // "1.26.3" or empty
  return { product: '', version: ver }
}


// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

/** Alias for template compatibility */
const getSeverityColor = getSeverityBadgeClass

function getSeverityDot(severity: string): string {
  const colors: Record<string, string> = {
    critical: 'bg-red-500',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
    info: 'bg-gray-400',
  }
  return colors[severity.toLowerCase()] || 'bg-gray-400'
}

/** Alias for template compatibility */
const getStatusBadge = getFindingStatusBadgeClass

function getMethodBadge(method: string): string {
  const colors: Record<string, string> = {
    GET: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    POST: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    PUT: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    PATCH: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400',
    DELETE: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  }
  return colors[method?.toUpperCase()] || 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
}

function getEventKindBadge(kind: string): string {
  const colors: Record<string, string> = {
    new_asset: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
    open_port: 'bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400',
    new_cert: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    new_path: 'bg-purple-100 text-purple-700 dark:bg-purple-900/30 dark:text-purple-400',
    finding: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
  }
  return colors[kind.toLowerCase()] || 'bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300'
}

/** Alias for template compatibility -- delegates to shared formatDate */
function formatRelativeDate(dateString: string | undefined | null): string {
  return formatDate(dateString, 'relative')
}

function certExpiryText(cert: Certificate): string {
  if (cert.is_expired) return 'Expired'
  if (cert.days_until_expiry === undefined || cert.days_until_expiry === null) return 'Unknown'
  if (cert.days_until_expiry <= 0) return 'Expired'
  if (cert.days_until_expiry <= 7) return `${cert.days_until_expiry}d (critical)`
  if (cert.days_until_expiry <= 30) return `${cert.days_until_expiry}d (warning)`
  return `${cert.days_until_expiry} days`
}

function certExpiryClass(cert: Certificate): string {
  if (cert.is_expired || (cert.days_until_expiry !== undefined && cert.days_until_expiry <= 0)) {
    return 'text-red-600 dark:text-red-400'
  }
  if (cert.days_until_expiry !== undefined && cert.days_until_expiry <= 30) {
    return 'text-orange-600 dark:text-orange-400'
  }
  return 'text-green-600 dark:text-green-400'
}

function httpStatusClass(code: number): string {
  if (code >= 200 && code < 300) return 'text-green-600 dark:text-green-400'
  if (code >= 300 && code < 400) return 'text-blue-600 dark:text-blue-400'
  if (code >= 400 && code < 500) return 'text-orange-600 dark:text-orange-400'
  if (code >= 500) return 'text-red-600 dark:text-red-400'
  return 'text-gray-600 dark:text-gray-400'
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

onMounted(() => {
  loadAssetDetails()
})

// Reload when navigating between assets (e.g. View Parent)
watch(assetId, () => {
  loadAssetDetails()
})

onUnmounted(() => {
  // Release object URLs to avoid memory leaks
  for (const url of Object.values(screenshotBlobs.value)) {
    URL.revokeObjectURL(url)
  }
})
</script>

<template>
  <div class="max-w-7xl mx-auto">

    <!-- ================================================================== -->
    <!-- ERROR STATE                                                        -->
    <!-- ================================================================== -->
    <div v-if="error" role="alert" class="rounded-lg bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 p-4 mb-6">
      <div class="flex items-center gap-3">
        <ExclamationTriangleIcon class="h-5 w-5 text-red-600 dark:text-red-400 flex-shrink-0" />
        <p class="text-sm text-red-800 dark:text-red-200">{{ error }}</p>
      </div>
    </div>

    <!-- ================================================================== -->
    <!-- LOADING STATE                                                      -->
    <!-- ================================================================== -->
    <div v-if="isLoading" role="status" class="space-y-6">
      <!-- Skeleton header -->
      <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
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
        <div v-for="n in 6" :key="n" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4">
          <div class="animate-pulse space-y-2">
            <div class="h-3 bg-gray-200 dark:bg-gray-700 rounded w-16" />
            <div class="h-7 bg-gray-200 dark:bg-gray-700 rounded w-10" />
          </div>
        </div>
      </div>
      <!-- Skeleton cards -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div v-for="n in 4" :key="n" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
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
      <!-- 1. HEADER SECTION                                                -->
      <!-- ================================================================ -->
      <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
        <div class="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-4">
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
              <h1 class="text-2xl lg:text-3xl font-bold text-gray-900 dark:text-dark-text-primary truncate font-mono">
                {{ asset.identifier }}
              </h1>
              <div class="mt-2 flex flex-wrap items-center gap-2">
                <!-- Asset type badge -->
                <span :class="['inline-flex items-center px-2.5 py-1 rounded-md text-xs font-semibold', assetTypeBadge.cls]">
                  {{ assetTypeBadge.label }}
                </span>
                <!-- Status badge -->
                <span
                  v-if="asset.is_active"
                  class="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-semibold bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400"
                >
                  <span class="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse-slow" />
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
                  :class="['inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold', cloudProviderInfo.color]"
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
              <div class="mt-3 flex flex-wrap items-center gap-4 text-xs text-gray-500 dark:text-dark-text-tertiary">
                <span class="inline-flex items-center gap-1">
                  <ClockIcon class="h-3.5 w-3.5" />
                  First seen {{ formatRelativeDate(asset.first_seen) }}
                </span>
                <span class="inline-flex items-center gap-1">
                  <ClockIcon class="h-3.5 w-3.5" />
                  Last seen {{ formatRelativeDate(asset.last_seen) }}
                </span>
                <span v-if="asset.last_enriched_at" class="inline-flex items-center gap-1">
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
                  cx="50" cy="50" r="38"
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
                  x="50" y="46"
                  text-anchor="middle"
                  dominant-baseline="middle"
                  :fill="riskScoreColor.fill"
                  font-size="18"
                  font-weight="bold"
                >
                  {{ riskScore }}
                </text>
                <text
                  x="50" y="62"
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
                @click="handleRescan"
                :disabled="isRescanning"
                class="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-primary-600 hover:bg-primary-700 disabled:opacity-50 rounded-lg transition-colors"
              >
                <ArrowPathIcon class="h-4 w-4" :class="{ 'animate-spin': isRescanning }" />
                Rescan
              </button>
            </div>
          </div>
        </div>
      </div>

      <!-- Rescan feedback -->
      <div v-if="rescanMessage" class="rounded-lg border p-4"
        :class="rescanMessage.includes('Failed') ? 'bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-800 dark:text-red-200' : 'bg-blue-50 dark:bg-blue-900/20 border-blue-200 dark:border-blue-800 text-blue-800 dark:text-blue-200'"
      >
        <p class="text-sm">{{ rescanMessage }}</p>
      </div>

      <!-- Parent asset banner (for SERVICE-type assets) -->
      <div
        v-if="parentAsset"
        class="bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-lg p-4 flex items-center justify-between"
      >
        <div class="flex items-center gap-3">
          <ServerStackIcon class="h-5 w-5 text-amber-600 dark:text-amber-400 flex-shrink-0" />
          <div>
            <p class="text-sm font-medium text-amber-800 dark:text-amber-200">
              This is a service-level asset. Data shown is inherited from the parent host.
            </p>
            <p class="text-xs text-amber-600 dark:text-amber-400 mt-0.5">
              Parent: <strong>{{ parentAsset.identifier }}</strong> ({{ parentAsset.type }})
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

      <!-- ================================================================ -->
      <!-- 2. SUMMARY KPI CARDS                                             -->
      <!-- ================================================================ -->
      <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <!-- Open Ports -->
        <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4">
          <div class="flex items-center gap-2 mb-2">
            <SignalIcon class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary" />
            <span class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Open Ports</span>
          </div>
          <p class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">{{ openPortsList.length }}</p>
          <p v-if="openPortsList.length > 0" class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary truncate" :title="openPortsList.join(', ')">
            {{ openPortsList.slice(0, 5).join(', ') }}<span v-if="openPortsList.length > 5">...</span>
          </p>
          <p v-else class="mt-1 text-xs text-gray-400 dark:text-dark-text-tertiary">None detected</p>
        </div>

        <!-- Open Findings -->
        <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4">
          <div class="flex items-center gap-2 mb-2">
            <ShieldExclamationIcon class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary" />
            <span class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Findings</span>
          </div>
          <p class="text-2xl font-bold" :class="openFindings.length > 0 ? 'text-red-600 dark:text-red-400' : 'text-gray-900 dark:text-dark-text-primary'">
            {{ summary?.open_findings ?? openFindings.length }}
          </p>
          <div class="mt-1 flex items-center gap-1 flex-wrap">
            <span v-if="severityBreakdown.critical" class="inline-flex items-center text-[10px] font-bold px-1 py-0.5 rounded bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">{{ severityBreakdown.critical }}C</span>
            <span v-if="severityBreakdown.high" class="inline-flex items-center text-[10px] font-bold px-1 py-0.5 rounded bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400">{{ severityBreakdown.high }}H</span>
            <span v-if="severityBreakdown.medium" class="inline-flex items-center text-[10px] font-bold px-1 py-0.5 rounded bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400">{{ severityBreakdown.medium }}M</span>
          </div>
        </div>

        <!-- Services -->
        <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4">
          <div class="flex items-center gap-2 mb-2">
            <ServerStackIcon class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary" />
            <span class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Services</span>
          </div>
          <p class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">{{ summary?.total_services ?? services.length }}</p>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary">
            {{ servicesWithTlsCount }} with TLS
          </p>
        </div>

        <!-- Certificates -->
        <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4">
          <div class="flex items-center gap-2 mb-2">
            <LockClosedIcon class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary" />
            <span class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Certificates</span>
          </div>
          <p class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">{{ summary?.total_certificates ?? certificates.length }}</p>
          <p v-if="expiringCerts.length > 0" class="mt-1 text-xs text-orange-600 dark:text-orange-400 font-medium">
            {{ expiringCerts.length }} expiring soon
          </p>
          <p v-else class="mt-1 text-xs text-green-600 dark:text-green-400">All valid</p>
        </div>

        <!-- Endpoints -->
        <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4">
          <div class="flex items-center gap-2 mb-2">
            <LinkIcon class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary" />
            <span class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Endpoints</span>
          </div>
          <p class="text-2xl font-bold text-gray-900 dark:text-dark-text-primary">{{ summary?.total_endpoints ?? endpoints.length }}</p>
          <p class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary">
            {{ apiEndpointsCount }} API
          </p>
        </div>

        <!-- Risk Score mini -->
        <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-4">
          <div class="flex items-center gap-2 mb-2">
            <ExclamationTriangleIcon class="h-4 w-4 text-gray-400 dark:text-dark-text-tertiary" />
            <span class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Risk</span>
          </div>
          <p class="text-2xl font-bold" :class="riskScoreColor.text">{{ riskScore }}<span class="text-sm font-normal text-gray-400 dark:text-dark-text-tertiary">/100</span></p>
          <div class="mt-1.5 w-full h-1.5 bg-gray-200 dark:bg-dark-bg-tertiary rounded-full overflow-hidden">
            <div class="h-full rounded-full transition-all duration-500" :class="riskScoreColor.bg" :style="{ width: riskScore + '%' }" />
          </div>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 3. DNS & NETWORK INTELLIGENCE                                    -->
      <!-- ================================================================ -->
      <div v-if="dnsInfo" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
        <div class="flex items-center gap-2 mb-5">
          <GlobeAltIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">DNS & Network Intelligence</h2>
        </div>
        <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          <!-- Resolved IPs -->
          <div v-if="dnsInfo.resolved_ips?.length">
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">Resolved IPs</h3>
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
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">Reverse DNS</h3>
            <p class="text-sm font-mono text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.reverse_dns }}</p>
          </div>

          <!-- Cloud Provider -->
          <div v-if="dnsInfo.cloud_provider">
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">Cloud Provider</h3>
            <span
              v-if="cloudProviderInfo"
              :class="['inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-semibold', cloudProviderInfo.color]"
            >
              <CloudIcon class="h-4 w-4" />
              {{ cloudProviderInfo.name }}
            </span>
          </div>

          <!-- WHOIS -->
          <div v-if="dnsInfo.whois_summary">
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">WHOIS Information</h3>
            <dl class="space-y-1.5">
              <div v-if="dnsInfo.whois_summary.registrar" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Registrar</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.whois_summary.registrar }}</dd>
              </div>
              <div v-if="dnsInfo.whois_summary.org" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Organization</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.whois_summary.org }}</dd>
              </div>
              <div v-if="dnsInfo.whois_summary.country" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Country</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.whois_summary.country }}</dd>
              </div>
              <div v-if="dnsInfo.whois_summary.created" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Created</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.whois_summary.created }}</dd>
              </div>
              <div v-if="dnsInfo.whois_summary.expires" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Expires</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.whois_summary.expires }}</dd>
              </div>
            </dl>
          </div>

          <!-- ASN -->
          <div v-if="dnsInfo.asn_info">
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">ASN Information</h3>
            <dl class="space-y-1.5">
              <div v-if="dnsInfo.asn_info.asn" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">ASN</dt>
                <dd class="text-xs font-mono text-gray-900 dark:text-dark-text-primary">AS{{ dnsInfo.asn_info.asn }}</dd>
              </div>
              <div v-if="dnsInfo.asn_info.org" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Organization</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.asn_info.org }}</dd>
              </div>
              <div v-if="dnsInfo.asn_info.country" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Country</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.asn_info.country }}</dd>
              </div>
            </dl>
          </div>

          <!-- GeoIP Location -->
          <div v-if="dnsInfo.geo_info">
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">Geolocation</h3>
            <dl class="space-y-1.5">
              <div v-if="dnsInfo.geo_info.country" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Country</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">
                  {{ dnsInfo.geo_info.country }}
                  <span v-if="dnsInfo.geo_info.country_code" class="text-gray-400 dark:text-dark-text-tertiary ml-1">({{ dnsInfo.geo_info.country_code }})</span>
                </dd>
              </div>
              <div v-if="dnsInfo.geo_info.region" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Region</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.geo_info.region }}</dd>
              </div>
              <div v-if="dnsInfo.geo_info.city" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">City</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.geo_info.city }}</dd>
              </div>
              <div v-if="dnsInfo.geo_info.lat && dnsInfo.geo_info.lon" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">Coordinates</dt>
                <dd class="text-xs font-mono text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.geo_info.lat.toFixed(4) }}, {{ dnsInfo.geo_info.lon.toFixed(4) }}</dd>
              </div>
              <div v-if="dnsInfo.geo_info.isp" class="flex gap-2">
                <dt class="text-xs text-gray-500 dark:text-dark-text-tertiary w-20 flex-shrink-0">ISP</dt>
                <dd class="text-xs text-gray-900 dark:text-dark-text-primary">{{ dnsInfo.geo_info.isp }}</dd>
              </div>
            </dl>
          </div>

          <!-- Nameservers -->
          <div v-if="dnsInfo.nameservers?.length">
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">Nameservers</h3>
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

      <!-- ================================================================ -->
      <!-- 4. TECHNOLOGY STACK                                              -->
      <!-- ================================================================ -->
      <div v-if="techStack.length > 0" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
        <div class="flex items-center gap-2 mb-5">
          <CpuChipIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Technology Stack</h2>
          <span class="ml-auto text-xs text-gray-400 dark:text-dark-text-tertiary">{{ techStack.length }} technologies detected</span>
        </div>
        <!-- If grouped -->
        <div v-if="Object.keys(groupedTech).length > 1" class="space-y-4">
          <div v-for="(techs, category) in groupedTech" :key="category">
            <h3 class="text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-2">{{ category }}</h3>
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
      <div v-if="httpInfo.length > 0" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
        <div class="flex items-center gap-2 mb-5">
          <GlobeAltIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">HTTP Services</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 dark:border-dark-border">
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Port</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Status</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Title</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Web Server</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">TLS</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Response</th>
                <th class="pb-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Technologies</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-border/50">
              <tr v-for="http in httpInfo" :key="http.port" class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50">
                <td class="py-3 pr-4 font-mono font-medium text-gray-900 dark:text-dark-text-primary">{{ http.port }}</td>
                <td class="py-3 pr-4">
                  <span class="font-mono font-medium" :class="httpStatusClass(http.status_code)">{{ http.status_code }}</span>
                </td>
                <td class="py-3 pr-4 text-gray-700 dark:text-dark-text-secondary max-w-xs truncate" :title="http.title">
                  {{ http.title || '--' }}
                </td>
                <td class="py-3 pr-4 text-gray-700 dark:text-dark-text-secondary">{{ http.web_server || '--' }}</td>
                <td class="py-3 pr-4">
                  <span v-if="http.has_tls" class="inline-flex items-center gap-1 text-green-600 dark:text-green-400">
                    <LockClosedIcon class="h-3.5 w-3.5" />
                    {{ http.tls_version || 'Yes' }}
                  </span>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary">--</span>
                </td>
                <td class="py-3 pr-4 text-gray-700 dark:text-dark-text-secondary">
                  <span v-if="http.response_time_ms" :class="http.response_time_ms > 2000 ? 'text-orange-600 dark:text-orange-400' : ''">
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
                    <span v-if="(http.technologies || []).length > 4" class="text-[10px] text-gray-400">
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
      <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
        <div class="flex items-center gap-2 mb-5">
          <ServerStackIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Services</h2>
          <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary">
            {{ services.length }}
          </span>
        </div>
        <div v-if="services.length > 0" class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 dark:border-dark-border">
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Port</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Service</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Product / Version</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">TLS</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Fingerprint</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Source</th>
                <th class="pb-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Last Seen</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-border/50">
              <tr v-for="service in services" :key="service.id" class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50">
                <td class="py-3 pr-4">
                  <span class="font-mono font-semibold text-gray-900 dark:text-dark-text-primary">{{ service.port ?? '--' }}</span>
                  <span class="text-gray-400 dark:text-dark-text-tertiary text-xs">/{{ service.protocol || 'tcp' }}</span>
                </td>
                <td class="py-3 pr-4">
                  <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-indigo-100 text-indigo-700 dark:bg-indigo-900/30 dark:text-indigo-300">
                    {{ getServiceName(service) }}
                  </span>
                  <p v-if="service.http_title" class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-1 truncate max-w-[200px]">
                    {{ service.http_title }}
                  </p>
                  <p v-if="service.web_server" class="text-xs text-gray-400 dark:text-dark-text-tertiary mt-0.5">
                    {{ service.web_server }}
                  </p>
                </td>
                <td class="py-3 pr-4">
                  <template v-if="service.version || (service.product && service.product !== service.protocol?.toUpperCase())">
                    <span v-if="parseProductVersion(service).product" class="text-gray-900 dark:text-dark-text-primary font-medium">{{ parseProductVersion(service).product }}</span>
                    <span v-if="parseProductVersion(service).version" class="ml-1 font-mono text-xs text-gray-500 dark:text-dark-text-tertiary">{{ parseProductVersion(service).version }}</span>
                  </template>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary">--</span>
                  <div v-if="service.http_status" class="mt-0.5">
                    <span class="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-mono"
                      :class="service.http_status < 300 ? 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300' :
                              service.http_status < 400 ? 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-300' :
                              'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'">
                      HTTP {{ service.http_status }}
                    </span>
                  </div>
                </td>
                <td class="py-3 pr-4">
                  <span v-if="service.has_tls" class="inline-flex items-center gap-1 text-green-600 dark:text-green-400 text-xs font-medium">
                    <LockClosedIcon class="h-3.5 w-3.5" />
                    {{ service.tls_version || 'Yes' }}
                  </span>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary text-xs">--</span>
                </td>
                <td class="py-3 pr-4">
                  <span v-if="service.tls_fingerprint" class="font-mono text-xs text-gray-500 dark:text-dark-text-tertiary truncate max-w-[120px] block" :title="service.tls_fingerprint">
                    {{ service.tls_fingerprint.substring(0, 16) }}...
                  </span>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary text-xs">--</span>
                </td>
                <td class="py-3 pr-4">
                  <span v-if="service.enrichment_source" class="inline-flex items-center px-1.5 py-0.5 rounded text-xs bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary">
                    {{ service.enrichment_source }}
                  </span>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary text-xs">--</span>
                </td>
                <td class="py-3 text-gray-500 dark:text-dark-text-tertiary text-xs">{{ formatRelativeDate(service.last_seen) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="text-center py-8">
          <ServerStackIcon class="h-10 w-10 text-gray-300 dark:text-gray-600 mx-auto mb-2" />
          <p class="text-sm text-gray-500 dark:text-dark-text-secondary">No services discovered</p>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 7. FINDINGS                                                      -->
      <!-- ================================================================ -->
      <div class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
        <div class="flex items-center gap-2 mb-5">
          <ShieldExclamationIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Findings</h2>
          <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary">
            {{ findings.length }}
          </span>
        </div>

        <!-- Severity breakdown bar -->
        <div v-if="findings.length > 0" class="mb-5">
          <div class="flex h-2 rounded-full overflow-hidden bg-gray-100 dark:bg-dark-bg-tertiary">
            <div
              v-if="severityBreakdown.critical"
              class="bg-red-500 transition-all duration-500"
              :style="{ width: (severityBreakdown.critical / findings.length * 100) + '%' }"
              :title="`Critical: ${severityBreakdown.critical}`"
            />
            <div
              v-if="severityBreakdown.high"
              class="bg-orange-500 transition-all duration-500"
              :style="{ width: (severityBreakdown.high / findings.length * 100) + '%' }"
              :title="`High: ${severityBreakdown.high}`"
            />
            <div
              v-if="severityBreakdown.medium"
              class="bg-yellow-500 transition-all duration-500"
              :style="{ width: (severityBreakdown.medium / findings.length * 100) + '%' }"
              :title="`Medium: ${severityBreakdown.medium}`"
            />
            <div
              v-if="severityBreakdown.low"
              class="bg-blue-500 transition-all duration-500"
              :style="{ width: (severityBreakdown.low / findings.length * 100) + '%' }"
              :title="`Low: ${severityBreakdown.low}`"
            />
            <div
              v-if="severityBreakdown.info"
              class="bg-gray-400 transition-all duration-500"
              :style="{ width: (severityBreakdown.info / findings.length * 100) + '%' }"
              :title="`Info: ${severityBreakdown.info}`"
            />
          </div>
          <div class="flex items-center gap-4 mt-2">
            <span v-for="(count, sev) in severityBreakdown" :key="sev" v-show="count > 0" class="inline-flex items-center gap-1.5 text-xs text-gray-600 dark:text-dark-text-secondary">
              <span class="w-2 h-2 rounded-full" :class="getSeverityDot(String(sev))" />
              <span class="capitalize">{{ sev }}</span>
              <span class="font-semibold">{{ count }}</span>
            </span>
          </div>
        </div>

        <!-- Findings table -->
        <div v-if="findings.length > 0" class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="border-b border-gray-200 dark:border-dark-border">
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-24">Severity</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Name</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">CVE</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">CVSS</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Status</th>
                <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Source</th>
                <th class="pb-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Last Seen</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-gray-100 dark:divide-dark-border/50">
              <tr
                v-for="finding in findings"
                :key="finding.id"
                @click="router.push(`/findings/${finding.id}`)"
                class="cursor-pointer hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 group"
              >
                <td class="py-3 pr-4">
                  <span
                    :class="['inline-flex items-center px-2 py-0.5 rounded text-xs font-bold uppercase', getSeverityColor(finding.severity)]"
                  >
                    {{ finding.severity }}
                  </span>
                </td>
                <td class="py-3 pr-4">
                  <span class="text-gray-900 dark:text-dark-text-primary font-medium group-hover:text-primary-600 dark:group-hover:text-primary-400 transition-colors">
                    {{ finding.name }}
                  </span>
                </td>
                <td class="py-3 pr-4">
                  <span v-if="finding.cve_id" class="font-mono text-xs text-gray-600 dark:text-dark-text-secondary">{{ finding.cve_id }}</span>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary">--</span>
                </td>
                <td class="py-3 pr-4">
                  <span v-if="finding.cvss_score" class="font-mono font-medium" :class="finding.cvss_score >= 9 ? 'text-red-600 dark:text-red-400' : finding.cvss_score >= 7 ? 'text-orange-600 dark:text-orange-400' : 'text-gray-700 dark:text-dark-text-secondary'">
                    {{ finding.cvss_score.toFixed(1) }}
                  </span>
                  <span v-else class="text-gray-400 dark:text-dark-text-tertiary">--</span>
                </td>
                <td class="py-3 pr-4">
                  <span :class="['inline-flex items-center px-2 py-0.5 rounded text-xs font-medium capitalize', getStatusBadge(finding.status)]">
                    {{ finding.status }}
                  </span>
                </td>
                <td class="py-3 pr-4 text-gray-500 dark:text-dark-text-tertiary text-xs">{{ finding.source }}</td>
                <td class="py-3 text-gray-500 dark:text-dark-text-tertiary text-xs">{{ formatRelativeDate(finding.last_seen) }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div v-else class="text-center py-8">
          <ShieldExclamationIcon class="h-10 w-10 text-gray-300 dark:text-gray-600 mx-auto mb-2" />
          <p class="text-sm text-gray-500 dark:text-dark-text-secondary">No findings reported</p>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 8. TLS CERTIFICATES                                              -->
      <!-- ================================================================ -->
      <div v-if="certificates.length > 0" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg p-6">
        <div class="flex items-center gap-2 mb-5">
          <LockClosedIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
          <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">TLS Certificates</h2>
          <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary">
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
                <h3 class="text-sm font-semibold text-gray-900 dark:text-dark-text-primary truncate font-mono">
                  {{ cert.subject_cn || 'Unknown CN' }}
                </h3>
                <p class="text-xs text-gray-500 dark:text-dark-text-tertiary mt-0.5">
                  Issued by {{ cert.issuer || 'Unknown' }}
                </p>
              </div>
              <!-- Expiry indicator -->
              <span :class="['text-xs font-semibold flex-shrink-0', certExpiryClass(cert)]">
                {{ certExpiryText(cert) }}
              </span>
            </div>

            <!-- Validity dates -->
            <div class="mt-3 grid grid-cols-2 gap-3">
              <div>
                <p class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Valid From</p>
                <p class="text-xs text-gray-700 dark:text-dark-text-secondary mt-0.5">{{ cert.not_before ? new Date(cert.not_before).toLocaleDateString() : '--' }}</p>
              </div>
              <div>
                <p class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Valid Until</p>
                <p class="text-xs mt-0.5" :class="certExpiryClass(cert)">{{ cert.not_after ? new Date(cert.not_after).toLocaleDateString() : '--' }}</p>
              </div>
            </div>

            <!-- Key info row -->
            <div v-if="cert.public_key_algorithm || cert.public_key_bits || cert.signature_algorithm" class="mt-3">
              <p class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-1">Key Information</p>
              <p class="text-xs text-gray-700 dark:text-dark-text-secondary">
                <span v-if="cert.public_key_algorithm">{{ cert.public_key_algorithm }}</span>
                <span v-if="cert.public_key_bits"> {{ cert.public_key_bits }}-bit</span>
                <span v-if="cert.signature_algorithm"> / {{ cert.signature_algorithm }}</span>
              </p>
            </div>

            <!-- SANs -->
            <div v-if="cert.san_domains?.length" class="mt-3">
              <p class="text-[10px] font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider mb-1">Subject Alternative Names</p>
              <div class="flex flex-wrap gap-1">
                <span
                  v-for="san in cert.san_domains.slice(0, 6)"
                  :key="san"
                  class="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary"
                >
                  {{ san }}
                </span>
                <span v-if="cert.san_domains.length > 6" class="text-[10px] text-gray-400 dark:text-dark-text-tertiary self-center">
                  +{{ cert.san_domains.length - 6 }} more
                </span>
              </div>
            </div>

            <!-- Security indicators -->
            <div class="mt-3 flex flex-wrap gap-1.5">
              <span v-if="cert.is_expired" class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">
                EXPIRED
              </span>
              <span v-if="cert.is_self_signed" class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400">
                SELF-SIGNED
              </span>
              <span v-if="cert.is_wildcard" class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                WILDCARD
              </span>
              <span v-if="cert.has_weak_signature" class="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400">
                WEAK SIGNATURE
              </span>
            </div>
          </div>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 9. DISCOVERED ENDPOINTS (collapsible)                            -->
      <!-- ================================================================ -->
      <div v-if="endpoints.length > 0" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg">
        <!-- Toggle header -->
        <button
          @click="showEndpoints = !showEndpoints"
          class="w-full flex items-center justify-between p-6 text-left hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 transition-colors rounded-lg"
        >
          <div class="flex items-center gap-2">
            <LinkIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
            <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Discovered Endpoints</h2>
            <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary">
              {{ endpoints.length }}
            </span>
          </div>
          <ChevronDownIcon v-if="!showEndpoints" class="h-5 w-5 text-gray-400" />
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
              <option v-for="t in endpointTypes" :key="t" :value="t">{{ t === 'all' ? 'All Types' : t }}</option>
            </select>
            <span class="text-xs text-gray-500 dark:text-dark-text-tertiary">{{ filteredEndpoints.length }} results</span>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-gray-200 dark:border-dark-border">
                  <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-20">Method</th>
                  <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Path</th>
                  <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-16">Status</th>
                  <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider">Type</th>
                  <th class="pb-3 pr-4 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-12">API</th>
                  <th class="pb-3 text-left text-xs font-medium text-gray-500 dark:text-dark-text-tertiary uppercase tracking-wider w-16">Depth</th>
                </tr>
              </thead>
              <tbody class="divide-y divide-gray-100 dark:divide-dark-border/50">
                <tr v-for="ep in filteredEndpoints.slice(0, 50)" :key="ep.id" class="hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50">
                  <td class="py-2.5 pr-4">
                    <span :class="['inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold', getMethodBadge(ep.method)]">
                      {{ ep.method }}
                    </span>
                  </td>
                  <td class="py-2.5 pr-4 font-mono text-xs text-gray-700 dark:text-dark-text-secondary truncate max-w-sm" :title="ep.path">
                    {{ ep.path }}
                  </td>
                  <td class="py-2.5 pr-4 font-mono text-xs" :class="httpStatusClass(ep.status_code)">{{ ep.status_code }}</td>
                  <td class="py-2.5 pr-4 text-xs text-gray-500 dark:text-dark-text-tertiary capitalize">{{ ep.endpoint_type || '--' }}</td>
                  <td class="py-2.5 pr-4">
                    <CheckCircleIcon v-if="ep.is_api" class="h-4 w-4 text-green-500" />
                    <span v-else class="text-gray-300 dark:text-gray-600">--</span>
                  </td>
                  <td class="py-2.5 text-xs text-gray-500 dark:text-dark-text-tertiary">{{ ep.depth }}</td>
                </tr>
              </tbody>
            </table>
            <p v-if="filteredEndpoints.length > 50" class="mt-3 text-xs text-gray-500 dark:text-dark-text-tertiary text-center">
              Showing 50 of {{ filteredEndpoints.length }} endpoints
            </p>
          </div>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- SCREENSHOTS                                                      -->
      <!-- ================================================================ -->
      <div v-if="screenshots.length > 0" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg">
        <button
          @click="showScreenshots = !showScreenshots"
          class="w-full flex items-center justify-between p-6 text-left hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 transition-colors rounded-lg"
        >
          <div class="flex items-center gap-2">
            <svg class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" />
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 13a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Screenshots</h2>
            <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary">
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
              @click="selectedScreenshot = ss; loadScreenshotBlob(ss, 'full')"
            >
              <div class="relative overflow-hidden rounded-lg border border-gray-200 dark:border-dark-border aspect-video bg-gray-100 dark:bg-dark-bg-tertiary">
                <img
                  v-if="screenshotUrl(ss, 'thumb')"
                  :src="screenshotUrl(ss, 'thumb')"
                  :alt="`Screenshot port ${ss.full.match(/\d+/)?.[0] || ''}`"
                  class="w-full h-full object-cover group-hover:opacity-80 transition-opacity"
                />
                <div v-else class="flex items-center justify-center h-full text-gray-400 dark:text-dark-text-tertiary text-xs">
                  Loading...
                </div>
              </div>
              <p class="mt-1 text-xs text-gray-500 dark:text-dark-text-tertiary truncate">
                Port {{ ss.full.match(/(\d+)_/)?.[1] || '?' }}
                &middot; {{ new Date(ss.captured_at).toLocaleDateString() }}
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
            <div v-else class="flex items-center justify-center h-64 text-white text-sm">
              Loading full image...
            </div>
          </div>
        </div>
      </div>

      <!-- ================================================================ -->
      <!-- 10. TIMELINE / EVENTS (collapsible)                              -->
      <!-- ================================================================ -->
      <div v-if="events.length > 0" class="bg-white dark:bg-dark-bg-secondary border border-gray-200 dark:border-dark-border rounded-lg">
        <!-- Toggle header -->
        <button
          @click="showEvents = !showEvents"
          class="w-full flex items-center justify-between p-6 text-left hover:bg-gray-50 dark:hover:bg-dark-bg-tertiary/50 transition-colors rounded-lg"
        >
          <div class="flex items-center gap-2">
            <ClockIcon class="h-5 w-5 text-gray-400 dark:text-dark-text-tertiary" />
            <h2 class="text-lg font-semibold text-gray-900 dark:text-dark-text-primary">Timeline</h2>
            <span class="ml-2 inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-gray-100 text-gray-600 dark:bg-dark-bg-tertiary dark:text-dark-text-tertiary">
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
            <div class="absolute left-3 top-0 bottom-0 w-px bg-gray-200 dark:bg-dark-border" />
            <div class="space-y-4">
              <div
                v-for="event in events.slice(0, 30)"
                :key="event.id"
                class="relative flex items-start gap-4 pl-8"
              >
                <!-- Dot -->
                <div class="absolute left-1.5 top-1.5 w-3 h-3 rounded-full border-2 border-white dark:border-dark-bg-secondary bg-gray-400 dark:bg-gray-500" />
                <div class="flex-1 min-w-0">
                  <div class="flex items-center gap-2 flex-wrap">
                    <span :class="['inline-flex items-center px-2 py-0.5 rounded text-[10px] font-bold uppercase', getEventKindBadge(event.kind)]">
                      {{ event.kind.replace(/_/g, ' ') }}
                    </span>
                    <span class="text-xs text-gray-500 dark:text-dark-text-tertiary">{{ formatRelativeDate(event.created_at) }}</span>
                  </div>
                  <p v-if="event.payload" class="mt-1 text-xs text-gray-600 dark:text-dark-text-secondary">
                    {{ typeof event.payload === 'string' ? event.payload : JSON.stringify(event.payload).slice(0, 120) }}
                  </p>
                </div>
              </div>
            </div>
            <p v-if="events.length > 30" class="mt-4 text-xs text-gray-500 dark:text-dark-text-tertiary text-center pl-8">
              Showing 30 of {{ events.length }} events
            </p>
          </div>
        </div>
      </div>

    </div>
  </div>
</template>
