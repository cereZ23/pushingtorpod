// Auth types
export interface User {
  id: number
  email: string
  username: string
  full_name?: string
  is_active: boolean
  is_superuser: boolean
  mfa_enabled?: boolean
  tenant_roles?: Record<number, string>
  created_at: string
  last_login?: string
}

export interface LoginMfaResponse {
  mfa_required: true
  mfa_token: string
}

export interface LoginRequest {
  email: string
  password: string
}

export interface LoginResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
  user: User
}

export interface RefreshResponse {
  access_token: string
  refresh_token: string
  token_type: string
  expires_in: number
}

// Tenant types
export interface Tenant {
  id: number
  name: string
  slug: string
  description?: string
  is_active: boolean
  created_at: string
  updated_at?: string
}

// Asset summary statistics (returned by detail endpoint)
export interface AssetSummary {
  total_services: number
  total_findings: number
  total_certificates: number
  total_endpoints: number
  open_ports: number[]
  has_tls: boolean
  has_http: boolean
  severity_breakdown: Record<string, number>
  open_findings: number
}

// DNS and network intelligence
export interface AssetDnsInfo {
  resolved_ips: string[]
  reverse_dns: string | null
  whois_summary: {
    registrar?: string
    org?: string
    country?: string
    created?: string
    expires?: string
  } | null
  asn_info: {
    asn?: number
    org?: string
    country?: string
  } | null
  cloud_provider: string | null
  nameservers: string[]
}

// HTTP service info
export interface AssetHttpInfo {
  port: number
  title: string
  status_code: number
  web_server: string
  technologies: string[]
  response_time_ms: number
  redirect_url: string
  has_tls: boolean
  tls_version: string
}

// Discovered endpoint
export interface AssetEndpoint {
  id: number
  url: string
  path: string
  method: string
  status_code: number
  content_type: string
  endpoint_type: string
  is_api: boolean
  depth: number
}

// Asset types
export interface Asset {
  id: number
  tenant_id: number
  type: 'domain' | 'subdomain' | 'ip' | 'url' | 'service'
  asset_type: string  // For compatibility
  identifier: string
  priority?: string
  risk_score?: number
  enrichment_status?: string
  is_active: boolean
  status: string  // For compatibility
  first_seen: string
  last_seen: string
  ip_address?: string
  last_enriched_at?: string
  priority_updated_at?: string
  priority_auto_calculated?: boolean
  service_count?: number
  certificate_count?: number
  endpoint_count?: number
  finding_count?: number
  metadata?: Record<string, unknown>
  raw_metadata?: Record<string, unknown>
  // CDN/WAF/Cloud detection (Phase 5b: cdncheck)
  cdn_name?: string
  waf_name?: string
  cloud_provider?: string
  // New enriched fields
  summary?: AssetSummary
  dns_info?: AssetDnsInfo
  tech_stack?: string[]
  http_info?: AssetHttpInfo[]
  endpoints?: AssetEndpoint[]
  // Nested data for detail view
  services?: Service[]
  findings?: Finding[]
  certificates?: Certificate[]
  events?: AssetEvent[]
  // Parent asset (for SERVICE-type assets)
  parent_asset?: {
    id: number
    identifier: string
    type: string
    risk_score?: number
    is_active: boolean
  }
}

// Asset Event types
export interface AssetEvent {
  id: number
  asset_id: number
  kind: string
  payload?: Record<string, unknown>
  created_at: string
}

// Threat intel enrichment embedded in finding evidence
export interface FindingThreatIntel {
  epss_score?: number
  is_kev?: boolean
  kev_date_added?: string
  kev_due_date?: string
}

export interface FindingEvidence {
  threat_intel?: FindingThreatIntel
  [key: string]: unknown
}

// Finding types
export interface Finding {
  id: number
  asset_id: number
  source: string
  template_id?: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss_score?: number
  cve_id?: string
  evidence?: FindingEvidence
  first_seen: string
  last_seen: string
  status: 'open' | 'suppressed' | 'fixed'
  fingerprint?: string
  occurrence_count: number
  asset_identifier?: string
  asset_type?: string
  matched_at?: string
  host?: string
  matcher_name?: string
}

// Certificate types
export interface Certificate {
  id: number
  asset_id: number
  subject_cn?: string
  issuer?: string
  serial_number?: string
  not_before?: string
  not_after?: string
  is_expired: boolean
  days_until_expiry?: number
  san_domains?: string[]
  signature_algorithm?: string
  public_key_algorithm?: string
  public_key_bits?: number
  is_self_signed: boolean
  is_wildcard: boolean
  has_weak_signature: boolean
  first_seen: string
  last_seen: string
}

// Service types
export interface Service {
  id: number
  asset_id: number
  asset_identifier?: string
  asset_type?: string
  port?: number
  protocol?: string
  product?: string
  version?: string
  http_title?: string
  http_status?: number
  web_server?: string
  http_technologies?: string[]
  technologies?: string[]  // Backend uses this field
  tls_fingerprint?: string
  has_tls: boolean
  tls_version?: string
  enrichment_source?: string
  enriched_at?: string
  response_time_ms?: number
  content_length?: number
  redirect_url?: string
  first_seen: string
  last_seen: string
}

// Dashboard stats
export interface TenantStats {
  total_assets: number
  assets_by_type: Record<string, number>
  total_services: number
  total_certificates: number
  total_endpoints: number
  total_findings: number
  findings_by_severity: Record<string, number>
  open_findings: number
  critical_findings: number
  high_findings: number
  expiring_certificates: number
  average_risk_score: number
}

export interface RecentActivity {
  id: number
  type: string
  description: string
  timestamp: string
  metadata?: Record<string, unknown>
}

export interface TrendingAsset {
  id: number
  identifier: string
  type: string
  risk_score: number
  finding_count: number
  last_seen?: string
}

export interface DashboardStats {
  tenant: Tenant
  stats: TenantStats
  recent_activity: RecentActivity[]
  trending_assets: TrendingAsset[]
  risk_distribution: Record<string, number>
}

// Pagination metadata (used by the new envelope format)
export interface PaginationMeta {
  total: number
  page: number
  page_size: number
  total_pages: number
}

// Paginated response envelope: { data, meta }
// Used by: assets, findings, services, issues list endpoints
export interface PaginatedResponse<T> {
  data: T[]
  meta: PaginationMeta
}

// Legacy paginated response (flat format): { items, total, page, ... }
// Used by: certificates, endpoints, projects, dnstwist, suppressions
export interface PaginatedResponseLegacy<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  total_pages: number
}
