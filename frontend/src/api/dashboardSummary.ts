import apiClient from './client'

// UI-3 operational dashboard aggregate — mirrors the typed backend contract
// (app/api/schemas/dashboard_summary.py). The frontend only LABELS these values; it never
// re-derives an outcome, coverage, or tier — the backend owns every decision.

export interface DashScans {
  total: number // = completed + completed_with_limitations + failed (cancelled tracked separately)
  completed: number
  completed_with_limitations: number
  failed: number
  cancelled: number
}

export interface DashEndpoints {
  selected: number // = verified + not_verifiable + failed + skipped
  verified: number
  not_verifiable: number
  failed: number
  skipped: number
  coverage_percent: number | null // null when selected == 0 (never 100)
}

export interface DashFindings {
  auto_closed: number
  reopened: number
  awaiting_confirmation: number
}

export interface DashTierBlock {
  scans: DashScans
  endpoints: DashEndpoints
  findings: DashFindings
}

export interface OperationalDashboard {
  schema_version: number
  period_days: number
  from: string // UTC ISO
  to: string // UTC ISO
  scans: DashScans
  endpoints: DashEndpoints
  findings: DashFindings
  by_tier: Record<string, DashTierBlock> // always keys "1" and "2"
}

export type DashboardPeriod = 7 | 30 | 90

export const dashboardSummaryApi = {
  async getOperational(tenantId: number, days: DashboardPeriod): Promise<OperationalDashboard> {
    const response = await apiClient.get<OperationalDashboard>(
      `/api/v1/tenants/${tenantId}/dashboard/operational-summary`,
      { params: { days } },
    )
    return response.data
  },
}
