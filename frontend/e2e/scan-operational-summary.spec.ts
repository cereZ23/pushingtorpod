import { expect, test, type Page } from '@playwright/test'

// Self-contained browser integration suite for the Scan result / endpoint verification card.
// It exercises the REAL router, stores, and ScanOperationalSummary rendering in a real browser, but
// needs NO backend: minimal auth state is injected into localStorage and every API the Scan Detail
// path touches is mocked with fixtures that match the typed backend contract. Any UNEXPECTED API
// request fails the test, so a missing mock can never be silently hidden. This is NOT a full-stack
// end-to-end test — auth.setup.ts is left untouched for a future full-stack suite.

const TENANT_ID = 1
const RUN_ID = 59100

type EndpointVerification = {
  available: boolean
  enabled: boolean
  state: string | null
  limitation: string | null
  limitations: string[]
  selected: number
  covered: number
  not_verifiable: number
  failed: number
  skipped: number
  unstarted: number
  coverage_percent: number | null
  data_inconsistent: boolean
}

type AutoClose = {
  detected: number
  eligible_miss: number
  would_close: number
  closed: number
  reopened: number
}

type OperationalSummary = {
  schema_version: number
  outcome: string
  tier: number | null
  trigger_type: string | null
  trigger_label: string | null
  endpoint_verification: EndpointVerification
  auto_close: AutoClose
}

function ev(partial: Partial<EndpointVerification> = {}): EndpointVerification {
  return {
    available: true,
    enabled: true,
    state: 'complete',
    limitation: null,
    limitations: [],
    selected: 100,
    covered: 100,
    not_verifiable: 0,
    failed: 0,
    skipped: 0,
    unstarted: 0,
    coverage_percent: 100,
    data_inconsistent: false,
    ...partial,
  }
}

function ac(partial: Partial<AutoClose> = {}): AutoClose {
  return { detected: 0, eligible_miss: 0, would_close: 0, closed: 0, reopened: 0, ...partial }
}

function summary(partial: Partial<OperationalSummary> = {}): OperationalSummary {
  return {
    schema_version: 1,
    outcome: 'completed',
    tier: 1,
    trigger_type: 'manual',
    trigger_label: null,
    endpoint_verification: partial.endpoint_verification ?? ev(),
    auto_close: partial.auto_close ?? ac(),
    ...partial,
  }
}

function scanRunPayload(operational_summary: OperationalSummary | null) {
  return {
    scan_run: {
      id: RUN_ID,
      project_id: 1,
      profile_id: 1,
      tenant_id: TENANT_ID,
      status: 'completed',
      triggered_by: 'manual',
      trigger_type: 'manual',
      trigger_label: null,
      scan_tier: 1,
      started_at: '2026-08-07T08:00:00Z',
      completed_at: '2026-08-07T08:20:00Z',
      stats: {},
      error_message: null,
      celery_task_id: null,
      created_at: '2026-08-07T08:00:00Z',
      duration_seconds: 1200,
      operational_summary,
    },
    phases: [],
  }
}

const USER = {
  id: 1,
  email: 'e2e@card.test',
  username: 'e2e',
  full_name: 'E2E User',
  is_active: true,
  is_superuser: false,
  tenant_roles: { [TENANT_ID]: 'admin' },
  created_at: '2026-08-01T00:00:00Z',
}

const TENANT = {
  id: TENANT_ID,
  name: 'E2E Tenant',
  slug: 'e2e-tenant',
  is_active: true,
  created_at: '2026-08-01T00:00:00Z',
}

function json(body: unknown) {
  return { status: 200, contentType: 'application/json', body: JSON.stringify(body) }
}

// Injects minimal auth state + mocks exactly the APIs the Scan Detail path consumes. Returns the
// list of UNEXPECTED API paths so each test can assert it stayed empty.
async function setup(page: Page, operational_summary: OperationalSummary | null): Promise<string[]> {
  const unexpected: string[] = []

  await page.addInitScript(() => {
    localStorage.setItem('accessToken', 'e2e-mock-token')
    localStorage.setItem('refreshToken', 'e2e-mock-refresh')
    localStorage.setItem('currentTenantId', '1')
  })

  // Catch-all FIRST so the specific routes (registered after) take precedence — an unmocked API
  // request lands here, is recorded, and fails the test.
  await page.route('**/api/**', (route) => {
    unexpected.push(new URL(route.request().url()).pathname)
    route.fulfill({ status: 500, contentType: 'application/json', body: '{}' })
  })

  await page.route(/\/api\/v1\/auth\/me$/, (route) => route.fulfill(json(USER)))
  await page.route(/\/api\/v1\/tenants$/, (route) => route.fulfill(json([TENANT])))
  await page.route(
    new RegExp(`/api/v1/tenants/\\d+/scans/${RUN_ID}/progress$`),
    (route) => route.fulfill(json(scanRunPayload(operational_summary))),
  )

  return unexpected
}

test.describe('Scan result / endpoint verification card (mocked API)', () => {
  test('scenario 1 — clean completed scan, 100% covered', async ({ page }) => {
    const unexpected = await setup(page, summary())
    await page.goto(`/scans/${RUN_ID}`)

    await expect(page.getByTestId('scan-outcome-badge')).toHaveText('Completed')
    await expect(page.getByTestId('endpoint-state-badge')).toHaveText('All endpoints verified')
    await expect(page.getByTestId('coverage-percent')).toContainText('100%')
    await expect(page.getByTestId('limitation-reasons')).toHaveCount(0)
    expect(unexpected).toEqual([])
  })

  test('scenario 2 — completed with limitations (96/100, unresponsive)', async ({ page }) => {
    const unexpected = await setup(
      page,
      summary({
        outcome: 'completed_with_limitations',
        endpoint_verification: ev({
          state: 'limited',
          limitation: 'unresponsive_origins',
          limitations: ['unresponsive_origins'],
          selected: 100,
          covered: 96,
          not_verifiable: 4,
          coverage_percent: 96,
        }),
      }),
    )
    await page.goto(`/scans/${RUN_ID}`)

    await expect(page.getByTestId('scan-outcome-badge')).toHaveText('Completed with limitations')
    await expect(page.getByTestId('endpoint-state-badge')).toHaveText('Verified with limitations')
    await expect(page.getByTestId('coverage-percent')).toContainText('96%')
    await expect(page.getByTestId('limitation-reasons')).toContainText('Some origins did not respond')
    // the raw enum code must never be shown to the customer
    await expect(page.getByTestId('endpoint-verification')).not.toContainText('unresponsive_origins')
    expect(unexpected).toEqual([])
  })

  test('scenario 3 — legacy / data unavailable, no invented coverage', async ({ page }) => {
    const unexpected = await setup(
      page,
      summary({
        outcome: 'completed',
        endpoint_verification: ev({
          available: false,
          state: null,
          limitation: null,
          selected: 0,
          covered: 0,
          coverage_percent: null,
        }),
      }),
    )
    await page.goto(`/scans/${RUN_ID}`)

    await expect(page.getByTestId('scan-outcome-badge')).toHaveText('Completed')
    await expect(page.getByTestId('endpoint-unavailable')).toContainText('not available')
    await expect(page.getByTestId('endpoint-verification')).toHaveCount(0)
    await expect(page.getByTestId('coverage-percent')).toHaveCount(0)
    expect(unexpected).toEqual([])
  })

  test('scenario 4 — auto-close activity (eligible/threshold/closed/reopened)', async ({ page }) => {
    const unexpected = await setup(
      page,
      summary({
        auto_close: ac({ detected: 3, eligible_miss: 2, would_close: 1, closed: 1, reopened: 1 }),
      }),
    )
    await page.goto(`/scans/${RUN_ID}`)

    await expect(page.getByTestId('auto-close-summary')).toBeVisible()
    await expect(page.getByTestId('auto-close-detected')).toContainText('3')
    await expect(page.getByTestId('auto-close-eligible-miss')).toContainText('Awaiting confirmation')
    await expect(page.getByTestId('auto-close-eligible-miss')).toContainText('2')
    await expect(page.getByTestId('auto-close-would-close')).toContainText('Reached close threshold')
    await expect(page.getByTestId('auto-close-closed')).toContainText('Automatically fixed')
    await expect(page.getByTestId('auto-close-reopened')).toContainText('1')
    expect(unexpected).toEqual([])
  })
})
