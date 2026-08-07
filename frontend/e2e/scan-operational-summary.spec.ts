import { expect, test, type Page } from '@playwright/test'

// Exercises the REAL ScanDetail.vue + router + store + ScanOperationalSummary card. Only the
// scan-detail/progress API is mocked — the Vue app runs for real. No scans are created and the
// production database is never touched.

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

function scanRun(operational_summary: OperationalSummary | null) {
  return {
    id: RUN_ID,
    project_id: 1,
    profile_id: 1,
    tenant_id: 0,
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
  }
}

async function mockProgress(page: Page, operational_summary: OperationalSummary | null) {
  await page.route(new RegExp(`/api/v1/tenants/\\d+/scans/${RUN_ID}/progress$`), async (route) => {
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ scan_run: scanRun(operational_summary), phases: [] }),
    })
  })
}

function card(page: Page) {
  return page.getByTestId('auto-close-summary').or(page.getByText('Scan result')).first()
}

test.describe('Scan result / endpoint verification card', () => {
  test('scenario 1 — clean completed scan, 100% covered', async ({ page }) => {
    await mockProgress(page, summary())
    await page.goto(`/scans/${RUN_ID}`)

    await expect(page.getByTestId('scan-outcome-badge')).toHaveText('Completed')
    await expect(page.getByTestId('endpoint-state-badge')).toHaveText('All endpoints verified')
    await expect(page.getByTestId('coverage-percent')).toContainText('100%')
    await expect(page.getByTestId('limitation-reasons')).toHaveCount(0)
  })

  test('scenario 2 — completed with limitations (96/100, unresponsive)', async ({ page }) => {
    await mockProgress(
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
  })

  test('scenario 3 — legacy / data unavailable, no invented coverage', async ({ page }) => {
    await mockProgress(
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
  })

  test('scenario 4 — auto-close activity (eligible/threshold/closed/reopened)', async ({ page }) => {
    await mockProgress(
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
    // ensure card is visible
    await expect(card(page)).toBeVisible()
  })
})
