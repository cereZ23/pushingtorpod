import { expect, test, type Page } from '@playwright/test'

type LifecycleEvent = {
  type: string
  scan_run_id: number | null
  created_at: string
  reason_code: string | null
}

type LifecycleScenario = {
  name: string
  findingStatus: 'open' | 'fixed'
  state: string
  streak: number
  events: LifecycleEvent[]
  expected: string[]
  absent?: string[]
}

const FINDING_ID = 9001

const finding = (status: LifecycleScenario['findingStatus']) => ({
  id: FINDING_ID,
  asset_id: 0,
  source: 'nuclei',
  template_id: 'e2e-lifecycle-probe',
  name: 'Lifecycle E2E probe',
  severity: 'medium',
  first_seen: '2026-08-01T08:00:00Z',
  last_seen: '2026-08-07T08:00:00Z',
  status,
  occurrence_count: 1,
})

async function mockFindingLifecycle(page: Page, scenario: LifecycleScenario) {
  await page.route(
    new RegExp(`/api/v1/tenants/\\d+/findings/${FINDING_ID}(?:/lifecycle)?$`),
    async (route) => {
      const pathname = new URL(route.request().url()).pathname
      const body = pathname.endsWith('/lifecycle')
        ? {
            finding_id: FINDING_ID,
            auto_close: {
              state: scenario.state,
              current_streak: scenario.streak,
              threshold: 2,
              last_detected_run_id: 700,
              last_eligible_run_id: scenario.streak ? 701 : null,
              coverage_scope: 'endpoint',
              origin_tier: 1,
            },
            events: scenario.events,
            total_events: scenario.events.length,
            has_more: false,
            has_history: scenario.events.length > 0,
          }
        : finding(scenario.findingStatus)

      await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(body) })
    },
  )
}

const scenarios: LifecycleScenario[] = [
  {
    name: 'open finding',
    findingStatus: 'open',
    state: 'open',
    streak: 0,
    events: [
      {
        type: 'detected',
        scan_run_id: 700,
        created_at: '2026-08-07T08:00:00Z',
        reason_code: null,
      },
    ],
    expected: ['Open', 'Automatically monitored', 'Detected', 'Run #700'],
  },
  {
    name: 'first covered miss',
    findingStatus: 'open',
    state: 'eligible_miss',
    streak: 1,
    events: [
      {
        type: 'eligible_miss',
        scan_run_id: 701,
        created_at: '2026-08-07T09:00:00Z',
        reason_code: 'covered_absence',
      },
    ],
    expected: [
      'Awaiting confirmation',
      'Not seen on the last covered scan',
      '1 of 2 covered misses',
      'Covered miss — not seen on a covered scan',
    ],
  },
  {
    name: 'automatically fixed finding',
    findingStatus: 'fixed',
    state: 'auto_fixed',
    streak: 2,
    events: [
      {
        type: 'would_close',
        scan_run_id: 702,
        created_at: '2026-08-07T10:00:00Z',
        reason_code: 'coverage_miss_streak',
      },
      {
        type: 'auto_closed',
        scan_run_id: 702,
        created_at: '2026-08-07T10:00:01Z',
        reason_code: 'coverage_miss_streak',
      },
    ],
    expected: [
      'Automatically fixed',
      'Closed after consecutive covered misses',
      'Reached the auto-close threshold',
    ],
  },
  {
    name: 'reopened finding',
    findingStatus: 'open',
    state: 'open',
    streak: 0,
    events: [
      {
        type: 'auto_closed',
        scan_run_id: 702,
        created_at: '2026-08-07T10:00:01Z',
        reason_code: 'coverage_miss_streak',
      },
      {
        type: 'reopened',
        scan_run_id: null,
        created_at: '2026-08-07T11:00:00Z',
        reason_code: 'manual_reopen',
      },
    ],
    expected: ['Open', 'Automatically fixed', 'Reopened (manual)'],
  },
  {
    name: 'legacy finding without history',
    findingStatus: 'open',
    state: 'open',
    streak: 0,
    events: [],
    expected: [
      'Open',
      'No lifecycle events recorded for this finding.',
      'History is available from migration 031 onward',
    ],
    absent: ['Automatically fixed', 'Covered miss — not seen on a covered scan'],
  },
]

test.describe('Finding lifecycle card', () => {
  for (const scenario of scenarios) {
    test(`renders ${scenario.name}`, async ({ page }) => {
      await mockFindingLifecycle(page, scenario)
      await page.goto(`/findings/${FINDING_ID}`)

      const card = page.locator('section').filter({
        has: page.getByRole('heading', { name: 'Verification status' }),
      })
      await expect(card).toBeVisible()

      for (const text of scenario.expected) {
        await expect(card.getByText(text, { exact: false }).first()).toBeVisible()
      }
      for (const text of scenario.absent ?? []) {
        await expect(card.getByText(text, { exact: false })).toHaveCount(0)
      }
    })
  }
})
