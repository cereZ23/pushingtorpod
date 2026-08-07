import { expect, test, type Page } from '@playwright/test'

// Self-contained mocked-API browser integration for the UI-3 operational dashboard. Real router +
// store + rendering, no backend: auth injected into localStorage, every consumed API mocked, and any
// UNEXPECTED request fails the test. Not full-stack; auth.setup.ts is untouched.

const TENANT_ID = 1

const USER = {
  id: 1,
  email: 'e2e@dash.test',
  username: 'e2e',
  full_name: 'E2E User',
  is_active: true,
  is_superuser: false,
  tenant_roles: { [TENANT_ID]: 'admin' },
  created_at: '2026-08-01T00:00:00Z',
}

const TENANT = { id: TENANT_ID, name: 'E2E Tenant', slug: 'e2e-tenant', is_active: true, created_at: '2026-08-01T00:00:00Z' }

function fulfillJson(body: unknown) {
  return { status: 200, contentType: 'application/json', body: JSON.stringify(body) }
}

function tierBlock() {
  return {
    scans: { total: 0, completed: 0, completed_with_limitations: 0, failed: 0, cancelled: 0 },
    endpoints: { selected: 0, verified: 0, not_verifiable: 0, failed: 0, skipped: 0, coverage_percent: null },
    findings: { auto_closed: 0, reopened: 0, awaiting_confirmation: 0 },
  }
}

// The dashboard payload varies by the `days` query param so a period switch is observable.
function dashboardFor(days: number) {
  const verified = days === 7 ? 40 : 96
  const selected = days === 7 ? 42 : 100
  return {
    schema_version: 1,
    period_days: days,
    from: '2026-07-08T12:00:00Z',
    to: '2026-08-07T12:00:00Z',
    scans: { total: 31, completed: 30, completed_with_limitations: 1, failed: 0, cancelled: 1 },
    endpoints: { selected, verified, not_verifiable: selected - verified, failed: 0, skipped: 0, coverage_percent: Math.round((verified * 1000) / selected) / 10 },
    findings: { auto_closed: 2, reopened: 1, awaiting_confirmation: 3 },
    by_tier: { '1': tierBlock(), '2': tierBlock() },
  }
}

async function setup(page: Page): Promise<string[]> {
  const unexpected: string[] = []
  await page.addInitScript(() => {
    localStorage.setItem('accessToken', 'e2e-mock-token')
    localStorage.setItem('refreshToken', 'e2e-mock-refresh')
    localStorage.setItem('currentTenantId', '1')
  })
  await page.route('**/api/**', (route) => {
    unexpected.push(new URL(route.request().url()).pathname)
    route.fulfill({ status: 500, contentType: 'application/json', body: '{}' })
  })
  await page.route(/\/api\/v1\/auth\/me$/, (route) => route.fulfill(fulfillJson(USER)))
  await page.route(/\/api\/v1\/tenants$/, (route) => route.fulfill(fulfillJson([TENANT])))
  await page.route(/\/api\/v1\/tenants\/\d+\/dashboard\/operational-summary/, (route) => {
    const days = Number(new URL(route.request().url()).searchParams.get('days') ?? 30)
    route.fulfill(fulfillJson(dashboardFor(days)))
  })
  return unexpected
}

test.describe('Operational dashboard (mocked API)', () => {
  test('renders scan / endpoint / finding cards + T1/T2 breakdown', async ({ page }) => {
    const unexpected = await setup(page)
    await page.goto('/operations')

    await expect(page.getByTestId('scans-completed')).toHaveText('30')
    await expect(page.getByTestId('scans-cwl')).toHaveText('1')
    await expect(page.getByTestId('endpoints-verified')).toHaveText('96')
    await expect(page.getByTestId('endpoints-coverage')).toContainText('96%')
    await expect(page.getByTestId('findings-auto-closed')).toHaveText('2')
    await expect(page.getByTestId('findings-awaiting')).toHaveText('3')
    await expect(page.getByTestId('tier-1')).toBeVisible()
    await expect(page.getByTestId('tier-2')).toBeVisible()
    expect(unexpected).toEqual([])
  })

  test('switching the period refetches and updates the view', async ({ page }) => {
    const unexpected = await setup(page)
    await page.goto('/operations')
    await expect(page.getByTestId('endpoints-verified')).toHaveText('96') // 30d default

    await page.getByTestId('period-7').click()
    await expect(page.getByTestId('endpoints-verified')).toHaveText('40') // 7d payload
    expect(unexpected).toEqual([])
  })
})
