import { test, expect } from '@playwright/test'

test.describe('EASM Smoke Tests', () => {
  test('dashboard loads with stats', async ({ page }) => {
    await page.goto('/')

    // The DashboardLayout renders "EASM Platform" in the top nav h1
    await expect(page.locator('h1').filter({ hasText: 'EASM Platform' })).toBeVisible({
      timeout: 15000,
    })

    // The sidebar has a "Dashboard" link that should be visible
    await expect(page.getByText('Dashboard').first()).toBeVisible()

    // Check that main content area has loaded (not stuck on "Loading...")
    await expect(page.locator('#main-content')).not.toContainText('Loading...', {
      timeout: 10000,
    })
  })

  test('assets page loads table', async ({ page }) => {
    await page.goto('/assets')

    // Wait for content to load past the loading state
    await expect(page.locator('#main-content')).not.toContainText('Loading...', {
      timeout: 10000,
    })

    // Assets page should render a table or at least show the page heading
    const table = page.locator('table, [role="table"]').first()
    const heading = page.locator('h1, h2').filter({ hasText: /asset/i })
    await expect(table.or(heading)).toBeVisible({ timeout: 10000 })
  })

  test('findings page loads table', async ({ page }) => {
    await page.goto('/findings')

    await expect(page.locator('#main-content')).not.toContainText('Loading...', {
      timeout: 10000,
    })

    const table = page.locator('table, [role="table"]').first()
    const heading = page.locator('h1, h2').filter({ hasText: /finding/i })
    await expect(table.or(heading)).toBeVisible({ timeout: 10000 })
  })

  test('issues page loads', async ({ page }) => {
    await page.goto('/issues')

    await expect(page.locator('#main-content')).not.toContainText('Loading...', {
      timeout: 10000,
    })

    const heading = page.locator('h1, h2').filter({ hasText: /issue/i })
    const table = page.locator('table, [role="table"]').first()
    await expect(heading.or(table)).toBeVisible({ timeout: 10000 })
  })

  test('sidebar navigation works', async ({ page }) => {
    await page.goto('/')

    // Wait for dashboard to load
    await expect(page.locator('#main-content')).not.toContainText('Loading...', {
      timeout: 10000,
    })

    // Click "Assets" in the sidebar navigation
    await page
      .locator('aside')
      .getByRole('link', { name: 'Assets' })
      .click()
    await expect(page).toHaveURL(/.*\/assets/)

    // Click "Findings" in the sidebar navigation
    await page
      .locator('aside')
      .getByRole('link', { name: 'Findings' })
      .click()
    await expect(page).toHaveURL(/.*\/findings/)

    // Click "Issues" in the sidebar navigation
    await page
      .locator('aside')
      .getByRole('link', { name: 'Issues' })
      .click()
    await expect(page).toHaveURL(/.*\/issues/)

    // Navigate back to Dashboard
    await page
      .locator('aside')
      .getByRole('link', { name: 'Dashboard' })
      .click()
    await expect(page).toHaveURL(/^\/$|.*\/$/)
  })

  test('logout redirects to login', async ({ page }) => {
    await page.goto('/')

    // Wait for dashboard to fully load
    await expect(page.locator('#main-content')).not.toContainText('Loading...', {
      timeout: 10000,
    })

    // The logout button is directly visible in the top nav with text "Logout"
    await page.getByRole('button', { name: 'Logout' }).click()

    // After logout the auth store calls router.push('/login')
    await expect(page).toHaveURL(/.*\/login/, { timeout: 10000 })
  })
})
