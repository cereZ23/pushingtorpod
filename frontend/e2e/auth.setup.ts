import { test as setup, expect } from '@playwright/test'
import path from 'path'

const authFile = path.join(__dirname, '.auth/user.json')

setup('authenticate', async ({ page }) => {
  await page.goto('/login')

  // The login form uses id="email" with sr-only label "Email address"
  // and id="password" with sr-only label "Password"
  await page.getByLabel('Email address').fill('admin@easm.io')
  await page.getByLabel('Password').fill('EasmAdmin2025')
  await page.getByRole('button', { name: 'Sign in' }).click()

  // After successful login the auth store calls router.push('/')
  // which renders the DashboardLayout at the root path
  await page.waitForURL('**/', { timeout: 15000 })

  // Verify we are on the authenticated dashboard
  await expect(page.getByText('EASM Platform').first()).toBeVisible()

  // Persist authentication state (localStorage tokens) for reuse
  await page.context().storageState({ path: authFile })
})
