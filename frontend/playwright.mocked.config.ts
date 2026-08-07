import { defineConfig, devices } from '@playwright/test'

// Dedicated config for the SELF-CONTAINED mocked-API browser integration suite. It does NOT depend
// on auth.setup.ts or any backend: the app is built + previewed with its API base pointed at the
// preview origin (so all API calls are same-origin and intercepted by page.route), and each spec
// injects auth state + mocks its fixtures. The full-stack Playwright config (playwright.config.ts)
// is left untouched for a future suite.

const PORT = 4319
const BASE_URL = `http://localhost:${PORT}`

export default defineConfig({
  testDir: './e2e',
  // Only the self-contained, auth-injected, fully-mocked specs — never auth.setup.ts / smoke.spec.ts
  // (those need a real backend and belong to the future full-stack suite).
  testMatch: /(scan-operational-summary|finding-lifecycle)\.spec\.ts/,
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    testIdAttribute: 'data-testid',
  },
  webServer: {
    // Build with the API base pointed at the preview origin, then serve the built app. Same-origin
    // API calls → intercepted by Playwright, no CORS.
    command: `pnpm build && pnpm preview --port ${PORT} --strictPort`,
    url: BASE_URL,
    timeout: 180_000,
    reuseExistingServer: !process.env.CI,
    env: { VITE_API_BASE_URL: BASE_URL },
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
})
