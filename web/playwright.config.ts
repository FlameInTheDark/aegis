import { defineConfig } from '@playwright/test'

// Browser test suites (run `npm run build` first):
//   - dropdowns.spec.ts        runs against the auto-started `vite preview`
//                              server (or AEGIS_UI_TEST_URL when targeting a
//                              real deployment) and mocks the API in-browser
//   - report-controls.spec.ts  self-contained: serves web/dist + mocks the API
//   - vulnerability-source.live.spec.ts
//                              opt-in integration check against a live stack at
//                              AEGIS_UI_TEST_URL; skipped unless
//                              AEGIS_TEST_EMAIL / AEGIS_TEST_PASSWORD are set
export default defineConfig({
  testDir: './tests',
  timeout: 30_000,
  expect: { timeout: 5_000 },
  fullyParallel: true,
  retries: 0,
  reporter: [['list']],
  outputDir: 'test-results',
  use: {
    baseURL: process.env.AEGIS_UI_TEST_URL ?? 'http://localhost:4173',
    trace: 'retain-on-failure',
  },
  webServer: {
    command: 'npm run preview -- --port 4173 --strictPort',
    url: 'http://localhost:4173',
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
})
