import { defineConfig, devices } from '@playwright/test';

// E2E pilot (audit F7). Richiede: npm i -D @playwright/test && npx playwright install chromium
// Esecuzione: npm run e2e  (oppure npx playwright test)
// Stato: NOT-RUN in questa sessione (Playwright non installato); gli spec sono
// pronti e l'API smoke (scripts/api_smoke.py) e' il ramo eseguito.
export default defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  retries: 0,
  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://localhost:5173',
    trace: 'retain-on-failure',
  },
  webServer: process.env.E2E_NO_SERVER
    ? undefined
    : {
        command: 'npm run dev',
        url: 'http://localhost:5173',
        reuseExistingServer: true,
        timeout: 60_000,
      },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
});
