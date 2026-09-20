import { defineConfig, devices } from '@playwright/test';

// E2E pilot (audit F7). Richiede: npm i -D @playwright/test && npx playwright install chromium
// Esecuzione: E2E_EMAIL=... E2E_PASSWORD=... npm run e2e
//
// La sessione si crea una volta sola nel progetto `setup` e viene riusata da
// tutti gli spec (`storageState`): con un login per test il rate limit di
// /auth/login faceva fallire in blocco test diversi, e il fallimento era della
// suite, non del prodotto.
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
  projects: [
    { name: 'setup', testMatch: /global\.setup\.ts/ },
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], storageState: 'e2e/.auth/state.json' },
      dependencies: ['setup'],
    },
  ],
});
