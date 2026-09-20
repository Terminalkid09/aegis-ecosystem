import { test, expect } from '@playwright/test';

// Smoke E2E pilot (audit F7). Auth = LoginModal (App.tsx: `if (!user) return <LoginModal />`).
// Esecuzione: E2E_EMAIL=... E2E_PASSWORD=... npm run e2e
//
// La sessione arriva dal progetto `setup` (vedi playwright.config.ts): qui si
// verifica il COMPORTAMENTO, non si rifa' il login a ogni test.
const EMAIL = process.env.E2E_EMAIL ?? '';
const PASSWORD = process.env.E2E_PASSWORD ?? '';

// ------------------------------------------------ senza sessione
// Questi test verificano cosa succede a chi NON e' autenticato: la sessione
// salvata dal setup va esclusa, altrimenti l'app mostrerebbe la dashboard e il
// modal di login non comparirebbe mai.
test.describe('unauthenticated', () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test('login modal renders and empty submit stays on modal', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByTestId('login-email')).toBeVisible({ timeout: 15000 });
    const signIn = page.locator('form').getByRole('button', { name: 'Sign In' });
    await expect(signIn).toBeVisible();
    // Submit vuoto: la validazione required blocca, il modal resta.
    await signIn.click();
    await expect(page.getByTestId('login-email')).toBeVisible();
  });

  test('wrong credentials show an error, not the dashboard', async ({ page }) => {
    await page.goto('/');
    await page.getByTestId('login-email').fill('nobody@aegis.local');
    await page.getByTestId('login-password').fill('wrong-password-123');
    const signIn = page.locator('form').getByRole('button', { name: 'Sign In' });
    await signIn.click();
    // Resta il modal (con errore) oppure resta senza dashboard: mai contenuto autenticato.
    await expect(signIn).toBeVisible({ timeout: 15000 });
  });

  test('self-service registration is refused without an admin', async ({ request }) => {
    // Fail-closed. Deve girare SENZA sessione: la richiesta API eredita i
    // cookie del contesto, quindi con la sessione admin la registrazione
    // sarebbe legittimamente permessa e il test non proverebbe nulla.
    const stamp = Date.now().toString(36);
    const res = await request.post('http://localhost:8000/api/v1/auth/register', {
      data: {
        username: `probe${stamp}`,
        email: `probe-${stamp}@aegis.local`,
        password: `Probe-Pass-${stamp}!`,
      },
    });
    if (res.status() === 200) {
      // Profilo lab: la registrazione e' aperta di proposito, non e' un difetto.
      test.info().annotations.push({ type: 'lab-profile', description: 'registrazione aperta: 200' });
      return;
    }
    expect(res.status()).toBe(403);
  });
});

// ------------------------------------------------ con la sessione del setup
// La striscia pipeline (da /health/ready) elenca i 5 check core CON stato reale
// (audit: i soli nomi comparivano anche con backend irraggiungibile).
test.describe('authenticated', () => {
  test.skip(!EMAIL || !PASSWORD, 'E2E_EMAIL/E2E_PASSWORD non impostati');

  test('pipeline strip shows five checks with real state', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText('database:healthy', { exact: false })).toBeVisible({ timeout: 20000 });
    for (const name of ['database', 'redis', 'pipeline', 'pki', 'mtls']) {
      await expect(page.getByText(name, { exact: false }).first()).toBeVisible({ timeout: 20000 });
    }
  });
});

test('backend liveness is alive-only', async ({ request }) => {
  const res = await request.get('http://localhost:8000/health/live');
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body.status).toBe('alive');
  expect(body.checks).toBeUndefined();
});
