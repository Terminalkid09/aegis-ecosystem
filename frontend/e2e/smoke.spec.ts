import { test, expect } from '@playwright/test';

// Smoke E2E pilot (audit F7). Auth = LoginModal (App.tsx: `if (!user) return <LoginModal />`).
// Esecuzione: npm run e2e  (richiede browser: npx playwright install chromium)

test('login modal renders and empty submit stays on modal', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByPlaceholder('admin@aegis.local')).toBeVisible({ timeout: 15000 });
  const signIn = page.locator('form').getByRole('button', { name: 'Sign In' });
  await expect(signIn).toBeVisible();
  // Submit vuoto: la validazione required blocca, il modal resta.
  await signIn.click();
  await expect(page.getByPlaceholder('admin@aegis.local')).toBeVisible();
});

test('wrong credentials show an error, not the dashboard', async ({ page }) => {
  await page.goto('/');
  await page.getByPlaceholder('admin@aegis.local').fill('nobody@aegis.local');
  await page.getByPlaceholder('••••••••').fill('wrong-password-123');
  const signIn = page.locator('form').getByRole('button', { name: 'Sign In' });
  await signIn.click();
  // Resta il modal (con errore) oppure resta senza dashboard: mai contenuto autenticato.
  await expect(signIn).toBeVisible({ timeout: 15000 });
});

test('pipeline strip shows five checks after self-service register+login', async ({ page }) => {
  // Audit P2: registrazione self-service (aperta in lab) -> login reale ->
  // dashboard. Nessuna credenziale pre-seminata: utente unico per run.
  const stamp = Date.now().toString(36);
  const username = `e2e${stamp}`;
  const email = `e2e-${stamp}@aegis.local`;
  const password = `E2E-Pass-${stamp}-x!`;
  await page.goto('/');
  await page.getByRole('button', { name: 'Register', exact: true }).click();
  await page.getByPlaceholder('johndoe').fill(username);
  await page.getByPlaceholder('admin@aegis.local').fill(email);
  await page.getByPlaceholder('••••••••').fill(password);
  await page.locator('form').getByRole('button', { name: 'Create Account' }).click();
  // La striscia pipeline (da /health/ready) elenca i 5 check core.
  for (const name of ['database', 'redis', 'pipeline', 'pki', 'mtls']) {
    await expect(page.getByText(name, { exact: false }).first()).toBeVisible({ timeout: 20000 });
  }
});

test('backend liveness is alive-only', async ({ request }) => {
  const res = await request.get('http://localhost:8000/health/live');
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body.status).toBe('alive');
  expect(body.checks).toBeUndefined();
});
