import { test, expect, type Page } from '@playwright/test';

// La sessione sopravvive a un reload. Il bug riportato era esattamente questo:
// "ricarico la pagina e mi richiede l'accesso". Tre cause concorrenti, tutte
// coperte a livello di backend (tests/test_session_lifecycle.py): cookie con
// max_age proprio diverso dal JWT, un duplicato rimasto su un altro path, e
// nessun rinnovo mentre l'utente lavora. Qui si verifica l'effetto finale dal
// punto di vista di chi usa la console.
//
// Credenziali da env (mai nel codice):
//   E2E_EMAIL=admin@aegis.local E2E_PASSWORD=... E2E_BASE_URL=http://localhost:3000 E2E_NO_SERVER=1
//   npx playwright test e2e/session.spec.ts
//
// NOTA: /auth/login ha un rate limit di 5/minuto: questo file fa UN solo login.
const EMAIL = process.env.E2E_EMAIL ?? '';
const PASSWORD = process.env.E2E_PASSWORD ?? '';

async function login(page: Page) {
  await page.goto('/');
  await page.getByPlaceholder('admin@aegis.local').fill(EMAIL);
  await page.getByPlaceholder('••••••••').fill(PASSWORD);
  await page.locator('form').getByRole('button', { name: 'Sign In' }).click();
  await expect(page.locator('#nav-dashboard')).toBeVisible({ timeout: 20000 });
}

test.describe('session', () => {
  test.skip(!EMAIL || !PASSWORD, 'E2E_EMAIL/E2E_PASSWORD non impostati');

  test('a reload keeps the session and does not ask for credentials again', async ({ page }) => {
    const failures: string[] = [];
    page.on('response', (res) => {
      if (res.status() >= 400 && !res.url().includes('favicon')) {
        failures.push(`${res.status()} ${new URL(res.url()).pathname}`);
      }
    });

    await login(page);

    await page.reload();
    await expect(page.locator('#nav-dashboard')).toBeVisible({ timeout: 20000 });
    // Il login non deve ricomparire: era il sintomo riferito.
    await expect(page.getByPlaceholder('admin@aegis.local')).toHaveCount(0);

    // E le pagine devono caricare i dati, non solo la shell: un 401 che svuota
    // l'interfaccia e' indistinguibile da "serve riaccedere".
    await page.locator('#nav-agents').click();
    await expect(page.locator('main')).toContainText('MSI', { timeout: 20000 });
    expect(failures, `richieste fallite dopo il reload: ${failures.join('; ')}`).toEqual([]);
  });

  test('logging out returns to the login and a reload does not restore it', async ({ page }) => {
    await login(page);
    // Il logout vive nel menu del profilo/sidebar: clicco l'elemento che lo
    // espone senza dipendere dal testo esatto dell'icona.
    const logout = page.getByRole('button', { name: /sign out|logout|esci/i }).first();
    await logout.click();
    await expect(page.getByPlaceholder('admin@aegis.local')).toBeVisible({ timeout: 15000 });
    await page.reload();
    await expect(page.getByPlaceholder('admin@aegis.local')).toBeVisible({ timeout: 15000 });
    await expect(page.locator('#nav-dashboard')).toHaveCount(0);
  });
});
