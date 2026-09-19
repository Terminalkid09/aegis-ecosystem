import { test as setup, expect } from '@playwright/test';

// Perche' esiste
// --------------
// Ogni spec faceva il proprio login. Con 3 worker in parallelo sono ~5 login
// per esecuzione, e /auth/login ha un rate limit (10/minuto): lanciando la
// suite due volte di fila si superava il limite e test diversi fallivano
// insieme, sempre con "elemento non visibile" perche' la sidebar non compariva.
// Il fallimento era del test, non del prodotto, e nascondeva quelli veri.
//
// Qui si autentica UNA volta e la sessione viene salvata e riusata: il cookie
// di sessione e' httpOnly, quindi va raccolto dal contesto del browser e non
// dal localStorage.
const EMAIL = process.env.E2E_EMAIL ?? '';
const PASSWORD = process.env.E2E_PASSWORD ?? '';
const STATE = 'e2e/.auth/state.json';

setup('authenticate once and store the session', async ({ page }) => {
  setup.skip(!EMAIL || !PASSWORD, 'E2E_EMAIL/E2E_PASSWORD non impostati');

  await page.goto('/');
  await page.getByTestId('login-email').fill(EMAIL);
  await page.getByTestId('login-password').fill(PASSWORD);
  await page.locator('form').getByRole('button', { name: 'Sign In' }).click();
  // La sidebar compare solo a sessione autenticata: e' la prova che il login
  // e' andato a buon fine prima di salvare lo stato.
  await expect(page.locator('#nav-dashboard')).toBeVisible({ timeout: 20000 });

  await page.context().storageState({ path: STATE });
});
