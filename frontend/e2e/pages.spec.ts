import { test, expect, type Page } from '@playwright/test';

// Ogni pagina deve RENDERIZZARE, non solo rispondere: il bug di YARA & FIM era
// un crash in render (`undefined.filter`) che finiva nell'error boundary, e da
// fuori sembrava "la pagina non carica". Qui si clicca ogni voce della sidebar
// e si verifica che nessuna pagina mostri il fallback.
//
// Credenziali da env (mai nel codice):
//   E2E_EMAIL=admin@aegis.local E2E_PASSWORD=... E2E_BASE_URL=http://localhost:3000 E2E_NO_SERVER=1
//   npx playwright test e2e/pages.spec.ts
//
// NOTA: /auth/login ha un rate limit di 5/minuto, quindi questo file fa UN
// login per test (3 in totale) e non uno per pagina.
const EMAIL = process.env.E2E_EMAIL ?? '';
const PASSWORD = process.env.E2E_PASSWORD ?? '';

const PAGES: { id: string; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'agents', label: 'Endpoints' },
  { id: 'discovery', label: 'Discovery' },
  { id: 'deploy', label: 'Deploy' },
  { id: 'sentinel', label: 'SentinelX' },
  { id: 'total', label: 'Aegis Total' },
  { id: 'ai', label: 'AI' },
  { id: 'vault', label: 'VaultX' },
  { id: 'playbooks', label: 'Playbooks' },
  { id: 'rules', label: 'Rules' },
  { id: 'incidents', label: 'Incidents' },
  { id: 'audit', label: 'Audit' },
  { id: 'syslog', label: 'Syslog' },
  { id: 'logsources', label: 'Log Sources' },
  { id: 'search', label: 'Search' },
  { id: 'yara', label: 'YARA & FIM' },
  { id: 'settings', label: 'Settings' },
];

const ERROR_BOUNDARY = 'This view hit an error';

async function login(page: Page) {
  await page.goto('/');
  await page.getByPlaceholder('admin@aegis.local').fill(EMAIL);
  await page.getByPlaceholder('••••••••').fill(PASSWORD);
  await page.locator('form').getByRole('button', { name: 'Sign In' }).click();
  // La sidebar compare solo a sessione autenticata.
  await expect(page.locator('#nav-dashboard')).toBeVisible({ timeout: 20000 });
}

test.describe('page rendering', () => {
  test.skip(!EMAIL || !PASSWORD, 'E2E_EMAIL/E2E_PASSWORD non impostati');

  test('every page renders without the error boundary', async ({ page }) => {
    // Traccia l'URL, non solo il messaggio: un 401 senza rotta non si debugga.
    const failures: string[] = [];
    page.on('response', (res) => {
      if (res.status() >= 400 && !res.url().includes('favicon')) {
        failures.push(`${res.status()} ${new URL(res.url()).pathname}`);
      }
    });

    await login(page);
    const broken: string[] = [];
    for (const { id, label } of PAGES) {
      await page.locator(`#nav-${id}`).click();
      // Il boundary è keyed su currentPage: cambiare pagina lo azzera, quindi
      // ogni iterazione parte pulita.
      await page.waitForTimeout(1200);
      const crashed = await page.getByText(ERROR_BOUNDARY).count();
      const text = (await page.locator('main').innerText()).trim();
      if (crashed > 0 || text.length <= 40) {
        broken.push(`${label} (boundary=${crashed > 0}, lunghezza=${text.length})`);
      }
    }
    expect(failures, `richieste fallite: ${failures.join('; ')}`).toEqual([]);
    expect(broken, `pagine senza render: ${broken.join('; ')}`).toEqual([]);
  });

  test('YARA & FIM loads rules and the endpoint watchlist', async ({ page }) => {
    await login(page);
    await page.locator('#nav-yara').click();

    await expect(page.getByRole('heading', { name: /File Integrity Monitoring/ })).toBeVisible({ timeout: 15000 });
    // Il contatore delle regole viene dal backend: se è renderizzato, la query
    // è andata a buon fine (0 regole è un valore valido, come lo spinner no).
    await expect(page.getByRole('heading', { name: /Rules \(\d+\)/ })).toBeVisible({ timeout: 15000 });
    // Il selettore endpoint è presente e pronto (non disabilitato): è il punto
    // che crashava quando la lista agenti non era ancora arrivata.
    const selector = page.locator('select').first();
    await expect(selector).toBeVisible();
    await expect(selector).toBeEnabled({ timeout: 15000 });
    await expect(page.getByText(ERROR_BOUNDARY)).toHaveCount(0);
  });

  test('Settings shows the AI provider section with English labels', async ({ page }) => {
    await login(page);
    await page.locator('#nav-settings').click();
    await expect(page.getByRole('heading', { name: 'AI Provider' })).toBeVisible({ timeout: 15000 });

    // Il select del provider è quello dentro la card con l'heading "AI Provider"
    // (l'altra card con un select è API Configuration).
    const aiCard = page.locator('div.card', { has: page.getByRole('heading', { name: 'AI Provider' }) }).first();
    // Il select compare quando /ai/settings risponde: senza questo wait si
    // legge la card in stato di caricamento e le opzioni sono vuote.
    await expect(aiCard.locator('select')).toBeVisible({ timeout: 20000 });
    const labels = (await aiCard.locator('select option').allInnerTexts()).join(' | ');
    expect(labels).toMatch(/Auto \(use whatever responds\)/);
    expect(labels).toMatch(/Disabled/);
    expect(labels).toMatch(/Ollama/);
    // Nessuna etichetta italiana: la UI è tutta in inglese.
    expect(labels).not.toMatch(/Disattivata|ciò che risponde|locale o server/);
  });
});
