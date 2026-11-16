import { test, expect } from '@playwright/test';

// Opt-in compose smoke test:
//   E2E_KRAKEN=1 E2E_BASE_URL=https://aegis.local E2E_NO_SERVER=1 \
//   E2E_IGNORE_HTTPS=1 E2E_RESOLVE_AEGIS=1 \
//   E2E_EMAIL=... E2E_PASSWORD=... npx playwright test e2e/kraken.spec.ts
//
// It verifies the whole vertical: Aegis page -> short-lived SSO assertion ->
// separate Kraken UI, while every non-local request is aborted (air-gapped).
const enabled = process.env.E2E_KRAKEN === '1';

test.describe('kraken vertical', () => {
  test.skip(!enabled, 'E2E_KRAKEN non impostato');
  test.use({ ignoreHTTPSErrors: true });

  test('Aegis reads Kraken and opens its UI without external assets', async ({ page, context }) => {
    const external: string[] = [];
    const consoleErrors: string[] = [];
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
    await context.route('**/*', route => {
      const url = new URL(route.request().url());
      if (url.protocol === 'about:' || url.hostname === 'aegis.local') {
        route.continue();
      } else {
        external.push(url.href);
        route.abort();
      }
    });

    await page.goto('/');
    await expect(page.locator('#nav-dashboard')).toBeVisible({ timeout: 20000 });
    await page.locator('#nav-kraken').click();
    await expect(page.getByRole('heading', { name: 'Kraken Deception' })).toBeVisible({ timeout: 20000 });
    await expect(page.getByText('203.0.113.77', { exact: true }).first()).toBeVisible({ timeout: 20000 });

    // Local Tailwind runtime must actually style the page (no CDN fallback).
    const cardBackground = await page.locator('.card').first().evaluate(
      el => getComputedStyle(el).backgroundColor,
    );
    expect(cardBackground).not.toBe('rgba(0, 0, 0, 0)');

    const [kraken] = await Promise.all([
      context.waitForEvent('page', { timeout: 20000 }),
      page.getByTestId('open-kraken').click(),
    ]);
    await kraken.waitForLoadState('domcontentloaded');
    await expect(kraken).toHaveURL(/\/kraken\/$/, { timeout: 20000 });
    await expect(kraken.getByText('Dashboard', { exact: true }).first()).toBeVisible({ timeout: 20000 });

    // Secondary pages must boot from local scripts too (no inline JS).
    await kraken.getByRole('link', { name: 'Attack Events' }).click();
    await expect(kraken).toHaveURL(/\/kraken\/events$/, { timeout: 20000 });
    await expect(kraken.getByText('203.0.113.77', { exact: true }).first()).toBeVisible({ timeout: 20000 });
    await kraken.getByRole('link', { name: 'Plugins' }).click();
    await expect(kraken.getByRole('heading', { name: 'Plugin Manager' })).toBeVisible({ timeout: 20000 });
    await kraken.getByRole('link', { name: 'Reports' }).click();
    await expect(kraken.getByRole('heading', { name: 'Professional Reports' })).toBeVisible({ timeout: 20000 });

    const krakenBg = await kraken.locator('body').evaluate(el => getComputedStyle(el).backgroundColor);
    expect(krakenBg).not.toBe('rgba(0, 0, 0, 0)');
    expect(external, `external requests attempted: ${external.join('; ')}`).toEqual([]);
    expect(consoleErrors.filter(e => /Content Security Policy|Refused to load/i.test(e))).toEqual([]);
  });
});
