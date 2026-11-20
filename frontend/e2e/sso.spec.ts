import { test, expect } from '@playwright/test'

// Opt-in real IdP test:
//   E2E_SSO=1 E2E_RESOLVE_KEYCLOAK=1 E2E_NO_SERVER=1 \
//   E2E_BASE_URL=http://localhost:3000 npx playwright test e2e/sso.spec.ts
// The Keycloak realm/user is created by the local test harness and is not
// shipped in a release. This test is skipped when E2E_SSO is not set.
const enabled = process.env.E2E_SSO === '1'

test.describe('OIDC SSO', () => {
  test.skip(!enabled, 'E2E_SSO non impostato')
  test.use({ storageState: { cookies: [], origins: [] } })

  test('a real user logs in through Keycloak and lands in the dashboard', async ({ page }) => {
    await page.goto('/')
    const sso = page.getByTestId('sso-login')
    await expect(sso).toBeVisible({ timeout: 20000 })
    await sso.click()

    // The browser is redirected to Keycloak's standard login form.
    await expect(page.locator('#username')).toBeVisible({ timeout: 30000 })
    await page.locator('#username').fill('sso-admin')
    await page.locator('#password').fill('Sso-Admin-Pass-123!')
    await page.locator('#kc-login').click()

    // The Brain sets the HttpOnly cookie and returns to the SPA, not to the
    // API root. A redirect to localhost:8000/ would be a broken user journey.
    await expect(page).toHaveURL(/localhost:3000\/?$/, { timeout: 30000 })
    await expect(page.locator('#nav-dashboard')).toBeVisible({ timeout: 30000 })
    await expect(page.getByText('sso-admin', { exact: false }).first()).toBeVisible({ timeout: 20000 })
  })
})
