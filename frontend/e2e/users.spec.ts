import { test, expect, type Page } from '@playwright/test'

// Admin-only management must be tested through the real UI and the real API,
// not just by rendering the page. The storageState comes from global.setup.ts.
const EMAIL = process.env.E2E_EMAIL ?? ''
const PASSWORD = process.env.E2E_PASSWORD ?? ''
// API calls run inside the page: same origin, HttpOnly cookie and the browser
// resolver. A separate Playwright request context does not resolve aegis.local
// and does not carry the UI session, which made this spec pass alone and fail
// in the compose/Caddy run.
const UI_ORIGIN = new URL(process.env.E2E_BASE_URL ?? 'http://localhost:3000').origin

type ApiResult<T> = { status: number; body: T }

async function api<T = unknown>(
  page: Page,
  method: string,
  path: string,
  data?: unknown,
): Promise<ApiResult<T>> {
  return (await page.evaluate(async ({ method, url, data }) => {
    const response = await fetch(url, {
      method,
      credentials: 'include',
      headers: data === undefined ? undefined : { 'Content-Type': 'application/json' },
      body: data === undefined ? undefined : JSON.stringify(data),
    })
    const text = await response.text()
    let body: unknown = text
    try {
      body = text ? JSON.parse(text) : null
    } catch {
      // Keep the text for a useful assertion message.
    }
    return { status: response.status, body }
  }, { method, url: `${UI_ORIGIN}/api/v1${path}`, data })) as ApiResult<T>
}

test.describe('users and roles', () => {
  test.skip(!EMAIL || !PASSWORD, 'E2E_EMAIL/E2E_PASSWORD non impostati')

  test('admin creates, disables, resets and re-enables an account', async ({ page }) => {
    await page.goto('/')
    await page.locator('#nav-users').click()
    await expect(page.getByRole('heading', { name: 'Users & Roles' })).toBeVisible({ timeout: 15000 })

    const stamp = Date.now().toString(36)
    const email = `e2e-${stamp}@aegis.local`
    const username = `e2e_${stamp}`
    const password = `E2e-Pass-${stamp}!`

    await page.getByTestId('user-create').click()
    await page.getByTestId('user-username').fill(username)
    await page.getByTestId('user-email').fill(email)
    await page.getByTestId('user-role').selectOption('viewer')
    await page.getByTestId('user-password').fill(password)
    await page.getByTestId('user-create-submit').click()

    await expect(page.getByTestId('temporary-credentials')).toBeVisible({ timeout: 15000 })
    await expect(page.getByTestId('temporary-credentials')).toContainText(email)

    const list = await api<{ users: Array<{ id: number; email: string; role: string }> }>(
      page, 'GET', '/users',
    )
    expect(list.status, 'admin API must accept the UI session').toBe(200)
    const created = list.body.users.find((u) => u.email === email)
    expect(created, 'created user must exist in the backend').toBeTruthy()
    expect(created!.role).toBe('viewer')

    const row = page.getByTestId(`user-row-${created!.id}`)
    await expect(row).toBeVisible()
    await page.getByTestId(`user-toggle-${created!.id}`).click()
    await expect(row.getByText('Disabled')).toBeVisible({ timeout: 15000 })

    page.once('dialog', dialog => dialog.accept())
    await page.getByTestId(`user-reset-${created!.id}`).click()
    await expect(page.getByTestId('temporary-credentials')).toBeVisible({ timeout: 15000 })
    await expect(page.getByText('Password reset. It is shown only in this panel.')).toBeVisible()

    await page.getByTestId(`user-toggle-${created!.id}`).click()
    await expect(row.getByText('Active')).toBeVisible({ timeout: 15000 })

    // The last active admin cannot disable or demote itself through the API.
    const me = await api<{ id: number }>(page, 'GET', '/auth/me')
    expect(me.status).toBe(200)
    const blocked = await api(page, 'PATCH', `/users/${me.body.id}`, { active: false })
    expect(blocked.status, 'last admin guard must be enforced server-side').toBe(409)
  })

  test('a non-admin cannot see Users & Roles or call the admin API', async ({ browser, page }) => {
    await page.goto('/')
    await expect(page.locator('#nav-dashboard')).toBeVisible({ timeout: 20000 })
    const stamp = Date.now().toString(36)
    const email = `viewer-${stamp}@aegis.local`
    const password = `Viewer-Pass-${stamp}!`

    const created = await api(page, 'POST', '/users', {
      username: `viewer_${stamp}`, email, password, role: 'viewer', active: true,
    })
    expect(created.status).toBe(201)

    const context = await browser.newContext({ storageState: { cookies: [], origins: [] } })
    const viewer = await context.newPage()
    try {
      await viewer.goto('/')
      await viewer.getByTestId('login-email').fill(email)
      await viewer.getByTestId('login-password').fill(password)
      await viewer.locator('form').getByRole('button', { name: 'Sign In' }).click()
      await expect(viewer.locator('#nav-dashboard')).toBeVisible({ timeout: 20000 })
      await expect(viewer.locator('#nav-users')).toHaveCount(0)

      const forbidden = await api(viewer, 'GET', '/users')
      expect(forbidden.status, 'non-admin API must be forbidden').toBe(403)
    } finally {
      await context.close()
    }
  })
})
