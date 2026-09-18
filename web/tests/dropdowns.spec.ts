import { test, expect } from '@playwright/test'

// Exercise the real deployed bundle with synthetic API responses only.
// No login, database writes, report generation, or scans are performed.
test.beforeEach(async ({ page }) => {
  const claims = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, perms: ['*'], role: 'owner' }))
  await page.route('**/api/v1/**', async (route) => {
    const path = new URL(route.request().url()).pathname
    const user = { id: 'test-user', email: 'ui@example.test', name: 'UI Test' }
    const body = path.endsWith('/auth/refresh') ? { access_token: `test.${claims}.test`, expires_in: 3600, user }
      : path.endsWith('/auth/me') ? { user }
      : path.endsWith('/sites') ? { items: [{ id: 'site-1', name: 'Test site' }], total: 1 }
      : { items: [], total: 0 }
    await route.fulfill({ json: body })
  })
})

const base = process.env.AEGIS_UI_TEST_URL ?? 'http://localhost:3000'

test('filter selection, empty value, keyboard navigation and focus restoration', async ({ page }) => {
  const response = await page.goto(`${base}/assets`)
  expect(response?.status()).toBe(200)
  const filter = page.getByRole('combobox', { name: 'Criticality filter' })
  await filter.click()
  await expect(page.getByRole('listbox')).toBeVisible()
  await page.getByRole('option', { name: 'high', exact: true }).click()
  await expect(page).toHaveURL(/criticality=high/)
  await expect(filter).toBeFocused()
  await filter.press('Enter')
  await expect(page.getByRole('option', { name: 'high', exact: true })).toBeFocused()
  await page.keyboard.press('Home')
  await expect(page.getByRole('option', { name: 'All criticality', exact: true })).toBeFocused()
  await page.keyboard.press('Enter')
  await expect(filter).toContainText('All criticality')
  await expect(page).not.toHaveURL(/criticality=/)
  await filter.press('ArrowDown')
  await expect(page.getByRole('listbox')).toBeVisible()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await expect(filter).toBeFocused()
  await expect(page.locator('select:visible')).toHaveCount(0)
})

test('portaled select stays inside report dialog behavior', async ({ page }) => {
  await page.goto(`${base}/reports`)
  await page.getByRole('button', { name: 'New report' }).click()
  const dialog = page.getByRole('dialog', { name: 'Generate report' })
  const format = page.getByRole('combobox', { name: 'Report format' })
  await format.click()
  await page.screenshot({ path: 'test-results/custom-dropdown.png' })
  await page.getByRole('option', { name: 'PDF', exact: true }).click()
  await expect(format).toHaveText('PDF')
  await expect(dialog).toBeVisible()
  await format.click()
  await page.keyboard.press('Escape')
  await expect(page.getByRole('listbox')).toHaveCount(0)
  await expect(dialog).toBeVisible()
  await expect(format).toBeFocused()
  const site = page.getByRole('combobox', { name: 'Report site' })
  await site.click()
  await page.getByRole('option', { name: 'Test site', exact: true }).click()
  await site.click()
  await page.getByRole('option', { name: 'Whole organization', exact: true }).click()
  await expect(site).toHaveText('Whole organization')
  await expect(dialog).toBeVisible()
})
