import { test, expect, type Page } from '@playwright/test'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

// Serve the build in-browser: no server, login, deployment, or live API writes.
const base = 'http://aegis-ui.test'
const assetId = '00000000-0000-4000-8000-000000000002'
const siteId = '00000000-0000-4000-8000-000000000001'
const device = { id: assetId, site_id: siteId, primary_ip: '192.0.2.20', os_name: 'Linux', device_type: 'server', risk_score: 0, criticality: 'medium', first_seen: new Date().toISOString(), last_seen: new Date().toISOString() }

async function setup(page: Page, role = 'owner') {
  let orgName = 'Example organization'
  const requests: { path: string; body: any }[] = []
  const claims = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, perms: ['*'], role }))
  await page.route('**/*', async (route) => {
    const path = new URL(route.request().url()).pathname
    if (!path.startsWith('/api/v1/')) {
      const file = path.startsWith('/assets/') && /\.(js|css)$/.test(path) ? path.slice(1) : 'index.html'
      return route.fulfill({ body: await readFile(resolve('dist', file)), contentType: file.endsWith('.js') ? 'application/javascript' : file.endsWith('.css') ? 'text/css' : 'text/html' })
    }
    const user = { id: 'user', email: 'ui@example.test', name: 'UI test' }
    if (route.request().method() === 'POST' && path.endsWith('/reports')) {
      requests.push({ path, body: route.request().postDataJSON() })
      return route.fulfill({ json: { job: { id: 'queued-job' } } })
    }
    if (route.request().method() === 'PATCH' && path.endsWith('/organizations/current')) {
      const body = route.request().postDataJSON()
      requests.push({ path, body }); orgName = body.name
      return route.fulfill({ json: { name: orgName } })
    }
    const body = path.endsWith('/auth/refresh') ? { access_token: `test.${claims}.test`, expires_in: 3600, user }
      : path.endsWith('/auth/me') ? { user, current_organization_id: 'org', organizations: [{ id: 'other', name: 'Other organization', role: 'viewer' }, { id: 'org', name: orgName, role }] }
      : path.endsWith('/sites') ? { items: [{ id: siteId, name: 'Head office' }] }
      : path.endsWith(`/assets/${assetId}`) ? { asset: device, services: [], software: [], interfaces: [] }
      : path.endsWith('/assets') ? { items: [device], total: 1 }
      : { items: [], total: 0 }
    return route.fulfill({ json: body })
  })
  return requests
}

test('requires site/device scope and submits names-backed selections', async ({ page }) => {
  const requests = await setup(page)
  await page.goto(`${base}/reports`)
  await page.getByRole('button', { name: 'New report' }).click()
  await page.getByRole('combobox', { name: 'Report type' }).click()
  await page.getByRole('option', { name: 'Site detail report', exact: true }).click()
  const generate = page.getByRole('button', { name: 'Generate', exact: true })
  await expect(generate).toBeDisabled()
  await page.getByRole('combobox', { name: 'Report site' }).click()
  await page.getByRole('option', { name: 'Head office', exact: true }).click()
  await expect(generate).toBeEnabled()
  await generate.click()
  await expect.poll(() => requests.length).toBe(1)
  expect(requests[0].body).toMatchObject({ type: 'site_detail', site_id: siteId })
  await page.getByRole('button', { name: 'New report' }).click()
  await page.getByRole('combobox', { name: 'Report type' }).click()
  await page.getByRole('option', { name: 'Device detail report', exact: true }).click()
  await expect(generate).toBeDisabled()
  await page.getByRole('combobox', { name: 'Report device' }).click()
  await page.getByRole('option', { name: '192.0.2.20 · Linux', exact: true }).click()
  await expect(page.getByRole('dialog')).not.toContainText(assetId)
  await generate.click()
  await expect.poll(() => requests.length).toBe(2)
  expect(requests[1].body).toMatchObject({ type: 'device_detail', asset_id: assetId, site_id: siteId })
})

test('deep linked device resolves its IP label', async ({ page }) => {
  await setup(page)
  await page.goto(`${base}/reports?type=device_detail&asset_id=${assetId}`)
  await expect(page.getByRole('combobox', { name: 'Report device' })).toContainText('192.0.2.20')
  await expect(page.getByRole('button', { name: 'Generate', exact: true })).toBeEnabled()
})

test('device action queues a report and exposes the queued job link', async ({ page }) => {
  const requests = await setup(page)
  await page.goto(`${base}/assets/${assetId}`)
  await expect(page.getByRole('heading', { name: '192.0.2.20' })).toBeVisible()
  await page.getByRole('button', { name: 'Generate report', exact: true }).click()
  await expect(page.getByRole('link', { name: 'View report' })).toHaveAttribute('href', '/reports?job=queued-job')
  expect(requests[0].body).toEqual({ type: 'device_detail', asset_id: assetId, format: 'pdf' })
})

test('renames active organization only after confirmation', async ({ page }) => {
  const requests = await setup(page)
  await page.goto(`${base}/settings`)
  await expect(page.getByLabel('Organization name')).toHaveValue('Example organization')
  await page.getByLabel('Organization name').fill('New company name')
  await page.getByRole('button', { name: 'Rename organization', exact: true }).click()
  expect(requests).toHaveLength(0)
  await page.getByRole('button', { name: 'Confirm rename', exact: true }).click()
  await expect(page.getByText('Organization name updated.')).toBeVisible()
  await expect(page.getByLabel('Organization name')).toHaveValue('New company name')
  expect(requests[0]).toEqual({ path: '/api/v1/organizations/current', body: { name: 'New company name' } })
})

test('viewer sees organization name but no rename action', async ({ page }) => {
  await setup(page, 'viewer')
  await page.goto(`${base}/settings`)
  await expect(page.getByLabel('Organization name')).toBeDisabled()
  await expect(page.getByRole('button', { name: 'Rename organization', exact: true })).toHaveCount(0)
})
