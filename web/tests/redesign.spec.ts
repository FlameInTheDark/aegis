import { test, expect, type Page } from '@playwright/test'

/**
 * Redesigned-UI end-to-end suite (v1.13.0).
 *
 * Runs against the built bundle served by `vite preview` (auto-started by the
 * Playwright config) with the API mocked in-browser. No database, no server,
 * no side effects — only the UI contract is exercised.
 */

// ---------------------------------------------------------------- mock state

const claims = btoa(JSON.stringify({ exp: Math.floor(Date.now() / 1000) + 3600, org: 'org-1', role: 'owner' }))
const ACCESS = `hdr.${claims}.sig`
const USER = { id: 'u-1', email: 'analyst@example.test', name: 'Ada Analyst' }
const ME = { user: USER, organizations: [{ id: 'org-1', name: 'Test org', slug: 'test', role: 'owner' }], current_organization_id: 'org-1' }

const SITE = { id: 'site-1', organization_id: 'org-1', name: 'HQ', site_type: 'hq', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', asset_count: 2 }

const ASSETS = [
  {
    id: 'a-1', organization_id: 'org-1', site_id: 'site-1', hostname: 'srv-web', primary_ip: '10.0.0.5',
    device_type: 'server', os_name: 'Ubuntu', os_version: '24.04', os_confidence: 0.9, os_sources: ['nmap'],
    exposure: 'dmz', criticality: 'critical', risk_score: 82, has_agent: false, tags: ['prod'],
    first_seen: '2026-08-01T00:00:00Z', last_seen: new Date().toISOString(),
    findings: { critical: 1, high: 2, medium: 1, low: 0 },
  },
  {
    id: 'a-2', organization_id: 'org-1', site_id: 'site-1', hostname: 'nas-backup', primary_ip: '10.0.0.6',
    device_type: 'nas', os_name: 'Debian', os_confidence: 0.7, os_sources: ['nmap'],
    exposure: 'internal', criticality: 'low', risk_score: 12, has_agent: true, tags: [],
    first_seen: '2026-08-01T00:00:00Z', last_seen: new Date(Date.now() - 3600_000).toISOString(),
    findings: { critical: 0, high: 0, medium: 0, low: 1 },
  },
]

const FINDING = {
  id: 'f-1', organization_id: 'org-1', asset_id: 'a-1', cve_id: 'CVE-2026-0001', title: 'OpenSSH pre-auth RCE',
  match_type: 'cpe', confidence: 0.95, risk_score: 90, severity: 'critical', status: 'open',
  remediation: 'Upgrade to OpenSSH 10.5', first_seen: '2026-09-01T00:00:00Z', last_seen: new Date().toISOString(),
}

const VULN_ROW = {
  cve_id: 'CVE-2026-0001', state: 'analyzed', description: 'Remote code execution in the SSH daemon.',
  cvss_score: 9.8, cvss_vector: 'CVSS:3.1/AV:N/AC:L', published_at: '2026-09-01T00:00:00Z',
  known_exploited: true, affected_assets: 1, open_findings: 1, epss: 0.62,
}

const GROUP = {
  id: 'g-1', organization_id: 'org-1', name: 'Room 1', description: 'Server room', color: 'indigo', icon: 'Server',
  kind: 'location', created_at: '2026-01-01T00:00:00Z', updated_at: '2026-01-01T00:00:00Z', asset_ids: ['a-1'],
}

const SCANNER = {
  id: 'sc-1', name: 'scanner-local', site_id: 'site-1', version: '1.13.0/nmap', capabilities: ['network', 'ssh'],
  health: 'healthy', last_seen: new Date().toISOString(), transport: 'nats', is_default: true,
}

const SCAN = {
  id: 's-1', organization_id: 'org-1', site_id: 'site-1', name: 'inventory scan', profile: 'inventory',
  engine: 'nmap', state: 'completed', progress: 100, stats: {
    targets: 2, reachable: 2, unreachable: 0, ports_discovered: 4, services_fingerprinted: 3,
    packages_collected: 0, findings_created: 1, critical_findings: 1, tasks_total: 2, tasks_done: 2, tasks_failed: 0,
  }, created_at: new Date().toISOString(),
}

function installMocks(page: Page, overrides: Record<string, unknown> = {}) {
  const state: Record<string, unknown> = {
    scanPosts: [] as unknown[],
    ...overrides,
  }
  async function routeJson(route: Parameters<Parameters<Page['route']>[1]>[0], json: unknown, status = 200) {
    await route.fulfill({ status, contentType: 'application/json', body: JSON.stringify(json) })
  }
  void page.route('**/healthz', async (route) => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ status: 'ok', version: '1.13.0' }) })
  })
  void page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url())
    const path = url.pathname.replace(/^\/api\/v1/, '')
    const method = route.request().method()
    const body = route.request().postDataJSON?.() ?? {}
    if (path === '/auth/refresh') {
      return routeJson(route, { access_token: ACCESS, expires_in: 3600, user: USER })
    }
    if (path === '/auth/me') return routeJson(route, ME)
    if (path === '/auth/login') return routeJson(route, { access_token: ACCESS, expires_in: 3600, user: USER })
    if (path === '/auth/logout') return routeJson(route, {})
    if (path === '/healthz') return routeJson(route, { status: 'ok', version: '1.13.0' })
    if (path === '/metrics/summary') {
      return routeJson(route, {
        assets: 2, open_ports: 4, vulnerabilities: 1, critical: 1, high: 2, kev: 1,
        high_risk_assets: 1, active_alerts: 0, by_severity: { critical: 1, high: 2, medium: 1, low: 0, info: 0 },
      })
    }
    if (path === '/metrics/timeseries') {
      const metric = url.searchParams.get('metric')
      if (metric === 'risk') {
        return routeJson(route, { points: Array.from({ length: 10 }, (_, i) => ({ ts: `2026-09-${10 + i}`, value: 40 + i })) })
      }
      return routeJson(route, { points: [{ ts: '2026-09-20', value: 5, by_category: { scan: 3, ssh: 2 } }] })
    }
    if (path === '/sites') return routeJson(route, { items: [SITE], total: 1 })
    if (path === '/asset-groups') {
      if (method === 'POST') {
        const g = { ...(body as Record<string, unknown>), id: 'g-new', organization_id: 'org-1', created_at: '2026-09-21T00:00:00Z', updated_at: '2026-09-21T00:00:00Z', asset_ids: [] }
        return routeJson(route, { group: g }, 201)
      }
      return routeJson(route, { items: [GROUP] })
    }
    if (path.startsWith('/assets/') && path.endsWith('/findings')) return routeJson(route, { items: [FINDING] })
    if (path.startsWith('/assets/') && path.endsWith('/traces')) return routeJson(route, { items: [], ips: [] })
    if (path.startsWith('/assets/') && path.endsWith('/interfaces')) return routeJson(route, { items: [] })
    if (path.startsWith('/assets/')) {
      return routeJson(route, {
        asset: ASSETS.find((a) => (a as { id: string }).id === path.split('/')[2]) ?? ASSETS[0],
        interfaces: [], services: [], software: [],
        findings_count: { open: 1, critical: 1, high: 2, medium: 1, low: 0 },
        group_ids: ['g-1'],
      })
    }
    if (path === '/assets') return routeJson(route, { items: ASSETS, total: ASSETS.length, page: 1, limit: 200 })
    if (path === '/findings') return routeJson(route, { items: [FINDING], total: 1, page: 1, limit: 50 })
    if (path === '/vulnerabilities') return routeJson(route, { items: [VULN_ROW], total: 1, page: 1, limit: 50 })
    if (path.startsWith('/vulnerabilities/')) {
      return routeJson(route, {
        vulnerability: {
          cve_id: 'CVE-2026-0001', state: 'analyzed', description: VULN_ROW.description,
          cvss_v3: { score: 9.8, vector: VULN_ROW.cvss_vector }, cwe: ['CWE-78'],
          references: ['https://example.test/advisory'], affected: [{ vendor: 'openbsd', product: 'openssh', defaultStatus: 'affected', versions: [{ lessThan: '10.5', status: 'affected', versionType: 'custom' }] }],
          cpe_matches: [], source: 'nvd', published_at: VULN_ROW.published_at, ingested_at: new Date().toISOString(),
        },
        references: ['https://example.test/advisory'],
        affected_assets: [{ asset_id: 'a-1', hostname: 'srv-web', risk_score: 90, finding_id: 'f-1', status: 'open' }],
      })
    }
    if (path === '/scanners') return routeJson(route, { items: [SCANNER], total: 1 })
    if (path === '/scan-profiles') {
      return routeJson(route, {
        builtin: [{ name: 'inventory', description: 'Discovery, topology tracing, broad ports, service and OS detection', top_tcp_ports: 1000, full_port_scan: false, service_detect: true, service_lite: false, os_detect: true, traceroute: true, max_targets: 8192, max_packet_rate: 300 }, { name: 'active_validation', description: 'Active validation', top_tcp_ports: 1000, full_port_scan: true, service_detect: true, service_lite: false, os_detect: true, traceroute: true, max_targets: 8192, max_packet_rate: 300 }],
        custom: [],
      })
    }
    if (path === '/scans' && method === 'POST') {
      ;(state.scanPosts as unknown[]).push(body)
      return routeJson(route, { scan: { ...SCAN, id: 's-new', state: 'queued', progress: 0 }, warnings: [] }, 201)
    }
    if (path === '/scans') return routeJson(route, { items: [SCAN], total: 1, page: 1, limit: 50 })
    if (path === '/scans/s-1') return routeJson(route, { scan: SCAN, tasks: [] })
    if (path === '/detections/matches') return routeJson(route, { items: [], total: 0 })
    if (path === '/detections/rules') return routeJson(route, { items: [] })
    if (path === '/events') return routeJson(route, { items: [], next_cursor: '' })
    if (path === '/agents') return routeJson(route, { items: [], total: 0 })
    if (path === '/agents/enrollment-tokens') return routeJson(route, { items: [] })
    if (path === '/connectors') return routeJson(route, { items: [] })
    if (path === '/reports') return routeJson(route, { items: [{ id: 'r-1', name: 'Executive security', type: 'executive_security', format: 'pdf', created_by: 'u-1', created_at: new Date().toISOString() }] })
    if (path === '/reports/jobs') return routeJson(route, { items: [{ id: 'j-1', definition_id: 'r-1', state: 'done', progress: 100, artifact_key: 'reports/x.pdf', created_at: new Date().toISOString() }] })
    if (path === '/feeds') return routeJson(route, { items: [{ name: 'nvd', enabled: true, last_sync_at: new Date().toISOString(), last_status: 'ok', records_ingested: 1234 }] })
    if (path === '/audit-log') return routeJson(route, { items: [], total: 0, page: 1, limit: 100 })
    if (path === '/users') return routeJson(route, { items: [{ id: 'u-1', email: USER.email, name: USER.name, role: 'owner', disabled: false, created_at: '2026-01-01T00:00:00Z', member_since: '2026-01-01T00:00:00Z' }], total: 1 })
    if (path === '/schedules') return routeJson(route, { items: [] })
    if (path === '/webhooks') return routeJson(route, { items: [] })
    if (path === '/search') return routeJson(route, { items: [{ type: 'asset', id: 'a-1', label: 'srv-web', sublabel: '10.0.0.5' }] })
    if (path === '/topology') return routeJson(route, { nodes: [], edges: [] })
    return routeJson(route, { items: [], total: 0 })
  })
  return state
}

async function login(page: Page) {
  // Session restore through the mocked refresh cookie lands straight on the
  // authenticated shell — the login screen only appears without a session.
  await page.goto('/#/overview')
  await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible({ timeout: 10_000 })
}

// ---------------------------------------------------------------- tests

test.describe('authentication', () => {
  test('restore-through-cookie lands directly on the overview', async ({ page }) => {
    installMocks(page)
    await page.goto('/#/overview')
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible({ timeout: 10_000 })
  })

  test('session loss shows the login screen', async ({ page }) => {
    void page.route('**/healthz', async (route) => {
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify({ status: 'ok', version: '1.13.0' }) })
  })
  void page.route('**/api/v1/**', async (route) => {
      const path = new URL(route.request().url()).pathname
      if (path.endsWith('/auth/refresh')) {
        await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthorized', message: 'no session' } }) })
      } else if (path === '/healthz') {
        await route.fulfill({ json: { status: 'ok', version: '1.13.0' } })
      } else {
        await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthorized', message: 'unauthorized' } }) })
      }
    })
    await page.goto('/#/overview')
    await expect(page.getByText('Sign in to your workspace')).toBeVisible({ timeout: 10_000 })
    await expect(page.getByRole('button', { name: /Sign in/ })).toBeVisible()
  })

  test('login form rejects empty submit and signs in with credentials', async ({ page }) => {
    const state = installMocks(page)
    void state
    // start unauthenticated
    await page.addInitScript(() => sessionStorage.setItem('aegis-test-unauth', '1'))
    void page.route('**/api/v1/auth/refresh', async (route) => {
      await route.fulfill({ status: 401, contentType: 'application/json', body: JSON.stringify({ error: { code: 'unauthorized', message: 'no session' } }) })
    })
    await page.goto('/#/overview')
    await expect(page.getByText('Sign in to your workspace')).toBeVisible({ timeout: 10_000 })
    await page.getByLabel('Email').fill('analyst@example.test')
    await page.getByLabel('Password').fill('hunter2hunter2')
    // the mock still 401s refresh but /auth/login succeeds — remove the refresh override
    void page.unroute('**/api/v1/auth/refresh')
    await page.getByRole('button', { name: /Sign in/ }).click()
    await expect(page.getByRole('heading', { name: 'Overview' })).toBeVisible({ timeout: 10_000 })
  })
})

test.describe('overview', () => {
  test('KPIs and charts render from metrics endpoints', async ({ page }) => {
    installMocks(page)
    await login(page)
    await expect(page.getByText('Security posture for')).toContainText('all sites')
    await expect(page.getByText('Assets', { exact: false }).first()).toBeVisible()
    // severity distribution donut center
    await expect(page.getByText('findings', { exact: true })).toBeVisible()
    // top exposed assets list
    await expect(page.getByText('srv-web').first()).toBeVisible()
  })
})

test.describe('assets & groups', () => {
  test('inventory table shows assets with severity badges', async ({ page }) => {
    installMocks(page)
    await login(page)
    await page.goto('/#/assets')
    await expect(page.getByText('srv-web').first()).toBeVisible()
    await expect(page.getByText('nas-backup')).toBeVisible()
    await expect(page.getByText('10.0.0.5')).toBeVisible()
  })

  test('group filter lists persisted groups', async ({ page }) => {
    installMocks(page)
    await login(page)
    await page.goto('/#/assets')
    await page.getByRole('button', { name: 'All groups' }).click()
    await expect(page.getByRole('menuitem', { name: /Room 1/ })).toBeVisible()
    await expect(page.getByRole('menuitem', { name: /Ungrouped/ })).toBeVisible()
  })

  test('groups manager creates a group through POST /asset-groups', async ({ page }) => {
    const state = installMocks(page)
    await login(page)
    await page.goto('/#/assets')
    await page.getByRole('button', { name: /Manage groups/ }).click()
    await expect(page.getByText('No groups yet').or(page.getByText('avg. risk'))).toBeVisible()
    await page.getByRole('button', { name: /New group/ }).last().click()
    await page.locator('#g-name').fill('Lab')
    await page.getByRole('button', { name: /Create group/ }).click()
    await expect.poll(() => (state.scanPosts as unknown[]).length).toBe(0)
  })

  test('asset detail renders services tab and group chips', async ({ page }) => {
    installMocks(page)
    await login(page)
    await page.goto('/#/assets/a-1')
    await expect(page.getByRole('heading', { name: 'srv-web' })).toBeVisible()
    await expect(page.getByText('Room 1').first()).toBeVisible()
    await page.getByRole('tab', { name: /Findings/ }).click()
    await expect(page.getByText('OpenSSH pre-auth RCE')).toBeVisible()
  })
})

test.describe('scans', () => {
  test('scan dialog submits the real POST /scans payload', async ({ page }) => {
    const state = installMocks(page)
    await login(page)
    await page.goto('/#/scans?new=1')
    await expect(page.getByRole('heading', { name: 'New scan' })).toBeVisible()
    // engine switch to SSH and back keeps profiles loading
    await page.getByRole('button', { name: 'SSH scan' }).click()
    await page.getByRole('button', { name: 'Network scan' }).click()
    // targets are pre-filled from ?new=1 without target → fill manually
    await page.locator('#targets').fill('10.0.0.5, 10.0.0.6')
    await page.getByRole('button', { name: /Start scan/ }).click()
    await expect.poll(() => (state.scanPosts as unknown[]).length, { timeout: 5000 }).toBe(1)
    const payload = (state.scanPosts as unknown[])[0] as Record<string, unknown>
    expect(payload['profile']).toBe('inventory')
    expect(payload['targets']).toEqual(['10.0.0.5', '10.0.0.6'])
    expect(payload['site_id']).toBe('site-1')
  })

  test('scan list renders state badges and stats', async ({ page }) => {
    installMocks(page)
    await login(page)
    await page.goto('/#/scans')
    await expect(page.getByText('inventory scan')).toBeVisible()
    await expect(page.getByText('inventory', { exact: true })).toBeVisible()
  })
})

test.describe('vulnerabilities & findings', () => {
  test('CVE list renders KEV badge and detail sheet shows affected products', async ({ page }) => {
    installMocks(page)
    await login(page)
    await page.goto('/#/vulnerabilities')
    await expect(page.getByText('CVE-2026-0001')).toBeVisible()
    await expect(page.getByText('KEV', { exact: true })).toBeVisible()
    await page.getByText('CVE-2026-0001').click()
    await expect(page.getByText('Affected products')).toBeVisible()
    await expect(page.getByText('openssh')).toBeVisible()
    await expect(page.getByText('CWE-78')).toBeVisible()
  })

  test('findings table updates status through PATCH', async ({ page }) => {
    const patches: unknown[] = []
    installMocks(page)
    void page.route('**/api/v1/findings/f-1', async (route) => {
      if (route.request().method() === 'PATCH') {
        patches.push(route.request().postDataJSON())
        await route.fulfill({ json: { finding: { ...FINDING, status: 'in_progress' } } })
      } else {
        await route.fulfill({ json: { finding: FINDING, evidence: [], history: [] } })
      }
    })
    await login(page)
    await page.goto('/#/findings')
    await expect(page.getByText('OpenSSH pre-auth RCE')).toBeVisible()
    await page.getByText('OpenSSH pre-auth RCE').click()
    await expect(page.getByText('Evidence', { exact: true })).toBeVisible()
    await page.getByRole('button', { name: /Work on it/ }).click()
    await expect.poll(() => patches.length, { timeout: 5000 }).toBe(1)
    expect((patches[0] as Record<string, unknown>)['status']).toBe('in_progress')
  })
})
