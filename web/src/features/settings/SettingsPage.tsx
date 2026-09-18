import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Page, Site, FeedSource, AuditEntry, Network } from '@/types'
import { Button, Dialog, Input, Panel, PanelHeader, Badge, Spinner, ErrorState, EmptyState, StatusDot, Select } from '@/components/ui'
import { relTime } from '@/lib/format'
import { useSites } from '@/features/assets/AssetsPage'

type Me = {
  user: { id: string; email: string; name: string }
  organizations: { id: string; name: string; role: string }[]
  current_organization_id: string
}

type UserRow = {
  id: string
  email: string
  name: string
  role: string
  disabled: boolean
  last_login_at?: string
  created_at: string
  member_since: string
}

const ROLE_LABELS: Record<string, string> = {
  owner: 'Owner',
  administrator: 'Administrator',
  security_analyst: 'Manager',
  operator: 'Operator',
  viewer: 'Viewer',
}

const ASSIGNABLE_ROLES = ['administrator', 'security_analyst', 'operator', 'viewer'] as const

function errText(e: unknown): string {
  return e instanceof Error ? e.message : 'Request failed'
}

export default function SettingsPage() {
  const [tab, setTab] = useState<'sites' | 'account' | 'presets' | 'users' | 'scanners' | 'feeds' | 'audit'>('sites')
  const sites = useSites()
  const me = useQuery({ queryKey: ['me'], queryFn: () => api.get<Me>('/auth/me') })
  const organization = me.data?.organizations?.find((org) => org.id === me.data?.current_organization_id)
  const role = organization?.role ?? ''
  const isAdmin = role === 'owner' || role === 'administrator'
  const tabs: readonly ('sites' | 'account' | 'presets' | 'users' | 'scanners' | 'feeds' | 'audit')[] = isAdmin
    ? ['sites', 'account', 'presets', 'users', 'scanners', 'feeds', 'audit']
    : ['sites', 'account']

  return (
    <div className="space-y-4">
      <div className="flex gap-1 border-b border-line">
        {tabs.map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 pb-2 text-[13px] capitalize ${t === tab ? 'border-accent text-fg' : 'border-transparent text-fg-dim hover:text-fg'}`}>
            {t === 'account' ? 'My account' : t}
          </button>
        ))}
      </div>

      {tab === 'sites' && <>
        {me.isError && <ErrorState message="Unable to load organization details." onRetry={() => me.refetch()} />}
        {organization && <OrganizationPanel key={organization.id} organization={organization} canRename={isAdmin} />}
        <SitesPanel sites={sites.data?.items ?? []} loading={sites.isLoading} />
      </>}
      {tab === 'account' && <AccountPanel email={me.data?.user?.email ?? ''} />}
      {tab === 'presets' && isAdmin && <PresetsPanel />}
      {tab === 'scanners' && isAdmin && <ScannersPanel />}
      {tab === 'users' && isAdmin && <UsersPanel meId={me.data?.user?.id ?? ''} />}
      {tab === 'feeds' && isAdmin && <FeedsPanel />}
      {tab === 'audit' && isAdmin && <AuditPanel />}
    </div>
  )
}

function OrganizationPanel({ organization, canRename }: { organization: { id: string; name: string }; canRename: boolean }) {
  const qc = useQueryClient()
  const [draft, setDraft] = useState<string | null>(null)
  const [confirm, setConfirm] = useState(false)
  const name = draft ?? organization.name
  const rename = useMutation({
    mutationFn: () => api.patch('/organizations/current', { name: name.trim() }),
    onSuccess: () => {
      setConfirm(false)
      setDraft(null)
      void qc.invalidateQueries({ queryKey: ['me'] })
      void qc.invalidateQueries({ queryKey: ['organizations'] })
    },
  })
  return <Panel>
    <PanelHeader title="Organization" />
    <div className="space-y-3 px-3.5 py-3">
      <label htmlFor="organization-name" className="block text-[12px] text-fg-dim">Organization name</label>
      <Input id="organization-name" value={name} onChange={(e) => { setDraft(e.target.value); rename.reset() }} disabled={!canRename || rename.isPending} className="w-full max-w-[520px]" />
      {canRename ? <Button disabled={rename.isPending || !name.trim() || name.trim() === organization.name} onClick={() => setConfirm(true)}>Rename organization</Button> : <p className="text-fg-dim">Only owners and administrators can rename the organization.</p>}
      {rename.isSuccess && <p role="status" className="text-ok">Organization name updated.</p>}
      {rename.isError && <p role="alert" className="text-crit">{errText(rename.error)}</p>}
    </div>
    <Dialog open={confirm} onClose={() => { if (!rename.isPending) setConfirm(false) }} title="Rename organization">
      <p className="mb-4">Rename {organization.name} to <strong>{name.trim()}</strong>? Future reports will use the new name.</p>
      {rename.isError && <p role="alert" className="mb-3 text-crit">{errText(rename.error)}</p>}
      <div className="flex justify-end gap-2"><Button disabled={rename.isPending} onClick={() => setConfirm(false)}>Cancel</Button><Button variant="primary" disabled={rename.isPending} onClick={() => rename.mutate()}>{rename.isPending ? 'Saving…' : 'Confirm rename'}</Button></div>
    </Dialog>
  </Panel>
}

// ---------------------------------------------------------------------------
// My account: self-service password change (every role).
function AccountPanel({ email }: { email: string }) {
  const qc = useQueryClient()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [done, setDone] = useState(false)
  const change = useMutation({
    mutationFn: () => api.post('/auth/password', { current_password: current, new_password: next }),
    onSuccess: () => {
      setDone(true)
      setCurrent('')
      setNext('')
      setConfirm('')
      qc.invalidateQueries({ queryKey: ['me'] })
    },
  })
  const mismatch = confirm.length > 0 && next !== confirm
  const usable = current.length > 0 && next.length >= 10 && next === confirm && !change.isPending
  return (
    <Panel className="max-w-[520px]">
      <PanelHeader title="Change password" />
      <div className="space-y-3 px-3.5 py-3">
        {email && <div className="text-[12px] text-fg-dim">Signed in as {email}</div>}
        {done && (
          <div className="rounded-sm2 border border-ok/30 bg-ok/10 px-3 py-2 text-[12.5px] text-ok">
            Password changed. Other devices have been signed out; this session stays active.
          </div>
        )}
        {change.isError && (
          <div className="rounded-sm2 border border-crit/30 bg-crit/10 px-3 py-2 text-[12.5px] text-crit">{errText(change.error)}</div>
        )}
        <Input type="password" placeholder="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} className="w-full" autoComplete="current-password" />
        <Input type="password" placeholder="New password (min 10 characters)" value={next} onChange={(e) => { setNext(e.target.value); setDone(false) }} className="w-full" autoComplete="new-password" />
        <Input type="password" placeholder="Repeat new password" value={confirm} onChange={(e) => setConfirm(e.target.value)} className="w-full" autoComplete="new-password" />
        {mismatch && <div className="text-[12px] text-crit">Passwords do not match.</div>}
        <div className="flex justify-end">
          <Button variant="primary" disabled={!usable} onClick={() => change.mutate()}>Update password</Button>
        </div>
      </div>
    </Panel>
  )
}

// ---------------------------------------------------------------------------
// User management (administrators only; requires user:manage on the server).
function UsersPanel({ meId }: { meId: string }) {
  const qc = useQueryClient()
  const users = useQuery({ queryKey: ['users'], queryFn: () => api.get<{ items: UserRow[] }>('/users') })
  const [open, setOpen] = useState(false)
  const [email, setEmail] = useState('')
  const [name, setName] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<string>('security_analyst')
  const [resetTarget, setResetTarget] = useState<UserRow | null>(null)
  const [resetPw, setResetPw] = useState('')

  const invalidate = () => qc.invalidateQueries({ queryKey: ['users'] })
  const create = useMutation({
    mutationFn: () => api.post('/users', { email, name, password, role }),
    onSuccess: () => { invalidate(); setOpen(false); setEmail(''); setName(''); setPassword('') },
  })
  const patch = useMutation({
    mutationFn: ({ id, body }: { id: string; body: Record<string, unknown> }) => api.patch(`/users/${id}`, body),
    onSuccess: invalidate,
  })
  const reset = useMutation({
    mutationFn: () => api.post(`/users/${resetTarget?.id}/reset-password`, { password: resetPw }),
    onSuccess: () => { invalidate(); setResetTarget(null); setResetPw('') },
  })

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-[12.5px] text-fg-dim">
          Managers (analysts/operators/viewers) can run scans and manage findings, but not users or system configuration.
        </p>
        <Button variant="primary" onClick={() => setOpen(true)}>New user</Button>
      </div>
      <Panel>
        {users.isLoading ? <Spinner /> : users.isError ? <ErrorState message={errText(users.error)} /> : (
          <table className="table-base">
            <thead><tr><th>User</th><th>Role</th><th>Status</th><th>Last login</th><th className="text-right">Actions</th></tr></thead>
            <tbody>
              {(users.data?.items ?? []).map((u) => (
                <tr key={u.id} className={u.disabled ? 'opacity-55' : ''}>
                  <td>
                    <div className="text-[13px] font-medium">{u.name}</div>
                    <div className="text-[11.5px] text-fg-dim">{u.email}</div>
                  </td>
                  <td>
                    {u.role === 'owner' || u.id === meId ? (
                      <Badge className="border-line text-fg-dim">{ROLE_LABELS[u.role] ?? u.role}</Badge>
                    ) : (
                      <Select
                        value={u.role}
                        onValueChange={(value) => patch.mutate({ id: u.id, body: { role: value } })}
                        options={ASSIGNABLE_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] }))}
                        className="py-1 text-[12.5px]"
                        aria-label={`Role for ${u.email}`}
                      />
                    )}
                  </td>
                  <td>
                    <StatusDot state={u.disabled ? 'offline' : 'healthy'} label={u.disabled ? 'disabled' : 'active'} />
                  </td>
                  <td className="text-fg-dim">{u.last_login_at ? relTime(u.last_login_at) : 'never'}</td>
                  <td className="text-right">
                    {u.id !== meId && u.role !== 'owner' && (
                      <div className="flex justify-end gap-1.5">
                        <Button onClick={() => { setResetTarget(u); setResetPw('') }}>Reset password</Button>
                        <Button variant="ghost" onClick={() => patch.mutate({ id: u.id, body: { disabled: !u.disabled } })}>
                          {u.disabled ? 'Enable' : 'Disable'}
                        </Button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
              {(users.data?.items ?? []).length === 0 && (
                <tr><td colSpan={5} className="text-center text-[12.5px] text-fg-dim">No users in this organization yet.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </Panel>

      <Dialog open={open} onClose={() => setOpen(false)} title="Create user">
        <div className="space-y-3">
          <Input placeholder="Email" value={email} onChange={(e) => setEmail(e.target.value)} className="w-full" />
          <Input placeholder="Full name" value={name} onChange={(e) => setName(e.target.value)} className="w-full" />
          <Input type="password" placeholder="Initial password (min 10 chars)" value={password} onChange={(e) => setPassword(e.target.value)} className="w-full" autoComplete="new-password" />
          <Select
            value={role}
            onValueChange={setRole}
            options={ASSIGNABLE_ROLES.map((r) => ({ value: r, label: ROLE_LABELS[r] }))}
            className="w-full text-[13px]"
            aria-label="New user role"
          />
          {create.isError && <div className="text-[12px] text-crit">{errText(create.error)}</div>}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" disabled={!email || !name || password.length < 10 || create.isPending} onClick={() => create.mutate()}>Create user</Button>
          </div>
        </div>
      </Dialog>

      <Dialog open={!!resetTarget} onClose={() => setResetTarget(null)} title={`Reset password — ${resetTarget?.name ?? ''}`}>
        <div className="space-y-3">
          <p className="text-[12.5px] text-fg-dim">The new password takes effect immediately and signs the user out of every device.</p>
          <Input type="password" placeholder="New password (min 10 chars)" value={resetPw} onChange={(e) => setResetPw(e.target.value)} className="w-full" autoComplete="new-password" />
          {reset.isError && <div className="text-[12px] text-crit">{errText(reset.error)}</div>}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setResetTarget(null)}>Cancel</Button>
            <Button variant="primary" disabled={resetPw.length < 10 || reset.isPending} onClick={() => reset.mutate()}>Reset</Button>
          </div>
        </div>
      </Dialog>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Scan presets (administrators): custom nmap profiles persisted server-side.
type PresetDef = {
  name: string
  description: string
  top_tcp_ports: number
  full_port_scan: boolean
  service_detect: boolean
  service_lite: boolean
  os_detect: boolean
  traceroute: boolean
  max_targets: number
  max_packet_rate: number
  extra_args?: string[]
}

const EMPTY_PRESET: PresetDef = {
  name: '',
  description: '',
  top_tcp_ports: 100,
  full_port_scan: false,
  service_detect: true,
  service_lite: false,
  os_detect: false,
  traceroute: true,
  max_targets: 4096,
  max_packet_rate: 100,
  extra_args: [],
}

function PresetsPanel() {
  const qc = useQueryClient()
  const presets = useQuery({ queryKey: ['scan-profiles'], queryFn: () => api.get<{ custom: PresetDef[] }>('/scan-profiles') })
  const [editing, setEditing] = useState<PresetDef | null>(null)
  const [isNew, setIsNew] = useState(false)
  const [argsText, setArgsText] = useState('')
  const [error, setError] = useState('')
  const open = editing !== null

  const save = useMutation({
    mutationFn: () =>
      api.post('/scan-profiles', { ...editing, extra_args: argsText.split(/\s+/).map((t) => t.trim()).filter(Boolean) }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['scan-profiles'] }); setEditing(null) },
    onError: (e) => setError(errText(e)),
  })
  const del = useMutation({
    mutationFn: (name: string) => api.del(`/scan-profiles/${name}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan-profiles'] }),
    onError: (e) => setError(errText(e)),
  })
  const openEdit = (p: PresetDef) => {
    setIsNew(p.name === '')
    setEditing({ ...p })
    setArgsText((p.extra_args ?? []).join(' '))
    setError('')
  }
  const valid = editing && /^[a-z][a-z0-9-]{2,31}$/.test(editing.name) && (editing.top_tcp_ports > 0 || editing.full_port_scan)

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-[12.5px] text-fg-dim">
          Custom nmap presets appear as profile options in the scan form. Extra arguments are allowlist-checked
          (timing, rate and port-spec knobs only — scripts and file inputs are rejected).
        </p>
        <Button variant="primary" onClick={() => openEdit(EMPTY_PRESET)}>New preset</Button>
      </div>
      {error && <div className="rounded-sm2 border border-crit/30 bg-crit/10 px-3 py-2 text-[12.5px] text-crit">{error}</div>}
      <Panel>
        {presets.isLoading ? <Spinner /> : (
          <table className="table-base">
            <thead><tr><th>Preset</th><th>Phases</th><th>Ports</th><th>Rate</th><th className="text-right">Actions</th></tr></thead>
            <tbody>
              {(presets.data?.custom ?? []).map((p) => (
                <tr key={p.name}>
                  <td>
                    <div className="font-mono text-[12.5px] font-medium">{p.name}</div>
                    <div className="text-[11.5px] text-fg-dim">{p.description || '—'}</div>
                  </td>
                  <td className="text-[12px] text-fg-dim">
                    {[p.service_detect && 'services', p.service_lite && 'lite', p.os_detect && 'OS', p.traceroute && 'trace'].filter(Boolean).join(', ') || 'discovery only'}
                  </td>
                  <td className="text-[12px] text-fg-dim">{p.full_port_scan ? 'all 65535' : `top ${p.top_tcp_ports || 100}`}</td>
                  <td className="num text-[12px] text-fg-dim">{p.max_packet_rate} pps</td>
                  <td className="text-right">
                    <div className="flex justify-end gap-1.5">
                      <Button onClick={() => openEdit(p)}>Edit</Button>
                      <Button variant="ghost" onClick={() => del.mutate(p.name)}>Delete</Button>
                    </div>
                  </td>
                </tr>
              ))}
              {(presets.data?.custom ?? []).length === 0 && (
                <tr><td colSpan={5} className="text-center text-[12.5px] text-fg-dim">No custom presets yet — create one to tailor nmap behavior.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </Panel>

      <Dialog open={open} onClose={() => setEditing(null)} title={isNew ? 'Create scan preset' : `Edit preset — ${editing?.name}`} wide>
        {editing && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[12px] text-fg-dim">Name (lowercase, dashes)</label>
                <Input value={editing.name} disabled={!isNew} onChange={(e) => setEditing({ ...editing, name: e.target.value })} className="w-full font-mono" placeholder="fast-inventory" />
              </div>
              <div>
                <label className="block text-[12px] text-fg-dim">Description</label>
                <Input value={editing.description} onChange={(e) => setEditing({ ...editing, description: e.target.value })} className="w-full" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <label className="flex items-center gap-2 text-[13px]">
                <input type="checkbox" checked={editing.full_port_scan} onChange={(e) => setEditing({ ...editing, full_port_scan: e.target.checked, top_tcp_ports: e.target.checked ? 0 : 100 })} />
                Full 65535-port sweep
              </label>
              <div>
                <label className="block text-[12px] text-fg-dim">Top-N TCP ports (ignored when full sweep)</label>
                <Input type="number" min={0} max={65535} value={editing.top_tcp_ports} disabled={editing.full_port_scan} onChange={(e) => setEditing({ ...editing, top_tcp_ports: Number(e.target.value) })} className="w-full" />
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2 text-[13px]">
              <label className="flex items-center gap-2"><input type="checkbox" checked={editing.service_detect} onChange={(e) => setEditing({ ...editing, service_detect: e.target.checked })} /> Service detection (-sV per port)</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={editing.service_lite} onChange={(e) => setEditing({ ...editing, service_lite: e.target.checked })} /> Light batched service pass</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={editing.os_detect} onChange={(e) => setEditing({ ...editing, os_detect: e.target.checked })} /> OS fingerprinting (-O)</label>
              <label className="flex items-center gap-2"><input type="checkbox" checked={editing.traceroute} onChange={(e) => setEditing({ ...editing, traceroute: e.target.checked })} /> Topology tracing</label>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-[12px] text-fg-dim">Max targets per scan</label>
                <Input type="number" min={1} max={262144} value={editing.max_targets} onChange={(e) => setEditing({ ...editing, max_targets: Number(e.target.value) })} className="w-full" />
              </div>
              <div>
                <label className="block text-[12px] text-fg-dim">Max packet rate (pps)</label>
                <Input type="number" min={1} max={100000} value={editing.max_packet_rate} onChange={(e) => setEditing({ ...editing, max_packet_rate: Number(e.target.value) })} className="w-full" />
              </div>
            </div>
            <div>
              <label className="block text-[12px] text-fg-dim">Extra nmap arguments (allowlist: -T1..-T5, --max-rate, --min-rate, --max-retries, --top-ports, -p, -F, -Pn, -n, --system-dns, --defeat-rst-ratelimit, --disable-arp-ping, --send-eth, --send-ip, --unprivileged)</label>
              <Input value={argsText} onChange={(e) => setArgsText(e.target.value)} className="w-full font-mono" placeholder="-T3 --max-rate 300 -p 22,80,443,3389" />
            </div>
            {save.isError && <div className="text-[12px] text-crit">{errText(save.error)}</div>}
            <div className="flex justify-end gap-2">
              <Button variant="ghost" onClick={() => setEditing(null)}>Cancel</Button>
              <Button variant="primary" disabled={!valid || save.isPending} onClick={() => save.mutate()}>{isNew ? 'Create preset' : 'Save changes'}</Button>
            </div>
          </div>
        )}
      </Dialog>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Scanner hub: remote gRPC scanners installed on physical hosts.
type ScannerRow = {
  id: string
  name: string
  site_id: string
  version: string
  health: string
  transport: string
  is_default: boolean
  last_seen: string
}

function ScannersPanel() {
  const qc = useQueryClient()
  const sites = useSites()
  const scanners = useQuery({ queryKey: ['scanners'], queryFn: () => api.get<{ items: ScannerRow[] }>('/scanners') })
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [siteId, setSiteId] = useState('')
  const [issued, setIssued] = useState<{ scanner_id: string; token: string } | null>(null)
  const [error, setError] = useState('')

  const enroll = useMutation({
    mutationFn: () => api.post<{ scanner_id: string; token: string }>('/scanners/enroll', { name, site_id: siteId }),
    onSuccess: (d) => { setIssued(d); setOpen(false); setName(''); qc.invalidateQueries({ queryKey: ['scanners'] }) },
    onError: (e) => setError(errText(e)),
  })
  const setDefault = useMutation({
    mutationFn: ({ id, is_default }: { id: string; is_default: boolean }) => api.post(`/scanners/${id}/default`, { is_default }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scanners'] }),
    onError: (e) => setError(errText(e)),
  })

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <p className="text-[12.5px] text-fg-dim">
          Remote scanners run on physical servers (no container NAT limits) and connect here over gRPC.
          Enroll one, then run on the host: <code className="font-mono">AEGIS_SCANNER_MODE=agent AEGIS_SCANNER_HUB_ADDR=host:9090 AEGIS_SCANNER_HUB_TOKEN=&lt;token&gt; aegis-scanner</code>
        </p>
        <Button variant="primary" onClick={() => { setIssued(null); setError(''); setOpen(true) }}>Enroll scanner</Button>
      </div>
      {error && <div className="rounded-sm2 border border-crit/30 bg-crit/10 px-3 py-2 text-[12.5px] text-crit">{error}</div>}
      {issued && (
        <div className="rounded-sm2 border border-warn/40 bg-warn/10 px-3 py-2.5 text-[12.5px]">
          <p className="font-medium text-warn">Enrollment token — copy it now, it is shown only once.</p>
          <p className="mt-1 break-all font-mono text-[12px] text-fg">{issued.token}</p>
        </div>
      )}
      <Panel>
        {scanners.isLoading ? <Spinner /> : (
          <table className="table-base">
            <thead><tr><th>Scanner</th><th>Transport</th><th>Health</th><th>Last seen</th><th className="text-right">Default</th></tr></thead>
            <tbody>
              {(scanners.data?.items ?? []).map((s) => (
                <tr key={s.id}>
                  <td>
                    <div className="text-[13px] font-medium">{s.name}</div>
                    <div className="text-[11.5px] text-fg-dim">{s.version}</div>
                  </td>
                  <td><Badge className="border-line text-fg-dim">{s.transport === 'grpc' ? 'gRPC agent' : 'embedded'}</Badge></td>
                  <td><StatusDot state={s.health} label={s.health} /></td>
                  <td className="text-fg-dim">{relTime(s.last_seen)}</td>
                  <td className="text-right">
                    <Button onClick={() => setDefault.mutate({ id: s.id, is_default: !s.is_default })} disabled={s.transport !== 'grpc'}>
                      {s.is_default ? 'Default ✓' : 'Make default'}
                    </Button>
                  </td>
                </tr>
              ))}
              {(scanners.data?.items ?? []).length === 0 && (
                <tr><td colSpan={5} className="text-center text-[12.5px] text-fg-dim">No scanners registered yet.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </Panel>

      <Dialog open={open} onClose={() => setOpen(false)} title="Enroll remote scanner">
        <div className="space-y-3">
          <Input placeholder="Scanner name (e.g. hq-physical)" value={name} onChange={(e) => setName(e.target.value)} className="w-full" />
          <Select
            value={siteId}
            onValueChange={setSiteId}
            options={[{ value: '', label: 'Select site…' }, ...(sites.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }))]}
            className="w-full text-[13px]"
            aria-label="Scanner site"
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" disabled={!name || !siteId || enroll.isPending} onClick={() => enroll.mutate()}>Enroll</Button>
          </div>
        </div>
      </Dialog>
    </div>
  )
}

// ---------------------------------------------------------------------------

function SitesPanel({ sites, loading }: { sites: Site[]; loading: boolean }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [type, setType] = useState('lab')
  const [cidr, setCidr] = useState('')
  const [forSite, setForSite] = useState('')
  const qc = useQueryClient()
  const createSite = useMutation({
    mutationFn: () => api.post('/sites', { name, site_type: type }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sites'] })
      setOpen(false)
      setName('')
    },
  })
  const createNetwork = useMutation({
    mutationFn: () => api.post(`/sites/${forSite}/networks`, { cidr, name: cidr }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['site-networks', forSite] })
      setCidr('')
    },
  })

  if (loading) return <Spinner />
  return (
    <div className="space-y-3">
      <div className="flex justify-end">
        <Button variant="primary" onClick={() => setOpen(true)}>New site</Button>
      </div>
      {sites.map((s) => (
        <SiteRow key={s.id} site={s} cidr={cidr} setCidr={setCidr} forSite={forSite} setForSite={setForSite} addNetwork={() => createNetwork.mutate()} />
      ))}
      <Dialog open={open} onClose={() => setOpen(false)} title="Create site">
        <div className="space-y-3">
          <Input placeholder="Site name (e.g. HQ, Datacenter)" value={name} onChange={(e) => setName(e.target.value)} className="w-full" />
          <Select
            value={type}
            onValueChange={setType}
            options={['hq', 'datacenter', 'cloud', 'branch', 'home', 'lab'].map((t) => ({ value: t, label: t }))}
            className="w-full text-[13px]"
            aria-label="Site type"
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
            <Button variant="primary" disabled={!name || createSite.isPending} onClick={() => createSite.mutate()}>Create</Button>
          </div>
        </div>
      </Dialog>
    </div>
  )
}

function SiteRow({ site, cidr, setCidr, forSite, setForSite, addNetwork }: {
  site: Site
  cidr: string
  setCidr: (v: string) => void
  forSite: string
  setForSite: (v: string) => void
  addNetwork: () => void
}) {
  const networks = useQuery({
    queryKey: ['site-networks', site.id],
    queryFn: () => api.get<{ items: Network[] }>(`/sites/${site.id}/networks`),
    enabled: forSite === site.id,
  })
  return (
    <Panel>
      <div className="flex cursor-pointer items-center justify-between px-3.5 py-2.5" onClick={() => setForSite(forSite === site.id ? '' : site.id)}>
        <div>
          <span className="text-[13px] font-medium">{site.name}</span>
          <Badge className="ml-2 border-line text-fg-dim">{site.site_type}</Badge>
        </div>
        <span className="text-[11.5px] text-fg-faint">created {relTime(site.created_at)}</span>
      </div>
      {forSite === site.id && (
        <div className="border-t border-line px-3.5 py-3">
          <div className="flex gap-2">
            <Input placeholder="CIDR (192.168.1.0/24)" value={cidr} onChange={(e) => setCidr(e.target.value)} className="w-[240px] font-mono" />
            <Button disabled={!cidr || forSite !== site.id} onClick={addNetwork}>Add network</Button>
          </div>
          <table className="table-base mt-2">
            <thead><tr><th>CIDR</th><th>VLAN</th><th>Exposure</th></tr></thead>
            <tbody>
              {(networks.data?.items ?? []).map((n) => (
                <tr key={n.id}>
                  <td className="font-mono text-[12px]">{n.cidr}</td>
                  <td className="text-fg-dim">{n.vlan_id ?? '—'}</td>
                  <td className="text-fg-dim">{n.exposure}</td>
                </tr>
              ))}
              {(networks.data?.items ?? []).length === 0 && (
                <tr><td colSpan={3} className="text-center text-[12px] text-fg-dim">No networks defined yet.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  )
}

function FeedsPanel() {
  const feeds = useQuery({ queryKey: ['feeds'], queryFn: () => api.get<{ items: FeedSource[] }>('/feeds') })
  return (
    <Panel>
      <PanelHeader title="Vulnerability intelligence feeds" />
      {feeds.isLoading ? <Spinner /> : feeds.isError ? <ErrorState message={(feeds.error as Error).message} /> : (
        <table className="table-base">
          <thead><tr><th>Source</th><th>Status</th><th>Last sync</th><th>Records</th><th>License</th></tr></thead>
          <tbody>
            {(feeds.data?.items ?? []).map((f) => (
              <tr key={f.name}>
                <td className="font-medium">{f.name}</td>
                <td>
                  <StatusDot state={f.last_status === 'healthy' ? 'healthy' : f.last_status ?? ''} label={(f.last_status || 'never synced').replace('_', ' ')} />
                  {f.last_error && <div className="max-w-[320px] truncate text-[11px] text-crit" title={f.last_error}>{f.last_error}</div>}
                </td>
                <td className="text-fg-dim">{f.last_sync_at ? relTime(f.last_sync_at) : '—'}</td>
                <td className="tabular-nums text-fg-dim">{f.records_ingested ?? 0}</td>
                <td className="max-w-[280px] truncate text-[11.5px] text-fg-faint" title={f.license}>{f.license || '—'}</td>
              </tr>
            ))}
            {(feeds.data?.items ?? []).length === 0 && (
              <tr><td colSpan={5} className="text-center text-[12.5px] text-fg-dim">No feeds configured — start the feed-worker.</td></tr>
            )}
          </tbody>
        </table>
      )}
    </Panel>
  )
}

function AuditPanel() {
  const audit = useQuery({
    queryKey: ['audit-log'],
    queryFn: () => api.get<Page<AuditEntry>>('/audit-log?limit=100'),
  })
  return (
    <Panel>
      <PanelHeader title="Audit log" />
      {audit.isLoading ? <Spinner /> : audit.isError ? <ErrorState message={(audit.error as Error).message} /> : (audit.data?.items ?? []).length === 0 ? (
        <EmptyState title="No audit entries" />
      ) : (
        <table className="table-base">
          <thead><tr><th>Action</th><th>Actor</th><th>Target</th><th>Result</th><th>When</th></tr></thead>
          <tbody>
            {(audit.data?.items ?? []).map((e) => (
              <tr key={e.id}>
                <td className="font-medium">{e.action}</td>
                <td className="font-mono text-[11px] text-fg-dim">{e.actor_id?.slice(0, 10) || 'anonymous'}</td>
                <td className="text-fg-dim">{e.target || '—'}</td>
                <td><Badge className={e.result === 'success' ? 'border-ok/30 text-ok' : 'border-crit/30 text-crit'}>{e.result}</Badge></td>
                <td className="text-fg-dim">{relTime(e.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </Panel>
  )
}
