import { useMemo, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Page, Scan, Scanner } from '@/types'
import { Pill, Button, Dialog, Panel, ChipSelect, StatusDot, Spinner, ErrorState, EmptyState, Meter, Select } from '@/components/ui'
import { relTime, exactTime } from '@/lib/format'
import { useSites } from '@/features/assets/AssetsPage'

// ProfileDef mirrors the server's ProfileDefinition (subset) for the
// scan-form preset options and the Settings editor.
type ProfileDef = {
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
  builtin?: boolean
}

function nmapArgsHint(p: ProfileDef): string {
  const bits: string[] = []
  if (p.full_port_scan) bits.push('all ports')
  else if (p.top_tcp_ports > 0) bits.push(`top ${p.top_tcp_ports}`)
  if (p.os_detect) bits.push('OS')
  if (p.service_detect || p.service_lite) bits.push('services')
  if (p.traceroute) bits.push('trace')
  return bits.length ? ` (${bits.join(', ')})` : ''
}

export default function ScansPage() {
  const [params, setParams] = useSearchParams()
  const [dialogOpen, setDialogOpen] = useState(params.get('new') === '1')
  const sites = useSites()
  const scanners = useQuery({ queryKey: ['scanners'], queryFn: () => api.get<Page<Scanner>>('/scanners') })
  const scans = useQuery({
    queryKey: ['scans', params.toString()],
    queryFn: () => api.get<Page<Scan>>(`/scans?${params.toString()}`),
    refetchInterval: (q) => {
      const items = (q.state.data as Page<Scan> | undefined)?.items ?? []
      return items.some((s) => s.state === 'running' || s.state === 'queued') ? 4000 : false
    },
  })

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params)
    if (v) next.set(k, v)
    else next.delete(k)
    setParams(next)
  }

  return (
    <div className="space-y-3">
      <div className="tbl-toolbar">
        <ChipSelect
          label="Site"
          value={params.get('site_id') ?? ''}
          onChange={(v) => setParam('site_id', v)}
          ariaLabel="Site filter"
          options={[{ value: '', label: 'All sites' }, ...(sites.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }))]}
        />
        <ChipSelect
          label="State"
          value={params.get('state') ?? ''}
          onChange={(v) => setParam('state', v)}
          ariaLabel="State filter"
          options={[{ value: '', label: 'All states' }, ...['queued', 'running', 'completed', 'failed', 'cancelled'].map((s) => ({ value: s, label: s }))]}
        />
        <div className="ml-auto">
          <Button variant="primary" onClick={() => setDialogOpen(true)}>New scan</Button>
        </div>
      </div>

      <Panel>
        {scans.isLoading ? <Spinner /> : scans.isError ? <ErrorState message={(scans.error as Error).message} onRetry={() => scans.refetch()} /> : (scans.data?.items ?? []).length === 0 ? (
          <EmptyState title="No scans yet" hint="Create your first discovery scan — start with discovery_safe." action={<Button variant="primary" onClick={() => setDialogOpen(true)}>Run your first scan</Button>} />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th scope="col">Name</th><th scope="col">Profile</th><th scope="col">Engine</th>
                  <th scope="col">State</th><th scope="col">Progress</th><th scope="col" className="num">Reachable</th>
                  <th scope="col" className="num">Ports</th><th scope="col" className="num">Services</th><th scope="col" className="num">Findings</th><th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {(scans.data?.items ?? []).map((s) => (
                  <tr key={s.id}>
                    <td><Link to={`/scans/${s.id}`} className="font-medium hover:text-accent">{s.name}</Link></td>
                    <td><Pill tone="neutral">{s.profile}</Pill></td>
                    <td className="text-fg-dim">{s.engine}</td>
                    <td><StatusDot state={s.state} /></td>
                    <td className="num">
                      <Meter
                        value={s.progress ?? 0}
                        max={100}
                        tone={s.state === 'completed' ? 'ok' : 'accent'}
                        label={`Scan progress ${(s.progress ?? 0).toFixed(0)}%`}
                      />
                      <span className="text-fg-dim">{(s.progress ?? 0).toFixed(0)}%</span>
                    </td>
                    <td className="num">{s.stats?.reachable ?? 0}/{s.stats?.targets ?? 0}</td>
                    <td className="num text-fg-dim">{s.stats?.ports_discovered ?? 0}</td>
                    <td className="num text-fg-dim">{s.stats?.services_fingerprinted ?? 0}</td>
                    <td className="num text-fg-dim">{s.stats?.findings_created ?? 0}</td>
                    <td className="text-fg-dim" title={exactTime(s.created_at)}>{relTime(s.created_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <NewScanDialog open={dialogOpen} onClose={() => { setDialogOpen(false); setParam('new', '') }} sites={sites.data?.items ?? []} scanners={scanners.data?.items ?? []} />
    </div>
  )
}

export function NewScanDialog({ open, onClose, sites, scanners }: {
  open: boolean
  onClose: () => void
  sites: { id: string; name: string }[]
  scanners: Scanner[]
}) {
  const [siteId, setSiteId] = useState(sites[0]?.id ?? '')
  const [profile, setProfile] = useState('discovery_safe')
  const [targets, setTargets] = useState('')
  const [denylist, setDenylist] = useState('')
  const [confirm, setConfirm] = useState(false)
  const [error, setError] = useState('')
  const qc = useQueryClient()
  const profilesQuery = useQuery({
    queryKey: ['scan-profiles'],
    queryFn: () => api.get<{ builtin: ProfileDef[]; custom: ProfileDef[] }>('/scan-profiles'),
  })
  const availableSites = useMemo(
    () => sites.filter((site) => scanners.some((scanner) => scanner.site_id === site.id && scanner.health === 'healthy')),
    [sites, scanners],
  )
  // Site and scanner data arrive asynchronously. Fall back during render so
  // the form never submits the initial empty/stale site selection.
  const selectedSiteId = availableSites.some((site) => site.id === siteId) ? siteId : (availableSites[0]?.id ?? '')
  const create = useMutation({
    mutationFn: () =>
      api.post<{ scan: Scan; warnings: string[] }>('/scans', {
        site_id: selectedSiteId,
        name: `${profile} scan`,
        profile,
        targets: targets.split('\n').map((t) => t.trim()).filter(Boolean),
        denylist: denylist.split('\n').map((t) => t.trim()).filter(Boolean),
        engine: 'nmap',
        confirm_elevated: confirm,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['scans'] })
      onClose()
    },
    onError: (e) => setError((e as Error).message),
  })

  return (
    <Dialog open={open} onClose={onClose} title="Create scan" wide>
      <div className="space-y-3">
        <label className="block text-[12px] text-fg-dim">Site</label>
        <Select
          value={selectedSiteId}
          onValueChange={setSiteId}
          options={availableSites.map((s) => ({ value: s.id, label: s.name }))}
          className="w-full text-[13px]"
          disabled={availableSites.length === 0}
          aria-label="Scan site"
        />
        {availableSites.length === 0 && <p className="text-[12px] text-crit">No healthy scanner is registered for any site. Register a scanner before creating a scan.</p>}
        <label className="block text-[12px] text-fg-dim">Profile</label>
        <Select
          value={profile}
          onValueChange={setProfile}
          options={[
            { value: 'discovery_safe', label: 'discovery_safe — host discovery, top 100 ports, low rate' },
            { value: 'trace', label: 'trace — fast topology trace: ping sweep + traceroute only, no port scans' },
            { value: 'fingerprint', label: 'fingerprint — device type + OS pass: classifies router/computer/phone/iot, refreshes OS data (light service pass + nmap -O)' },
            { value: 'inventory', label: 'inventory — broad ports, service + OS detection, safe NSE' },
            { value: 'vulnerability_safe', label: 'vulnerability_safe — inventory + CVE correlation + safe validation' },
            { value: 'full_audit', label: 'full_audit — ALL 65535 ports, full service/OS fingerprinting, topology tracing' },
            { value: 'active_validation', label: 'active_validation — ELEVATED: requires confirmation, fully audited' },
            ...(profilesQuery.data?.custom ?? []).map((p) => ({ value: p.name, label: `${p.name} — custom preset${nmapArgsHint(p)}` })),
          ]}
          className="w-full text-[13px]"
          aria-label="Scan profile"
        />
        {profile === 'full_audit' && (
          <div className="rounded-sm2 border border-warn/30 bg-warn/10 p-2.5">
            <p className="text-[12px] text-warn">
              full_audit scans all 65535 TCP ports of every discovered host with version and OS fingerprinting.
              It is noticeably louder and slower than inventory scans — run it only against networks you are authorized to assess.
            </p>
          </div>
        )}
        {profile === 'active_validation' && (
          <div className="rounded-sm2 border border-crit/30 bg-crit/10 p-2.5">
            <p className="text-[12px] text-crit">
              This profile performs active validation probes. Ensure every target is inside your authorized scope.
              All actions are audit-logged with your identity.
            </p>
            <label className="mt-2 flex items-center gap-2 text-[12.5px]">
              <input type="checkbox" checked={confirm} onChange={(e) => setConfirm(e.target.checked)} />
              I confirm the scope is authorized for active validation
            </label>
          </div>
        )}
        <label className="block text-[12px] text-fg-dim">Targets — CIDRs, ranges or single IPs (one per line)</label>
        <textarea
          value={targets}
          onChange={(e) => setTargets(e.target.value)}
          rows={4}
          placeholder={'192.168.1.0/24\n10.0.5.0-10.0.5.50\n192.168.1.1'}
          className="w-full rounded-sm2 border border-line bg-bg-raise px-2.5 py-2 font-mono text-[12px] outline-none focus:border-accent"
        />
        <label className="block text-[12px] text-fg-dim">Denylist — never touched (one CIDR, range or IP per line)</label>
        <textarea
          value={denylist}
          onChange={(e) => setDenylist(e.target.value)}
          rows={2}
          placeholder={'192.168.1.1\n10.0.0.0/30'}
          className="w-full rounded-sm2 border border-line bg-bg-raise px-2.5 py-2 font-mono text-[12px] outline-none focus:border-accent"
        />
        {error && <p className="rounded-sm2 border border-crit/30 bg-crit/10 px-2.5 py-1.5 text-[12.5px] text-crit" role="alert">{error}</p>}
        <div className="flex justify-end gap-2">
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!selectedSiteId || !targets || create.isPending} onClick={() => create.mutate()}>
            {create.isPending ? 'Creating…' : 'Create scan'}
          </Button>
        </div>
      </div>
    </Dialog>
  )
}
