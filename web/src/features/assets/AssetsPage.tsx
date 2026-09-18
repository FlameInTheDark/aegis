import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Asset, Page, Site } from '@/types'
import { Badge, Input, ChipSelect, Pagination, Panel, StatusDot, Pill, Meter, severityTone } from '@/components/ui'
import { relTime, exactTime, fmtNum, humanize, riskLabel } from '@/lib/format'

export function useSites() {
  return useQuery({
    queryKey: ['sites'],
    queryFn: () => api.get<Page<Site>>('/sites'),
    staleTime: 60_000,
  })
}

export function riskTone(score: number) {
  if (score >= 80) return 'text-crit'
  if (score >= 60) return 'text-high'
  if (score >= 35) return 'text-med'
  return 'text-fg-dim'
}

// Friendly device-class names — mirrors the backend taxonomy
// (domain.DeviceType.Label). "Unknown Device" is the honest default.
export const deviceLabels: Record<string, string> = {
  workstation: 'Computer', server: 'Server', laptop: 'Laptop', mobile: 'Phone',
  router: 'Router', switch: 'Switch', firewall: 'Firewall', access_point: 'Access Point',
  printer: 'Printer', camera: 'Camera', nas: 'NAS', hypervisor: 'Hypervisor',
  virtual_machine: 'Virtual Machine', container_host: 'Container Host', iot: 'IoT Device',
  unknown: 'Unknown Device',
}

const deviceDot: Record<string, string> = {
  router: '#FB923C', switch: '#FBBF24', firewall: '#F87171', server: '#60A5FA',
  workstation: '#5E6AD2', laptop: '#818CF8', printer: '#34D399', access_point: '#A78BFA',
  camera: '#F87171', iot: '#F472B6', mobile: '#22D3EE', nas: '#4ADE80',
  virtual_machine: '#38BDF8', hypervisor: '#60A5FA', container_host: '#2DD4BF',
  unknown: '#6B7280',
}

// assetName prefers what operators named the device, then the address it
// answers on — an IP/hostname is always more useful than a generic class
// label. The device class (when actually identified) decorates the Type
// column instead of hiding the address behind "Unknown Device · …".
export function assetName(a: Asset): string {
  if (a.hostname) return a.hostname
  if (a.fqdn) return a.fqdn
  if (a.primary_ip) return a.primary_ip
  return deviceLabels[a.device_type] ?? 'Device'
}

export default function AssetsPage() {
  const [params, setParams] = useSearchParams()
  const page = Number(params.get('page') ?? 1)
  const search = params.get('search') ?? ''
  const deviceType = params.get('device_type') ?? ''
  const criticality = params.get('criticality') ?? ''
  const [searchDraft, setSearchDraft] = useState(search)
  const sites = useSites()
  const qc = useQueryClient()
  // Per-row "Rediscover" state: which asset is running, and the last
  // outcome shown as a notice under the table.
  const [rediscovering, setRediscovering] = useState<string | null>(null)
  const [notice, setNotice] = useState('')
  const rediscover = useMutation({
    mutationFn: (id: string) =>
      api.post<{ findings_created: number; detail: string }>(`/assets/${id}/rediscover`),
    onMutate: (id) => {
      setNotice('')
      setRediscovering(id)
    },
    onSettled: () => setRediscovering(null),
    onSuccess: (data, id) => {
      qc.invalidateQueries({ queryKey: ['assets'] })
      qc.invalidateQueries({ queryKey: ['findings'] })
      qc.invalidateQueries({ queryKey: ['asset'] })
      setNotice(
        `Rediscovery finished for ${assetName(assets.data?.items.find((a) => a.id === id) ?? ({ id } as Asset))}: ${data.findings_created} new finding${data.findings_created === 1 ? '' : 's'} — ${data.detail}`,
      )
    },
    onError: (e) => setNotice(`Rediscovery failed: ${(e as Error).message}`),
  })

  const assets = useQuery({
    queryKey: ['assets', params.toString()],
    queryFn: () => api.get<Page<Asset>>(`/assets?${params.toString()}`),
  })

  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params)
    if (v) next.set(k, v)
    else next.delete(k)
    if (k !== 'page') next.delete('page')
    setParams(next)
  }

  return (
    <div className="space-y-3">
      <div className="tbl-toolbar">
        <Input
          placeholder="Search hostname, IP, FQDN…"
          value={searchDraft}
          onChange={(e) => setSearchDraft(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && setParam('search', searchDraft)}
          className="w-[260px]"
          aria-label="Search assets"
        />
        <ChipSelect
          label="Type"
          value={deviceType}
          onChange={(v) => setParam('device_type', v)}
          ariaLabel="Device type filter"
          options={[
            { value: '', label: 'All device types' },
            ...['workstation', 'server', 'laptop', 'router', 'switch', 'firewall', 'access_point', 'printer', 'camera', 'nas', 'hypervisor', 'virtual_machine', 'container_host', 'iot', 'mobile', 'unknown'].map((d) => ({ value: d, label: humanize(d) })),
          ]}
        />
        <ChipSelect
          label="Criticality"
          value={criticality}
          onChange={(v) => setParam('criticality', v)}
          ariaLabel="Criticality filter"
          options={[{ value: '', label: 'All criticality' }, ...['critical', 'high', 'medium', 'low'].map((c) => ({ value: c, label: c }))]}
        />
        <ChipSelect
          label="Site"
          value={params.get('site_id') ?? ''}
          onChange={(v) => setParam('site_id', v)}
          ariaLabel="Site filter"
          options={[{ value: '', label: 'All sites' }, ...(sites.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }))]}
        />
      </div>

      <Panel>
        <div className="overflow-x-auto">
          <table className="table-base">
            <thead>
              <tr>
                <th scope="col">Asset</th>
                <th scope="col">Type</th>
                <th scope="col">OS</th>
                <th scope="col" className="num">Confidence</th>
                <th scope="col">Exposure</th>
                <th scope="col">Criticality</th>
                <th scope="col" className="num">Risk</th>
                <th scope="col">Agent</th>
                <th scope="col">Last seen</th>
                <th scope="col" aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {(assets.data?.items ?? []).map((a) => (
                <tr key={a.id}>
                  <td>
                    <div className="flex items-center gap-2">
                      <span aria-hidden className="inline-block h-2 w-2 shrink-0 rounded-full" style={{ backgroundColor: deviceDot[a.device_type] ?? deviceDot.unknown }} />
                      <Link to={`/assets/${a.id}`} className="font-medium text-fg hover:text-accent">
                        {assetName(a)}
                      </Link>
                    </div>
                    {a.demo_source && <Badge className="ml-4 border-line bg-bg-raise text-fg-faint" title="Simulated/demo record">demo</Badge>}
                  </td>
                  <td className="text-fg-dim">{a.device_type ? (deviceLabels[a.device_type] ?? humanize(a.device_type)) : '—'}</td>
                  <td className="text-fg-dim">{a.os_name ? `${a.os_name}${a.os_version ? ` ${a.os_version}` : ''}` : 'Unknown'}</td>
                  <td className="num" title={`Sources: ${(a.os_sources ?? []).join(', ')}`}>
                    <Meter value={a.os_confidence * 100} max={100} tone="accent" label="OS fingerprint confidence" />
                    <span className="text-fg-dim">{(a.os_confidence * 100).toFixed(0)}%</span>
                  </td>
                  <td className="text-fg-dim">{humanize(a.exposure)}</td>
                  <td><Pill tone={severityTone(a.criticality)} title={`Criticality: ${a.criticality}`}>{a.criticality}</Pill></td>
                  <td className="num" title={`Risk ${a.risk_score.toFixed(0)} — ${riskLabel(a.risk_score)}`}>
                    <Meter value={a.risk_score} max={100} label={`Risk score ${a.risk_score.toFixed(0)} (${riskLabel(a.risk_score)})`} />
                    <span className={`font-medium ${riskTone(a.risk_score)}`}>{a.risk_score.toFixed(0)}</span>
                  </td>
                  <td>{a.has_agent ? <StatusDot state="online" label="agent" /> : <span className="text-fg-faint">none</span>}</td>
                  <td className="text-fg-dim" title={exactTime(a.last_seen)}>{relTime(a.last_seen)}</td>
                  <td>
                    <button
                      type="button"
                      className="text-[11.5px] text-accent hover:underline disabled:cursor-wait disabled:opacity-50"
                      disabled={rediscovering !== null}
                      title="Re-match this asset's discovered services and software against the latest CVE database — no network scan, instant"
                      onClick={() => rediscover.mutate(a.id)}
                    >
                      {rediscovering === a.id ? 'Rediscovering…' : 'Rediscover'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {assets.data && <Pagination page={page} limit={assets.data.limit ?? 50} total={assets.data.total} onPage={(p) => setParam('page', String(p))} />}
      </Panel>
      {notice && (
        <p className="text-[11.5px] text-fg-dim" role="status">{notice}</p>
      )}
      <p className="text-[11.5px] text-fg-faint">{fmtNum(assets.data?.total)} assets · confidence reflects fingerprint evidence strength, not certainty. “Rediscover” re-runs vulnerability matching against the current CVE index without scanning.</p>
    </div>
  )
}
