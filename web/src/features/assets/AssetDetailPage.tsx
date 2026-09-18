import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { assetLabel } from '@/lib/labels'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Asset, Finding, Service, Software, Network } from '@/types'
import { Panel, PanelHeader, SeverityBadge, Spinner, ErrorState, StatusDot, Select, Button, EmptyState, Pill, StatusPill, Meter, MiniBars } from '@/components/ui'
import { relTime, exactTime, humanize, riskLabel } from '@/lib/format'
import { riskTone } from './AssetsPage'

interface AssetBundle {
  asset: Asset
  interfaces: { id: string; mac?: string; name?: string; status?: string; addresses?: { ip: string; is_primary?: boolean }[] }[]
  services: Service[]
  software: Software[]
  findings_count: { open: number; critical: number; high: number; medium: number; low: number }
}

// The backend historically serialized empty relations as null (Go nil
// slices); guard every list locally too — a view must never crash on data.
function asList<T>(v: T[] | null | undefined): T[] {
  return Array.isArray(v) ? v : []
}

export default function AssetDetailPage() {
  const { id } = useParams()
  const [tab, setTab] = useState('overview')
  const [redisNotice, setRedisNotice] = useState('')
  const qc = useQueryClient()
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['asset', id],
    queryFn: () => api.get<AssetBundle>(`/assets/${id}`),
  })
  const findings = useQuery({
    queryKey: ['asset-findings', id],
    queryFn: () => api.get<Finding[]>(`/assets/${id}/findings`).then((r) => (Array.isArray(r) ? r : (r as { items: Finding[] }).items)),
    enabled: tab === 'findings',
  })
  const patch = useMutation({
    mutationFn: (fields: Record<string, unknown>) => api.patch(`/assets/${id}`, fields),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['asset', id] })
      qc.invalidateQueries({ queryKey: ['assets'] })
    },
  })
  // Rediscover: re-run vulnerability matching for this asset's already
  // discovered services + software against the current CVE index (e.g.
  // right after new CVEs synced). No network scan involved.
  const rediscover = useMutation({
    mutationFn: () => api.post<{ findings_created: number; detail: string }>(`/assets/${id}/rediscover`),
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ['asset', id] })
      qc.invalidateQueries({ queryKey: ['asset-findings', id] })
      qc.invalidateQueries({ queryKey: ['assets'] })
      setRedisNotice(`${d.findings_created} new finding${d.findings_created === 1 ? '' : 's'} — ${d.detail}`)
    },
    onError: (e) => setRedisNotice(`Rediscovery failed: ${(e as Error).message}`),
  })

  const report = useMutation({
    mutationFn: () => api.post<{ job: { id: string } }>('/reports', { type: 'device_detail', asset_id: id, format: 'pdf' }),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ['report-jobs'] }); void qc.invalidateQueries({ queryKey: ['reports'] }) },
  })

  if (isLoading) return <Spinner />
  if (isError) return <ErrorState message={(error as Error).message} onRetry={() => refetch()} />
  const a = data!.asset
  const services = asList(data?.services)
  const software = asList(data?.software)
  const interfaces = asList(data?.interfaces)
  const counts = (data?.findings_count ?? {}) as Record<string, number>

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[17px] font-semibold">{assetLabel(a)}</h1>
          <p className="mt-0.5 text-[12.5px] text-fg-dim">
            {a.device_type ? `${humanize(a.device_type)} · ` : ''}
            {a.os_name || 'OS unknown'} · first seen {relTime(a.first_seen)} ·{' '}
            <span title={exactTime(a.last_seen)}>last seen {relTime(a.last_seen)}</span>
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Button onClick={() => report.mutate()} disabled={report.isPending}>{report.isPending ? 'Queuing report…' : 'Generate report'}</Button>
          {report.isSuccess && <span role="status">Report queued. <Link className="text-accent hover:underline" to={`/reports?job=${encodeURIComponent(report.data.job.id)}`}>View report</Link></span>}
          {report.isError && <span role="alert" className="text-crit">{(report.error as Error).message}</span>}
          {redisNotice && <span className="max-w-[320px] truncate text-[11.5px] text-fg-dim" role="status" title={redisNotice}>{redisNotice}</span>}
          <span title="Re-match this asset's discovered services and software against the latest CVE database — no network scan, instant">
            <Button
              onClick={() => {
                setRedisNotice('Rediscovering…')
                rediscover.mutate()
              }}
              disabled={rediscover.isPending}
            >
              {rediscover.isPending ? 'Rediscovering…' : 'Rediscover'}
            </Button>
          </span>
          {a.has_agent && <StatusDot state="online" label="agent connected" />}
          <span className={`text-[20px] font-semibold tabular-nums ${riskTone(a.risk_score)}`} title={a.risk_explanation}>
            {(a.risk_score ?? 0).toFixed(0)}
          </span>
        </div>
      </div>

      <div className="flex gap-1 border-b border-line" role="tablist">
        {['overview', 'network', 'services', 'software', 'findings'].map((t) => (
          <button
            key={t}
            role="tab"
            aria-selected={t === tab}
            onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 pb-2 text-[13px] capitalize ${t === tab ? 'border-accent text-fg' : 'border-transparent text-fg-dim hover:text-fg'}`}
          >
            {t}
          </button>
        ))}
      </div>

      {tab === 'overview' && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
          <Panel>
            <PanelHeader title="Identity" />
            <dl className="space-y-1.5 px-3.5 py-3 text-[12.5px]">
              <Row k="Address" v={a.primary_ip || '—'} />
              <Row k="FQDN" v={a.fqdn || '—'} />
              <Row k="Vendor" v={a.vendor || '—'} />
              <Row k="Model" v={a.model || '—'} />
              <Row k="Device type" v={humanize(a.device_type)} />
              <Row k="OS" v={`${a.os_name || 'unknown'} ${a.os_version ?? ''}`} />
              <Row k="OS confidence" v={`${((a.os_confidence ?? 0) * 100).toFixed(0)}% — sources: ${(a.os_sources ?? []).join(', ') || 'none'}`} />
              <Row k="Criticality" v={
                <Select
                  value={a.criticality}
                  onValueChange={(value) => patch.mutate({ criticality: value })}
                  options={['low', 'medium', 'high', 'critical'].map((c) => ({ value: c, label: c }))}
                  aria-label="Asset criticality"
                />
              } />
              <Row k="Exposure" v={humanize(a.exposure)} />
              <Row k="Risk" v={<span title={a.risk_explanation}>{(a.risk_score ?? 0).toFixed(0)}</span>} />
            </dl>
          </Panel>
          <Panel>
            <PanelHeader title="Security posture" />
            <div className="space-y-2 px-3.5 py-3 text-[12.5px]">
              <div className="grid grid-cols-5 gap-2 text-center">
                {(['critical', 'high', 'medium', 'low'] as const).map((k) => (
                  <div key={k} className="rounded-sm2 border border-line bg-bg-raise py-2">
                    <div className="text-[16px] font-semibold tabular-nums">{counts[k] ?? 0}</div>
                    <div className="text-[10.5px] uppercase text-fg-dim">{k}</div>
                  </div>
                ))}
                <div className="rounded-sm2 border border-line bg-bg-raise py-2">
                  <div className="text-[16px] font-semibold tabular-nums">{counts.open ?? 0}</div>
                  <div className="text-[10.5px] uppercase text-fg-dim">open</div>
                </div>
              </div>
              <p className="pt-1 text-[11.5px] text-fg-faint">
                Counts reflect findings correlated from network fingerprints and agent inventory. Confidence and evidence are shown per finding.
              </p>
              <div className="flex items-center gap-2 pt-1" title="Finding counts by severity, most severe first">
                <MiniBars
                  values={[counts.critical ?? 0, counts.high ?? 0, counts.medium ?? 0, counts.low ?? 0, counts.open ?? 0]}
                  label="Findings by severity (critical, high, medium, low, open)"
                />
                <span className="text-[10.5px] uppercase tracking-wide text-fg-faint">distribution</span>
              </div>
            </div>
          </Panel>
          </div>
          <Panel>
            <PanelHeader
              title={`Detected ports & services (${services.length})`}
              action={services.length > 0 ? <button className="text-[11.5px] text-accent hover:underline" onClick={() => setTab('services')}>View all</button> : undefined}
            />
            {services.length === 0 ? (
              <EmptyState
                title="No services detected yet"
                hint="Run an inventory-profile scan against this asset to enumerate its open ports and detect the software behind them."
              />
            ) : (
              <div className="flex flex-wrap gap-1.5 px-3.5 py-3">
                {services.slice(0, 12).map((s) => (
                  <Pill key={s.id} tone="neutral" title={`${s.protocol.toUpperCase()}/${s.port}${s.product ? ` — ${s.product}` : ''}${s.detected_version ? ` ${s.detected_version}` : ''}`}>
                    <span className="tabular-nums font-medium">{s.port}</span>
                    <span aria-hidden className="opacity-50">/</span>
                    <span className="opacity-80">{s.service_name || s.protocol}</span>
                  </Pill>
                ))}
                {services.length > 12 && (
                  <button type="button" className="pill" data-tone="neutral" onClick={() => setTab('services')} title="Show all observed services">
                    +{services.length - 12} more
                  </button>
                )}
              </div>
            )}
          </Panel>
        </div>
      )}

      {tab === 'network' && (
        <Panel>
          <PanelHeader title={`Interfaces (${interfaces.length})`} />
          {interfaces.length === 0 ? (
            <EmptyState title="No interfaces recorded" hint="Interfaces appear after a scan or agent inventory." />
          ) : (
            <table className="table-base">
              <thead><tr><th>Interface</th><th>MAC</th><th>Addresses</th><th>Status</th></tr></thead>
              <tbody>
                {interfaces.map((i) => (
                  <tr key={i.id}>
                    <td>{i.name || '—'}</td>
                    <td className="font-mono text-[11.5px]">{i.mac || '—'}</td>
                    <td>{(i.addresses ?? []).map((x) => x.ip).join(', ') || '—'}</td>
                    <td>{i.status || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {tab === 'services' && (
        <Panel>
          <PanelHeader title={`Observed services (${services.length})`} />
          {services.length === 0 ? (
            <EmptyState title="No services observed" hint="Run an inventory-profile scan to enumerate ports." />
          ) : (
            <table className="table-base">
              <thead><tr><th className="num">Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th className="num">Confidence</th><th>Last seen</th></tr></thead>
              <tbody>
                {services.map((s) => (
                  <tr key={s.id}>
                    <td className="num font-medium">{s.port}</td>
                    <td className="uppercase text-fg-dim">{s.protocol}</td>
                    <td>{s.service_name || '—'}</td>
                    <td>{s.product || '—'}</td>
                    <td>{s.detected_version || '—'}</td>
                    <td className="num text-fg-dim" title={s.banner}>{((s.confidence ?? 0) * 100).toFixed(0)}%</td>
                    <td className="text-fg-dim" title={exactTime(s.last_seen)}>{relTime(s.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {tab === 'software' && (
        <Panel>
          <PanelHeader title={`Software inventory (${software.length})`} />
          {software.length === 0 ? (
            <EmptyState title="No software inventory" hint="Install an endpoint agent to collect packages." />
          ) : (
            <table className="table-base">
              <thead><tr><th>Package</th><th>Version</th><th>Ecosystem</th><th>PURL</th></tr></thead>
              <tbody>
                {software.map((s) => (
                  <tr key={s.id}>
                    <td>{s.name}</td>
                    <td className="tabular-nums">{s.version || '—'}</td>
                    <td className="text-fg-dim">{s.ecosystem || '—'}</td>
                    <td className="font-mono text-[11px] text-fg-dim">{s.purl || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}

      {tab === 'findings' && (
        <Panel>
          <PanelHeader title="Findings" />
          {findings.isLoading ? <Spinner /> : (findings.data ?? []).length === 0 ? (
            <EmptyState title="No vulnerabilities matched" hint="Either none were detected or feeds are still syncing." />
          ) : (
            <table className="table-base">
              <thead><tr><th>Severity</th><th>CVE</th><th>Title</th><th className="num">Risk</th><th>Status</th></tr></thead>
              <tbody>
                {(findings.data ?? []).map((f) => (
                  <tr key={f.id}>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td className="font-mono text-[11.5px]">{f.cve_id || f.osv_id || '—'}</td>
                    <td className="max-w-[420px] truncate">{f.title}</td>
                    <td className="num" title={`Risk ${f.risk_score.toFixed(0)} — ${riskLabel(f.risk_score)}`}>
                      <Meter value={f.risk_score} max={100} label={`Risk ${f.risk_score.toFixed(0)} (${riskLabel(f.risk_score)})`} />
                      <span className={`font-medium ${riskTone(f.risk_score)}`}>{f.risk_score.toFixed(0)}</span>
                    </td>
                    <td><StatusPill state={f.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
      )}
    </div>
  )
}

function Row({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-4">
      <dt className="shrink-0 text-fg-dim">{k}</dt>
      <dd className="min-w-0 truncate text-right">{v}</dd>
    </div>
  )
}
