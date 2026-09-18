import { useState } from 'react'
import { useQuery, useQueries, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import { api } from '@/lib/api'
import type { ReportJob, Asset } from '@/types'
import { Badge, Button, Dialog, Panel, StatusDot, Spinner, ErrorState, EmptyState, Select, Meter, Input } from '@/components/ui'
import { relTime } from '@/lib/format'
import { assetLabel, assetOptionLabel, REPORT_TYPE_LABELS } from '@/lib/labels'
import { useSites } from '@/features/assets/AssetsPage'

type Definition = { id: string; type: string; format: string; site_id?: string; asset_id?: string }

export default function ReportsPage() {
  const [params, setParams] = useSearchParams()
  const [dialogOpen, setDialogOpen] = useState(() => Boolean(REPORT_TYPE_LABELS[params.get('type') ?? '']))
  const [dlError, setDlError] = useState('')
  const [dlId, setDlId] = useState('')
  const qc = useQueryClient()
  const sites = useSites()
  const definitions = useQuery({ queryKey: ['reports'], queryFn: () => api.get<{ items: Definition[] }>('/reports') })
  const assetIds = [...new Set((definitions.data?.items ?? []).flatMap((d) => d.asset_id ? [d.asset_id] : []))]
  const devices = useQueries({ queries: assetIds.map((id) => ({
    queryKey: ['report-asset-label', id], queryFn: () => api.get<{ asset: Asset }>(`/assets/${id}`), staleTime: 60_000,
  })) })
  const names = new Map(assetIds.map((id, i) => [id, devices[i].data ? assetLabel(devices[i].data!.asset) : 'Device']))
  const label = (job: ReportJob) => {
    const def = definitions.data?.items?.find((d) => d.id === job.definition_id)
    const scope = def?.asset_id ? names.get(def.asset_id) : def?.site_id ? sites.data?.items?.find((s) => s.id === def.site_id)?.name ?? 'Site' : 'Whole organization'
    return `${REPORT_TYPE_LABELS[def?.type ?? ''] ?? 'Report'} · ${scope}`
  }
  const jobs = useQuery({
    queryKey: ['report-jobs'],
    queryFn: () => api.get<{ items: ReportJob[] }>('/reports/jobs'),
    refetchInterval: (q) => (q.state.data?.items ?? []).some((j) => j.state === 'queued' || j.state === 'running') ? 3000 : false,
  })
  const download = useMutation({
    mutationFn: (job: ReportJob) => api.download(`/reports/jobs/${job.id}/download`, `aegis-report.${definitions.data?.items?.find((d) => d.id === job.definition_id)?.format ?? 'html'}`),
    onMutate: (job) => { setDlError(''); setDlId(job.id) },
    onError: (e) => setDlError((e as Error).message),
    onSettled: () => setDlId(''),
  })
  const close = () => {
    setDialogOpen(false)
    setParams((p) => { p.delete('type'); p.delete('asset_id'); p.delete('site_id'); return p }, { replace: true })
    void qc.invalidateQueries({ queryKey: ['report-jobs'] })
    void qc.invalidateQueries({ queryKey: ['reports'] })
  }
  return (
    <div className="space-y-3">
      <div className="tbl-toolbar">
        <p className="text-[12.5px] text-fg-dim">Reports generate asynchronously. Downloads are authenticated and scoped to your organization.</p>
        <div className="ml-auto"><Button variant="primary" onClick={() => setDialogOpen(true)}>New report</Button></div>
      </div>
      <Panel>
        {jobs.isLoading ? <Spinner /> : jobs.isError ? <ErrorState message={(jobs.error as Error).message} onRetry={() => jobs.refetch()} /> : (jobs.data?.items ?? []).length === 0 ? (
          <EmptyState title="No reports generated" hint="Create a report for your organization, a site, or a device." />
        ) : (
          <table className="table-base">
            <thead><tr><th>Report</th><th>State</th><th className="num">Progress</th><th>Created</th><th>Download</th></tr></thead>
            <tbody>{(jobs.data?.items ?? []).map((j) => (
              <tr key={j.id} className={params.get('job') === j.id ? 'bg-accent/10' : ''}>
                <td>{label(j)}</td><td><StatusDot state={j.state} /></td>
                <td className="num">
                  <Meter value={j.progress ?? 0} max={100} tone={j.state === 'completed' ? 'ok' : 'accent'} label={`Report progress ${(j.progress ?? 0).toFixed(0)}%`} />
                  <span className="text-fg-dim">{j.progress?.toFixed(0) ?? 0}%</span>
                  {j.error && <span className="ml-2 text-crit">{j.error}</span>}
                </td>
                <td className="text-fg-dim">{relTime(j.created_at)}</td>
                <td>{j.state === 'completed' ? (
                  <button type="button" className="text-accent hover:underline disabled:opacity-50" disabled={download.isPending} onClick={() => download.mutate(j)} aria-label={`Download ${label(j)}`}>
                    {dlId === j.id ? 'Preparing…' : 'Download'}
                  </button>
                ) : <span className="text-fg-faint">—</span>}</td>
              </tr>
            ))}</tbody>
          </table>
        )}
      </Panel>
      {dlError && <p className="text-[12.5px] text-crit" role="alert">{dlError}</p>}
      {dialogOpen && <NewReportDialog onClose={close} initialType={params.get('type') ?? ''} initialAsset={params.get('asset_id') ?? ''} initialSite={params.get('site_id') ?? ''} />}
    </div>
  )
}

function NewReportDialog({ onClose, initialType, initialAsset, initialSite }: { onClose: () => void; initialType: string; initialAsset: string; initialSite: string }) {
  const sites = useSites()
  const [type, setType] = useState(REPORT_TYPE_LABELS[initialType] ? initialType : 'executive_security')
  const [format, setFormat] = useState('html')
  const [siteId, setSiteId] = useState(initialSite)
  const [assetId, setAssetId] = useState(initialAsset)
  const [search, setSearch] = useState('')
  const deviceDetail = type === 'device_detail'
  const assets = useQuery({
    queryKey: ['report-assets', siteId, search],
    queryFn: () => api.get<{ items: Asset[]; total: number }>(`/assets?${new URLSearchParams({ limit: '200', site_id: siteId, search })}`),
    enabled: deviceDetail,
  })
  // Resolve a deep-linked device even when it isn't on the first list page.
  const selected = useQuery({ queryKey: ['report-asset-label', assetId], queryFn: () => api.get<{ asset: Asset }>(`/assets/${assetId}`), enabled: deviceDetail && Boolean(assetId) })
  const choices = new Map((assets.data?.items ?? []).map((a) => [a.id, a]))
  if (selected.data?.asset && (!siteId || selected.data.asset.site_id === siteId)) choices.set(assetId, selected.data.asset)
  const validSite = Boolean(sites.data?.items?.some((s) => s.id === siteId))
  const validDevice = Boolean(assetId && choices.has(assetId))
  const canCreate = type === 'site_detail' ? validSite : deviceDetail ? validDevice : !siteId || validSite
  const create = useMutation({
    mutationFn: () => {
      if (!canCreate) throw new Error(deviceDetail ? 'Select a device.' : 'Select a site.')
      return api.post<{ job: ReportJob }>('/reports', { type, format, site_id: deviceDetail ? choices.get(assetId)?.site_id : siteId, asset_id: deviceDetail ? assetId : undefined })
    },
    onSuccess: onClose,
  })
  return (
    <Dialog open onClose={onClose} title="Generate report">
      <div className="space-y-3">
        <label className="block text-[12px] text-fg-dim">Type</label>
        <Select value={type} onValueChange={setType} options={Object.entries(REPORT_TYPE_LABELS).map(([value, label]) => ({ value, label }))} className="w-full" aria-label="Report type" />
        <label className="block text-[12px] text-fg-dim">Format</label>
        <Select value={format} onValueChange={setFormat} options={['html', 'pdf', 'csv', 'json'].map((f) => ({ value: f, label: f.toUpperCase() }))} className="w-full" aria-label="Report format" />
        <label className="block text-[12px] text-fg-dim">Site{type === 'site_detail' ? ' (required)' : ''}</label>
        <Select value={siteId} onValueChange={(id) => { setSiteId(id); setAssetId('') }} options={[{ value: '', label: type === 'site_detail' ? 'Select a site' : 'Whole organization' }, ...(sites.data?.items ?? []).map((s) => ({ value: s.id, label: s.name || 'Unnamed site' }))]} className="w-full" aria-label="Report site" />
        {sites.isError && <ErrorState message="Unable to load sites." onRetry={() => sites.refetch()} />}
        {deviceDetail && <>
          <label className="block text-[12px] text-fg-dim">Device (required)</label>
          <Input aria-label="Search report devices" placeholder="Search by name or IP" value={search} onChange={(e) => setSearch(e.target.value)} className="w-full" />
          <Select value={validDevice ? assetId : ''} onValueChange={setAssetId} options={[{ value: '', label: assets.isLoading ? 'Loading devices…' : 'Select a device' }, ...[...choices.values()].map((a) => ({ value: a.id, label: assetOptionLabel(a) }))]} className="w-full" aria-label="Report device" />
          {assets.isError && <ErrorState message="Unable to load devices." onRetry={() => assets.refetch()} />}
          {selected.isError && <p role="alert" className="text-crit">The selected device could not be loaded. Choose a device from the list.</p>}
          {(assets.data?.total ?? 0) > 200 && <p className="text-fg-dim">Showing the first 200 devices. Search by name or IP to narrow the list.</p>}
        </>}
        {create.isError && <p className="text-[12.5px] text-crit" role="alert">{(create.error as Error).message}</p>}
        <div className="flex justify-end gap-2"><Button variant="ghost" onClick={onClose}>Cancel</Button><Button variant="primary" disabled={create.isPending || !canCreate} onClick={() => create.mutate()}>Generate</Button></div>
      </div>
    </Dialog>
  )
}

export function ReportBadge({ state }: { state: string }) {
  return <Badge className="border-line text-fg-dim">{state}</Badge>
}
