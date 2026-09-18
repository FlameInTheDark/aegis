import { useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Scan, ScanTask, Change } from '@/types'
import { Button, Panel, PanelHeader, StatusDot, Spinner, ErrorState, Pill } from '@/components/ui'
import { relTime, exactTime, humanize } from '@/lib/format'

interface ScanBundle {
  scan: Scan
  scope?: { cidrs?: string[]; ip_ranges?: string[]; hostnames?: string[]; denylist?: string[] }
  tasks: ScanTask[]
}

export default function ScanDetailPage() {
  const { id } = useParams()
  const qc = useQueryClient()
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['scan', id],
    queryFn: () => api.get<ScanBundle>(`/scans/${id}`),
    refetchInterval: (q) => {
      const s = (q.state.data as ScanBundle | undefined)?.scan
      return s && (s.state === 'running' || s.state === 'queued') ? 3000 : false
    },
  })
  const changes = useQuery({
    queryKey: ['scan-changes', id],
    queryFn: () => api.get<{ items: Change[] }>(`/scans/${id}/changes`),
  })
  const cancel = useMutation({
    mutationFn: () => api.post(`/scans/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scan', id] }),
  })

  if (isLoading) return <Spinner />
  if (isError) return <ErrorState message={(error as Error).message} onRetry={() => refetch()} />
  const s = data!.scan

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[17px] font-semibold">{s.name}</h1>
          <p className="mt-0.5 text-[12.5px] text-fg-dim">
            <Pill tone="neutral" className="mr-1">{s.profile}</Pill>
            engine {s.engine} · created {relTime(s.created_at)}
            {s.error && <span className="ml-2 text-crit">— {s.error}</span>}
          </p>
        </div>
        {(s.state === 'running' || s.state === 'queued') && (
          <Button variant="danger" onClick={() => cancel.mutate()} disabled={cancel.isPending}>Cancel scan</Button>
        )}
      </div>

      <div className="grid grid-cols-6 gap-3">
        {[
          ['Targets', s.stats.targets],
          ['Reachable', s.stats.reachable],
          ['Unreachable', s.stats.unreachable],
          ['Ports discovered', s.stats.ports_discovered],
          ['Services fingerprinted', s.stats.services_fingerprinted],
          ['Findings created', s.stats.findings_created],
        ].map(([label, v]) => (
          <Panel key={label as string} className="px-3.5 py-2.5">
            <div className="text-[17px] font-semibold tabular-nums">{v as number}</div>
            <div className="text-[10.5px] uppercase tracking-wide text-fg-dim">{label}</div>
          </Panel>
        ))}
      </div>

      <Panel>
        <PanelHeader title={`Progress — ${s.state} · phase ${s.phase || '—'} · ${s.progress.toFixed(0)}%`} />
        <div className="px-3.5 py-3">
          <div className="h-1.5 w-full overflow-hidden rounded-full bg-bg-raise" role="progressbar" aria-valuenow={s.progress} aria-valuemin={0} aria-valuemax={100}>
            <div className="h-full rounded-full bg-accent transition-all" style={{ width: `${s.progress}%` }} />
          </div>
          <p className="mt-2 text-[11.5px] text-fg-faint">
            Failures are shown, never hidden: {s.stats.tasks_failed} failed task(s) of {s.stats.tasks_total}.
            {s.kill_switch && <span className="ml-1 text-crit">Kill switch engaged — scanners will stop between probes.</span>}
          </p>
        </div>
      </Panel>

      <div className="grid grid-cols-2 gap-4">
        <Panel>
          <PanelHeader title="Scope" />
          <div className="space-y-1.5 px-3.5 py-3 font-mono text-[11.5px] text-fg-dim">
            {(data!.scope?.cidrs ?? []).map((c) => <div key={c}>{c}</div>)}
            {(data!.scope?.denylist ?? []).length > 0 && (
              <div className="pt-1 text-crit/80">denied: {(data!.scope?.denylist ?? []).join(', ')}</div>
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="Tasks" />
          <div className="overflow-x-auto">
          <table className="table-base">
            <thead><tr><th>Task</th><th>Type</th><th>State</th><th>Attempt</th></tr></thead>
            <tbody>
              {(data!.tasks ?? []).map((t) => (
                <tr key={t.id}>
                  <td className="font-mono text-[11px]">{t.id.slice(0, 14)}</td>
                  <td className="text-fg-dim">{humanize(t.type)}</td>
                  <td><StatusDot state={t.state} /></td>
                  <td className="tabular-nums text-fg-dim">{t.attempt}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHeader title="Changes detected by this scan" />
        {(changes.data?.items ?? []).length === 0 ? (
          <p className="px-3.5 py-5 text-center text-[12.5px] text-fg-dim">No deltas recorded — deltas appear when a scan observes differences from the previous state.</p>
        ) : (
          <div className="overflow-x-auto">
          <table className="table-base">
            <thead><tr><th>Change</th><th>Entity</th><th>Before</th><th>After</th><th>When</th></tr></thead>
            <tbody>
              {(changes.data?.items ?? []).map((c) => (
                <tr key={c.id}>
                  <td><Pill tone="neutral">{c.type}</Pill></td>
                  <td className="text-fg-dim">{c.entity || c.asset_id || '—'}</td>
                  <td className="max-w-[200px] truncate text-fg-dim">{c.before || '—'}</td>
                  <td className="max-w-[200px] truncate">{c.after || '—'}</td>
                  <td className="text-fg-dim" title={exactTime(c.created_at)}>{relTime(c.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          </div>
        )}
      </Panel>
    </div>
  )
}
