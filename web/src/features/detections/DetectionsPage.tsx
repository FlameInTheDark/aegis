import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { DetectionMatch, DetectionRule, Page } from '@/types'
import { Badge, Button, Panel, PanelHeader, SeverityBadge, Spinner, ErrorState, EmptyState, StatusDot } from '@/components/ui'
import { relTime, exactTime } from '@/lib/format'

export default function DetectionsPage() {
  const [tab, setTab] = useState<'matches' | 'rules'>('matches')
  const qc = useQueryClient()
  const matches = useQuery({
    queryKey: ['detection-matches'],
    queryFn: () => api.get<Page<DetectionMatch>>('/detections/matches?limit=50'),
    refetchInterval: 15_000,
  })
  const rules = useQuery({
    queryKey: ['detection-rules'],
    queryFn: () => api.get<{ items: DetectionRule[] }>('/detections/rules'),
  })
  const toggle = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => api.patch(`/detections/rules/${id}`, { enabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['detection-rules'] }),
  })

  return (
    <div className="space-y-3">
      <div className="flex gap-1 border-b border-line">
        {(['matches', 'rules'] as const).map((t) => (
          <button key={t} onClick={() => setTab(t)}
            className={`-mb-px border-b-2 px-3 pb-2 text-[13px] capitalize ${t === tab ? 'border-accent text-fg' : 'border-transparent text-fg-dim hover:text-fg'}`}>
            {t}
          </button>
        ))}
      </div>

      {tab === 'matches' && (
        <Panel>
          {matches.isLoading ? <Spinner /> : matches.isError ? <ErrorState message={(matches.error as Error).message} onRetry={() => matches.refetch()} /> : (matches.data?.items ?? []).length === 0 ? (
            <EmptyState title="No detection matches" hint="Matches appear once sensors or agents stream events." />
          ) : (
            <div className="overflow-x-auto">
              <table className="table-base">
                <thead>
                  <tr>
                    <th scope="col">Level</th><th scope="col">Rule</th><th scope="col">Summary</th>
                    <th scope="col">Entity</th><th scope="col">Events</th><th scope="col">When</th>
                  </tr>
                </thead>
                <tbody>
                  {(matches.data?.items ?? []).map((m) => (
                    <tr key={m.id}>
                      <td><SeverityBadge severity={m.level} /></td>
                      <td className="font-medium">{m.rule_title}</td>
                      <td className="max-w-[420px] truncate text-fg-dim" title={m.summary}>{m.summary}</td>
                      <td className="font-mono text-[11.5px] text-fg-dim">{m.entity || m.src_ip || '—'}</td>
                      <td className="tabular-nums text-fg-dim">×{m.count}</td>
                      <td className="text-fg-dim" title={exactTime(m.timestamp)}>{relTime(m.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      )}

      {tab === 'rules' && (
        <Panel>
          <PanelHeader title="Detection rules" />
          {rules.isLoading ? <Spinner /> : rules.isError ? <ErrorState message={(rules.error as Error).message} /> : (
            <table className="table-base">
              <thead><tr><th>Rule</th><th>Type</th><th>Window</th><th>Level</th><th>Status</th><th>Enabled</th></tr></thead>
              <tbody>
                {(rules.data?.items ?? []).map((r) => (
                  <tr key={r.id}>
                    <td>
                      <div className="font-medium">{r.title}</div>
                      <div className="text-[11.5px] text-fg-faint">{r.description}</div>
                    </td>
                    <td><Badge className="border-line text-fg-dim">{r.type}</Badge></td>
                    <td className="text-fg-dim">{r.window || '—'}</td>
                    <td><SeverityBadge severity={r.level} /></td>
                    <td><Badge className="border-line text-fg-dim">{r.status}</Badge></td>
                    <td>
                      <button
                        role="switch"
                        aria-checked={r.enabled}
                        aria-label={`Toggle rule ${r.title}`}
                        onClick={() => toggle.mutate({ id: r.id, enabled: !r.enabled })}
                        className={`h-4 w-8 rounded-full transition-colors ${r.enabled ? 'bg-accent' : 'bg-bg-raise border border-line'}`}
                      >
                        <span className={`block h-3 w-3 rounded-full bg-white transition-transform ${r.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <p className="px-3.5 py-2.5 text-[11.5px] text-fg-faint">
            Rules are typed (threshold / temporal / entity aggregation) with deduplication windows — one incident per rule and entity, not alert storms.
            Statistical baselines flag anomalies; an anomaly is never presented as confirmed malicious activity.
          </p>
        </Panel>
      )}
      <div className="hidden"><StatusDot state="ok" /></div>
    </div>
  )
}
