import { useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Agent, Page } from '@/types'
import { Button, Dialog, Panel, PanelHeader, Spinner, ErrorState, EmptyState, StatusDot, StatusPill, Input, Select } from '@/components/ui'
import { relTime, exactTime, humanize } from '@/lib/format'
import { useSites } from '@/features/assets/AssetsPage'

export default function AgentsPage() {
  const [dialogOpen, setDialogOpen] = useState(false)
  const agents = useQuery({
    queryKey: ['agents'],
    queryFn: () => api.get<Page<Agent>>('/agents'),
    refetchInterval: 20_000,
  })

  return (
    <div className="space-y-3">
      <div className="tbl-toolbar">
        <p className="text-[12.5px] text-fg-dim">Endpoint agents report authoritative inventory. The agent never sends private keys and supports only typed tasks — there is no remote shell.</p>
        <div className="ml-auto">
          <Button variant="primary" onClick={() => setDialogOpen(true)}>Create enrollment token</Button>
        </div>
      </div>
      <Panel>
        {agents.isLoading ? <Spinner /> : agents.isError ? <ErrorState message={(agents.error as Error).message} onRetry={() => agents.refetch()} /> : (agents.data?.items ?? []).length === 0 ? (
          <EmptyState title="No agents enrolled" hint="Create an enrollment token and install the agent binary on endpoints." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th scope="col">Hostname</th><th scope="col">Platform</th><th scope="col">Version</th>
                  <th scope="col">Status</th><th scope="col">Asset</th><th scope="col">Last seen</th>
                </tr>
              </thead>
              <tbody>
                {(agents.data?.items ?? []).map((a) => (
                  <tr key={a.id}>
                    <td><Link to={`/agents/${a.id}`} className="font-medium hover:text-accent">{a.hostname}</Link></td>
                    <td className="text-fg-dim">{a.platform}</td>
                    <td className="text-fg-dim">{a.agent_version || '—'}</td>
                    <td><StatusPill state={a.status} /></td>
                    <td>{a.asset_id ? <Link to={`/assets/${a.asset_id}`} className="font-mono text-[11.5px] text-fg-dim hover:text-accent">{a.asset_id.slice(0, 10)}</Link> : <span className="text-fg-faint">unlinked</span>}</td>
                    <td className="text-fg-dim" title={exactTime(a.last_seen)}>{relTime(a.last_seen)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
      <EnrollDialog open={dialogOpen} onClose={() => setDialogOpen(false)} />
    </div>
  )
}

function EnrollDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const sites = useSites()
  const [siteId, setSiteId] = useState('')
  const [result, setResult] = useState<{ token: string; prefix: string; expires_at: string } | null>(null)
  const create = useMutation({
    mutationFn: () => api.post<{ token: string; prefix: string; expires_at: string }>('/agents/enrollment-tokens', { site_id: siteId }),
    onSuccess: setResult,
  })
  return (
    <Dialog open={open} onClose={onClose} title="Agent enrollment token" wide>
      {!result ? (
        <div className="space-y-3">
          <label className="block text-[12px] text-fg-dim">Site to bind enrolled endpoints to</label>
          <Select
            value={siteId}
            onValueChange={setSiteId}
            options={[{ value: '', label: 'Choose a site…' }, ...(sites.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }))]}
            className="w-full text-[13px]"
            aria-label="Agent enrollment site"
          />
          <div className="flex justify-end gap-2">
            <Button variant="ghost" onClick={onClose}>Cancel</Button>
            <Button variant="primary" disabled={!siteId || create.isPending} onClick={() => create.mutate()}>Generate token</Button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-[12.5px] text-fg-dim">
            Copy this token now — it is shown <strong className="text-fg">only once</strong> and stored only as a hash.
            One-time use, expires {new Date(result.expires_at).toLocaleString()}.
          </p>
          <div className="rounded-sm2 border border-line bg-bg-raise p-2.5 font-mono text-[12px] break-all">{result.token}</div>
          <p className="text-[12px] text-fg-dim">Install the agent with:</p>
          <pre className="overflow-x-auto rounded-sm2 border border-line bg-bg-raise p-2.5 text-[11.5px] text-fg-dim">{`aegis-agent --config agent.yaml\n# AEGIS_ENROLL_TOKEN=${result.token}`}</pre>
          <div className="flex justify-end"><Button onClick={onClose}>Done</Button></div>
        </div>
      )}
    </Dialog>
  )
}

export function AgentDetailPage() {
  const { id } = useParams()
  const qc = useQueryClient()
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['agent', id],
    queryFn: () => api.get<{ agent: Agent; tasks: { id: string; type: string; state: string; issued_at: string; error?: string }[]; events: Record<string, unknown>[] }>(`/agents/${id}`),
  })
  const issue = useMutation({
    mutationFn: (type: string) => api.post(`/agents/${id}/tasks`, { type }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['agent', id] }),
  })

  if (isLoading) return <Spinner />
  if (isError) return <ErrorState message={(error as Error).message} onRetry={() => refetch()} />
  const a = data!.agent

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-[17px] font-semibold">{a.hostname}</h1>
          <p className="mt-0.5 text-[12.5px] text-fg-dim">
            {a.platform} · agent {a.agent_version || '?'} · last seen {relTime(a.last_seen)}
          </p>
        </div>
        <StatusDot state={a.status} />
      </div>

      <div className="flex flex-wrap gap-2">
        {['inventory_refresh', 'software_inventory', 'socket_inventory', 'security_posture'].map((t) => (
          <Button key={t} disabled={issue.isPending} onClick={() => issue.mutate(t)}>Run {humanize(t)}</Button>
        ))}
      </div>

      <Panel>
        <PanelHeader title="Recent tasks" />
        {(data!.tasks ?? []).length === 0 ? (
          <EmptyState title="No tasks issued" hint="Typed tasks appear here; there is deliberately no arbitrary command execution." />
        ) : (
          <table className="table-base">
            <thead><tr><th>Task</th><th>Type</th><th>State</th><th>Issued</th></tr></thead>
            <tbody>
              {(data!.tasks ?? []).map((t) => (
                <tr key={t.id}>
                  <td className="font-mono text-[11px]">{t.id.slice(0, 12)}</td>
                  <td>{humanize(t.type)}</td>
                  <td><StatusPill state={t.state} /></td>
                  <td className="text-fg-dim" title={t.issued_at}>{relTime(t.issued_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>

      <Panel>
        <PanelHeader title="Recent telemetry" />
        {(data!.events ?? []).length === 0 ? (
          <p className="px-3.5 py-5 text-center text-[12.5px] text-fg-dim">No telemetry events yet.</p>
        ) : (
          <table className="table-base">
            <thead><tr><th>Type</th><th>Payload</th><th>When</th></tr></thead>
            <tbody>
              {(data!.events ?? []).map((e, i) => (
                <tr key={i}>
                  <td>{humanize(String(e['type'] ?? ''))}</td>
                  <td className="max-w-[520px] truncate font-mono text-[11px] text-fg-dim">{JSON.stringify(e['payload'] ?? {})}</td>
                  <td className="text-fg-dim">{relTime(String(e['occurred_at'] ?? ''))}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
      <div className="hidden"><Input /></div>
    </div>
  )
}
