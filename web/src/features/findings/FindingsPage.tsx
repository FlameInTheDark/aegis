import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { Finding, Evidence, Page } from '@/types'
import { Button, ConfirmDialog, Dialog, Input, Pagination, Panel, PanelHeader, SeverityBadge, ChipSelect, ChipToggle, StatusPill, Meter, Spinner, ErrorState, EmptyState, Badge } from '@/components/ui'
import { relTime, exactTime, riskLabel } from '@/lib/format'
import { riskTone } from '@/features/assets/AssetsPage'

export default function FindingsPage() {
  const [params, setParams] = useSearchParams()
  const page = Number(params.get('page') ?? 1)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [bulkStatus, setBulkStatus] = useState('')
  const [confirmOpen, setConfirmOpen] = useState(false)
  const [reason, setReason] = useState('')
  const qc = useQueryClient()

  const findings = useQuery({
    queryKey: ['findings', params.toString()],
    queryFn: () => api.get<Page<Finding>>(`/findings?${params.toString()}`),
  })
  const setParam = (k: string, v: string) => {
    const next = new URLSearchParams(params)
    if (v) next.set(k, v)
    else next.delete(k)
    if (k !== 'page') next.delete('page')
    setParams(next)
  }
  const bulk = useMutation({
    mutationFn: () => api.post<{ updated: number }>('/findings/bulk', { ids: [...selected], status: bulkStatus, reason, confirm: true }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['findings'] })
      setSelected(new Set())
      setConfirmOpen(false)
      setReason('')
    },
  })

  const dangerous = ['false_positive', 'accepted_risk', 'suppressed'].includes(bulkStatus)
  const toggle = (id: string) => {
    const next = new Set(selected)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelected(next)
  }

  return (
    <div className="space-y-3">
      <div className="tbl-toolbar">
        <ChipSelect
          label="Status"
          value={params.get('status') ?? ''}
          onChange={(v) => setParam('status', v)}
          ariaLabel="Status filter"
          options={[{ value: '', label: 'All statuses' }, ...['open', 'acknowledged', 'in_progress', 'resolved', 'accepted_risk', 'false_positive', 'suppressed'].map((s) => ({ value: s, label: s }))]}
        />
        <ChipSelect
          label="Severity"
          value={params.get('severity') ?? ''}
          onChange={(v) => setParam('severity', v)}
          ariaLabel="Severity filter"
          options={[{ value: '', label: 'All severities' }, ...['critical', 'high', 'medium', 'low'].map((s) => ({ value: s, label: s }))]}
        />
        <ChipToggle
          label="KEV only"
          tone="critical"
          active={params.get('kev') === 'true'}
          onClick={() => setParam('kev', params.get('kev') === 'true' ? '' : 'true')}
          title="Only CVEs present in the CISA Known Exploited catalog"
        />
        {selected.size > 0 && (
          <div className="ml-auto flex items-center gap-2">
            <span className="text-[12.5px] text-fg-dim">{selected.size} selected</span>
            <ChipSelect
              label="Set state"
              value={bulkStatus}
              onChange={setBulkStatus}
              ariaLabel="Bulk action"
              options={[{ value: '', label: 'Bulk action…' }, ...['acknowledged', 'in_progress', 'resolved', 'false_positive', 'accepted_risk', 'suppressed'].map((s) => ({ value: s, label: s }))]}
            />
            <Button disabled={!bulkStatus} onClick={() => setConfirmOpen(true)}>Apply</Button>
          </div>
        )}
      </div>

      <Panel>
        {findings.isLoading ? <Spinner /> : findings.isError ? <ErrorState message={(findings.error as Error).message} onRetry={() => findings.refetch()} /> : (findings.data?.items ?? []).length === 0 ? (
          <EmptyState title="No vulnerability findings" hint="No vulnerabilities matched in the selected scope." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th scope="col" className="w-8"><input type="checkbox" className="tbl-check" aria-label="Select all on page"
                    checked={selected.size > 0 && selected.size === (findings.data?.items?.length ?? 0)}
                    onChange={(e) => setSelected(e.target.checked ? new Set((findings.data?.items ?? []).map((f) => f.id)) : new Set())} /></th>
                  <th scope="col" className="num">Risk</th><th scope="col">Severity</th><th scope="col">Vulnerability</th>
                  <th scope="col">Asset</th><th scope="col">Match type</th><th scope="col">First seen</th><th scope="col">Status</th>
                </tr>
              </thead>
              <tbody>
                {(findings.data?.items ?? []).map((f) => (
                  <tr key={f.id} data-selected={selected.has(f.id) || undefined}>
                    <td><input type="checkbox" className="tbl-check" aria-label={`Select finding ${f.id}`} checked={selected.has(f.id)} onChange={() => toggle(f.id)} /></td>
                    <td className="num" title={`Risk ${f.risk_score.toFixed(0)} — ${riskLabel(f.risk_score)}`}>
                      <Meter value={f.risk_score} max={100} label={`Risk ${f.risk_score.toFixed(0)} (${riskLabel(f.risk_score)})`} />
                      <span className={`font-medium ${riskTone(f.risk_score)}`}>{f.risk_score.toFixed(0)}</span>
                    </td>
                    <td><SeverityBadge severity={f.severity} /></td>
                    <td className="max-w-[380px]">
                      <Link to={`/vulnerabilities/${f.cve_id}`} className="block truncate hover:text-accent" title={f.title}>
                        {f.cve_id && <span className="mr-1.5 font-mono text-[11.5px] text-fg-dim">{f.cve_id}</span>}
                        {f.title}
                      </Link>
                    </td>
                    <td><Link to={`/assets/${f.asset_id}`} className="font-mono text-[11.5px] text-fg-dim hover:text-accent">{f.asset_id.slice(0, 10)}</Link></td>
                    <td className="text-fg-dim">{f.match_type}</td>
                    <td className="text-fg-dim" title={exactTime(f.first_seen)}>{relTime(f.first_seen)}</td>
                    <td><StatusPill state={f.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {findings.data && <Pagination page={page} limit={findings.data.limit ?? 50} total={findings.data.total} onPage={(p) => setParam('page', String(p))} />}
      </Panel>

      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)} title={dangerous ? 'Confirm dangerous bulk operation' : `Set ${selected.size} findings to ${bulkStatus}`}>
        <p className="text-[12.5px] text-fg-dim">
          {dangerous
            ? `You are about to mark ${selected.size} finding(s) as ${bulkStatus}. This affects future correlation and alerting.`
            : `Status will change for ${selected.size} finding(s) with full audit trail.`}
        </p>
        <label className="mt-3 block text-[12px] text-fg-dim">Reason (required, recorded in the audit log)</label>
        <Input value={reason} onChange={(e) => setReason(e.target.value)} className="mt-1 w-full" placeholder="e.g. verified false positive — legacy host" />
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="ghost" onClick={() => setConfirmOpen(false)}>Cancel</Button>
          <Button variant={dangerous ? 'danger' : 'primary'} disabled={!reason || bulk.isPending}
            onClick={() => bulk.mutate()}>
            {dangerous ? 'I confirm, apply' : 'Apply'}
          </Button>
        </div>
      </Dialog>
    </div>
  )
}

export function FindingDetailPanel({ findingId, onClose }: { findingId: string; onClose: () => void }) {
  const { data, isLoading } = useQuery({
    queryKey: ['finding', findingId],
    queryFn: () => api.get<{ finding: Finding; evidence: Evidence[]; history: { from: string; to: string; changed_by: string; reason?: string; created_at: string }[] }>(`/findings/${findingId}`),
  })
  if (isLoading) return <Spinner />
  if (!data) return null
  const f = data.finding
  return (
    <Panel className="fixed inset-y-0 right-0 z-40 w-[480px] overflow-y-auto rounded-none border-y-0 border-r-0">
      <PanelHeader title="Finding" action={<Button variant="ghost" onClick={onClose}>Close</Button>} />
      <div className="space-y-3 p-3.5">
        <SeverityBadge severity={f.severity} />
        <p className="text-[13px]">{f.title}</p>
        <dl className="space-y-1 text-[12px] text-fg-dim">
          <div className="flex justify-between"><dt>CVE</dt><dd className="font-mono">{f.cve_id || f.osv_id || '—'}</dd></div>
          <div className="flex justify-between"><dt>Risk</dt><dd>{f.risk_score.toFixed(0)} — {riskLabel(f.risk_score)}</dd></div>
          <div className="flex justify-between"><dt>Match</dt><dd>{f.match_type} ({(f.confidence * 100).toFixed(0)}%)</dd></div>
          <div className="flex justify-between"><dt>Status</dt><dd>{f.status}</dd></div>
          {f.remediation && <div><dt className="mb-1">Remediation</dt><dd className="text-fg">{f.remediation}</dd></div>}
        </dl>
        <div>
          <h4 className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-fg-dim">Evidence</h4>
          <ul className="space-y-1.5">
            {data.evidence.map((e) => (
              <li key={e.id} className="rounded-sm2 border border-line bg-bg-raise px-2.5 py-2 text-[12px]">
                <Badge className="mr-2 border-line text-fg-faint">{e.kind}</Badge>
                {e.statement}
              </li>
            ))}
            {data.evidence.length === 0 && <li className="text-[12px] text-fg-dim">No structured evidence rows.</li>}
          </ul>
        </div>
        <div>
          <h4 className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-fg-dim">Status history</h4>
          <ul className="space-y-1 text-[12px] text-fg-dim">
            {data.history.map((h, i) => (
              <li key={i}>{h.from} → {h.to} by {h.changed_by} · {relTime(h.created_at)}{h.reason && ` — ${h.reason}`}</li>
            ))}
            {data.history.length === 0 && <li>No status changes recorded.</li>}
          </ul>
        </div>
      </div>
    </Panel>
  )
}
