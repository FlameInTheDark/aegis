import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { CursorPage, SecEvent } from '@/types'
import { Panel, SeverityBadge, Spinner, ErrorState, EmptyState, Button, ChipSelect, Pill } from '@/components/ui'
import { relTime, exactTime } from '@/lib/format'

export default function EventsPage() {
  const [params, setParams] = useState<Record<string, string>>({})
  const [rows, setRows] = useState<SecEvent[]>([])
  const [cursor, setCursor] = useState<string | undefined>()
  const [done, setDone] = useState(false)

  const buildPath = (cur?: string) => {
    const q = new URLSearchParams(params)
    if (cur) q.set('cursor', cur)
    q.set('limit', '100')
    return `/events?${q.toString()}`
  }

  const events = useQuery({
    queryKey: ['events', params, cursor ?? ''],
    queryFn: () => api.get<CursorPage<SecEvent>>(buildPath(cursor)),
    placeholderData: (prev) => prev,
  })

  // Cursor pages accumulate in the view (Load more), per spec §119.
  const items = events.data?.items ?? []
  const visible = cursor ? rows.concat(items) : items

  const loadMore = () => {
    setRows(visible)
    setCursor(events.data?.next_cursor)
  }
  // Reset accumulation when the query has no more pages.
  if (!events.data?.next_cursor && cursor && !done) setDone(true)

  const setParam = (k: string, v: string) => {
    const next = { ...params }
    if (v) next[k] = v
    else delete next[k]
    setParams(next)
    setRows([])
    setCursor(undefined)
    setDone(false)
  }

  return (
    <div className="space-y-3">
      <div className="tbl-toolbar">
        <ChipSelect
          label="Range"
          value={params.from ?? ''}
          onChange={(v) => setParam('from', v)}
          ariaLabel="Time range"
          options={[
            { value: '', label: 'Last 24h' },
            ...[['1h', 'Last hour'], ['24h', 'Last 24h'], ['7d', 'Last 7 days'], ['30d', 'Last 30 days']].map(([v, l]) => (
              { value: new Date(Date.now() - (v === '1h' ? 3600e3 : v === '24h' ? 86400e3 : v === '7d' ? 604800e3 : 2592000e3)).toISOString(), label: l }
            )),
          ]}
        />
        <ChipSelect
          label="Event"
          value={params.event_type ?? ''}
          onChange={(v) => setParam('event_type', v)}
          ariaLabel="Event type"
          options={[{ value: '', label: 'All event types' }, ...['alert', 'flow', 'dns', 'http', 'tls', 'ssh', 'fileinfo', 'anomaly', 'notice'].map((t) => ({ value: t, label: t }))]}
        />
        <ChipSelect
          label="Severity"
          value={params.severity ?? ''}
          onChange={(v) => setParam('severity', v)}
          ariaLabel="Severity"
          options={[{ value: '', label: 'All severities' }, ...['critical', 'high', 'medium', 'low', 'info'].map((s) => ({ value: s, label: s }))]}
        />
        <ChipSelect
          label="Sensor"
          value={params.source ?? ''}
          onChange={(v) => setParam('source', v)}
          ariaLabel="Source sensor"
          options={[{ value: '', label: 'All sensors' }, ...['suricata', 'zeek', 'snort', 'agent'].map((s) => ({ value: s, label: s }))]}
        />
        <input
          value={params.src_ip ?? ''}
          onChange={(e) => setParam('src_ip', e.target.value)}
          placeholder="Source IP"
          className="h-8 w-[150px] rounded-sm2 border border-line bg-bg-raise px-2 font-mono text-[12px]"
          aria-label="Source IP filter"
        />
      </div>

      <Panel>
        {events.isLoading && visible.length === 0 ? <Spinner /> : events.isError ? (
          <ErrorState message={(events.error as Error).message} onRetry={() => events.refetch()} />
        ) : visible.length === 0 ? (
          <EmptyState title="No telemetry" hint="Attach a network sensor or endpoint agent — events stream into ClickHouse and appear here." />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <th scope="col">Time</th><th scope="col">Severity</th><th scope="col">Event</th><th scope="col">Source</th>
                  <th scope="col">Origin</th><th scope="col">Destination</th><th scope="col">Rule / App</th>
                </tr>
              </thead>
              <tbody>
                {visible.map((e) => (
                  <tr key={e.event_id}>
                    <td className="text-fg-dim" title={exactTime(e.timestamp)}>{relTime(e.timestamp)}</td>
                    <td><SeverityBadge severity={e.severity ?? ''} /></td>
                    <td><Pill tone="neutral">{e.event_type}</Pill></td>
                    <td className="text-fg-dim">{e.source}</td>
                    <td className="font-mono text-[11.5px]">{e.src_ip}{e.src_port ? `:${e.src_port}` : ''}</td>
                    <td className="font-mono text-[11.5px] text-fg-dim">{e.dst_ip}{e.dst_port ? `:${e.dst_port}` : ''}</td>
                    <td className="max-w-[260px] truncate text-fg-dim" title={e.rule_name}>{e.rule_name || e.application || e.hostname || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div className="flex items-center justify-between border-t border-line px-3 py-2">
          <span className="text-[11.5px] text-fg-faint">
            Server-side cursor pagination — the browser never holds the full event history.
          </span>
          <Button disabled={!events.data?.next_cursor || events.isFetching} onClick={loadMore}>
            {events.isFetching ? 'Loading…' : 'Load more'}
          </Button>
        </div>
      </Panel>
    </div>
  )
}
