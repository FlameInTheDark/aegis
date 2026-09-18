import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { api } from '@/lib/api'
import type { MetricsSummary, Page, Finding, DetectionMatch, Asset } from '@/types'
import { KPICard, Panel, PanelHeader, SeverityBadge, Spinner, ErrorState, StatusDot } from '@/components/ui'
import { TimeSeriesChart, SeverityDonut } from '@/components/charts/Chart'
import { relTime, humanize, fmtNum } from '@/lib/format'

export default function DashboardPage() {
  const summary = useQuery({
    queryKey: ['metrics-summary'],
    queryFn: () => api.get<MetricsSummary>('/metrics/summary'),
    refetchInterval: 30_000,
  })
  const riskTrend = useQuery({
    queryKey: ['metrics-ts-risk'],
    queryFn: () => api.get<{ points: { ts: string; value: number }[] }>('/metrics/timeseries?metric=risk&days=30'),
  })
  const eventTrend = useQuery({
    queryKey: ['metrics-ts-events'],
    queryFn: () => api.get<{ points: { ts: string; value: number }[] }>('/metrics/timeseries?metric=events&days=7'),
  })
  const topFindings = useQuery({
    queryKey: ['dash-top-findings'],
    queryFn: () => api.get<Page<Finding>>('/findings?limit=6'),
  })
  const recentMatches = useQuery({
    queryKey: ['dash-recent-matches'],
    queryFn: () => api.get<Page<DetectionMatch>>('/detections/matches?limit=6'),
  })
  const exposedAssets = useQuery({
    queryKey: ['dash-top-assets'],
    queryFn: () => api.get<Page<Asset>>('/assets?limit=6'),
  })

  if (summary.isLoading) return <Spinner />
  if (summary.isError) return <ErrorState message={(summary.error as Error).message} onRetry={() => summary.refetch()} />
  const s = summary.data!

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-7 gap-3">
        <KPICard label="Assets" value={fmtNum(s.assets)} />
        <KPICard label="Open ports" value={fmtNum(s.open_ports)} />
        <KPICard label="Vulnerabilities" value={fmtNum(s.vulnerabilities)} />
        <KPICard label="Critical" value={fmtNum(s.critical)} tone="crit" />
        <KPICard label="KEV" value={fmtNum(s.kev)} tone="crit" />
        <KPICard label="High risk assets" value={fmtNum(s.high_risk_assets)} tone="high" />
        <KPICard label="Active alerts" value={fmtNum(s.active_alerts)} />
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Panel className="col-span-2">
          <PanelHeader title="Risk trend (30d)" />
          <TimeSeriesChart points={riskTrend.data?.points ?? []} label="risk" />
        </Panel>
        <Panel>
          <PanelHeader title="Severity distribution" />
          <SeverityDonut bySeverity={s.by_severity} />
        </Panel>
      </div>

      <div className="grid grid-cols-3 gap-4">
        <Panel className="col-span-2">
          <PanelHeader title="Event volume (7d)" />
          <TimeSeriesChart points={eventTrend.data?.points ?? []} color="#60A5FA" label="events" />
        </Panel>
        <Panel>
          <PanelHeader title="Top exposed assets" />
          <div className="divide-y divide-line/50">
            {(exposedAssets.data?.items ?? []).slice().sort((a, b) => b.risk_score - a.risk_score).slice(0, 6).map((a) => (
              <Link key={a.id} to={`/assets/${a.id}`} className="flex items-center justify-between px-3.5 py-2 text-[12.5px] hover:bg-white/[0.02]">
                <span className="truncate">{a.hostname || a.id.slice(0, 12)}</span>
                <span className="tabular-nums text-fg-dim">{a.risk_score.toFixed(0)}</span>
              </Link>
            ))}
            {(exposedAssets.data?.items ?? []).length === 0 && <p className="px-3.5 py-6 text-center text-[12.5px] text-fg-dim">No assets discovered yet — run your first discovery scan.</p>}
          </div>
        </Panel>
      </div>

      <div className="grid grid-cols-2 gap-4">
        <Panel>
          <PanelHeader title="Top critical findings" action={<Link to="/findings" className="text-[11.5px] text-accent">View all</Link>} />
          <div className="divide-y divide-line/50">
            {(topFindings.data?.items ?? []).map((f) => (
              <Link key={f.id} to={`/findings?focus=${f.id}`} className="flex items-center gap-2 px-3.5 py-2 text-[12.5px] hover:bg-white/[0.02]">
                <SeverityBadge severity={f.severity} />
                <span className="truncate">{f.title}</span>
                <span className="ml-auto shrink-0 tabular-nums text-fg-dim">{f.risk_score.toFixed(0)}</span>
              </Link>
            ))}
            {(topFindings.data?.items ?? []).length === 0 && (
              <p className="px-3.5 py-6 text-center text-[12.5px] text-fg-dim">No vulnerabilities matched in the selected scope.</p>
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="Recent detections" action={<Link to="/detections" className="text-[11.5px] text-accent">View all</Link>} />
          <div className="divide-y divide-line/50">
            {(recentMatches.data?.items ?? []).map((m) => (
              <div key={m.id} className="flex items-center gap-2 px-3.5 py-2 text-[12.5px]">
                <SeverityBadge severity={m.level} />
                <span className="truncate">{m.summary}</span>
                <span className="ml-auto shrink-0 text-fg-faint" title={m.timestamp}>{relTime(m.timestamp)}</span>
              </div>
            ))}
            {(recentMatches.data?.items ?? []).length === 0 && (
              <p className="px-3.5 py-6 text-center text-[12.5px] text-fg-dim">No detections yet — attach a network sensor or endpoint agent.</p>
            )}
          </div>
        </Panel>
      </div>

      <Panel>
        <PanelHeader title="Coverage notes" />
        <p className="px-3.5 py-3 text-[12.5px] text-fg-dim">
          Metrics reflect only scanned scopes and ingested telemetry. {humanize('')}A lack of findings does not imply security — check site coverage
          and sensor visibility in Settings before drawing conclusions.
        </p>
      </Panel>
    </div>
  )
}
