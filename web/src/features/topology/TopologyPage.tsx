import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import * as echarts from 'echarts'
import { api } from '@/lib/api'
import type { TopologyNode, TopologyEdge } from '@/types'
import { Panel, PanelHeader, Button, Spinner, ErrorState, EmptyState, Select } from '@/components/ui'
import { Chart } from '@/components/charts/Chart'
import { relTime, humanize } from '@/lib/format'
import { useSites } from '@/features/assets/AssetsPage'

const kindColor: Record<string, string> = {
  router: '#FB923C', switch: '#FBBF24', firewall: '#F87171', server: '#60A5FA',
  workstation: '#5E6AD2', printer: '#34D399', access_point: '#A78BFA', iot: '#F472B6',
  mobile: '#22D3EE', virtual_machine: '#38BDF8', unknown: '#6B7280',
}

// Edge styling by kind: routed hop chains are solid and brighter, evidence
// links (observed_through) are dashed — the graph reads like a packet path.
function edgeStyle(kind: string) {
  if (kind === 'routes_to') {
    return { color: 'rgba(96,165,250,0.55)', width: 2, curveness: 0.12, type: 'solid' as const }
  }
  return { color: 'rgba(255,255,255,0.16)', width: 1, curveness: 0.18, type: 'dashed' as const }
}

export default function TopologyPage() {
  const [siteId, setSiteId] = useState('')
  const [view, setView] = useState<'graph' | 'table'>('graph')
  const navigate = useNavigate()
  const sites = useSites()
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['topology', siteId],
    queryFn: () => api.get<{ nodes: TopologyNode[]; edges: TopologyEdge[] }>(`/topology?site_id=${siteId}`),
  })

  const option = useMemo(() => {
    const nodes = (data?.nodes ?? []).map((n) => ({
      id: n.id,
      name: n.label,
      category: 0,
      symbolSize: n.kind === 'router' || n.kind === 'firewall' ? 34 : 22,
      itemStyle: {
        color: kindColor[n.kind] ?? kindColor.unknown,
        // Asset-backed nodes are clickable: give them a bright ring so the
        // affordance is visible (router nodes that merely bridge paths stay dim).
        borderColor: n.asset_id ? 'rgba(255,255,255,0.55)' : 'rgba(255,255,255,0.2)',
        borderWidth: n.asset_id ? 2 : 1,
      },
      cursor: 'pointer',
      label: { show: true, position: 'bottom', color: '#8A8F98', fontSize: 10 },
      value: { asset: n.asset_id, kind: n.kind, risk: n.risk },
    }))
    const links = (data?.edges ?? []).map((e) => ({
      source: e.source,
      target: e.dest,
      // Directional connection lines: the arrow marks where packets flow
      // next, so a traced path reads gateway -> router -> host.
      lineStyle: edgeStyle(e.kind),
      edgeSymbol: ['none', 'arrow'],
      edgeSymbolSize: 7,
      value: { confidence: e.confidence, kind: e.kind },
    }))
    return {
      tooltip: {
        formatter: (p: unknown) => {
          const d = (p as { data?: { value?: { kind?: string; risk?: number; confidence?: number } } }).data?.value
          if (!d) return ''
          const parts = [d.kind === 'routes_to' ? 'routed hop' : d.kind === 'observed_through' ? 'observed through' : d.kind ?? '']
          if (typeof d.risk === 'number') parts.push(`risk ${d.risk.toFixed(0)}`)
          if (typeof d.confidence === 'number') parts.push(`confidence ${(d.confidence * 100).toFixed(0)}%`)
          return parts.filter(Boolean).join(' · ')
        },
      },
      series: [{
        type: 'graph', layout: 'force', roam: true,
        force: { repulsion: 220, edgeLength: 90, gravity: 0.08 },
        data: nodes, links,
        emphasis: { focus: 'adjacency' },
      }],
    }
  }, [data]) as unknown as echarts.EChartsOption

  if (isLoading) return <Spinner />
  if (isError) return <ErrorState message={(error as Error).message} onRetry={() => refetch()} />

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2">
        <Select
          value={siteId}
          onValueChange={setSiteId}
          options={[{ value: '', label: 'All sites' }, ...(sites.data?.items ?? []).map((s) => ({ value: s.id, label: s.name }))]}
          aria-label="Site filter"
        />
        <div className="ml-auto flex gap-1">
          <Button variant={view === 'graph' ? 'primary' : 'default'} onClick={() => setView('graph')}>Graph</Button>
          <Button variant={view === 'table' ? 'primary' : 'default'} onClick={() => setView('table')}>Table</Button>
        </div>
      </div>

      {(data?.nodes ?? []).length === 0 ? (
        <Panel><EmptyState title="No topology data yet" hint="Topology builds from scan evidence (ARP/LLDP/SNMP) and agent reports." /></Panel>
      ) : view === 'graph' ? (
        <Panel className="p-1">
          <Chart
            option={option}
            height={520}
            onSelect={(p) => {
              // Click-through: any node backed by an inventory asset opens
              // that asset's detail page; pure router hops have no asset.
              const d = p.data as { value?: { asset?: string } } | undefined
              const asset = d?.value?.asset
              if (asset) navigate(`/assets/${asset}`)
            }}
          />
          <p className="px-3 pb-2 text-[11px] text-fg-faint">
            Drag to pan, scroll to zoom. Ringed nodes are inventory assets — click one to open it in the assets view.
            A table view is available — the graph is never the only representation.
          </p>
        </Panel>
      ) : (
        <Panel>
          <PanelHeader title="Topology edges" />
          <table className="table-base">
            <thead><tr><th>Source</th><th>Destination</th><th>Kind</th><th>Confidence</th><th>Last seen</th></tr></thead>
            <tbody>
              {(data?.edges ?? []).map((e) => (
                <tr key={e.id}>
                  <td><EdgeLink nodes={data?.nodes ?? []} id={e.source} /></td>
                  <td><EdgeLink nodes={data?.nodes ?? []} id={e.dest} /></td>
                  <td className="text-fg-dim">{humanize(e.kind)}</td>
                  <td className="tabular-nums text-fg-dim">{e.confidence !== undefined ? `${(e.confidence * 100).toFixed(0)}%` : '—'}</td>
                  <td className="text-fg-dim" title={e.last_seen}>{e.last_seen ? relTime(e.last_seen) : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  )
}

function labelFor(nodes: TopologyNode[], id: string | undefined): string {
  if (!id) return '—'
  return nodes.find((n) => n.id === id)?.label ?? id.slice(0, 10)
}

// Edge endpoints link to the ASSET detail page (not the raw node id):
// router/infra nodes have no asset and render as plain text.
function EdgeLink({ nodes, id }: { nodes: TopologyNode[]; id: string }) {
  const navigate = useNavigate()
  const node = nodes.find((n) => n.id === id)
  if (node?.asset_id) {
    return <button className="hover:text-accent" onClick={() => navigate(`/assets/${node.asset_id}`)}>{node.label}</button>
  }
  return <span className="text-fg-dim">{node?.label ?? labelFor(nodes, id)}</span>
}
