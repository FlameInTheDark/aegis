import { useEffect, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from '@/lib/api'
import type { AffectedProduct, AffectedVersion, CPEMatchRow, Page, VulnerabilityRow } from '@/types'
import { Badge, Input, Pagination, Panel, PanelHeader, KEVBadge, SeverityBadge, Spinner, ErrorState, EmptyState, ChipSelect, ChipToggle, Meter, Pill, StatusPill } from '@/components/ui'
import { relTime, fmtNum } from '@/lib/format'

// statusToneForAffected maps a CVE v5 status to a pill tone: affected
// ranges are the dangerous ones, unaffected carve-outs are good news.
function statusToneForAffected(s?: string): 'high' | 'ok' | 'neutral' {
  if (s === 'affected') return 'high'
  if (s === 'unaffected') return 'ok'
  return 'neutral'
}

// rangeLabel renders one affected-version statement as a compact,
// human-readable range: "= 1.0.2k", "≥ 2.0, < 2.7.3", "< 10.4",
// "≥ 2.5 (no upper bound)", plus any status changes.
export function rangeLabel(v: AffectedVersion): string {
  const parts: string[] = []
  if (v.lessThan) {
    if (v.version) parts.push(`≥ ${v.version}`)
    parts.push(`< ${v.lessThan}`)
  } else if (v.lessThanOrEqual) {
    if (v.version) parts.push(`≥ ${v.version}`)
    parts.push(`≤ ${v.lessThanOrEqual}`)
  } else if (v.version) {
    parts.push(`= ${v.version}`)
  } else {
    parts.push('all versions')
  }
  let label = parts.join(', ')
  if (!v.lessThan && !v.lessThanOrEqual && v.version) label = `= ${v.version}`
  if ((v.changes ?? []).length > 0) label += ` · ${v.changes!.length} status change${v.changes!.length > 1 ? 's' : ''}`
  return label
}

// SortTh is a server-sorted column header: the table pages through API data,
// so sorting must be encoded in the query (sort/order params) rather than
// applied client-side to the visible page only.
function SortTh({ label, sortKey, activeSort, activeOrder, onSort, align }: {
  label: string; sortKey: string; activeSort: string; activeOrder: string; onSort: (key: string) => void; align?: 'right'
}) {
  const active = activeSort === sortKey
  const arrow = !active ? '↕' : activeOrder === 'asc' ? '↑' : '↓'
  return (
    <th scope="col" aria-sort={active ? (activeOrder === 'asc' ? 'ascending' : 'descending') : undefined} className={align === 'right' ? 'num' : undefined}>
      <button className="inline-flex items-center gap-1 hover:text-fg" onClick={() => onSort(sortKey)}>
        {label}
        <span aria-hidden className="text-[10px] text-fg-faint">{arrow}</span>
      </button>
    </th>
  )
}

function sevOf(score: number): 'critical' | 'high' | 'medium' | 'low' | 'info' {
  if (score >= 9) return 'critical'
  if (score >= 7) return 'high'
  if (score >= 4) return 'medium'
  if (score > 0) return 'low'
  return 'info'
}

// Sort presets mirror the server-side whitelist (repo_vulns vulnOrderClause).
const SORT_PRESETS: { value: string; label: string; sort: string; order: string }[] = [
  { value: 'relevance', label: 'Relevance (KEV, CVSS)', sort: '', order: '' },
  { value: 'published_desc', label: 'Newest published', sort: 'published_at', order: 'desc' },
  { value: 'published_asc', label: 'Oldest published', sort: 'published_at', order: 'asc' },
  { value: 'name_asc', label: 'Name A→Z', sort: 'cve_id', order: 'asc' },
  { value: 'name_desc', label: 'Name Z→A', sort: 'cve_id', order: 'desc' },
  { value: 'cvss_desc', label: 'Highest CVSS', sort: 'cvss_score', order: 'desc' },
  { value: 'cvss_asc', label: 'Lowest CVSS', sort: 'cvss_score', order: 'asc' },
  { value: 'updated_desc', label: 'Recently updated', sort: 'updated_at', order: 'desc' },
]

function presetValue(sort: string | null, order: string | null): string {
  const hit = SORT_PRESETS.find((p) => p.sort === (sort ?? '') && p.order === (order ?? ''))
  return hit?.value ?? 'relevance'
}

export default function VulnerabilitiesPage() {
  const [params, setParams] = useSearchParams()
  const page = Number(params.get('page') ?? 1)
  const [draft, setDraft] = useState(params.get('search') ?? '')
  // Debounced search: typing applies the filter automatically (400 ms);
  // substring matching runs against CVE id, description and references.
  useEffect(() => {
    const t = setTimeout(() => {
      const next = new URLSearchParams(params)
      const cur = params.get('search') ?? ''
      if (draft !== cur) {
        if (draft) next.set('search', draft)
        else next.delete('search')
        next.delete('page')
        setParams(next)
      }
    }, 400)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [draft])
  const vulns = useQuery({
    queryKey: ['vulns', params.toString()],
    queryFn: () => api.get<Page<VulnerabilityRow>>(`/vulnerabilities?${params.toString()}`),
  })
  const setParam = (k: string, v: string) => patchParams({ [k]: v })
  // patchParams applies ALL key changes against ONE params snapshot in a
  // single setParams call. The previous sort handlers called setParam twice
  // in a row; each call built its URL from the same STALE params object, so
  // the second setParams overwrote the first and the sort key never reached
  // the API — the server kept answering in default relevance order no
  // matter which sort the user picked (field-reported bug).
  const patchParams = (patch: Record<string, string>) => {
    const next = new URLSearchParams(params)
    for (const [k, v] of Object.entries(patch)) {
      if (v) next.set(k, v)
      else next.delete(k)
    }
    if (!('page' in patch)) next.delete('page')
    setParams(next)
  }
  // Header sorting: server-driven (sort+order params). Clicking the active
  // column flips direction; clicking a new one applies its default direction
  // (names read A→Z, everything else is "most interesting first").
  const onHeaderSort = (key: string) => {
    const active = params.get('sort') === key
    const dir = active ? (params.get('order') === 'asc' ? 'desc' : 'asc') : key === 'cve_id' ? 'asc' : 'desc'
    patchParams({ sort: key, order: dir })
  }
  const sort = params.get('sort') ?? ''
  const order = params.get('order') ?? ''
  const hasFilters = ['search', 'kev', 'severity', 'min_score', 'state', 'source', 'sort', 'order', 'published_after', 'published_before'].some((k) => params.get(k))

  return (
    <div className="space-y-3">
      <div className="tbl-toolbar">
        <Input
          placeholder="Search CVE id, description, reference… (e.g. CVE-2005-24)"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          className="w-[320px]"
          aria-label="Search vulnerabilities"
        />
        <ChipToggle
          label="KEV only"
          tone="critical"
          active={params.get('kev') === 'true'}
          onClick={() => setParam('kev', params.get('kev') === 'true' ? '' : 'true')}
          title="Only CVEs present in the CISA Known Exploited catalog"
        />
        <ChipSelect
          label="Severity"
          value={params.get('severity') ?? ''}
          onChange={(v) => setParam('severity', v)}
          ariaLabel="Severity filter"
          options={[{ value: '', label: 'All severities' }, ...['critical', 'high', 'medium', 'low'].map((s) => ({ value: s, label: s }))]}
        />
        <ChipSelect
          label="CVSS"
          value={params.get('min_score') ?? ''}
          onChange={(v) => setParam('min_score', v)}
          ariaLabel="Minimum CVSS filter"
          options={[{ value: '', label: 'Any' }, { value: '9', label: '≥ 9' }, { value: '7', label: '≥ 7' }, { value: '4', label: '≥ 4' }]}
        />
        <ChipSelect
          label="State"
          value={params.get('state') ?? ''}
          onChange={(v) => setParam('state', v)}
          ariaLabel="CVE state filter"
          options={[{ value: '', label: 'Any' }, ...['PUBLISHED', 'REJECTED', 'RESERVED', 'DISPUTED'].map((s) => ({ value: s, label: s.toLowerCase() }))]}
        />
        <ChipSelect
          label="Source"
          value={params.get('source') ?? ''}
          onChange={(v) => setParam('source', v)}
          ariaLabel="CVE source filter"
          options={[{ value: '', label: 'Any' }, ...['nvd', 'cvelistv5'].map((s) => ({ value: s, label: s }))]}
        />
        <div className="tbl-chip" title="Published between">
          <span className="tbl-chip-label">Published:</span>
          <input type="date" className="tbl-chip-input" value={params.get('published_after') ?? ''}
            onChange={(e) => setParam('published_after', e.target.value)} aria-label="Published after" />
          <span aria-hidden className="text-fg-faint">–</span>
          <input type="date" className="tbl-chip-input" value={params.get('published_before') ?? ''}
            onChange={(e) => setParam('published_before', e.target.value)} aria-label="Published before" />
        </div>
        <ChipSelect
          label="Sort"
          value={presetValue(params.get('sort'), params.get('order'))}
          ariaLabel="Sort order"
          onChange={(v) => {
            const p = SORT_PRESETS.find((x) => x.value === v)
            if (!p) return
            patchParams({ sort: p.sort, order: p.order })
          }}
          options={SORT_PRESETS.map((p) => ({ value: p.value, label: p.label }))}
        />
        {hasFilters && (
          <button type="button" className="tbl-chip tbl-chip-toggle" onClick={() => setParams(new URLSearchParams())} aria-label="Clear all filters">
            Reset
          </button>
        )}
      </div>

      <Panel>
        {vulns.isLoading ? <Spinner /> : vulns.isError ? <ErrorState message={(vulns.error as Error).message} onRetry={() => vulns.refetch()} /> : (vulns.data?.items ?? []).length === 0 ? (
          <EmptyState title="No matching vulnerabilities" hint={params.get('search') ? 'Nothing matches this search — try a shorter substring, or clear filters.' : 'The feed worker may still be syncing CVE intelligence on first boot.'} />
        ) : (
          <div className="overflow-x-auto">
            <table className="table-base">
              <thead>
                <tr>
                  <SortTh label="CVE" sortKey="cve_id" activeSort={sort} activeOrder={order} onSort={onHeaderSort} />
                  <th scope="col">Severity</th>
                  <SortTh label="CVSS" sortKey="cvss_score" activeSort={sort} activeOrder={order} onSort={onHeaderSort} align="right" />
                  <th scope="col">Description</th>
                  <th scope="col" className="num">EPSS</th>
                  <SortTh label="KEV" sortKey="known_exploited" activeSort={sort} activeOrder={order} onSort={onHeaderSort} />
                  <th scope="col" className="num">Affected assets</th>
                  <th scope="col" className="num">Open findings</th>
                  <SortTh label="Published" sortKey="published_at" activeSort={sort} activeOrder={order} onSort={onHeaderSort} />
                </tr>
              </thead>
              <tbody>
                {(vulns.data?.items ?? []).map((v) => (
                  <tr key={v.cve_id}>
                    <td>
                      <Link to={`/vulnerabilities/${v.cve_id}`} className="font-mono text-[12px] font-medium hover:text-accent">{v.cve_id}</Link>
                    </td>
                    <td><SeverityBadge severity={sevOf(v.cvss_score)} /></td>
                    <td className="num" title={v.cvss_vector}>
                      <Meter value={v.cvss_score} max={10} label={`CVSS ${v.cvss_score.toFixed(1)}`} />
                      <span className="font-medium">{v.cvss_score.toFixed(1)}</span>
                    </td>
                    <td className="max-w-[340px] truncate text-[12px] text-fg-dim" title={v.description}>{v.description || '—'}</td>
                    <td className="num text-fg-dim">{v.epss !== undefined ? `${(v.epss * 100).toFixed(1)}%` : '—'}</td>
                    <td>{v.known_exploited ? <KEVBadge /> : <span className="text-fg-faint">—</span>}</td>
                    <td className="num">{fmtNum(v.affected_assets)}</td>
                    <td className="num text-fg-dim">{fmtNum(v.open_findings)}</td>
                    <td className="text-fg-dim" title={v.published_at}>{v.published_at ? relTime(v.published_at) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {vulns.data && <Pagination page={page} limit={vulns.data.limit ?? 50} total={vulns.data.total} onPage={(p) => setParam('page', String(p))} />}
      </Panel>
      <p className="text-[11.5px] text-fg-faint">
        {fmtNum(vulns.data?.total)} CVEs match the current filters · search covers CVE ids, description text and reference URLs.
      </p>
    </div>
  )
}

export function VulnerabilityDetailPage() {
  const { cveId } = useParams()
  const { data, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['vuln', cveId],
    queryFn: () => api.get<{
      vulnerability: {
        cve_id: string; description: string; state: string
        cvss_v2?: { score: number; vector: string; version: string }
        cvss_v3?: { score: number; vector: string; version: string }
        cvss_v4?: { score: number; vector: string; version: string }
        cwe: string[]; known_exploited?: { known_exploited: boolean; date_added?: string; required_action?: string; ransomware_use?: string }
        epss?: { epss: number; percentile: number; date: string }
        affected?: AffectedProduct[]
        cpe_matches?: CPEMatchRow[]
      }
      references: string[]
      affected_assets: { asset_id: string; hostname?: string; risk_score: number; finding_id: string; status: string }[]
    }>(`/vulnerabilities/${cveId}`),
  })

  if (isLoading) return <Spinner />
  if (isError) return <ErrorState message={(error as Error).message} onRetry={() => refetch()} />
  const v = data!.vulnerability
  const affectedAssets = data!.affected_assets ?? []
  const references = data!.references ?? []

  return (
    <div className="space-y-4">
      <div>
        <h1 className="font-mono text-[17px] font-semibold">{v.cve_id}</h1>
        <div className="mt-1 flex items-center gap-2">
          {v.cvss_v3 && <SeverityBadge severity={sevOf(v.cvss_v3.score)} />}
          {v.known_exploited?.known_exploited && <KEVBadge />}
          <Pill tone="neutral">{v.state}</Pill>
        </div>
      </div>

      <Panel>
        <PanelHeader title="Description" />
        <p className="px-3.5 py-3 text-[13px] leading-relaxed text-fg-dim">{v.description || 'No description available.'}</p>
      </Panel>

      <div className="grid grid-cols-3 gap-4">
        <Panel>
          <PanelHeader title="CVSS" />
          <div className="space-y-1.5 px-3.5 py-3 text-[12.5px]">
            {(['cvss_v3', 'cvss_v2', 'cvss_v4'] as const).map((k) =>
              v[k] ? (
                <div key={k} className="flex justify-between">
                  <span className="text-fg-dim">{k.replace('cvss_', 'v')}</span>
                  <span className="tabular-nums">{v[k]!.score.toFixed(1)} <span className="text-fg-faint">{v[k]!.vector}</span></span>
                </div>
              ) : null,
            )}
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="EPSS" />
          <div className="px-3.5 py-3 text-[12.5px] text-fg-dim">
            {v.epss ? (
              <>
                <div className="text-[20px] font-semibold text-fg">{(v.epss.epss * 100).toFixed(2)}%</div>
                <p>probability of exploitation in the next 30 days ({v.epss.date}). EPSS is exploitation likelihood, not severity.</p>
              </>
            ) : 'No EPSS snapshot.'}
          </div>
        </Panel>
        <Panel>
          <PanelHeader title="CWE" />
          <div className="flex flex-wrap gap-1.5 px-3.5 py-3">
            {(v.cwe ?? []).map((c) => <Badge key={c} className="border-line text-fg-dim">{c}</Badge>)}
            {(v.cwe ?? []).length === 0 && <span className="text-[12.5px] text-fg-dim">—</span>}
          </div>
        </Panel>
      </div>

      <AffectedProductsPanel products={v.affected ?? []} cpeMatches={v.cpe_matches ?? []} />

      {v.known_exploited?.known_exploited && (
        <div className="rounded-md2 border border-crit/30 bg-crit/10 px-3.5 py-3 text-[12.5px] text-crit">
          <strong>Known exploited.</strong> Added to CISA KEV {v.known_exploited.date_added ?? ''}.
          {v.known_exploited.required_action && <span> Required action: {v.known_exploited.required_action}</span>}
        </div>
      )}

      <div className="grid grid-cols-2 gap-4">
        <Panel>
          <PanelHeader title={`Affected assets (${affectedAssets.length})`} />
          {affectedAssets.length === 0 ? (
            <p className="px-3.5 py-5 text-center text-[12.5px] text-fg-dim">No assets currently match this CVE.</p>
          ) : (
            <table className="table-base">
              <thead><tr><th>Asset</th><th className="num">Risk</th><th>Finding status</th></tr></thead>
              <tbody>
                {affectedAssets.map((a) => (
                  <tr key={a.finding_id}>
                    <td><Link to={`/assets/${a.asset_id}`} className="hover:text-accent">{a.hostname || a.asset_id.slice(0, 12)}</Link></td>
                    <td className="num">
                      <Meter value={a.risk_score} max={100} label={`Risk score ${a.risk_score.toFixed(0)}`} />
                      <span className="font-medium">{a.risk_score.toFixed(0)}</span>
                    </td>
                    <td><StatusPill state={a.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Panel>
        <Panel>
          <PanelHeader title="References" />
          <ul className="space-y-1.5 px-3.5 py-3 text-[12.5px]">
            {references.slice(0, 12).map((r) => (
              <li key={r}>
                <a href={r} target="_blank" rel="noreferrer noopener" className="break-all text-accent hover:underline">{r}</a>
              </li>
            ))}
            {references.length === 0 && <li className="text-fg-dim">No references recorded.</li>}
          </ul>
        </Panel>
      </div>
    </div>
  )
}

// AffectedProductsPanel renders the CVE's applicability statement exactly
// as the vendor published it: which products, which version ranges, which
// statuses — so an operator can see WHY a discovered version matched (or
// why a newer one is safe). Backed by vulnerabilities.affected (JSONB);
// the machine-matchable form of the same data is the CPE match set.
function AffectedProductsPanel({ products, cpeMatches }: { products: AffectedProduct[]; cpeMatches: CPEMatchRow[] }) {
  if (products.length === 0 && cpeMatches.length === 0) {
    return (
      <Panel>
        <PanelHeader title="Affected products" />
        <EmptyState
          title="No affected-product statement recorded"
          hint="This record was ingested without a machine-readable affected list (older ingest or NVD-only data). Matching falls back to product-identity candidates."
        />
      </Panel>
    )
  }
  return (
    <Panel>
      <PanelHeader title={`Affected products (${products.length})`} />
      <p className="px-3.5 pt-2.5 text-[11.5px] text-fg-faint">
        Version statements exactly as the vulnerability reporter published them. The matching engine compares discovered software versions
        against these ranges using each statement's declared versionType (custom, semver, rpm, deb, python, …).
      </p>
      <div className="overflow-x-auto">
        <table className="table-base">
          <thead>
            <tr>
              <th scope="col">Vendor</th>
              <th scope="col">Product</th>
              <th scope="col">Version statement</th>
              <th scope="col">Status</th>
              <th scope="col">Version type</th>
            </tr>
          </thead>
          <tbody>
            {products.map((p, pi) =>
              (p.versions ?? []).length === 0 ? (
                <tr key={`${pi}-plain`}>
                  <td className="text-fg-dim">{p.vendor || '—'}</td>
                  <td className="font-medium">{p.product}</td>
                  <td className="text-fg-dim" colSpan={1}>{'all versions (no range given)'}</td>
                  <td><Pill tone={statusToneForAffected(p.defaultStatus)}>{p.defaultStatus || 'unknown'}</Pill></td>
                  <td className="text-fg-faint">—</td>
                </tr>
              ) : (
                (p.versions ?? []).map((vr, vi) => (
                  <tr key={`${pi}-${vi}`}>
                    <td className="text-fg-dim">{vi === 0 ? (p.vendor || '—') : ''}</td>
                    <td className="font-medium">{vi === 0 ? p.product : ''}</td>
                    <td className="font-mono text-[11.5px]">{rangeLabel(vr)}</td>
                    <td>
                      <Pill tone={statusToneForAffected(vr.status || p.defaultStatus)}>{vr.status || p.defaultStatus || 'unknown'}</Pill>
                      {(vr.changes ?? []).map((c, ci) => (
                        <span key={ci} className="ml-1.5 text-[10.5px] text-fg-faint" title={`From ${c.at || '?'}: ${c.status}`}>{ci === 0 ? `↻ ${c.at}` : `· ${c.at}`}</span>
                      ))}
                    </td>
                    <td className="text-fg-dim">{vr.versionType ? <Badge className="border-line text-fg-dim">{vr.versionType}</Badge> : '—'}</td>
                  </tr>
                ))
              ),
            )}
            {products.length === 0 && cpeMatches.length > 0 && (
              <tr>
                <td className="text-fg-dim">—</td>
                <td className="text-fg-dim">{cpeMatches.length} CPE match{cpeMatches.length > 1 ? 'es' : ''}</td>
                <td className="font-mono text-[11.5px] text-fg-dim" colSpan={3}>{cpeMatches[0].cpe}</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
      {cpeMatches.length > 0 && (
        <p className="px-3.5 py-2.5 text-[11px] text-fg-faint">
          {cpeMatches.length} machine-matchable CPE expression{cpeMatches.length > 1 ? 's' : ''} derived from this statement (bounds per range).
        </p>
      )}
    </Panel>
  )
}
