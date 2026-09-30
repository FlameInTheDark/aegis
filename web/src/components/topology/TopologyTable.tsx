import * as React from "react";
import { Boxes, ChevronDown, ChevronRight, Crosshair, ExternalLink, Pin } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import { colorOf, iconOf } from "@/lib/groups";
import type { GraphNode } from "@/components/topology/TopologyGraph";
import { useAsset, useAssetFindings, useAssetTraces } from "@/lib/queries";
import type { Asset, AssetGroup } from "@/data/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { GroupChip } from "@/components/groups/GroupChip";
import { CriticalityBadge, ExposureBadge, Mono, RiskMeter, SeverityBadge, SeverityCountsInline, SeverityStack } from "@/components/shared";

/** One grouped section of the topology table view (a group or the
 *  ungrouped remainder). */
export interface TopologyBucket {
  id: string;
  label: string;
  color?: string;
  icon?: string;
  items: GraphNode[];
}

/**
 * TopologyTable — the table view of the topology page: every visible node
 * as a row (groups render as collapsible buckets with aggregate severity /
 * risk headers) with an expandable detail row per node.
 */
export function TopologyTable({
  tableNodes,
  tableBuckets,
  tableGroupBy,
  collapsedRows,
  onToggleCollapsedRow,
  expanded,
  onExpand,
  upstreamByAsset,
  overrideByChild,
  groupsOf,
  hasQuery,
}: {
  tableNodes: GraphNode[];
  tableBuckets: TopologyBucket[];
  tableGroupBy: "none" | "group";
  collapsedRows: Set<string>;
  onToggleCollapsedRow: (id: string) => void;
  expanded: string | null;
  onExpand: (id: string | null) => void;
  /** observed upstream neighbour per asset (tree parent = routes_to source) */
  upstreamByAsset: Map<string, GraphNode>;
  /** analyst parent pins (migration 0032), child asset id → parent asset id */
  overrideByChild: Map<string, string>;
  groupsOf: (assetId: string) => AssetGroup[];
  /** the search box has a query — table rows were pre-filtered by the page */
  hasQuery: boolean;
}) {
  return (
    <Card className="min-h-0 flex-1 overflow-auto py-0">
      <table className="w-full min-w-[1300px] table-fixed border-collapse text-sm">
        <colgroup>
          <col className="w-9" />
          <col className="w-[240px]" />
          <col className="w-[170px]" />
          <col className="w-[120px]" />
          <col className="w-[120px]" />
          <col className="w-[110px]" />
          <col className="w-[128px]" />
          <col className="w-[160px]" />
          <col className="w-[130px]" />
          <col />
        </colgroup>
        <thead className="sticky top-0 z-10 bg-card">
          <tr className="border-b text-left">
            <th className="h-9 px-3" />
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Node</th>
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Groups</th>
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Type</th>
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Upstream</th>
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Exposure</th>
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Findings</th>
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Risk</th>
            <th className="h-9 px-3 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Last seen</th>
            <th className="h-9 px-3" />
          </tr>
        </thead>
        <tbody>
          {(tableGroupBy === "group" ? tableBuckets.flatMap((b) => {
            const hidden = collapsedRows.has(b.id);
            const c = b.color ? colorOf(b.color) : undefined;
            const Icon = b.icon ? iconOf(b.icon) : Boxes;
            const agg = b.items.reduce(
              (acc, n) => ({
                critical: acc.critical + (n.asset.findings?.critical ?? 0),
                high: acc.high + (n.asset.findings?.high ?? 0),
                medium: acc.medium + (n.asset.findings?.medium ?? 0),
                low: acc.low + (n.asset.findings?.low ?? 0),
              }),
              { critical: 0, high: 0, medium: 0, low: 0 }
            );
            const avgRisk = Math.round(b.items.reduce((n, x) => n + x.asset.risk, 0) / b.items.length);
            const header = (
              <tr key={`g-${b.id}`} className="border-y bg-muted/50">
                <td colSpan={10} className="px-2 py-1.5">
                  <button
                    className="flex w-full items-center gap-2.5 text-left cursor-pointer"
                    onClick={() => onToggleCollapsedRow(b.id)}
                  >
                    <ChevronDown className={cn("size-3.5 text-muted-foreground transition-transform", hidden && "-rotate-90")} />
                    <span className="flex size-5 items-center justify-center rounded" style={c ? { backgroundColor: c.soft, color: c.solid } : undefined}>
                      <Icon className={cn("size-3", !c && "text-muted-foreground")} />
                    </span>
                    <span className="text-sm font-semibold" style={c ? { color: c.solid } : undefined}>
                      {b.label}
                    </span>
                    <Badge variant="muted" className="tabular">
                      {b.items.length}
                    </Badge>
                    <span className="ml-auto flex items-center gap-4">
                      <SeverityCountsInline counts={agg} />
                      <span className="w-24">
                        <SeverityStack counts={agg} />
                      </span>
                      <span className="text-[11px] text-muted-foreground">avg risk</span>
                      <RiskMeter value={avgRisk} />
                    </span>
                  </button>
                </td>
              </tr>
            );
            return hidden ? [header] : [header, ...b.items.map((n) => renderNodeRow(n))];
          }) : tableNodes.map((n) => renderNodeRow(n)))}
          {tableNodes.length === 0 && (
            <tr className="hover:bg-transparent">
              <td colSpan={10} className="px-4 py-10 text-center text-sm text-muted-foreground">
                {hasQuery ? "No nodes match the current search." : "Nothing to list — no assets match the current site or group filter."}
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </Card>
  );

  /* table row + expansion, hoisted so grouped/ungrouped rendering can share it */
  function renderNodeRow(n: GraphNode) {
    const a = n.asset;
    const Icon = assetTypeMeta[a.type].icon;
    const isOpen = expanded === a.id;
    return (
      <React.Fragment key={a.id}>
        <tr className={cn("cursor-pointer border-b transition-colors hover:bg-accent/40", isOpen && "bg-accent/30")} onClick={() => onExpand(isOpen ? null : a.id)}>
          <td className="px-3 py-2">
            <ChevronRight className={cn("size-3.5 text-muted-foreground transition-transform duration-200", isOpen && "rotate-90")} />
          </td>
          <td className="px-3 py-2">
            <div className="flex items-center gap-2.5">
              <span className="flex size-7 shrink-0 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                <Icon className="size-3.5" />
              </span>
              <div className="min-w-0 leading-tight">
                <div className="truncate font-medium">{a.hostname ?? a.ip}</div>
                <div className="font-mono text-[11px] text-muted-foreground">{a.ip}</div>
              </div>
              {n.hub && <Badge variant="primary">hub</Badge>}
            </div>
          </td>
          <td className="px-3 py-2">
            <div className="flex flex-wrap gap-1">
              {groupsOf(a.id).slice(0, 2).map((g) => (
                <GroupChip key={g.id} group={g} size="sm" />
              ))}
              {groupsOf(a.id).length === 0 && <span className="text-xs text-muted-foreground">—</span>}
            </div>
          </td>
          <td className="truncate px-3 py-2 text-muted-foreground">{assetTypeMeta[a.type].label}</td>
          <td className="px-3 py-2">
            {(() => {
              const up = upstreamByAsset.get(a.id);
              if (n.hub && !up) return <Badge variant="primary">gateway</Badge>;
              if (!up) return <span className="text-xs text-muted-foreground">—</span>;
              return (
                <span className="flex min-w-0 items-center gap-1.5 text-xs">
                  <Mono className="text-[11px]">{up.asset.ip}</Mono>
                  {up.asset.hostname && <span className="truncate text-muted-foreground">{up.asset.hostname}</span>}
                  {overrideByChild.get(a.id) === up.asset.id && (
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span>
                          <Pin className="size-3 shrink-0 text-warning" />
                        </span>
                      </TooltipTrigger>
                      <TooltipContent>Parent pinned by an analyst — overrides the observed evidence</TooltipContent>
                    </Tooltip>
                  )}
                </span>
              );
            })()}
          </td>
          <td className="px-3 py-2">
            <ExposureBadge value={a.exposure} />
          </td>
          <td className="px-3 py-2">
            <SeverityCountsInline counts={a.findings ?? { critical: 0, high: 0, medium: 0, low: 0 }} />
          </td>
          <td className="px-3 py-2">
            <RiskMeter value={a.risk} />
          </td>
          <td className="px-3 py-2 tabular text-xs text-muted-foreground">{timeAgo(a.lastSeen)}</td>
          {/* the table defines a trailing spare column (10 cols total) — without
              this cell the row's right edge is dead: no hover, no clicks */}
          <td className="px-3 py-2" aria-hidden />
        </tr>
        {isOpen && (
          <tr className="bg-muted/20">
            <td colSpan={10} className="p-0">
              <RowExpansion asset={a} />
            </td>
          </tr>
        )}
      </React.Fragment>
    );
  }
}

/* ------------------------------------------------------------------ */
/* Expanded-row content: identity, ports, findings, trace              */
/* ------------------------------------------------------------------ */
function RowExpansion({ asset: a }: { asset: Asset }) {
  const bundleQ = useAsset(a.id);
  const findingsQ = useAssetFindings(a.id);
  const tracesQ = useAssetTraces(a.id);
  const bundle = bundleQ.data;
  const fs = (findingsQ.data ?? []).filter((f) => f.status !== "resolved" && f.status !== "accepted_risk" && f.status !== "false_positive" && f.status !== "suppressed");
  const trace = (tracesQ.data?.traces ?? [])[0];
  const openPorts = (bundle?.ports ?? []).filter((p) => p.state === "open");

  return (
    <div className="grid gap-4 p-4 lg:grid-cols-4" style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,1.2fr) minmax(0,1.3fr) minmax(0,1fr)" }}>
      <div className="flex flex-col gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Identity</div>
        <dl className="space-y-1 text-xs">
          <div className="flex justify-between gap-3">
            <dt className="text-muted-foreground">OS</dt>
            <dd className="truncate text-right">{a.os ?? "Unknown"}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-muted-foreground">Vendor</dt>
            <dd className="truncate text-right">{a.vendor ?? "—"}</dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-muted-foreground">Criticality</dt>
            <dd>
              <CriticalityBadge value={a.criticality} />
            </dd>
          </div>
          <div className="flex justify-between gap-3">
            <dt className="text-muted-foreground">Owner</dt>
            <dd className="truncate text-right">{a.owner ?? "—"}</dd>
          </div>
        </dl>
      </div>
      <div className="flex flex-col gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Open ports ({openPorts.length})</div>
        {openPorts.length ? (
          <div className="flex flex-wrap gap-1">
            {openPorts.slice(0, 12).map((p) => (
              <span key={`${p.proto}${p.port}`} className="rounded border bg-card px-1.5 py-0.5 font-mono text-[11px]">
                {p.port}/{p.service}
              </span>
            ))}
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">{bundleQ.isLoading ? "Loading…" : "No listening services detected"}</span>
        )}
      </div>
      <div className="flex flex-col gap-2">
        <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Top findings</div>
        {fs.length ? (
          <ul className="space-y-1">
            {fs.slice(0, 3).map((f) => (
              <li key={f.id} className="flex items-start gap-1.5 text-xs">
                <SeverityBadge severity={f.severity} compact />
                <span className="min-w-0 flex-1 truncate">{f.title}</span>
              </li>
            ))}
          </ul>
        ) : (
          <span className="text-xs text-muted-foreground">No open findings</span>
        )}
      </div>
      <div className="flex flex-col items-start justify-between gap-3">
        <div className="flex flex-col gap-2">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Path</div>
          <div className="flex flex-wrap items-center gap-1.5 text-xs">
            {trace ? (
              trace.hops.map((h, i) => (
                <React.Fragment key={h.ttl}>
                  {i > 0 && <span className="text-muted-foreground">→</span>}
                  <Mono className="text-[11px]">{h.address}</Mono>
                </React.Fragment>
              ))
            ) : (
              <span className="text-muted-foreground">No trace recorded</span>
            )}
          </div>
        </div>
        <div className="flex gap-2">
          <Button size="xs" asChild>
            <Link to={`/assets/${a.id}`}>
              <ExternalLink /> Open asset
            </Link>
          </Button>
          <Button size="xs" variant="outline" asChild>
            <Link to={`/topology?focus=${a.id}`}>
              <Crosshair /> Show in graph
            </Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
