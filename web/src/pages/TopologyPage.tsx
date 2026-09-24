import * as React from "react";
import { Boxes, ChevronDown, ChevronRight, Crosshair, ExternalLink, Focus, LayoutGrid, ListTree, Network, Orbit, Pin, PinOff, Search, Table2, Waypoints, X } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import { colorOf, iconOf, UNGROUPED_ID, useGroups } from "@/lib/groups";
import { computeLayout, deriveForest, routeSet, type ArrangeMode, type ClusterMeta, type Pt } from "@/lib/topology-graph";
import TopologyGraph, { type GraphLink, type GraphNode, type TopologyGraphHandle } from "@/components/topology/TopologyGraph";
import { useAsset, useAssetFindings, useAssetTraces, useAssets, useSites, useTopology } from "@/lib/queries";
import type { Asset, AssetGroup } from "@/data/types";
import { useScope, useStatusSlot } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { GroupChip } from "@/components/groups/GroupChip";
import { GroupFilterButton } from "@/components/groups/GroupFilterButton";
import { GroupsManager } from "@/components/groups/GroupsManager";
import {
  CriticalityBadge,
  ExposureBadge,
  GroupingToggle,
  Mono,
  PageHeader,
  RiskMeter,
  SegmentedControl,
  SeverityBadge,
  SeverityCountsInline,
  SeverityStack,
  StatusDot,
} from "@/components/shared";

/**
 * Topology page — the network-topology-view reference graph logic, wired to
 * live platform data:
 *
 *   - evidence edges (traceroute / gateway observation) resolve into
 *     asset-to-asset pairs and grow the parent tree (best confidence wins);
 *   - without evidence a synthetic per-site star feeds the same engine, so
 *     the fallback stays readable;
 *   - Hierarchy lays the tree out as a patch panel (children wrap into grid
 *     rows under their parent, links route through a gutter), Groups and
 *     Sites patch assets into labelled trays, Radial rings the segment;
 *   - positions are canonical + user offsets, so refetches never move a
 *     node a hand did not move.
 */

interface Node {
  asset: Asset;
  x: number;
  y: number;
  r: number;
  hub: boolean;
}

/**
 * Resolve stored topology edges into asset-id pairs — position independent,
 * so the tree derivation can consume them before any coordinates exist.
 * Asset-kind nodes resolve through their asset id; router/gateway hop nodes
 * resolve when their reference IP belongs to an inventoried asset. The
 * result is deduped per unordered pair (highest-confidence record wins, an
 * observed route beats an inferred one) so one physical link lays out once.
 */
function resolveEvidencePairs(
  topoNodes: { id: string; kind: string; assetId?: string; refId?: string }[],
  topoEdges: { srcNodeId: string; dstNodeId: string; kind: string; confidence?: number }[],
  assets: Asset[],
): { source: string; target: string; confidence: number }[] {
  if (!topoEdges.length || !assets.length) return [];
  const byAsset = new Map(assets.map((a) => [a.id, a.id]));
  const byIp = new Map(assets.map((a) => [a.ip, a.id]));
  const endpoint = new Map<string, string>();
  topoNodes.forEach((tn) => {
    if (tn.kind === "asset" && tn.assetId) {
      const id = byAsset.get(tn.assetId);
      if (id) endpoint.set(tn.id, id);
    } else if (tn.kind !== "asset" && tn.refId) {
      const id = byIp.get(tn.refId);
      if (id) endpoint.set(tn.id, id);
    }
  });
  const rank = (e: { kind: string; confidence?: number }) => (e.confidence ?? 0) + (e.kind === "routes_to" ? 1 : 0);
  const best = new Map<string, { kind: string; confidence: number; source: string; target: string }>();
  topoEdges.forEach((te) => {
    const source = endpoint.get(te.srcNodeId);
    const target = endpoint.get(te.dstNodeId);
    if (!source || !target || source === target) return;
    const key = [source, target].sort().join("|");
    const prev = best.get(key);
    if (!prev || rank(te) > rank(prev)) best.set(key, { kind: te.kind, confidence: te.confidence ?? 0.7, source, target });
  });
  return [...best.values()].map((e) => ({ source: e.source, target: e.target, confidence: e.confidence }));
}

const INFRA_RANK: Record<string, number> = { router: 0, firewall: 1, switch: 2, access_point: 3 };
const infraRank = (type: string) => INFRA_RANK[type] ?? 4;
const baseRadius = (a: Asset) => (a.criticality === "critical" ? 13 : a.criticality === "high" ? 11 : a.criticality === "medium" ? 9 : 8);

/**
 * Fallback for graphs without trace evidence: one synthetic hub-and-spoke
 * per site, the hub elected from device metadata (router > firewall >
 * switch > first asset). Once evidence exists it fully replaces these links.
 */
function syntheticSiteEdges(scoped: Asset[]): { source: string; target: string; confidence?: number }[] {
  const bySite = new Map<string, Asset[]>();
  scoped.forEach((a) => bySite.set(a.site, [...(bySite.get(a.site) ?? []), a]));
  const edges: { source: string; target: string }[] = [];
  bySite.forEach((list) => {
    const hub = list.find((a) => a.type === "router") ?? list.find((a) => a.type === "firewall") ?? list.find((a) => a.type === "switch") ?? list[0];
    list.filter((a) => a !== hub).forEach((a) => edges.push({ source: hub.id, target: a.id }));
  });
  return edges;
}

const SITE_COLOR = "oklch(0.66 0.17 275)";
const NEUTRAL_COLOR = "oklch(0.62 0.02 262)";

export function TopologyPage() {
  const { query, navigate } = useRouter();
  const { site: globalSite } = useScope();
  const { groups, groupsOf } = useGroups();
  const sitesQ = useSites();
  const assetsQ = useAssets({ site: globalSite, limit: 200 });
  const allAssets = assetsQ.data?.items ?? [];

  const [site, setSite] = React.useState(globalSite);
  const [view, setView] = React.useState<"graph" | "table">("graph");
  const [arrange, setArrange] = React.useState<ArrangeMode>("hierarchy");
  const [groupFilter, setGroupFilter] = React.useState("all");
  const [tableGroupBy, setTableGroupBy] = React.useState<"none" | "group">("group");
  const [collapsedRows, setCollapsedRows] = React.useState<Set<string>>(new Set());
  const [selected, setSelected] = React.useState<string | null>(query.get("focus"));
  const [search, setSearch] = React.useState("");
  const [trace, setTrace] = React.useState<string[]>([]);
  const [collapsed, setCollapsed] = React.useState<Set<string>>(new Set());
  const [offsets, setOffsets] = React.useState<Record<string, Pt>>({});
  const [expanded, setExpanded] = React.useState<string | null>(null);
  const [managerOpen, setManagerOpen] = React.useState(false);
  const searchRef = React.useRef<HTMLInputElement>(null);
  const graphRef = React.useRef<TopologyGraphHandle>(null);

  React.useEffect(() => setSite(globalSite), [globalSite]);

  // "/" focuses the search field, like every other wire-down page
  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (e.key === "/" && tag !== "INPUT" && tag !== "TEXTAREA") {
        e.preventDefault();
        searchRef.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const topoQ = useTopology(site);

  const scoped = React.useMemo(
    () =>
      allAssets.filter((a) => {
        if (site !== "all" && a.site !== site) return false;
        if (groupFilter !== "all") {
          const mine = groupsOf(a.id);
          if (groupFilter === UNGROUPED_ID ? mine.length > 0 : !mine.some((g) => g.id === groupFilter)) return false;
        }
        return true;
      }),
    [allAssets, site, groupFilter, groupsOf]
  );

  // ---- analyst parent overrides (migration 0032) ---------------------------
  // A transparent L2 switch never appears as a routable hop, so the evidence
  // wires the hosts behind it straight to the router. When the analyst pins
  // a node's parent (asset detail → Edit identity), the pin always wins.
  const overrideByChild = React.useMemo(() => {
    const m = new Map<string, string>();
    scoped.forEach((a) => {
      if (a.parentOverride) m.set(a.id, a.parentOverride);
    });
    return m;
  }, [scoped]);

  // anchor parents: a pinned parent filtered out of the current view is still
  // drawn — hiding a switch that visible children hang from would strand them
  const anchorAssets = React.useMemo(() => {
    if (overrideByChild.size === 0) return [];
    const inScope = new Set(scoped.map((a) => a.id));
    const out: Asset[] = [];
    const seen = new Set<string>();
    for (const parentId of overrideByChild.values()) {
      if (inScope.has(parentId) || seen.has(parentId)) continue;
      seen.add(parentId);
      const a = allAssets.find((x) => x.id === parentId);
      if (a) out.push(a);
    }
    return out;
  }, [overrideByChild, scoped, allAssets]);

  const graphAssets = React.useMemo(() => [...scoped, ...anchorAssets], [scoped, anchorAssets]);

  // ---- evidence → tree ----------------------------------------------------
  const pairs = React.useMemo(
    () => resolveEvidencePairs(topoQ.data?.nodes ?? [], topoQ.data?.edges ?? [], graphAssets),
    [topoQ.data, graphAssets],
  );
  // pins ride with the evidence (upstream → child, confidence 1.0) so the
  // forced link always has a renderable edge, not just a re-parented node
  const linkPairs = React.useMemo(
    () =>
      pairs.length || overrideByChild.size
        ? [
            ...pairs,
            ...[...overrideByChild].map(([child, par]) => ({ source: par, target: child, confidence: 1 })),
          ]
        : syntheticSiteEdges(graphAssets),
    [pairs, overrideByChild, graphAssets],
  );
  const forceParent = React.useMemo(
    () => Object.fromEntries(overrideByChild),
    [overrideByChild],
  );
  const tree = React.useMemo(
    () =>
      deriveForest(
        graphAssets.map((a) => a.id),
        linkPairs.map((p) => ({ source: p.source, target: p.target, confidence: p.confidence })),
        infraRank,
        forceParent,
      ),
    [graphAssets, linkPairs, forceParent],
  );

  // collapsed branches hide their descendants in every arrangement
  const collapsedHidden = React.useMemo(() => {
    const hidden = new Set<string>();
    for (const id of collapsed) {
      const walk = (cur: string) => {
        for (const child of tree.children[cur] ?? []) {
          hidden.add(child);
          walk(child);
        }
      };
      walk(id);
    }
    return hidden;
  }, [collapsed, tree.children]);

  const active = React.useMemo(() => graphAssets.filter((a) => !collapsedHidden.has(a.id)), [graphAssets, collapsedHidden]);
  const activeSet = React.useMemo(() => new Set(active.map((a) => a.id)), [active]);

  const childFn = React.useCallback(
    (id: string) => (tree.children[id] ?? []).filter((c) => activeSet.has(c)),
    [tree.children, activeSet],
  );

  // ---- cluster trays (groups / sites arrangements) --------------------------
  const clusterSpec = React.useMemo(() => {
    if (arrange === "groups") {
      const titles: Record<string, ClusterMeta> = {};
      groups.forEach((g) => (titles[g.id] = { label: g.name, color: g.color }));
      titles[UNGROUPED_ID] = { label: "Ungrouped", color: NEUTRAL_COLOR };
      const firstGroupOf = new Map<string, string>();
      groups.forEach((g) => g.assetIds.forEach((id) => { if (!firstGroupOf.has(id)) firstGroupOf.set(id, g.id); }));
      return { keyOf: (id: string) => firstGroupOf.get(id) ?? UNGROUPED_ID, titles };
    }
    const titles: Record<string, ClusterMeta> = {};
    (sitesQ.data?.items ?? []).forEach((s) => {
      titles[s.id] = { label: s.name, color: SITE_COLOR };
    });
    const siteOf = new Map(graphAssets.map((a) => [a.id, a.site]));
    return { keyOf: (id: string) => siteOf.get(id) ?? "", titles };
  }, [arrange, groups, sitesQ.data, graphAssets]);

  // ---- canonical layout + user offsets -------------------------------------
  const layout = React.useMemo(
    () =>
      computeLayout(
        arrange,
        active.map((a) => ({ id: a.id, ip: a.ip })),
        tree.roots,
        childFn,
        offsets,
        arrange === "groups" || arrange === "sites" ? clusterSpec : undefined,
      ),
    [arrange, active, tree.roots, childFn, offsets, clusterSpec],
  );

  const graphNodes = React.useMemo<GraphNode[]>(() => {
    const pairIds = new Set<string>();
    linkPairs.forEach((p) => { pairIds.add(p.source); pairIds.add(p.target); });
    const rootSet = new Set(tree.roots);
    const isolatedInfra = new Set(
      active.filter((a) => !pairIds.has(a.id) && infraRank(a.type) <= 2).map((a) => a.id),
    );
    return active.map((a) => ({
      asset: a,
      r: rootSet.has(a.id) || isolatedInfra.has(a.id) ? 18 : baseRadius(a),
      hub: rootSet.has(a.id) || isolatedInfra.has(a.id),
    }));
  }, [active, tree.roots, linkPairs]);

  const graphLinks = React.useMemo<GraphLink[]>(() => {
    const evidence = pairs.length > 0;
    return tree.oriented
      .filter((e) => activeSet.has(e.source) && activeSet.has(e.target))
      .map((e, i) => ({
        id: String(i),
        source: e.source,
        target: e.target,
        observed: evidence && e.confidence >= 0.8,
        manual: !!(e.confidence >= 1 && overrideByChild.get(e.source) === e.target),
        confidence: e.confidence,
      }));
  }, [tree.oriented, activeSet, pairs.length, overrideByChild]);

  // a lit route always wins: the union of every pinned trace plus the selection
  const lit = React.useMemo(() => {
    const ids = [...trace];
    if (selected && !ids.includes(selected)) ids.push(selected);
    if (!ids.length) return null;
    return routeSet(ids, tree.parent, graphLinks);
  }, [trace, selected, tree.parent, graphLinks]);

  const matchSet = React.useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return new Set(active.map((a) => a.id));
    return new Set(
      active
        .filter((a) =>
          [a.ip, a.hostname ?? "", a.vendor ?? "", a.os ?? "", assetTypeMeta[a.type].label]
            .join(" ")
            .toLowerCase()
            .includes(needle),
        )
        .map((a) => a.id),
    );
  }, [search, active]);
  const hasQuery = search.trim().length > 0;

  // observed upstream neighbour per asset (tree parent = routes_to source)
  const upstreamByAsset = React.useMemo(() => {
    const m = new Map<string, GraphNode>();
    const byId = new Map(graphNodes.map((n) => [n.asset.id, n]));
    for (const [child, par] of Object.entries(tree.parent)) {
      const up = byId.get(par);
      if (up && !m.has(child)) m.set(child, up);
    }
    return m;
  }, [graphNodes, tree.parent]);

  // ---- interactions ---------------------------------------------------------
  const toggleTrace = (id: string) => setTrace((t) => (t.includes(id) ? t.filter((x) => x !== id) : [...t, id]));

  const toggleCollapse = (id: string) =>
    setCollapsed((c) => {
      const next = new Set(c);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const moveNode = (id: string, ox: number, oy: number) => setOffsets((o) => ({ ...o, [id]: { x: ox, y: oy } }));
  const resetLayout = () => setOffsets({});
  const resetFilters = () => {
    setSite("all");
    setGroupFilter("all");
    setSearch("");
  };

  // re-fit on arrangement / filter / collapse changes only — never mid-drag
  const fitKey = `${arrange}|${site}|${groupFilter}|${[...collapsed].sort().join(",")}|${active.length}|${view}`;

  // topology counters live in the app's bottom status bar, out of the way
  const setStatusSlot = useStatusSlot();
  const statsLine = React.useMemo(
    () => (
      <>
        <span>{graphNodes.length} nodes</span>
        <span className="text-muted-foreground/50">·</span>
        <span>{graphLinks.length} links</span>
        {(arrange === "groups" || arrange === "sites") && layout.boxes.length > 0 && (
          <>
            <span className="text-muted-foreground/50">·</span>
            <span>{layout.boxes.length} trays</span>
          </>
        )}
        {graphNodes.length > 0 && pairs.length === 0 && overrideByChild.size === 0 && (
          <>
            <span className="text-muted-foreground/50">·</span>
            <span className="text-warning">no trace evidence yet — run a trace scan to map links</span>
          </>
        )}
        {overrideByChild.size > 0 && (
          <>
            <span className="text-muted-foreground/50">·</span>
            <span>
              {overrideByChild.size} pinned parent{overrideByChild.size === 1 ? "" : "s"}
            </span>
          </>
        )}
      </>
    ),
    [graphNodes.length, graphLinks.length, arrange, layout.boxes.length, pairs.length, overrideByChild],
  );
  React.useEffect(() => {
    setStatusSlot(statsLine);
    return () => setStatusSlot(null);
  }, [setStatusSlot, statsLine]);

  const selNode = graphNodes.find((n) => n.asset.id === selected);

  /* ---------------- table grouping (same pattern as Assets) ---------------- */
  // the search box must do its job here too: in table view it filters rows
  // (in graph view matchSet drives the dim/spotlight behaviour instead)
  const tableNodes = React.useMemo(
    () => (hasQuery ? graphNodes.filter((n) => matchSet.has(n.asset.id)) : graphNodes),
    [hasQuery, graphNodes, matchSet],
  );
  const tableBuckets = React.useMemo(() => {
    if (tableGroupBy !== "group") return [];
    const out: { id: string; label: string; color?: string; icon?: string; items: GraphNode[] }[] = [];
    const claimedIds = new Set<string>();
    groups.forEach((g) => {
      const items = tableNodes.filter((n) => g.assetIds.includes(n.asset.id));
      if (items.length) {
        items.forEach((n) => claimedIds.add(n.asset.id));
        out.push({ id: g.id, label: g.name, color: g.color, icon: g.icon, items });
      }
    });
    const rest = tableNodes.filter((n) => !claimedIds.has(n.asset.id));
    if (rest.length) out.push({ id: UNGROUPED_ID, label: "Ungrouped", items: rest });
    return out;
  }, [tableGroupBy, tableNodes, groups]);

  const groupColorOf = React.useCallback(
    (id: string) => {
      const primary = groupsOf(id)[0];
      // empty string = ungrouped: the pin renders no group dot at all
      return primary ? colorOf(primary.color).solid : "";
    },
    [groupsOf],
  );

  return (
    <div className="flex h-[calc(100vh-8.5rem)] min-h-[600px] flex-col gap-4">
      <PageHeader
        title="Topology"
        description="Hierarchy wires assets under their elected gateway as a patch panel; Groups and Sites tray them side by side; Radial rings the segment. Solid links are observed routes, dashed are inferred, amber is an analyst-pinned parent. Click lights the route, shift-click pins a trace, double-click collapses a branch."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => setManagerOpen(true)}>
              <Boxes /> Groups
            </Button>
            <Select value={site} onValueChange={setSite}>
              <SelectTrigger size="sm" className="w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All sites</SelectItem>
                {(sitesQ.data?.items ?? []).map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    {s.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {view === "graph" && (
              <SegmentedControl
                ariaLabel="Arrange topology"
                value={arrange}
                onChange={(v) => setArrange(v as ArrangeMode)}
                options={[
                  { value: "hierarchy", label: "Hierarchy", icon: ListTree, title: "Tidy tree under the elected gateway, cables routed through the gutter" },
                  { value: "groups", label: "Groups", icon: Boxes, title: "Tray assets inside their asset group cards" },
                  { value: "sites", label: "Sites", icon: Network, title: "Tray assets per site" },
                  { value: "radial", label: "Radial", icon: Orbit, title: "Gateway centered, branches on weighted rings" },
                ]}
              />
            )}
            <Tabs value={view} onValueChange={(v) => setView(v as "graph" | "table")}>
              <TabsList className="h-8">
                <TabsTrigger value="graph" className="text-xs">
                  <Waypoints /> Graph
                </TabsTrigger>
                <TabsTrigger value="table" className="text-xs">
                  <Table2 /> Table
                </TabsTrigger>
              </TabsList>
            </Tabs>
          </>
        }
      />

      {/* compact filter row */}
      <div className="flex flex-wrap items-center gap-2">
        <GroupFilterButton value={groupFilter} onChange={setGroupFilter} site={site} onManage={() => setManagerOpen(true)} onNew={() => setManagerOpen(true)} />
        {view === "table" && <GroupingToggle value={tableGroupBy} onChange={setTableGroupBy} />}

        {trace.length > 0 && (
          <div className="flex items-center gap-1.5">
            <span className="text-[11px] uppercase tracking-wider text-muted-foreground">trace</span>
            {trace.map((id) => {
              const a = allAssets.find((x) => x.id === id);
              return (
                <button
                  key={id}
                  onClick={() => toggleTrace(id)}
                  className="flex items-center gap-1 rounded-md border bg-muted/40 px-2 py-1 font-mono text-[10.5px] text-foreground transition-colors hover:bg-muted"
                  title="Remove from trace"
                >
                  {a?.ip ?? id}
                  <X className="size-3" />
                </button>
              );
            })}
          </div>
        )}

        <div className="relative ml-auto">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            ref={searchRef}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search ip, host, os, vendor…  ( / )"
            className="h-8 w-[210px] pl-8 pr-16 text-[13px]"
          />
          {/* match counter lives INSIDE the input so it can never push the
              search field around — the previous sibling-span version shifted
              the bar left on every keystroke that changed the count */}
          {hasQuery && (
            <span className="pointer-events-none absolute right-7 top-1/2 -translate-y-1/2 text-[10px] tabular text-primary">
              {matchSet.size} match{matchSet.size === 1 ? "" : "es"}
            </span>
          )}
          {search && (
            <button onClick={() => setSearch("")} className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground" aria-label="Clear search">
              <X className="size-3.5" />
            </button>
          )}
        </div>
      </div>

      {view === "table" ? (
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
                        onClick={() =>
                          setCollapsedRows((s) => {
                            const n2 = new Set(s);
                            if (n2.has(b.id)) n2.delete(b.id);
                            else n2.add(b.id);
                            return n2;
                          })
                        }
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
      ) : (
        <div className="relative min-h-0 flex-1">
          <TopologyGraph
            ref={graphRef}
            nodes={graphNodes}
            links={graphLinks}
            mode={arrange}
            layout={layout}
            selectedId={selected}
            trace={trace}
            collapsed={collapsed}
            offsets={offsets}
            lit={lit}
            matchSet={matchSet}
            hasQuery={hasQuery}
            parentOf={(id) => tree.parent[id]}
            childrenOf={childFn}
            childrenStatic={tree.children}
            groupColorOf={groupColorOf}
            onSelect={setSelected}
            onToggleTrace={toggleTrace}
            onToggleCollapse={toggleCollapse}
            onMove={moveNode}
            onResetLayout={resetLayout}
            onResetFilters={resetFilters}
            fitKey={fitKey}
          />

          {/* Floating detail panel */}
          <div className={cn("pointer-events-none absolute right-3 top-14 z-20 w-80 transition-all duration-300 ease-[cubic-bezier(0.32,0.72,0,1)]", selNode ? "translate-x-0 opacity-100" : "translate-x-6 opacity-0")}>
            {selNode && (
              <Card className="pointer-events-auto gap-3 border-primary/30 bg-popover/95 shadow-2xl backdrop-blur-md">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 pr-6">
                    {selNode.asset.hostname ?? selNode.asset.ip}
                    {selNode.hub && <Badge variant="primary">hub</Badge>}
                    {overrideByChild.has(selNode.asset.id) && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Badge variant="medium" className="gap-1">
                            <Pin className="size-3" /> pinned parent
                          </Badge>
                        </TooltipTrigger>
                        <TooltipContent>
                          An analyst pinned this node's topology parent (Edit identity on the asset page) — the amber
                          link overrides the observed evidence.
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </CardTitle>
                  <Button variant="ghost" size="icon-xs" className="absolute right-3 top-3 text-muted-foreground" onClick={() => setSelected(null)}>
                    <X />
                  </Button>
                </CardHeader>
                <CardContent className="flex max-h-[calc(100vh-18rem)] flex-col gap-3 overflow-y-auto text-sm">
                  <div className="flex items-center gap-2">
                    <Mono>{selNode.asset.ip}</Mono>
                    <span className="text-muted-foreground">·</span>
                    <span className="text-muted-foreground">{assetTypeMeta[selNode.asset.type].label}</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    <ExposureBadge value={selNode.asset.exposure} />
                    <CriticalityBadge value={selNode.asset.criticality} />
                  </div>
                  {groupsOf(selNode.asset.id).length > 0 && (
                    <div className="flex flex-wrap gap-1">
                      {groupsOf(selNode.asset.id).map((g) => (
                        <GroupChip key={g.id} group={g} size="sm" onClick={() => setGroupFilter(g.id)} />
                      ))}
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted/30 p-2.5 text-xs">
                    <div>
                      <div className="text-muted-foreground">Risk</div>
                      <RiskMeter value={selNode.asset.risk} className="mt-1" />
                    </div>
                    <div>
                      <div className="text-muted-foreground">Findings</div>
                      <SeverityCountsInline counts={selNode.asset.findings ?? { critical: 0, high: 0, medium: 0, low: 0 }} className="mt-1.5" />
                    </div>
                    <div className="min-w-0">
                      <div className="text-muted-foreground">OS</div>
                      <div className="truncate">{selNode.asset.os ?? "Unknown"}</div>
                    </div>
                    <div>
                      <div className="text-muted-foreground">Last seen</div>
                      <div className="flex items-center gap-1.5">
                        <StatusDot tone="success" className="size-1.5" /> {timeAgo(selNode.asset.lastSeen)}
                      </div>
                    </div>
                  </div>
                  <NodePorts assetId={selNode.asset.id} />
                  <div className="grid grid-cols-2 gap-2 pt-1">
                    <Button size="sm" asChild>
                      <Link to={`/assets/${selNode.asset.id}`}>
                        <ExternalLink /> Open asset
                      </Link>
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => graphRef.current?.centerOn(selNode.asset.id)}>
                      <Crosshair /> Center
                    </Button>
                    <Button size="sm" variant={trace.includes(selNode.asset.id) ? "default" : "outline"} onClick={() => toggleTrace(selNode.asset.id)}>
                      {trace.includes(selNode.asset.id) ? <PinOff /> : <Pin />} {trace.includes(selNode.asset.id) ? "Unpin" : "Pin trace"}
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => toggleCollapse(selNode.asset.id)}>
                      <LayoutGrid /> {collapsed.has(selNode.asset.id) ? "Expand" : "Collapse"}
                    </Button>
                  </div>
                  <Button size="sm" variant="ghost" className="text-muted-foreground" asChild>
                    <Link to={`/assets/${selNode.asset.id}?tab=traces`}>
                      <Focus /> View trace path
                    </Link>
                  </Button>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      )}

      <GroupsManager open={managerOpen} onOpenChange={setManagerOpen} />
    </div>
  );

  /* table row + expansion, hoisted so grouped/ungrouped rendering can share it */
  function renderNodeRow(n: GraphNode) {
    const a = n.asset;
    const Icon = assetTypeMeta[a.type].icon;
    const isOpen = expanded === a.id;
    return (
      <React.Fragment key={a.id}>
        <tr className={cn("cursor-pointer border-b transition-colors hover:bg-accent/40", isOpen && "bg-accent/30")} onClick={() => setExpanded(isOpen ? null : a.id)}>
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

/** Side-panel open ports line fed by the asset bundle query. */
function NodePorts({ assetId }: { assetId: string }) {
  const bundleQ = useAsset(assetId);
  const open = (bundleQ.data?.ports ?? []).filter((p) => p.state === "open");
  return (
    <div className="text-xs text-muted-foreground">
      Open ports:{" "}
      {open.length ? (
        <span className="font-mono text-foreground">{open.map((p) => p.port).join(", ")}</span>
      ) : bundleQ.isLoading ? (
        "…"
      ) : (
        "none"
      )}
    </div>
  );
}
