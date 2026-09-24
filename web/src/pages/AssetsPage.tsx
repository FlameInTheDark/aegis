import * as React from "react";
import {
  ArrowDown,
  ArrowUp,
  ArrowUpDown,
  Boxes,
  ChevronDown,
  ChevronUp,
  Download,
  GripVertical,
  FileText,
  FolderPlus,
  Layers,
  MoreHorizontal,
  RefreshCw,
  RotateCcw,
  Search,
  Settings2,
  Trash2,
  X,
} from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import { colorOf, iconOf, UNGROUPED_ID, useGroups } from "@/lib/groups";
import { useAssets, useRediscoverAsset, useSites } from "@/lib/queries";
import type { Asset, AssetType, Criticality, Exposure } from "@/data/types";
import { useScope } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "@/components/ui/toaster";
import { DeleteAssetDialog } from "@/components/assets/DeleteAssetDialog";
import { AssetGroupCell, GroupChip } from "@/components/groups/GroupChip";
import { GroupFilterButton } from "@/components/groups/GroupFilterButton";
import { GroupsManager } from "@/components/groups/GroupsManager";
import {
  ConfidenceMeter,
  CriticalityBadge,
  EmptyState,
  ExposureBadge,
  GroupingToggle,
  Mono,
  PageHeader,
  RiskMeter,
  SeverityCountsInline,
  SeverityStack,
  StatusDot,
  TableFooterBar,
  usePagination,
} from "@/components/shared";

type SortKey = "asset" | "type" | "os" | "exposure" | "criticality" | "risk" | "lastSeen";

const criticalityRank: Partial<Record<Criticality, number>> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
const exposureRank: Partial<Record<Exposure, number>> = { internet: 3, dmz: 2, internal: 1, unknown: 0 };

/* ------------------------------------------------------------------ */
/* Columns                                                             */
/* ------------------------------------------------------------------ */
interface ColumnDef {
  id: string;
  label: string;
  /** cannot be hidden */
  locked?: boolean;
  sort?: SortKey;
  align?: "right";
}

const COLUMNS: ColumnDef[] = [
  { id: "asset", label: "Asset", locked: true, sort: "asset" },
  { id: "groups", label: "Groups" },
  { id: "type", label: "Type", sort: "type" },
  { id: "os", label: "OS", sort: "os" },
  { id: "confidence", label: "Confidence" },
  { id: "exposure", label: "Exposure", sort: "exposure" },
  { id: "criticality", label: "Criticality", sort: "criticality" },
  { id: "findings", label: "Findings" },
  { id: "risk", label: "Risk", sort: "risk" },
  { id: "agent", label: "Agent" },
  { id: "site", label: "Site" },
  { id: "mac", label: "MAC" },
  { id: "ports", label: "Open ports", align: "right" },
  { id: "lastSeen", label: "Last seen", sort: "lastSeen" },
];

// Keep the first view decision-oriented. Confidence, agent, site, MAC and port
// inventory stay available through Columns without making the default table wide.
const DEFAULT_VISIBLE = ["asset", "groups", "type", "os", "exposure", "criticality", "findings", "risk", "lastSeen"];
const DEFAULT_ORDER = COLUMNS.map((c) => c.id);
const COLS_KEY = "aegis.assets.columns.v2";

interface ColumnPrefs {
  order: string[];
  visible: string[];
}

/** Ordered, toggleable, reorderable and persisted column preferences. */
function useColumnPrefs() {
  const [prefs, setPrefs] = React.useState<ColumnPrefs>(() => {
    try {
      const raw = localStorage.getItem(COLS_KEY);
      if (raw) {
        const p = JSON.parse(raw) as ColumnPrefs;
        // heal against columns added/removed since the prefs were written
        const order = [...p.order.filter((id) => DEFAULT_ORDER.includes(id)), ...DEFAULT_ORDER.filter((id) => !p.order.includes(id))];
        return { order, visible: p.visible.filter((id) => DEFAULT_ORDER.includes(id)) };
      }
    } catch {
      /* ignore */
    }
    return { order: DEFAULT_ORDER, visible: DEFAULT_VISIBLE };
  });

  React.useEffect(() => {
    try {
      localStorage.setItem(COLS_KEY, JSON.stringify(prefs));
    } catch {
      /* ignore */
    }
  }, [prefs]);

  const isOn = React.useCallback((id: string) => prefs.visible.includes(id), [prefs.visible]);

  /** columns in display order, definitions resolved */
  const ordered = React.useMemo(() => prefs.order.map((id) => COLUMNS.find((c) => c.id === id)!).filter(Boolean), [prefs.order]);

  const toggle = (id: string) =>
    setPrefs((p) => ({ ...p, visible: p.visible.includes(id) ? p.visible.filter((x) => x !== id) : [...p.visible, id] }));

  const move = (id: string, dir: -1 | 1) =>
    setPrefs((p) => {
      const i = p.order.indexOf(id);
      const j = i + dir;
      if (i < 0 || j < 0 || j >= p.order.length) return p;
      const order = [...p.order];
      [order[i], order[j]] = [order[j], order[i]];
      return { ...p, order };
    });

  return {
    ordered,
    visibleCount: prefs.visible.length,
    isOn,
    toggle,
    move,
    reset: () => setPrefs({ order: DEFAULT_ORDER, visible: DEFAULT_VISIBLE }),
    showAll: () => setPrefs((p) => ({ ...p, visible: DEFAULT_ORDER })),
  };
}

/* ------------------------------------------------------------------ */
export function AssetsPage() {
  const { navigate, query } = useRouter();
  const { site } = useScope();
  const { groups, groupsOf } = useGroups();
  const sitesQ = useSites();
  const rediscoverM = useRediscoverAsset();

  const [q, setQ] = React.useState("");
  const [type, setType] = React.useState("all");
  const [crit, setCrit] = React.useState("all");
  const [exposure, setExposure] = React.useState("all");
  const [groupFilter, setGroupFilter] = React.useState(query.get("group") ?? "all");
  const [groupBy, setGroupBy] = React.useState<"none" | "group">("none");
  const [sort, setSort] = React.useState<{ key: SortKey; dir: "asc" | "desc" }>(() =>
    query.get("sort") === "risk" ? { key: "risk", dir: "desc" } : { key: "lastSeen", dir: "desc" }
  );
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [collapsedGroups, setCollapsedGroups] = React.useState<Set<string>>(new Set());
  const [managerOpen, setManagerOpen] = React.useState(false);
  const [managerSeed, setManagerSeed] = React.useState<{ groupId?: string; assetIds?: string[] }>({});
  const [deleteTarget, setDeleteTarget] = React.useState<Asset | null>(null);

  const cols = useColumnPrefs();

  const assetsRaw = useAssets({ site, search: q.trim() || undefined, type: type !== "all" ? type : undefined, criticality: crit !== "all" ? crit : undefined, limit: 200 });
  const filtered = React.useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (assetsRaw.data?.items ?? []).filter((a) => {
      if (site !== "all" && a.site !== site) return false;
      if (type !== "all" && a.type !== type) return false;
      if (crit !== "all" && a.criticality !== crit) return false;
      if (exposure !== "all" && a.exposure !== exposure) return false;
      if (groupFilter !== "all") {
        const mine = groupsOf(a.id);
        if (groupFilter === UNGROUPED_ID ? mine.length > 0 : !mine.some((g) => g.id === groupFilter)) return false;
      }
      if (!needle) return true;
      const groupNames = groupsOf(a.id).map((g) => g.name);
      return [a.ip, a.hostname, a.fqdn, a.vendor, a.os, ...a.tags, ...groupNames].some((v) => v?.toLowerCase().includes(needle));
    });
  }, [assetsRaw.data, q, type, crit, exposure, site, groupFilter, groupsOf]);

  const sorted = React.useMemo(() => {
    const dir = sort.dir === "asc" ? 1 : -1;
    const val = (a: Asset): string | number => {
      switch (sort.key) {
        case "asset":
          return a.ip.split(".").map((n) => n.padStart(3, "0")).join(".");
        case "type":
          return a.type;
        case "os":
          return a.os ?? "";
        case "exposure":
          return exposureRank[a.exposure] ?? 0;
        case "criticality":
          return criticalityRank[a.criticality] ?? 0;
        case "risk":
          return a.risk;
        case "lastSeen":
          return new Date(a.lastSeen).getTime();
      }
    };
    return [...filtered].sort((a, b) => {
      const va = val(a);
      const vb = val(b);
      if (va < vb) return -1 * dir;
      if (va > vb) return 1 * dir;
      return 0;
    });
  }, [filtered, sort]);

  const paged = usePagination(sorted, "assets");
  const rows = groupBy === "group" ? sorted : paged.slice;

  const toggleSort = (key: SortKey) =>
    setSort((s) => (s.key === key ? { key, dir: s.dir === "asc" ? "desc" : "asc" } : { key, dir: key === "asset" || key === "type" || key === "os" ? "asc" : "desc" }));

  const allOnPage = rows.length > 0 && rows.every((a) => selected.has(a.id));
  const togglePage = () =>
    setSelected((s) => {
      const n = new Set(s);
      if (allOnPage) rows.forEach((a) => n.delete(a.id));
      else rows.forEach((a) => n.add(a.id));
      return n;
    });

  const hasFilters = q || type !== "all" || crit !== "all" || exposure !== "all" || groupFilter !== "all";
  const clear = () => {
    setQ("");
    setType("all");
    setCrit("all");
    setExposure("all");
    setGroupFilter("all");
  };

  const exportCsv = () => {
    const rows = [ ["ip","hostname","fqdn","type","os","exposure","criticality","risk","first_seen","last_seen"], ...filtered.map((a) => [a.ip, a.hostname ?? "", a.fqdn ?? "", a.type, a.os ?? "", a.exposure, a.criticality, String(a.risk), a.firstSeen, a.lastSeen]) ];
    const csv = rows.map((r) => r.map((v) => `"${v.replace(/"/g, '""')}"`).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const el = document.createElement("a");
    el.href = url;
    el.download = "aegis-assets.csv";
    el.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  };

  const highRisk = filtered.filter((a) => a.risk >= 70).length;
  const unmanaged = filtered.filter((a) => !a.agentId).length;
  const ungrouped = filtered.filter((a) => groupsOf(a.id).length === 0).length;

  /* -------------------------------------------------- grouped buckets */
  const buckets = React.useMemo(() => {
    if (groupBy !== "group") return [];
    const out: { id: string; name: string; color?: string; icon?: string; items: Asset[] }[] = [];
    groups.forEach((g) => {
      const items = sorted.filter((a) => g.assetIds.includes(a.id));
      if (items.length) out.push({ id: g.id, name: g.name, color: g.color, icon: g.icon, items });
    });
    const rest = sorted.filter((a) => groupsOf(a.id).length === 0);
    if (rest.length) out.push({ id: UNGROUPED_ID, name: "Ungrouped", items: rest });
    return out;
  }, [groupBy, groups, sorted, groupsOf]);

  const colCount = cols.visibleCount + 2;

  /* -------------------------------------------------- cell renderers */
  const headCell = (c: ColumnDef) => {
    if (!cols.isOn(c.id)) return null;
    const content = c.sort ? (
      <button className="inline-flex items-center gap-1 hover:text-foreground cursor-pointer" onClick={() => toggleSort(c.sort!)}>
        {c.label}
        {sort.key === c.sort ? sort.dir === "asc" ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" /> : <ArrowUpDown className="size-3 opacity-40" />}
      </button>
    ) : (
      c.label
    );
    return (
      <TableHead key={c.id} className={c.align === "right" ? "text-right" : undefined}>
        {content}
      </TableHead>
    );
  };

  const bodyCell = (c: ColumnDef, a: Asset) => {
    if (!cols.isOn(c.id)) return null;
    const Icon = assetTypeMeta[a.type].icon;
    const device = a.endpoint;
    const fresh = Date.now() - new Date(a.lastSeen).getTime() < 5 * 60_000;
    switch (c.id) {
      case "asset":
        return (
          <TableCell key={c.id}>
            <div className="flex items-center gap-2.5">
              <span className="flex size-7 shrink-0 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                <Icon className="size-3.5" />
              </span>
              <div className="min-w-0 leading-tight">
                <div className="flex items-center gap-1.5">
                  <StatusDot tone={fresh ? "success" : "muted"} className="size-1.5" />
                  <span className="font-medium">{a.hostname ?? a.ip}</span>
                </div>
                <div className="font-mono text-[11px] text-muted-foreground">{a.hostname ? a.ip : (a.fqdn ?? "")}</div>
              </div>
            </div>
          </TableCell>
        );
      case "groups":
        return (
          <TableCell key={c.id}>
            <AssetGroupCell assetId={a.id} />
          </TableCell>
        );
      case "type":
        return (
          <TableCell key={c.id} className="text-muted-foreground">
            {assetTypeMeta[a.type].label}
          </TableCell>
        );
      case "os":
        return (
          <TableCell key={c.id}>
            <span className={cn(!a.os && "text-muted-foreground")}>{a.os ?? "Unknown"}</span>
          </TableCell>
        );
      case "confidence":
        return (
          <TableCell key={c.id}>
            <ConfidenceMeter value={a.osConfidence} />
          </TableCell>
        );
      case "exposure":
        return (
          <TableCell key={c.id}>
            <ExposureBadge value={a.exposure} />
          </TableCell>
        );
      case "criticality":
        return (
          <TableCell key={c.id}>
            <CriticalityBadge value={a.criticality} />
          </TableCell>
        );
      case "findings":
        return (
          <TableCell key={c.id}>
            <SeverityCountsInline counts={a.findings ?? { critical: 0, high: 0, medium: 0, low: 0 }} />
          </TableCell>
        );
      case "risk":
        return (
          <TableCell key={c.id}>
            <RiskMeter value={a.risk} />
          </TableCell>
        );
      case "agent":
        return (
          <TableCell key={c.id}>
            {device ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <span className="inline-flex items-center gap-1.5 text-xs">
                    <StatusDot tone={device.status === "online" ? "success" : device.status === "degraded" ? "warning" : "muted"} className="size-1.5" />
                    {device.version ? `v${device.version}` : "endpoint"}
                  </span>
                </TooltipTrigger>
                <TooltipContent>
                  {device.hostname} · {device.status} · last seen {device.lastSeen ? timeAgo(device.lastSeen) : "—"}
                </TooltipContent>
              </Tooltip>
            ) : (
              <span className="text-xs text-muted-foreground">none</span>
            )}
          </TableCell>
        );
      case "site":
        return (
          <TableCell key={c.id} className="text-xs text-muted-foreground">
            {(sitesQ.data?.items ?? []).find((s) => s.id === a.site)?.name ?? "—"}
          </TableCell>
        );
      case "ports":
        return (
          <TableCell key={c.id} className="tabular text-right text-muted-foreground">—</TableCell>
        );
      case "lastSeen":
        return (
          <TableCell key={c.id} className="tabular text-xs text-muted-foreground">
            {timeAgo(a.lastSeen)}
          </TableCell>
        );
      default:
        return null;
    }
  };

  const renderRow = (a: Asset) => (
    <TableRow key={a.id} data-state={selected.has(a.id) ? "selected" : undefined} className="cursor-pointer" onClick={() => navigate(`/assets/${a.id}`)}>
      <TableCell onClick={(e) => e.stopPropagation()}>
        <Checkbox
          checked={selected.has(a.id)}
          onCheckedChange={(v) =>
            setSelected((s) => {
              const n = new Set(s);
              if (v) n.add(a.id);
              else n.delete(a.id);
              return n;
            })
          }
          aria-label={`Select ${a.ip}`}
        />
      </TableCell>
      {cols.ordered.map((c) => bodyCell(c, a))}
      <TableCell onClick={(e) => e.stopPropagation()}>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-xs" className="text-muted-foreground">
              <MoreHorizontal />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => navigate(`/assets/${a.id}`)}>Open asset</DropdownMenuItem>
            <DropdownMenuItem
              onClick={() =>
                rediscoverM.mutate(a.id, {
                  onSuccess: (res) => toast({ title: `Rediscovery complete for ${a.hostname ?? a.ip}`, description: res.detail || `${res.findings_created} finding(s) matched.`, variant: "success" }),
                  onError: (e) => toast({ title: "Rediscovery failed", description: (e as Error).message, variant: "error" }),
                })
              }
            >
              <RefreshCw /> Rediscover
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate(`/scans?new=1&target=${a.ip}`)}>Scan this host…</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => {
                setManagerSeed({ assetIds: [a.id] });
                setManagerOpen(true);
              }}
            >
              <FolderPlus /> Add to new group…
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate(`/reports?new=1&asset=${a.id}`)}>
              <FileText /> Generate report
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => navigate(`/topology?focus=${a.id}`)}>Show in topology</DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem variant="destructive" onClick={() => setDeleteTarget(a)}>
              <Trash2 /> Delete asset…
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  );

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Assets"
        description="Every host and device observed by scanners, sensors and agents. Confidence reflects fingerprint evidence strength, not certainty."
        actions={
          <>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setManagerSeed({});
                setManagerOpen(true);
              }}
            >
              <Boxes /> Manage groups
            </Button>
            <Button variant="outline" size="sm" onClick={exportCsv}>
              <Download /> Export CSV
            </Button>
            <Button size="sm" onClick={() => navigate("/scans?new=1")}>
              <RefreshCw /> Discover
            </Button>
          </>
        }
      />

      {/* Summary strip */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Badge variant="outline" className="tabular gap-1.5 py-1">
          <Layers className="size-3 text-muted-foreground" /> {filtered.length} assets
        </Badge>
        <Badge variant={highRisk ? "high" : "outline"} className="tabular py-1">
          {highRisk} high-risk
        </Badge>
        <Badge variant="outline" className="tabular py-1">
          {unmanaged} without agent
        </Badge>
        <Badge variant={ungrouped ? "medium" : "outline"} className="tabular py-1 cursor-pointer" onClick={() => setGroupFilter(ungrouped ? UNGROUPED_ID : "all")}>
          {ungrouped} ungrouped
        </Badge>
      </div>

      {/* Compact group filter */}
      <div className="flex items-center gap-2">
        <GroupFilterButton
          value={groupFilter}
          onChange={setGroupFilter}
          site={site}
          onNew={() => {
            setManagerSeed({});
            setManagerOpen(true);
          }}
          onManage={() => {
            setManagerSeed({});
            setManagerOpen(true);
          }}
        />
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search hostname, IP, vendor, group…" className="h-8 pl-8 text-[13px]" />
        </div>
        <Select value={type} onValueChange={setType}>
          <SelectTrigger size="sm" className="w-[150px]">
            <span className="text-muted-foreground">Type:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All types</SelectItem>
            {(Object.keys(assetTypeMeta) as AssetType[]).map((t) => (
              <SelectItem key={t} value={t}>
                {assetTypeMeta[t].label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={crit} onValueChange={setCrit}>
          <SelectTrigger size="sm" className="w-[155px]">
            <span className="text-muted-foreground">Criticality:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        <Select value={exposure} onValueChange={setExposure}>
          <SelectTrigger size="sm" className="w-[145px]">
            <span className="text-muted-foreground">Exposure:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any</SelectItem>
            <SelectItem value="internet">Internet</SelectItem>
            <SelectItem value="dmz">DMZ</SelectItem>
            <SelectItem value="internal">Internal</SelectItem>
          </SelectContent>
        </Select>
        {hasFilters && (
          <Button variant="ghost" size="sm" onClick={clear} className="text-muted-foreground">
            <X /> Clear
          </Button>
        )}
        <div className="flex-1" />
        <GroupingToggle value={groupBy} onChange={setGroupBy} />

        {/* Columns */}
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="sm" className="text-muted-foreground">
              <Settings2 /> Columns
              <Badge variant="muted" className="tabular ml-0.5 px-1">
                {cols.visibleCount}
              </Badge>
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-64">
            <DropdownMenuLabel className="flex items-center justify-between">
              Columns
              <button className="text-[11px] font-normal text-primary hover:underline cursor-pointer" onClick={cols.reset}>
                Reset
              </button>
            </DropdownMenuLabel>
            <div className="px-2 pb-1 text-[10px] text-muted-foreground">Toggle visibility · reorder with the arrows</div>
            <DropdownMenuSeparator />
            <div className="max-h-80 overflow-y-auto">
              {cols.ordered.map((c, i) => (
                <DropdownMenuItem
                  key={c.id}
                  onSelect={(e) => e.preventDefault()}
                  onClick={() => !c.locked && cols.toggle(c.id)}
                  className={cn("group gap-2 pr-1", c.locked && "opacity-70")}
                >
                  <GripVertical className="size-3 shrink-0 text-muted-foreground/40" />
                  <Checkbox checked={cols.isOn(c.id)} disabled={c.locked} className="pointer-events-none" />
                  <span className="flex-1 truncate">{c.label}</span>
                  {c.locked ? (
                    <span className="pr-1 text-[10px] text-muted-foreground">fixed</span>
                  ) : (
                    <span className="flex shrink-0 opacity-0 transition-opacity group-hover:opacity-100 group-focus:opacity-100">
                      <button
                        className="rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 cursor-pointer"
                        disabled={i === 0}
                        onClick={(e) => {
                          e.stopPropagation();
                          cols.move(c.id, -1);
                        }}
                      >
                        <ChevronUp className="size-3" />
                      </button>
                      <button
                        className="rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground disabled:opacity-30 cursor-pointer"
                        disabled={i === cols.ordered.length - 1}
                        onClick={(e) => {
                          e.stopPropagation();
                          cols.move(c.id, 1);
                        }}
                      >
                        <ChevronDown className="size-3" />
                      </button>
                    </span>
                  )}
                </DropdownMenuItem>
              ))}
            </div>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={cols.showAll}>
              <RotateCcw /> Show all columns
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Bulk bar */}
      {selected.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 rounded-lg border border-primary/30 bg-primary/8 px-3 py-2 text-sm">
          <span className="tabular font-medium">{selected.size} selected</span>
          <div className="h-4 w-px bg-border" />
          <BulkGroupMenu assetIds={[...selected]} onNewGroup={() => {
            setManagerSeed({ assetIds: [...selected] });
            setManagerOpen(true);
          }} />
          <Button
            size="xs"
            variant="outline"
            onClick={() => {
              toast({ title: `Rediscovery queued for ${selected.size} asset${selected.size > 1 ? "s" : ""}`, description: "Re-matching against the current CVE index — no packets sent.", variant: "success" });
              setSelected(new Set());
            }}
          >
            <RefreshCw /> Rediscover
          </Button>
          <Button size="xs" variant="outline" onClick={() => navigate("/reports?new=1")}>
            <FileText /> Generate report
          </Button>
          <Button size="xs" variant="ghost" className="ml-auto text-muted-foreground" onClick={() => setSelected(new Set())}>
            Clear selection
          </Button>
        </div>
      )}

      {/* Table */}
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-10">
                <Checkbox checked={allOnPage} onCheckedChange={togglePage} aria-label="Select all" />
              </TableHead>
              {cols.ordered.map(headCell)}
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={colCount}>
                  <EmptyState
                    icon={Search}
                    title="No assets match"
                    description={hasFilters ? "Try loosening the filters or search terms." : "Run a discovery scan against an authorized site to populate the inventory."}
                    action={
                      hasFilters ? (
                        <Button variant="outline" size="sm" onClick={clear}>
                          Clear filters
                        </Button>
                      ) : (
                        <Button size="sm" onClick={() => navigate("/scans?new=1")}>
                          New scan
                        </Button>
                      )
                    }
                  />
                </TableCell>
              </TableRow>
            ) : groupBy === "group" ? (
              buckets.map((b) => {
                const c = b.color ? colorOf(b.color) : undefined;
                const Icon = b.icon ? iconOf(b.icon) : Boxes;
                const isCollapsed = collapsedGroups.has(b.id);
                const agg = b.items.reduce(
                  (acc, a) => ({
                    critical: acc.critical + (a.findings?.critical ?? 0),
                    high: acc.high + (a.findings?.high ?? 0),
                    medium: acc.medium + (a.findings?.medium ?? 0),
                    low: acc.low + (a.findings?.low ?? 0),
                  }),
                  { critical: 0, high: 0, medium: 0, low: 0 }
                );
                const avgRisk = Math.round(b.items.reduce((n, a) => n + a.risk, 0) / b.items.length);
                return (
                  <React.Fragment key={b.id}>
                    <TableRow className="border-y bg-muted/40 hover:bg-muted/60">
                      <TableCell colSpan={colCount} className="py-1.5">
                        <button
                          className="flex w-full items-center gap-2.5 text-left cursor-pointer"
                          onClick={() =>
                            setCollapsedGroups((s) => {
                              const n = new Set(s);
                              if (n.has(b.id)) n.delete(b.id);
                              else n.add(b.id);
                              return n;
                            })
                          }
                        >
                          <ChevronDown className={cn("size-3.5 text-muted-foreground transition-transform duration-200", isCollapsed && "-rotate-90")} />
                          <span className="flex size-6 items-center justify-center rounded-md" style={c ? { backgroundColor: c.soft, color: c.solid } : undefined}>
                            <Icon className={cn("size-3.5", !c && "text-muted-foreground")} />
                          </span>
                          <span className="text-sm font-semibold" style={c ? { color: c.solid } : undefined}>
                            {b.name}
                          </span>
                          <Badge variant="muted" className="tabular">
                            {b.items.length}
                          </Badge>
                          <div className="ml-auto flex items-center gap-4">
                            <SeverityCountsInline counts={agg} />
                            <div className="hidden w-28 sm:block">
                              <SeverityStack counts={agg} />
                            </div>
                            <span className="text-[11px] text-muted-foreground">avg risk</span>
                            <RiskMeter value={avgRisk} />
                          </div>
                        </button>
                      </TableCell>
                    </TableRow>
                    {!isCollapsed && b.items.map(renderRow)}
                  </React.Fragment>
                );
              })
            ) : (
              rows.map(renderRow)
            )}
          </TableBody>
        </Table>
        {groupBy === "none" ? (
          <TableFooterBar total={paged.total} page={paged.page} pageSize={paged.pageSize} onPage={paged.setPage} onPageSize={paged.setPageSize} label="assets">
            <span className="hidden text-muted-foreground sm:inline">· “Rediscover” re-runs CVE matching without scanning</span>
          </TableFooterBar>
        ) : (
          <div className="border-t px-3 py-2 text-xs text-muted-foreground">
            {sorted.length} assets in {buckets.length} group{buckets.length === 1 ? "" : "s"} · pagination is disabled while grouping
          </div>
        )}
      </div>

      <GroupsManager
        open={managerOpen}
        onOpenChange={(o) => {
          setManagerOpen(o);
          if (!o) setManagerSeed({});
        }}
        initialGroupId={managerSeed.groupId}
        preselectAssetIds={managerSeed.assetIds}
      />

      <DeleteAssetDialog
        asset={deleteTarget}
        open={!!deleteTarget}
        onOpenChange={(o) => {
          if (!o) setDeleteTarget(null);
        }}
        onDeleted={() => {
          // Deselect the removed row so the bulk bar never references a
          // deleted asset id.
          if (deleteTarget) {
            const id = deleteTarget.id;
            setSelected((s) => {
              const n = new Set(s);
              n.delete(id);
              return n;
            });
          }
          setDeleteTarget(null);
        }}
      />
    </div>
  );
}

/* ------------------------------------------------------------------ */
function BulkGroupMenu({ assetIds, onNewGroup }: { assetIds: string[]; onNewGroup: () => void }) {
  const { groups, assign, unassign } = useGroups();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="xs" variant="outline">
          <Boxes /> Groups
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-60">
        <DropdownMenuLabel>Add {assetIds.length} asset{assetIds.length === 1 ? "" : "s"} to</DropdownMenuLabel>
        <DropdownMenuSeparator />
        {groups.map((g) => {
          const all = assetIds.every((id) => g.assetIds.includes(id));
          return (
            <DropdownMenuItem
              key={g.id}
              onSelect={(e) => e.preventDefault()}
              onClick={() => {
                if (all) {
                  unassign(g.id, assetIds, {
                    onSuccess: () => toast({ title: `Removed from “${g.name}”`, variant: "warning" }),
                  });
                } else {
                  assign(g.id, assetIds, {
                    onSuccess: () =>
                      toast({
                        title: `Added to “${g.name}”`,
                        description: `${assetIds.length} asset${assetIds.length === 1 ? "" : "s"} assigned.`,
                        variant: "success",
                      }),
                  });
                }
              }}
              className="gap-2"
            >
              <Checkbox checked={all} className="pointer-events-none" />
              <GroupChip group={g} size="sm" />
            </DropdownMenuItem>
          );
        })}
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={onNewGroup}>
          <FolderPlus /> New group from selection…
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
