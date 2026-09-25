import * as React from "react";
import { Bell, ChevronRight, ChevronsUpDown, FilePlus2, Globe, Plus, Radar, Search } from "lucide-react";

import { timeAgo } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { navItems, assetTypeMeta } from "@/lib/domain";
import { colorOf, iconOf, useGroups } from "@/lib/groups";
import { useAuth } from "@/lib/auth";
import {
  useAssetGroups, useAsset, useConnections, useDetectionMatches,
  useFeeds, useMetricsSummary, useScans, useSites,
} from "@/lib/queries";
import { useAlertOccurrences } from "@/lib/queries.alerts";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from "@/components/ui/command";
import { Toaster } from "@/components/ui/toaster";
import { Sidebar } from "@/components/layout/Sidebar";
import { useNotificationStream } from "@/lib/scanstream";
import { Kbd, SeverityBadge, StatusDot } from "@/components/shared";

/* ------------------------------------------------------------------ */
/* Scope (site) context                                                */
/* ------------------------------------------------------------------ */
interface ScopeContextValue {
  site: string; // "all" | site id
  setSite: (s: string) => void;
}
const ScopeContext = React.createContext<ScopeContextValue>({ site: "all", setSite: () => {} });
export const useScope = () => React.useContext(ScopeContext);

/** Footer status slot — a page can pin live counters (e.g. topology
 *  "14 nodes · 13 links · 3 trays") into the app's bottom status bar so
 *  they stay available without spending in-page space. Setting null clears. */
const StatusSlotContext = React.createContext<(node: React.ReactNode) => void>(() => {});
export const useStatusSlot = () => React.useContext(StatusSlotContext);

/* ------------------------------------------------------------------ */
/* Live badge counts for the sidebar                                   */
/* ------------------------------------------------------------------ */
function useNavCounts(): Record<string, number | string> {
  const { site } = useScope();
  const siteParam = site === "all" ? {} : { site };
  const metrics = useMetricsSummary(site);
  const scans = useScans({ ...siteParam, state: "running", limit: 50 });
  const detections = useDetectionMatches({ status: "new", limit: 1 });
  const alerts = useAlertOccurrences({ state: "active", limit: 1 });
  const connections = useConnections();
  const groups = useAssetGroups();

  return React.useMemo(() => ({
    assets: metrics.data?.assets ?? 0,
    scans: scans.data?.items.length ?? 0,
    findings: metrics.data?.vulnerabilities ?? 0,
    detections: detections.data?.total ?? 0,
    alerts: alerts.data?.total ?? 0,
    connections: connections.data?.filter((c) => c.status === "pending" || !c.online).length ?? 0,
    groups: groups.data?.length ?? 0,
  }), [metrics.data, scans.data, detections.data, connections.data, groups.data]);
}

/* ------------------------------------------------------------------ */
/* Top bar                                                             */
/* ------------------------------------------------------------------ */
function Breadcrumbs() {
  const { segments } = useRouter();
  const root = navItems.find((n) => n.id === (segments[0] ?? "overview"));
  const assetId = segments[0] === "assets" ? segments[1] : undefined;
  const assetQ = useAsset(assetId);
  const asset = assetQ.data?.asset;
  const crumbs: { label: string; to?: string }[] = [];
  if (root) crumbs.push({ label: root.label, to: segments.length > 1 ? root.path : undefined });
  if (assetId) {
    crumbs.push({ label: asset ? (asset.hostname ?? asset.ip) : assetId });
  }
  return (
    <div className="flex min-w-0 items-center gap-1 text-sm">
      {crumbs.map((c, i) => (
        <React.Fragment key={i}>
          {i > 0 && <ChevronRight className="size-3.5 text-muted-foreground/60" />}
          {c.to ? (
            <Link to={c.to} className="text-muted-foreground hover:text-foreground">
              {c.label}
            </Link>
          ) : (
            <span className="truncate font-medium">{c.label}</span>
          )}
        </React.Fragment>
      ))}
    </div>
  );
}

function TopBar({ onOpenPalette }: { onOpenPalette: () => void }) {
  const { site, setSite } = useScope();
  const { navigate } = useRouter();
  const sites = useSites();
  const detections = useDetectionMatches({ limit: 4 });
  const recent = detections.data?.items ?? [];
  const unread = detections.data?.total ?? 0;

  return (
    <header className="flex h-14 shrink-0 items-center gap-3 border-b bg-background/80 pl-7 pr-4 backdrop-blur">
      <Breadcrumbs />
      <div className="flex-1" />

      <button
        onClick={onOpenPalette}
        className="hidden h-8 w-64 items-center gap-2 rounded-md border bg-muted/40 px-2.5 text-sm text-muted-foreground transition-colors hover:bg-muted md:flex cursor-pointer"
      >
        <Search className="size-4" />
        <span className="flex-1 text-left text-[13px]">Search or jump to…</span>
        <Kbd>⌘K</Kbd>
      </button>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" size="sm" className="gap-2 font-normal">
            <Globe className="size-3.5 text-muted-foreground" />
            <span className="max-w-32 truncate">{site === "all" ? "All sites" : sites.data?.items.find((s) => s.id === site)?.name ?? "Site"}</span>
            <ChevronsUpDown className="size-3 text-muted-foreground" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-60">
          <DropdownMenuLabel>Scope</DropdownMenuLabel>
          <DropdownMenuRadioGroup value={site} onValueChange={setSite}>
            <DropdownMenuRadioItem value="all">All sites</DropdownMenuRadioItem>
            {(sites.data?.items ?? []).map((s) => (
              <DropdownMenuRadioItem key={s.id} value={s.id} className="justify-between">
                <span className="truncate">{s.name}</span>
                <span className="tabular text-xs text-muted-foreground">{s.assets}</span>
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
          <DropdownMenuSeparator />
          <DropdownMenuItem onClick={() => navigate("/settings?tab=sites")}>Manage sites…</DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="ghost" size="icon-sm" className="relative text-muted-foreground">
            <Bell />
            {unread > 0 && (
              <span className="absolute right-1 top-1 flex size-3.5 items-center justify-center rounded-full bg-critical text-[9px] font-bold text-white">{unread}</span>
            )}
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-80 p-0">
          <div className="flex items-center justify-between px-3 py-2">
            <span className="text-sm font-medium">Recent detections</span>
            <Badge variant="critical" className="tabular">
              {unread} new
            </Badge>
          </div>
          <DropdownMenuSeparator className="my-0" />
          <div className="max-h-80 overflow-y-auto">
            {recent.map((d) => (
              <DropdownMenuItem key={d.id} className="items-start gap-3 rounded-none px-3 py-2.5" onClick={() => navigate(`/detections?id=${d.id}`)}>
                <SeverityBadge severity={d.severity} compact className="mt-0.5" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-[13px]">{d.title}</div>
                  <div className="text-[11px] text-muted-foreground">
                    {d.ruleType ?? "correlation"} · {timeAgo(d.timestamp)}
                  </div>
                </div>
              </DropdownMenuItem>
            ))}
            {recent.length === 0 && (
              <div className="px-3 py-6 text-center text-xs text-muted-foreground">No detections yet</div>
            )}
          </div>
          <DropdownMenuSeparator className="my-0" />
          <DropdownMenuItem className="justify-center rounded-none py-2 text-xs text-primary" onClick={() => navigate("/detections")}>
            View all detections
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

    </header>
  );
}

/* ------------------------------------------------------------------ */
/* Command palette                                                     */
/* ------------------------------------------------------------------ */
function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const { navigate } = useRouter();
  const { groups } = useGroups();
  const go = (to: string) => {
    onOpenChange(false);
    navigate(to);
  };
  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Search or jump to" description="Navigate pages, open assets, run actions">
      <CommandInput placeholder="Search assets, groups, pages, actions…" />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>
        <CommandGroup heading="Actions">
          <CommandItem onSelect={() => go("/scans?new=1")}>
            <Radar /> New scan
            <CommandShortcut>N</CommandShortcut>
          </CommandItem>
          <CommandItem onSelect={() => go("/reports?new=1")}>
            <FilePlus2 /> Generate report
          </CommandItem>
          <CommandItem onSelect={() => go("/connections?create=agent")}>
            <Plus /> Connect endpoint
          </CommandItem>
        </CommandGroup>
        <CommandSeparator />
        <CommandGroup heading="Asset groups">
          {groups.map((g) => {
            const c = colorOf(g.color);
            const Icon = iconOf(g.icon);
            return (
              <CommandItem key={g.id} value={`group ${g.name} ${g.description ?? ""}`} onSelect={() => go(`/assets?group=${g.id}`)}>
                <Icon style={{ color: c.solid }} />
                {g.name}
                <span className="ml-auto tabular text-xs text-muted-foreground">{g.assetIds.length} assets</span>
              </CommandItem>
            );
          })}
        </CommandGroup>
        <CommandSeparator />
        <CommandGroup heading="Pages">
          {navItems.map((n) => (
            <CommandItem key={n.id} value={`${n.label} ${n.description}`} onSelect={() => go(n.path)}>
              <n.icon /> {n.label}
              <span className="ml-2 text-xs text-muted-foreground">{n.description}</span>
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}

/* ------------------------------------------------------------------ */
/* Shell                                                               */
/* ------------------------------------------------------------------ */
export function AppShell({ children }: { children: React.ReactNode }) {
  useNotificationStream(); // org notification stream: toasts + badge invalidation
  const { user } = useAuth();
  const [collapsed, setCollapsed] = React.useState(() => localStorage.getItem("aegis.sidebar") === "collapsed");
  const [paletteOpen, setPaletteOpen] = React.useState(false);
  const [site, setSite] = React.useState("all");
  const [statusSlot, setStatusSlot] = React.useState<React.ReactNode>(null);
  const feeds = useFeeds();
  const lastFeedSync = feeds.data?.map((f) => f.lastSync).filter(Boolean).sort().at(-1);
  const counts = useNavCounts();

  React.useEffect(() => {
    localStorage.setItem("aegis.sidebar", collapsed ? "collapsed" : "expanded");
  }, [collapsed]);

  React.useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
        return;
      }
      const el = document.activeElement;
      const typing = el instanceof HTMLElement && (el.tagName === "INPUT" || el.tagName === "TEXTAREA" || el.isContentEditable);
      if (e.key === "[" && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        setCollapsed((c) => !c);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const scope = React.useMemo(() => ({ site, setSite }), [site]);
  const statusSlotApi = React.useMemo(() => setStatusSlot, []);

  return (
    <ScopeContext.Provider value={scope}>
      <StatusSlotContext.Provider value={statusSlotApi}>
        <div className="flex h-screen w-full overflow-hidden bg-background">
          <Sidebar collapsed={collapsed} onToggle={() => setCollapsed((c) => !c)} counts={counts} user={user ?? undefined} />
          <div className="flex min-w-0 flex-1 flex-col">
            <TopBar onOpenPalette={() => setPaletteOpen(true)} />
            <main id="main-scroll" className="flex-1 overflow-y-auto">
              <div className="mx-auto w-full max-w-[1600px] p-5 lg:p-6">{children}</div>
            </main>
            <footer className="flex h-7 shrink-0 items-center justify-between border-t bg-sidebar px-4 text-[11px] text-muted-foreground">
              <span className="flex min-w-0 items-center gap-3">
                <span className="flex items-center gap-1.5">
                  <StatusDot tone="success" className="size-1.5" /> scanner-local
                </span>
                <span className="flex items-center gap-1.5">
                  <StatusDot tone={lastFeedSync ? "success" : "warning"} className="size-1.5" /> feeds synced {lastFeedSync ? timeAgo(lastFeedSync) : "never"}
                </span>
                {statusSlot && <span className="flex items-center gap-1.5 border-l pl-3 tabular">{statusSlot}</span>}
              </span>
              <span className="hidden shrink-0 sm:inline">Authorized networks only · All actions audited</span>
            </footer>
          </div>
        </div>
        <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
        <Toaster />
      </StatusSlotContext.Provider>
    </ScopeContext.Provider>
  );
}
