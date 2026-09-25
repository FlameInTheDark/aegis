import * as React from "react";
import {
  ArrowLeft,
  BellPlus,
  Check,
  ChevronDown,
  Copy,
  Cpu,
  FileText,
  Gauge,
  MemoryStick,
  MoreHorizontal,
  Pencil,
  Radar,
  RefreshCw,
  Route,
  ShieldAlert,
  Loader2,
  Tag,
  Trash2,
  Waypoints,
  Package,
  Network as NetworkIcon,
  Activity,
} from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type {
  AssetIfaceSeries, AssetMetricLatest, AssetMetricPoint, AssetType, Criticality, Trace,
} from "@/data/types";
import { fmtBps, fmtBytes } from "@/lib/format";
import { VulnDiagnosticsSheet } from "@/components/vulns/VulnDiagnosticsSheet";
import { Chart } from "@/components/charts/Chart";
import { Sparkline } from "@/components/charts/Sparkline";
import {
  DEFAULT_PERF_PREFS, PERF_REFRESH_PRESETS, PERF_WINDOW_PRESETS, fmtRangeLabel, fmtTick,
  formatWindowLabel, initialTimelineExtent, loadPerfPrefs, minuteFloor, nextTimelineExtent,
  parseCustomWindow, savePerfPrefs, splitWindow, windowSeconds, type PerfPrefs,
} from "@/components/assets/perf-config";
import { useScope } from "@/components/layout/AppShell";
import {
  useAddNote, useAsset, useAssetFindings, useAssetMetrics, useAssetTraces, useAssets,
  useEvents, useRediscoverAsset, useSites, useSiteNetworks, useTopology, useUpdateAsset,
} from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle, CardAction } from "@/components/ui/card";
import { Tabs, TabsContent, TabsUnderlineList, TabsUnderlineTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "@/components/ui/toaster";
import { AssetGroupCell } from "@/components/groups/GroupChip";
import { DeleteAssetDialog } from "@/components/assets/DeleteAssetDialog";
import { VersionCell } from "@/components/ui/VersionCell";
import {
  ConfidenceMeter,
  CriticalityBadge,
  EmptyState,
  ExposureBadge,
  KeyValue,
  Mono,
  SeverityBadge,
  SeverityStack,
  severityMeta,
  StateBadge,
  StatusDot,
  RiskRing,
  TableFooterBar,
  usePagination,
} from "@/components/shared";

const findingTone = (s: string) => (s === "open" ? "danger" : s === "in_progress" ? "primary" : s === "acknowledged" ? "warning" : s === "resolved" ? "success" : "muted");

export function AssetDetailPage({ id }: { id: string }) {
  const { navigate, query } = useRouter();
  const { site: scopeSite } = useScope();
  const bundleQ = useAsset(id);
  const bundle = bundleQ.data;
  const asset = bundle?.asset;
  const findingsQ = useAssetFindings(id);
  const tracesQ = useAssetTraces(id);
  const sites = useSites();
  const allAssets = useAssets({ site: scopeSite, limit: 200 });
  // long inventories paginate client-side over the full bundle lists
  const pagedPorts = usePagination(bundle?.ports ?? [], "asset-ports");
  const pagedSoftware = usePagination(bundle?.software ?? [], "asset-software");
  const topologyQ = useTopology(scopeSite);
  const rediscoverM = useRediscoverAsset();
  const updateAsset = useUpdateAsset();
  const addNote = useAddNote();
  // Performance history of the bound endpoint device (empty until a
  // connector binds + reports this asset). The viewer's mode/window/refresh
  // preferences persist locally; range mode is static by design.
  const [perf, setPerf] = React.useState<PerfPrefs>(() =>
    typeof window === "undefined" ? DEFAULT_PERF_PREFS : loadPerfPrefs(window.localStorage),
  );
  React.useEffect(() => {
    if (typeof window !== "undefined") savePerfPrefs(window.localStorage, perf);
  }, [perf]);
  const metricsQ = useAssetMetrics(
    id,
    perf.mode === "range"
      ? { mode: "range", window: "", from: perf.from, to: perf.to, refreshMs: 0 }
      : { mode: "latest", window: perf.window, refreshMs: perf.refreshMs },
  );

  const [tab, setTab] = React.useState(query.get("tab") ?? "overview");
  const [tagsOpen, setTagsOpen] = React.useState(false);
  const [identityOpen, setIdentityOpen] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [diagOpen, setDiagOpen] = React.useState(false);
  // Every hook runs unconditionally — the bundle id may not exist yet, so the
  // detail queries key off empty strings and stay idle until it resolves.
  const siteNetworksQ = useSiteNetworksIsolated(asset?.site);
  const assetEventQ = useEvents({ srcIp: asset?.ip, limit: 6, enabled: !!asset });
  const eventsForAsset = assetEventQ.data?.items ?? [];

  React.useEffect(() => {
    setTab(query.get("tab") ?? "overview");
  }, [query]);

  if (bundleQ.isLoading) {
    // Neutral loading signal: the red threat shield used to present a normal
    // network fetch as a security alarm.
    return (
      <p className="flex items-center justify-center gap-2 px-4 py-16 text-sm text-muted-foreground">
        <Loader2 className="size-4 animate-spin" /> Loading asset…
      </p>
    );
  }
  if (!asset || !bundle) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="Asset not found"
        description={`No asset with id “${id}” exists in the inventory.`}
        action={
          <Button variant="outline" size="sm" asChild>
            <Link to="/assets">
              <ArrowLeft /> Back to assets
            </Link>
          </Button>
        }
      />
    );
  }

  const Icon = assetTypeMeta[asset.type].icon;
  const endpointDevice = bundle.endpoint;
  const assetFindings = findingsQ.data ?? [];
  const openFindings = assetFindings.filter((f) => f.status !== "resolved" && f.status !== "accepted_risk" && f.status !== "false_positive" && f.status !== "suppressed");
  const traces = tracesQ.data?.traces ?? [];
  const trace: Trace | undefined = traces[0];
  const site = sites.data?.items.find((s) => s.id === asset.site);
  const openPorts = bundle.ports.filter((p) => p.state === "open");
  // Primary NIC for the Identity card: the interface observed at the
  // asset's address (any of its recorded addresses, primary flagged by the
  // backend), else the first one carrying a MAC. Interfaces only exist
  // once a scan/agent reported the host's MAC (migration 0030 fixed the
  // upserts that silently failed before, so older assets may have none).
  const primaryIface =
    bundle.interfaces.find((i) => i.mac && i.addresses.some((a) => a.ip === asset.ip)) ??
    bundle.interfaces.find((i) => i.mac && i.ip === asset.ip) ??
    bundle.interfaces.find((i) => i.mac);

  const node = (topologyQ.data?.nodes ?? []).find((n) => n.assetId === asset.id);
  const neighborIds = node
    ? (topologyQ.data?.edges ?? [])
        .filter((e) => e.srcNodeId === node.id || e.dstNodeId === node.id)
        .map((e) => (e.srcNodeId === node.id ? e.dstNodeId : e.srcNodeId))
        .filter((x) => x !== node.id)
    : [];
  const neighbors = (topologyQ.data?.nodes ?? [])
    .filter((n) => neighborIds.includes(n.id) && n.assetId)
    .map((n) => (allAssets.data?.items ?? []).find((a) => a.id === n.assetId))
    .filter(Boolean);

  const rediscover = () => {
    rediscoverM.mutate(asset.id, {
      onSuccess: (res) =>
        toast({
          title: "Rediscovery complete",
          description: res.detail || `${res.findings_created} finding(s) matched for ${asset.hostname ?? asset.ip}.`,
          variant: "success",
        }),
      onError: (e) => toast({ title: "Rediscovery failed", description: (e as Error).message, variant: "error" }),
    });
  };

  const changeTab = (t: string) => {
    setTab(t);
    navigate(`/assets/${asset.id}?tab=${t}`, { replace: true });
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Header */}
      <div className="flex flex-col gap-4">
        <Link to="/assets" className="inline-flex w-fit items-center gap-1 text-xs text-muted-foreground hover:text-foreground">
          <ArrowLeft className="size-3.5" /> Assets
        </Link>
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="flex min-w-0 items-start gap-4">
            <span className="flex size-12 shrink-0 items-center justify-center rounded-xl border bg-muted/40 text-muted-foreground">
              <Icon className="size-6" />
            </span>
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <h1 className="text-xl font-semibold tracking-tight">{asset.hostname ?? asset.ip}</h1>
                {asset.hostname && <Mono className="text-muted-foreground">{asset.ip}</Mono>}
                <ExposureBadge value={asset.exposure} />
                <CriticalityBadge value={asset.criticality} />
                {(asset.nameOverride || asset.typeOverride || asset.parentOverride) && (
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Badge variant="primary" className="gap-1">
                        <Pencil className="size-3" /> overridden
                      </Badge>
                    </TooltipTrigger>
                    <TooltipContent>
                      An analyst correction is active — the scanned value is kept
                      and can be restored via Edit identity.
                    </TooltipContent>
                  </Tooltip>
                )}
                <AssetGroupCell assetId={asset.id} max={4} />
                {asset.tags.map((t) => (
                  <Badge key={t} variant="muted" className="gap-1">
                    <Tag className="size-3" /> {t}
                  </Badge>
                ))}
              </div>
              <p className="mt-1 flex flex-wrap items-center gap-x-2 text-sm text-muted-foreground">
                <span>{assetTypeMeta[asset.type].label}</span>
                <span>·</span>
                <span>{asset.os ?? "OS unknown"}</span>
                {asset.vendor && (
                  <>
                    <span>·</span>
                    <span>
                      {asset.vendor} {asset.model}
                    </span>
                  </>
                )}
                <span>·</span>
                <span>{site?.name ?? "site"}</span>
                <span>·</span>
                <span>first seen {timeAgo(asset.firstSeen)}</span>
                <span>·</span>
                <span className="inline-flex items-center gap-1.5">
                  <StatusDot tone={Date.now() - +new Date(asset.lastSeen) < 5 * 60_000 ? "success" : "muted"} className="size-1.5" />
                  last seen {timeAgo(asset.lastSeen)}
                </span>
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Tooltip>
              <TooltipTrigger asChild>
                <div className="flex items-center gap-2 rounded-lg border bg-card px-3 py-1.5">
                  <RiskRing value={asset.risk} size={40} stroke={4} />
                  <div className="leading-tight">
                    <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Risk score</div>
                    <div className="text-xs text-muted-foreground">
                      {openFindings.length} open finding{openFindings.length === 1 ? "" : "s"}
                    </div>
                  </div>
                </div>
              </TooltipTrigger>
              <TooltipContent>Risk = exposure × criticality × weighted open findings</TooltipContent>
            </Tooltip>
            <Button variant="outline" size="sm" onClick={() => navigate(`/reports?new=1&asset=${asset.id}`)}>
              <FileText /> Generate report
            </Button>
            <Button variant="outline" size="sm" onClick={rediscover} disabled={rediscoverM.isPending}>
              <RefreshCw className={cn(rediscoverM.isPending && "animate-spin")} /> {rediscoverM.isPending ? "Matching…" : "Rediscover"}
            </Button>
            <Button size="sm" onClick={() => navigate(`/scans?new=1&target=${asset.ip}`)}>
              <Radar /> Scan
            </Button>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="icon-sm" aria-label="Asset actions">
                  <MoreHorizontal />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => navigate(`/topology?focus=${asset.id}`)}>
                  <Waypoints /> Show in topology
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setIdentityOpen(true)}>
                  <Pencil /> Edit identity
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => setTagsOpen(true)}>
                  <Tag /> Edit tags
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={() => setTagsOpen(true)}>
                  <Tag /> Edit tags &amp; notes
                </DropdownMenuItem>
                <DropdownMenuSeparator />
                <DropdownMenuItem variant="destructive" onClick={() => setDeleteOpen(true)}>
                  <Trash2 /> Delete asset…
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </div>

      <Tabs value={tab} onValueChange={changeTab}>
        <TabsUnderlineList>
          <TabsUnderlineTrigger value="overview">Overview</TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="network">Network</TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="services">
            Services <Badge variant="muted" className="tabular px-1.5">{openPorts.length}</Badge>
          </TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="software">
            Software <Badge variant="muted" className="tabular px-1.5">{bundle.software.length}</Badge>
          </TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="findings">
            Findings{" "}
            <Badge variant={openFindings.length ? "critical" : "muted"} className="tabular px-1.5">
              {openFindings.length}
            </Badge>
          </TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="traces">Traces</TabsUnderlineTrigger>
          {endpointDevice && <TabsUnderlineTrigger value="performance">Performance</TabsUnderlineTrigger>}
        </TabsUnderlineList>

        {/* ---------------- Overview ---------------- */}
        <TabsContent value="overview" className="grid gap-4 xl:grid-cols-3">
          <Card className="xl:col-span-2">
            <CardHeader>
              <CardTitle>Identity</CardTitle>
              <CardDescription>Merged from nmap fingerprints{endpointDevice ? ", endpoint inventory" : ""} and DNS</CardDescription>
            </CardHeader>
            <CardContent className="grid gap-x-8 sm:grid-cols-2">
              <div className="divide-y">
                <KeyValue label="Address" mono>
                  {asset.ip}
                </KeyValue>
                <KeyValue label="FQDN" mono>
                  {asset.fqdn ?? "—"}
                </KeyValue>
                <KeyValue label="MAC address" mono>
                  {primaryIface?.mac ?? "—"}
                  {primaryIface?.vendor && (
                    <span className="text-muted-foreground"> · {primaryIface.vendor}</span>
                  )}
                </KeyValue>
                <KeyValue label="Vendor">{asset.vendor ?? "—"}</KeyValue>
                <KeyValue label="Model">{asset.model ?? "—"}</KeyValue>
                <KeyValue label="Device type">{assetTypeMeta[asset.type].label}</KeyValue>
                <KeyValue label="Owner">{asset.owner ?? "—"}</KeyValue>
              </div>
              <div className="divide-y">
                <KeyValue label="Operating system">{asset.os ?? "Unknown"}</KeyValue>
                <KeyValue label="OS confidence">
                  <span className="inline-flex items-center gap-2">
                    <ConfidenceMeter value={asset.osConfidence} />
                    <span className="text-xs text-muted-foreground">via {asset.osSources.join(", ") || "fingerprint"}</span>
                  </span>
                </KeyValue>
                <KeyValue label="Criticality">
                  <CriticalitySelect
                    value={asset.criticality}
                    onChange={(c) =>
                      updateAsset.mutate(
                        { id: asset.id, criticality: c },
                        { onSuccess: () => toast({ title: "Criticality updated", variant: "success" }) },
                      )
                    }
                  />
                </KeyValue>
                <KeyValue label="Exposure">
                  <ExposureBadge value={asset.exposure} />
                </KeyValue>
                <KeyValue label="Site">{site?.name ?? "—"}</KeyValue>
                <KeyValue label="Risk">
                  <span className="tabular font-semibold">{asset.risk}</span>
                  <span className="text-muted-foreground"> / 100</span>
                </KeyValue>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Security posture</CardTitle>
              <CardDescription>Open findings by severity</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <div className="grid grid-cols-4 gap-2">
                {(["critical", "high", "medium", "low"] as const).map((k) => (
                  <button
                    key={k}
                    onClick={() => changeTab("findings")}
                    className={cn(
                      "flex flex-col items-center rounded-lg border py-2.5 transition-colors hover:bg-accent/40 cursor-pointer",
                      bundle.findingsCounts[k] > 0 && "border-current/20"
                    )}
                  >
                    <span className={cn("tabular text-xl font-semibold", bundle.findingsCounts[k] > 0 ? severityMeta[k].text : "text-muted-foreground")}>
                      {bundle.findingsCounts[k]}
                    </span>
                    <span className="text-[10px] uppercase tracking-wider text-muted-foreground">{k}</span>
                  </button>
                ))}
              </div>
              <div>
                <div className="mb-1.5 flex items-center justify-between text-[11px] text-muted-foreground">
                  <span className="font-semibold uppercase tracking-wider">Distribution</span>
                  <span className="tabular">{bundle.findingsCounts.open} open</span>
                </div>
                <SeverityStack counts={bundle.findingsCounts} height="h-2" />
              </div>
              <div className="border-t pt-3">
                <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Endpoint collection</div>
                {endpointDevice ? (
                  <Link to="/connections" className="flex items-center gap-3 rounded-lg border p-2.5 transition-colors hover:bg-accent/40">
                    <span className="flex size-8 items-center justify-center rounded-md bg-primary/10 text-primary">
                      <Cpu className="size-4" />
                    </span>
                    <div className="min-w-0 flex-1 leading-tight">
                      <div className="flex items-center gap-2 text-sm font-medium">
                        {endpointDevice.hostname} {endpointDevice.version && <Badge variant="muted">v{endpointDevice.version}</Badge>}
                      </div>
                      <div className="text-xs text-muted-foreground">last seen {endpointDevice.lastSeen ? timeAgo(endpointDevice.lastSeen) : "—"} · via a connector</div>
                    </div>
                    <StateBadge label={endpointDevice.status} tone={endpointDevice.status === "online" ? "success" : endpointDevice.status === "degraded" ? "warning" : "muted"} />
                  </Link>
                ) : (
                  <div className="flex items-center justify-between gap-3 rounded-lg border border-dashed p-2.5">
                    <span className="text-xs text-muted-foreground">No endpoint collector — software inventory is limited to network fingerprints.</span>
                    <Button size="xs" variant="outline" asChild>
                      <Link to="/connections?create=agent">Connect endpoint</Link>
                    </Button>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>

          <Card className="xl:col-span-2">
            <CardHeader>
              <CardTitle>Detected ports &amp; services</CardTitle>
              <CardDescription>{openPorts.length} open · {bundle.ports.length - openPorts.length} other</CardDescription>
              <CardAction>
                <Button variant="ghost" size="xs" onClick={() => changeTab("services")}>
                  View all
                </Button>
              </CardAction>
            </CardHeader>
            <CardContent>
              {bundle.ports.length === 0 ? (
                <EmptyState compact icon={NetworkIcon} title="No listening services detected" description="Host responded to discovery but no TCP/UDP ports were open in the scanned range." />
              ) : (
                <div className="flex flex-wrap gap-2">
                  {bundle.ports.map((p) => (
                    <button
                      key={`${p.proto}${p.port}`}
                      onClick={() => changeTab("services")}
                      className={cn(
                        "group inline-flex items-center gap-1.5 rounded-md border bg-muted/30 px-2 py-1 font-mono text-xs transition-colors hover:border-primary/40 hover:bg-accent/50 cursor-pointer",
                        p.state !== "open" && "border-dashed opacity-70"
                      )}
                    >
                      <span className="font-semibold">{p.port}</span>
                      <span className="text-muted-foreground">/{p.proto}</span>
                      <span className="text-muted-foreground">·</span>
                      <span>{p.service}</span>
                      {p.version && <span className="text-muted-foreground">{p.version}</span>}
                    </button>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Recent activity</CardTitle>
              <CardDescription>Sensor events from this address</CardDescription>
            </CardHeader>
            <CardContent className="px-0">
              {eventsForAsset.length === 0 ? (
                <EmptyState compact icon={Activity} title="No recent events" />
              ) : (
                <ul className="divide-y">
                  {eventsForAsset.slice(0, 5).map((e) => (
                    <li key={e.id} className="flex gap-3 px-4 py-2 text-sm">
                      <StatusDot tone={e.level === "critical" || e.level === "error" ? "danger" : e.level === "warning" ? "warning" : "muted"} className="mt-1.5 size-1.5" />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[13px]">{e.message}</div>
                        <div className="text-[11px] text-muted-foreground">{e.timestamp && timeAgo(e.timestamp)}</div>
                      </div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---------------- Network ---------------- */}
        <TabsContent value="network" className="grid gap-4 xl:grid-cols-3">
          <Card className="xl:col-span-2">
            <CardHeader>
              <CardTitle>Interfaces</CardTitle>
              <CardDescription>Addresses observed on this host</CardDescription>
            </CardHeader>
            <CardContent className="px-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="pl-4">Interface</TableHead>
                    <TableHead>Address</TableHead>
                    <TableHead>MAC</TableHead>
                    <TableHead>MAC vendor</TableHead>
                    <TableHead>VLAN</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {bundle.interfaces.length === 0 ? (
                    <TableRow className="hover:bg-transparent">
                      <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">No interfaces recorded</TableCell>
                    </TableRow>
                  ) : (
                    bundle.interfaces.map((i) => (
                      <TableRow key={i.name + i.ip}>
                        <TableCell className="pl-4 font-medium">{i.name}</TableCell>
                        <TableCell>
                          {/* Every address the endpoint/scan ever observed on
                              this NIC (agent inventory records IPv4 AND IPv6);
                              the primary is the management-facing one picked by
                              the hub. Fallback keeps old payloads readable. */}
                          {i.addresses.length > 0 ? (
                            <div className="flex flex-col items-start gap-0.5">
                              {i.addresses.map((a) => (
                                <span key={a.ip} className="flex items-center gap-1.5">
                                  <Mono className={a.is_primary ? "" : "text-muted-foreground"}>{a.ip}</Mono>
                                  {a.is_primary && (
                                    <span className="rounded bg-muted px-1 py-px text-[10px] uppercase tracking-wide text-muted-foreground">
                                      primary
                                    </span>
                                  )}
                                </span>
                              ))}
                            </div>
                          ) : (
                            <Mono className="text-muted-foreground">{i.ip || "—"}</Mono>
                          )}
                        </TableCell>
                        <TableCell>
                          <Mono className="text-muted-foreground">{i.mac ?? "—"}</Mono>
                        </TableCell>
                        <TableCell className="text-muted-foreground">{i.vendor ?? "—"}</TableCell>
                        <TableCell className="tabular text-muted-foreground">{i.vlan ?? "—"}</TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Path &amp; exposure</CardTitle>
            </CardHeader>
            <CardContent className="divide-y">
              <KeyValue label="Hops from scanner">{trace ? trace.hops.length : "—"}</KeyValue>
              <KeyValue label="Exposure">
                <ExposureBadge value={asset.exposure} />
              </KeyValue>
              <KeyValue label="DNS names">{asset.fqdn ?? "—"}</KeyValue>
              <KeyValue label="Site networks" mono>
                {(siteNetworksQ.data?.items ?? []).map((n) => n.cidr).join(", ") || "—"}
              </KeyValue>
              <KeyValue label="Notes">
                <span className="line-clamp-3 whitespace-pre-wrap text-left text-xs">{asset.notes ?? "—"}</span>
              </KeyValue>
            </CardContent>
          </Card>

          <Card className="xl:col-span-3">
            <CardHeader>
              <CardTitle>Topology neighbors</CardTitle>
              <CardDescription>Assets adjacent to this host in the inferred network graph</CardDescription>
              <CardAction>
                <Button variant="ghost" size="xs" asChild>
                  <Link to={`/topology?focus=${asset.id}`}>
                    <Waypoints /> Open topology
                  </Link>
                </Button>
              </CardAction>
            </CardHeader>
            <CardContent>
              <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
                {neighbors.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No inferred neighbors yet — run discovery scans to build the topology graph.</p>
                ) : (
                  neighbors.slice(0, 8).map((n) => {
                    if (!n) return null;
                    const NIcon = assetTypeMeta[n.type].icon;
                    return (
                      <Link key={n.id} to={`/assets/${n.id}`} className="flex items-center gap-2.5 rounded-lg border p-2 transition-colors hover:bg-accent/40">
                        <span className="flex size-7 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                          <NIcon className="size-3.5" />
                        </span>
                        <div className="min-w-0 leading-tight">
                          <div className="truncate text-sm font-medium">{n.hostname ?? n.ip}</div>
                          <div className="font-mono text-[11px] text-muted-foreground">{n.ip}</div>
                        </div>
                      </Link>
                    );
                  })
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ---------------- Services ---------------- */}
        <TabsContent value="services">
          <Card className="py-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Port</TableHead>
                  <TableHead>State</TableHead>
                  <TableHead>Service</TableHead>
                  <TableHead>Product / version</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead className="text-right pr-4">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bundle.ports.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={6}>
                      <EmptyState icon={NetworkIcon} title="No services detected" description="Run an inventory scan to enumerate listening services." action={<Button size="sm" onClick={() => navigate(`/scans?new=1&target=${asset.ip}`)}>Scan host</Button>} />
                    </TableCell>
                  </TableRow>
                ) : (
                  pagedPorts.slice.map((p) => (
                    <TableRow key={`${p.proto}${p.port}`}>
                      <TableCell className="pl-4">
                        <Mono className="font-semibold">
                          {p.port}
                          <span className="font-normal text-muted-foreground">/{p.proto}</span>
                        </Mono>
                      </TableCell>
                      <TableCell>
                        <StateBadge label={p.state} tone={p.state === "open" ? "success" : "muted"} />
                      </TableCell>
                      <TableCell className="font-medium">{p.service}</TableCell>
                      <TableCell className="text-muted-foreground">
                        {p.product ?? "—"} {p.version && <VersionCell version={p.version} meta={p.versionMeta} />}
                      </TableCell>
                      <TableCell>
                        <div className="flex w-24 items-center gap-2">
                          <Progress value={p.confidence ?? 0} className="h-1" />
                          <span className="tabular text-xs text-muted-foreground">{p.confidence ?? 0}%</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-right pr-4">
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" size="xs" onClick={() => setDiagOpen(true)}>
                            Diagnostics
                          </Button>
                          <Button variant="ghost" size="xs" onClick={() => navigate(`/vulnerabilities?q=${encodeURIComponent(p.product ?? p.service)}`)}>
                            Search CVEs
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {pagedPorts.slice.length > 0 && <TableFooterBar total={pagedPorts.total} page={pagedPorts.page} pageSize={pagedPorts.pageSize} onPage={pagedPorts.setPage} onPageSize={pagedPorts.setPageSize} label="services" />}
          </Card>
        </TabsContent>

        {/* ---------------- Software ---------------- */}
        <TabsContent value="software">
          <Card className="py-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Package</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Ecosystem</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bundle.software.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={5}>
                      <EmptyState
                        icon={Package}
                        title="No software inventory"
                        description="Connect a collector to this asset's connector or run an ssh_inventory scan to collect installed packages."
                        action={
                          <div className="flex gap-2">
                            <Button size="sm" variant="outline" asChild>
                              <Link to="/connections?create=agent">Connect endpoint</Link>
                            </Button>
                            <Button size="sm" onClick={() => navigate(`/scans?new=1&target=${asset.ip}&preset=ssh_inventory`)}>
                              SSH inventory
                            </Button>
                          </div>
                        }
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  pagedSoftware.slice.map((s) => (
                    <TableRow key={s.id}>
                      <TableCell className="pl-4 font-medium">{s.name}</TableCell>
                      <TableCell>
                        <VersionCell version={s.version} meta={s.versionMeta} />
                      </TableCell>
                      <TableCell>
                        {s.ecosystem ? <Badge variant="muted">{s.ecosystem}</Badge> : <span className="text-xs text-muted-foreground">—</span>}
                      </TableCell>
                      <TableCell>
                        <Badge variant="muted">{s.source ?? "—"}</Badge>
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-1">
                          <Button variant="ghost" size="xs" onClick={() => setDiagOpen(true)}>
                            Diagnostics
                          </Button>
                          <Button variant="ghost" size="xs" onClick={() => navigate(`/vulnerabilities?q=${encodeURIComponent(s.name)}`)}>
                            Search CVEs
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            {pagedSoftware.slice.length > 0 && <TableFooterBar total={pagedSoftware.total} page={pagedSoftware.page} pageSize={pagedSoftware.pageSize} onPage={pagedSoftware.setPage} onPageSize={pagedSoftware.setPageSize} label="packages" />}
          </Card>
        </TabsContent>

        {/* ---------------- Findings ---------------- */}
        <TabsContent value="findings">
          <Card className="py-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Severity</TableHead>
                  <TableHead>Finding</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>CVE</TableHead>
                  <TableHead>Confidence</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Last seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assetFindings.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={7}>
                      <EmptyState icon={ShieldAlert} title="No findings for this asset" description="Nothing correlated against the current CVE index. Rediscover after feed updates to re-match." />
                    </TableCell>
                  </TableRow>
                ) : (
                  assetFindings.map((f) => (
                    <TableRow key={f.id} className="cursor-pointer" onClick={() => navigate(`/findings?id=${f.id}`)}>
                      <TableCell className="pl-4">
                        <SeverityBadge severity={f.severity} />
                      </TableCell>
                      <TableCell className="max-w-md">
                        <div className="truncate font-medium">{f.title}</div>
                        <div className="truncate text-xs text-muted-foreground">{f.id.slice(0, 8)} · {f.category}</div>
                      </TableCell>
                      <TableCell className="text-muted-foreground">{f.category}</TableCell>
                      <TableCell>
                        {f.cve ? (
                          <span className="inline-flex items-center gap-1.5">
                            <Mono>{f.cve}</Mono>
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">—</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <div className="flex w-24 items-center gap-2">
                          <Progress value={f.confidence} className="h-1" />
                          <span className="tabular text-xs text-muted-foreground">{f.confidence}%</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <StateBadge label={f.status} tone={findingTone(f.status)} />
                      </TableCell>
                      <TableCell className="tabular text-xs text-muted-foreground">{timeAgo(f.lastSeen)}</TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </Card>
        </TabsContent>

        {/* ---------------- Traces ---------------- */}
        <TabsContent value="traces">
          {!trace ? (
            <Card>
              <CardContent>
                <EmptyState
                  icon={Route}
                  title="No trace recorded"
                  description="Run a trace scan against this host to record the network path from the scanner."
                  action={
                    <Button size="sm" onClick={() => navigate(`/scans?new=1&target=${asset.ip}&preset=discovery`)}>
                      <Radar /> Trace now
                    </Button>
                  }
                />
              </CardContent>
            </Card>
          ) : (
            <TraceView trace={trace} assetIp={asset.ip} />
          )}
        </TabsContent>

        {/* ---------------- Performance ---------------- */}
        {endpointDevice && (
          <TabsContent value="performance" className="flex flex-col gap-4">
            <AssetPerformance
              assetId={asset.id}
              assetLabel={asset.hostname ?? asset.ip}
              points={metricsQ.data?.points ?? []}
              latest={metricsQ.data?.latest ?? null}
              ifaces={metricsQ.data?.ifaces ?? []}
              loading={metricsQ.isLoading}
              fetching={metricsQ.isFetching}
              perf={perf}
              onPerf={setPerf}
              effective={
                metricsQ.data
                  ? { from: metricsQ.data.from, to: metricsQ.data.to, bucket: metricsQ.data.bucket, tail: metricsQ.data.tail }
                  : null
              }
            />
          </TabsContent>
        )}
      </Tabs>

      <VulnDiagnosticsSheet assetId={id} open={diagOpen} onClose={() => setDiagOpen(false)} />

      <TagsNotesDialog
        open={tagsOpen}
        onOpenChange={setTagsOpen}
        asset={{ id: asset.id, tags: asset.tags, notes: asset.notes, label: asset.hostname ?? asset.ip }}
        onSave={(tags, notes) =>
          updateAsset.mutate(
            { id: asset.id, tags, notes },
            {
              onSuccess: () => toast({ title: "Asset updated", variant: "success" }),
              onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
            },
          )
        }
      />

      <IdentityOverrideDialog
        open={identityOpen}
        onOpenChange={setIdentityOpen}
        asset={{
          id: asset.id,
          label: asset.hostname ?? asset.ip,
          nameOverride: asset.nameOverride ?? null,
          typeOverride: asset.typeOverride ?? null,
          effectiveType: asset.type,
          parentOverride: asset.parentOverride ?? null,
          parentLabel: (() => {
            if (!asset.parentOverride) return null;
            const p = (allAssets.data?.items ?? []).find((a) => a.id === asset.parentOverride);
            return p ? `${p.hostname ?? p.ip} (${p.ip})` : asset.parentOverride;
          })(),
          candidates: (allAssets.data?.items ?? [])
            .filter((a) => a.id !== asset.id)
            .map((a) => ({ id: a.id, label: `${a.hostname ?? a.ip} · ${a.ip}` })),
        }}
        onSave={(nameOverride, deviceTypeOverride, parentOverride) =>
          updateAsset.mutate(
            { id: asset.id, name_override: nameOverride, device_type_override: deviceTypeOverride, parent_override: parentOverride },
            {
              onSuccess: () => toast({ title: "Identity updated", description: "Scanned data stays untouched — clear the override any time to restore it.", variant: "success" }),
              onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
            },
          )
        }
      />

      <DeleteAssetDialog
        asset={{ id: asset.id, hostname: asset.hostname, ip: asset.ip }}
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        onDeleted={() => navigate("/assets")}
      />
    </div>
  );
}

/** Isolated child so the conditional site lookup respects hook rules. */
function useSiteNetworksIsolated(siteId: string | undefined) {
  return useSiteNetworks(siteId);
}

function CriticalitySelect({ value, onChange }: { value: Criticality; onChange: (c: Criticality) => void }) {
  const [v, setV] = React.useState<Criticality>(value);
  React.useEffect(() => setV(value), [value]);
  return (
    <Select
      value={v}
      onValueChange={(next) => {
        if (next === v) return;
        setV(next as Criticality);
        onChange(next as Criticality);
      }}
    >
      <SelectTrigger size="sm" className="h-7 w-28 text-xs capitalize">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {(["critical", "high", "medium", "low", "none"] as Criticality[]).map((c) => (
          <SelectItem key={c} value={c} className="capitalize">
            {c === "none" ? "unrated" : c}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function TagsNotesDialog({
  open,
  onOpenChange,
  asset,
  onSave,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  asset: { id: string; tags: string[]; notes?: string; label: string };
  onSave: (tags: string[], notes: string) => void;
}) {
  const [tags, setTags] = React.useState<string[]>(asset.tags);
  const [notes, setNotes] = React.useState(asset.notes ?? "");
  const [draft, setDraft] = React.useState("");
  React.useEffect(() => {
    if (open) {
      setTags(asset.tags);
      setNotes(asset.notes ?? "");
    }
  }, [open, asset.tags, asset.notes]);
  const add = () => {
    const t = draft.trim();
    if (t && !tags.includes(t)) setTags([...tags, t]);
    setDraft("");
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit tags &amp; notes</DialogTitle>
          <DialogDescription>{asset.label}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">Tags</span>
            <div className="flex flex-wrap gap-1.5">
              {tags.map((t) => (
                <Badge key={t} variant="muted" className="gap-1">
                  {t}
                  <button onClick={() => setTags(tags.filter((x) => x !== t))} className="text-muted-foreground hover:text-foreground cursor-pointer">×</button>
                </Badge>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    add();
                  }
                }}
                placeholder="Add a tag…"
                className="h-8"
              />
              <Button variant="outline" size="sm" onClick={add}>
                Add
              </Button>
            </div>
          </div>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">Notes</span>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="min-h-24 rounded-md border bg-transparent px-3 py-2 text-sm"
              placeholder="Analyst notes for this asset…"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => { onSave(tags, notes); onOpenChange(false); }}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

const SCANNED_TYPE = "__scanned__";
const NO_PARENT = "__none__";

/**
 * IdentityOverrideDialog — non-destructive analyst corrections for the
 * asset's display name, device type and topology parent. Detection
 * occasionally mislabels a host (a router fingerprinted as a workstation)
 * or misses its wiring entirely (a transparent L2 switch never shows up as
 * a routable hop, so hosts behind it are wired straight to the router);
 * overrides live in dedicated columns (migrations 0031/0032) and are never
 * applied to the scanned data itself, so clearing them restores exactly
 * what the scanner reported.
 */
function IdentityOverrideDialog({
  open,
  onOpenChange,
  asset,
  onSave,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  asset: {
    id: string;
    label: string;
    nameOverride: string | null;
    typeOverride: string | null;
    effectiveType: AssetType;
    parentOverride: string | null;
    /** human label of the currently pinned parent, resolved by the page */
    parentLabel: string | null;
    /** selectable parent candidates (same site, this asset excluded) */
    candidates: { id: string; label: string }[];
  };
  onSave: (nameOverride: string | null, deviceTypeOverride: string | null, parentOverride: string | null) => void;
}) {
  const [name, setName] = React.useState(asset.nameOverride ?? "");
  const [type, setType] = React.useState(asset.typeOverride ?? SCANNED_TYPE);
  const [parent, setParent] = React.useState(asset.parentOverride ?? NO_PARENT);
  React.useEffect(() => {
    if (open) {
      setName(asset.nameOverride ?? "");
      setType(asset.typeOverride ?? SCANNED_TYPE);
      setParent(asset.parentOverride ?? NO_PARENT);
    }
  }, [open, asset.nameOverride, asset.typeOverride, asset.parentOverride]);
  const dirty =
    (name.trim() || null) !== asset.nameOverride ||
    (type === SCANNED_TYPE ? null : type) !== asset.typeOverride ||
    (parent === NO_PARENT ? null : parent) !== asset.parentOverride;
  // the current parent stays selectable even when it is not among the page's
  // candidates (beyond the 200-asset window, or in another site)
  const options =
    asset.parentOverride && !asset.candidates.some((c) => c.id === asset.parentOverride)
      ? [{ id: asset.parentOverride, label: asset.parentLabel ?? asset.parentOverride }, ...asset.candidates]
      : asset.candidates;
  const typeOptions = Object.entries(assetTypeMeta) as [AssetType, { label: string }][];
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit identity</DialogTitle>
          <DialogDescription>{asset.label}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label htmlFor="asset-name-override">Display name</Label>
            <Input
              id="asset-name-override"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Leave empty to show the scanned name"
              className="h-8"
            />
            <p className="text-[11px] text-muted-foreground">
              Shown everywhere instead of the scanned hostname. Clear it to reveal the scanned value again.
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label>Device type</Label>
            <Select value={type} onValueChange={setType}>
              <SelectTrigger className="w-full text-xs capitalize">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={SCANNED_TYPE} className="capitalize">
                  Scanned value ({assetTypeMeta[asset.effectiveType].label})
                </SelectItem>
                {typeOptions.map(([k, m]) => (
                  <SelectItem key={k} value={k} className="capitalize">
                    {m.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">
              Use this when detection mislabels the host — a router read as a workstation, for example.
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label>Topology parent</Label>
            <Select value={parent} onValueChange={setParent}>
              <SelectTrigger className="w-full text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_PARENT}>Observed evidence (no pin)</SelectItem>
                {options.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">
              Pin this asset beneath another node on the topology map — for hosts sitting behind a transparent switch
              that a network scan cannot see as a hop.
            </p>
          </div>
          <p className="rounded-md border bg-muted/30 px-2.5 py-2 text-[11px] leading-relaxed text-muted-foreground">
            Overrides are non-destructive: the scanned data is kept untouched and comes back the moment the
            override is cleared.
          </p>
        </div>
        <DialogFooter>
          {(asset.nameOverride || asset.typeOverride || asset.parentOverride) && (
            <Button
              variant="outline"
              className="mr-auto"
              onClick={() => {
                onSave(null, null, null);
                onOpenChange(false);
              }}
            >
              Restore scanned data
            </Button>
          )}
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            disabled={!dirty}
            onClick={() => {
              onSave(name.trim() || null, type === SCANNED_TYPE ? null : type, parent === NO_PARENT ? null : parent);
              onOpenChange(false);
            }}
          >
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function TraceView({ trace, assetIp }: { trace: Trace; assetIp: string }) {
  const [rawOpen, setRawOpen] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const allAssets = useAssets({ limit: 200 });
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(trace.raw);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  const confTone = trace.confidence >= 80 ? "text-success" : trace.confidence >= 60 ? "text-medium" : "text-high";

  return (
    <Card>
      <CardHeader>
        <CardTitle>Trace to {assetIp}</CardTitle>
        <CardDescription>
          {trace.hops.length} hops · last seen {timeAgo(trace.lastSeen)} · <span className={confTone}>{trace.confidence}% path confidence</span>
        </CardDescription>
        <CardAction>
          <StateBadge label={trace.status} tone={trace.status === "complete" ? "success" : trace.status === "partial" ? "warning" : "danger"} />
        </CardAction>
      </CardHeader>
      <CardContent className="flex flex-col gap-5">
        {/* Visual path */}
        <div className="flex items-center gap-0 overflow-x-auto rounded-lg border bg-muted/20 p-4">
          <HopNode label="scanner-local" sub="origin" tone="primary" />
          {trace.hops.map((h, i) => (
            <React.Fragment key={h.ttl}>
              <div className="relative mx-1 h-px w-12 shrink-0 bg-border sm:w-20">
                {h.rtt !== undefined && (
                  <span className="absolute -top-4 left-1/2 -translate-x-1/2 whitespace-nowrap font-mono text-[10px] text-muted-foreground">{h.rtt.toFixed(2)} ms</span>
                )}
              </div>
              <HopNode label={h.address} sub={h.hostname ?? `ttl ${h.ttl}`} tone={i === trace.hops.length - 1 ? "target" : "hop"} />
            </React.Fragment>
          ))}
        </div>

        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="w-16">TTL</TableHead>
              <TableHead>Address</TableHead>
              <TableHead>Hostname</TableHead>
              <TableHead className="text-right">RTT</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {trace.hops.map((h, i) => {
              const hopAsset = (allAssets.data?.items ?? []).find((a) => a.ip === h.address);
              const isTarget = i === trace.hops.length - 1;
              return (
                <TableRow key={h.ttl}>
                  <TableCell className="tabular text-muted-foreground">{h.ttl}</TableCell>
                  <TableCell>
                    <span className="inline-flex items-center gap-2">
                      <Mono>{h.address}</Mono>
                      {isTarget ? (
                        <Badge variant="primary" className="font-mono text-[10px]">this asset</Badge>
                      ) : hopAsset ? (
                        <Link to={`/assets/${hopAsset.id}`} className="text-xs text-primary hover:underline">
                          {hopAsset.hostname ?? hopAsset.ip}
                        </Link>
                      ) : null}
                    </span>
                  </TableCell>
                  <TableCell className="text-muted-foreground">{h.hostname ?? "—"}</TableCell>
                  <TableCell className="tabular text-right">{h.rtt !== undefined ? `${h.rtt.toFixed(2)} ms` : "—"}</TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>

        {trace.raw && (
          <Collapsible open={rawOpen} onOpenChange={setRawOpen}>
            <div className="flex items-center justify-between">
              <CollapsibleTrigger asChild>
                <button className="inline-flex items-center gap-1.5 text-sm text-muted-foreground hover:text-foreground cursor-pointer">
                  <ChevronDown className={cn("size-4 transition-transform", rawOpen && "rotate-180")} /> Raw probe output
                </button>
              </CollapsibleTrigger>
              {rawOpen && (
                <Button variant="ghost" size="xs" onClick={copy} className="text-muted-foreground">
                  {copied ? <Check className="text-success" /> : <Copy />} {copied ? "Copied" : "Copy"}
                </Button>
              )}
            </div>
            <CollapsibleContent>
              <pre className="mt-2 max-h-72 overflow-auto rounded-lg border bg-[oklch(0.11_0.01_262)] p-4 font-mono text-[11.5px] leading-relaxed text-foreground/80">
                {trace.raw}
              </pre>
            </CollapsibleContent>
          </Collapsible>
        )}
      </CardContent>
    </Card>
  );
}

function HopNode({ label, sub, tone }: { label: string; sub: string; tone: "primary" | "hop" | "target" }) {
  return (
    <div className="flex shrink-0 flex-col items-center gap-1.5">
      <span
        className={cn(
          "flex size-8 items-center justify-center rounded-full border-2",
          tone === "primary" && "border-primary bg-primary/15 text-primary",
          tone === "hop" && "border-border bg-card text-muted-foreground",
          tone === "target" && "border-success bg-success/15 text-success"
        )}
      >
        {tone === "primary" ? <Radar className="size-3.5" /> : tone === "target" ? <Check className="size-3.5" /> : <span className="size-2 rounded-full bg-current" />}
      </span>
      <span className="font-mono text-[11px]">{label}</span>
      <span className="max-w-28 truncate text-[10px] text-muted-foreground">{sub}</span>
    </div>
  );
}

/** RFC3339 → datetime-local input value ("2026-09-24T14:30"), rendered in
 * the browser timezone so the input shows what the user expects. */
function isoToLocalInput(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** datetime-local input value → RFC3339 (empty input → undefined). */
function localInputToIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** The initial range bounds when the viewer switches to range mode without
 * having picked dates: the trailing hour. */
function defaultRange(): { from: string; to: string } {
  const to = new Date();
  const from = new Date(to.getTime() - 3_600_000);
  return { from: from.toISOString(), to: to.toISOString() };
}

/** PerfControls — the viewer-facing control bar of the performance tab:
 * mode toggle (live tail vs. static range), the tail window presets plus a
 * custom value, the refresh cadence (latest mode only — a historical range
 * never changes, so polling would refetch identical data), and the range
 * bounds as datetime inputs. */
function PerfControls({ perf, onPerf }: { perf: PerfPrefs; onPerf: (p: PerfPrefs) => void }) {
  const isPreset = PERF_WINDOW_PRESETS.some((p) => p.value === perf.window);
  // Custom editor: initialized from the current window when it is already
  // custom, else from a non-colliding default — a colliding default (say
  // "5m") would make picking Custom… look like a no-op.
  const [custom, setCustom] = React.useState(() => splitWindow(isPreset ? "45m" : perf.window));
  const applyCustom = () => onPerf({ ...perf, window: parseCustomWindow(custom.value, custom.unit) });
  const setMode = (mode: "latest" | "range") => {
    if (mode === "range" && (!perf.from || !perf.to)) {
      onPerf({ ...perf, mode, ...defaultRange() });
    } else {
      onPerf({ ...perf, mode });
    }
  };
  const rangeInvalid = !!perf.from && !!perf.to && new Date(perf.from).getTime() >= new Date(perf.to).getTime();
  const modeBtn = (active: boolean) =>
    cn(
      "rounded px-3 py-1 text-xs font-medium transition-colors cursor-pointer",
      active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground",
    );
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-3 py-4">
        <div className="flex items-center gap-2.5">
          <span className="text-xs uppercase tracking-wider text-muted-foreground">Data range</span>
          <div className="flex rounded-md border p-0.5">
            <button type="button" className={modeBtn(perf.mode === "latest")} onClick={() => setMode("latest")}>
              Latest
            </button>
            <button type="button" className={modeBtn(perf.mode === "range")} onClick={() => setMode("range")}>
              Range
            </button>
          </div>
        </div>
        {perf.mode === "latest" ? (
          <>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Window</span>
              <Select
                value={isPreset ? perf.window : "custom"}
                onValueChange={(v) => {
                  if (v === "custom") {
                    const next = splitWindow(isPreset ? "45m" : perf.window);
                    setCustom(next);
                    onPerf({ ...perf, window: parseCustomWindow(next.value, next.unit) });
                  } else {
                    onPerf({ ...perf, window: v });
                  }
                }}
              >
                <SelectTrigger className="h-8 w-40">
                  <SelectValue>
                    {isPreset
                      ? PERF_WINDOW_PRESETS.find((p) => p.value === perf.window)?.label ?? perf.window
                      : `${formatWindowLabel(perf.window)} (custom)`}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {PERF_WINDOW_PRESETS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                  <SelectSeparator />
                  <SelectItem value="custom">Custom…</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {!isPreset && (
              <div className="flex items-center gap-1.5">
                <Input
                  type="number"
                  min={1}
                  value={custom.value}
                  onChange={(e) => setCustom({ ...custom, value: Math.max(1, Math.floor(Number(e.target.value) || 1)) })}
                  onKeyDown={(e) => e.key === "Enter" && applyCustom()}
                  className="h-8 w-20"
                  aria-label="Custom window value"
                />
                <Select value={custom.unit} onValueChange={(v) => setCustom({ ...custom, unit: v as "s" | "m" | "h" | "d" })}>
                  <SelectTrigger className="h-8 w-28" aria-label="Custom window unit">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="s">seconds</SelectItem>
                    <SelectItem value="m">minutes</SelectItem>
                    <SelectItem value="h">hours</SelectItem>
                    <SelectItem value="d">days</SelectItem>
                  </SelectContent>
                </Select>
                <Button size="sm" variant="outline" className="h-8" onClick={applyCustom}>
                  Apply
                </Button>
              </div>
            )}
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Refresh</span>
              <Select value={String(perf.refreshMs)} onValueChange={(v) => onPerf({ ...perf, refreshMs: Number(v) })}>
                <SelectTrigger className="h-8 w-24" aria-label="Refresh interval">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PERF_REFRESH_PRESETS.map((r) => (
                    <SelectItem key={r.value} value={String(r.value)}>
                      {r.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">From</span>
              <Input
                type="datetime-local"
                value={isoToLocalInput(perf.from)}
                onChange={(e) => onPerf({ ...perf, from: localInputToIso(e.target.value) })}
                className="h-8 w-56"
                aria-label="Range start"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">To</span>
              <Input
                type="datetime-local"
                value={isoToLocalInput(perf.to)}
                onChange={(e) => onPerf({ ...perf, to: localInputToIso(e.target.value) })}
                className="h-8 w-56"
                aria-label="Range end"
              />
            </div>
            <span className={cn("text-xs", rangeInvalid ? "text-critical" : "text-muted-foreground")}>
              {rangeInvalid ? "From must be before To" : "Static view — historical ranges do not update"}
            </span>
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** RangeTimeline — the visual date picker for range mode. Shows a coarse
 * CPU/RAM/network overview of a fixed context window and a draggable slider
 * window; committing a drag re-queries the charts. The context window
 * (extent) is held stable across commits — it only grows when the selection
 * comes near an edge — so dragging never refetches or rescales the strip
 * (which used to redraw it and visually re-center the selection) and
 * keepPreviousData keeps the strip mounted while any expansion loads. The
 * overview query returns at most ~360 buckets, so the strip stays readable
 * instead of overloading with points. RAM rides the left percent axis as
 * used/total; throughput rides a separate right axis (bytes/s) — one axis
 * for both scales would flatten the percent lines into noise. */
function RangeTimeline({ assetId, from, to, onChange }: { assetId: string; from: string; to: string; onChange: (from: string, to: string) => void }) {
  const fromMs = new Date(from).getTime();
  const toMs = new Date(to).getTime();
  // Overview extent: initialized once from the incoming selection, then
  // only grown when a committed selection comes within a quarter-span of
  // an edge. Bounds are minute-quantized — a raw Date.now() would change
  // the query key on every render and loop the overview refetch forever.
  const [extent, setExtent] = React.useState(() => initialTimelineExtent(fromMs, toMs, minuteFloor(Date.now())));
  React.useEffect(() => {
    setExtent((prev) => nextTimelineExtent(prev, fromMs, toMs, minuteFloor(Date.now())));
  }, [fromMs, toMs]);
  const ctx = React.useMemo(
    () => ({ from: new Date(extent.fromMs).toISOString(), to: new Date(extent.toMs).toISOString() }),
    [extent.fromMs, extent.toMs],
  );
  const overviewQ = useAssetMetrics(assetId, { mode: "range", window: "", from: ctx.from, to: ctx.to, refreshMs: 0 });
  const commitRef = React.useRef<number | null>(null);
  React.useEffect(() => () => {
    if (commitRef.current) window.clearTimeout(commitRef.current);
  }, []);
  const onZoom = (start: number, end: number) => {
    if (commitRef.current) window.clearTimeout(commitRef.current);
    commitRef.current = window.setTimeout(() => {
      onChange(new Date(start).toISOString(), new Date(end).toISOString());
    }, 400);
  };
  const data = overviewQ.data?.points ?? [];
  // RAM as a percent of installed memory; null (gap) when a bucket carries
  // no memory reading, so a missing series never renders as a false 0%.
  const ramPct = (p: AssetMetricPoint): number | null =>
    p.mem_total > 0 ? Number(((p.mem_used / p.mem_total) * 100).toFixed(2)) : null;
  return (
    <Card>
      <CardHeader className="pb-0">
        <CardTitle>Timeline</CardTitle>
        <CardDescription>Drag the handles to set the range dates visually</CardDescription>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <EmptyState compact icon={Activity} title={overviewQ.isLoading ? "Loading timeline…" : "No samples around this range"} />
        ) : (
          <Chart
            height={190}
            onDataZoom={onZoom}
            option={{
              // Legend row on top and right-axis labels on the side cost
              // vertical/horizontal room; bottom stays reserved for the slider.
              grid: { left: 44, right: 56, top: 26, bottom: 70 },
              xAxis: {
                type: "time",
                axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } },
                axisLabel: {
                  color: "#8A8F98",
                  fontSize: 10,
                  hideOverlap: true,
                  // Day-qualified labels with minutes — hour-only text made
                  // every intra-hour tick render the identical label.
                  formatter: (v: number) => {
                    const d = new Date(v);
                    const pad = (n: number) => String(n).padStart(2, "0");
                    return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
                  },
                },
              },
              yAxis: [
                {
                  type: "value",
                  max: 100,
                  axisLabel: { formatter: "{value}%", color: "#8A8F98", fontSize: 10 },
                  splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } },
                },
                {
                  type: "value",
                  axisLabel: { formatter: (v: number) => fmtBytes(v), color: "#8A8F98", fontSize: 10 },
                  splitLine: { show: false },
                  splitNumber: 4,
                },
              ],
              tooltip: {
                trigger: "axis",
                // Percent series and byte-rate series share the tooltip; a
                // single valueFormatter would mislabel one of them.
                formatter: (params: unknown) => {
                  const arr = (Array.isArray(params) ? params : [params]) as {
                    seriesName?: string; marker?: string; value?: unknown; axisValueLabel?: string;
                  }[];
                  if (arr.length === 0) return "";
                  const title = arr[0]?.axisValueLabel ?? "";
                  const rows = arr.map((p) => {
                    const raw = Array.isArray(p.value) ? p.value[1] : p.value;
                    const isBps = p.seriesName === "in" || p.seriesName === "out";
                    const val = raw === null || raw === undefined ? "—"
                      : isBps ? fmtBps(Number(raw)) : `${Number(raw).toFixed(1)}%`;
                    return `${p.marker ?? ""} ${p.seriesName} ${val}`;
                  });
                  return [title, ...rows].join("<br/>");
                },
              },
              dataZoom: [
                {
                  type: "slider",
                  xAxisIndex: 0,
                  height: 42,
                  bottom: 12,
                  startValue: fromMs,
                  endValue: toMs,
                  minSpan: 1,
                  brushSelect: false,
                  throttle: 200,
                  borderColor: "rgba(255,255,255,0.14)",
                  fillerColor: "rgba(94,106,210,0.28)",
                  dataBackground: {
                    lineStyle: { color: "rgba(255,255,255,0.18)" },
                    areaStyle: { color: "rgba(255,255,255,0.06)" },
                  },
                  selectedDataBackground: {
                    lineStyle: { color: "#5E6AD2" },
                    areaStyle: { color: "rgba(94,106,210,0.12)" },
                  },
                  handleStyle: { color: "#5E6AD2" },
                  moveHandleStyle: { color: "#5E6AD2" },
                  emphasis: { handleStyle: { borderColor: "#5E6AD2" } },
                  textStyle: { color: "#8A8F98", fontSize: 10 },
                  labelFormatter: (v: number) =>
                    new Date(v).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
                },
              ],
              legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 10 } },
              series: [
                {
                  name: "cpu",
                  type: "line",
                  data: data.map((p) => [new Date(p.ts).getTime(), Number(p.cpu_avg.toFixed(2))]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#5E6AD2", width: 1.5 },
                  areaStyle: { color: "#5E6AD222" },
                },
                {
                  name: "ram",
                  type: "line",
                  data: data.map((p) => [new Date(p.ts).getTime(), ramPct(p)]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#60A5FA", width: 1.25 },
                },
                {
                  name: "in",
                  type: "line",
                  yAxisIndex: 1,
                  data: data.map((p) => [new Date(p.ts).getTime(), Number(p.rx_bps.toFixed(1))]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#34D399", width: 1.25 },
                },
                {
                  name: "out",
                  type: "line",
                  yAxisIndex: 1,
                  data: data.map((p) => [new Date(p.ts).getTime(), Number(p.tx_bps.toFixed(1))]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#FBBF24", width: 1.25 },
                },
              ],
            }}
          />
        )}
      </CardContent>
    </Card>
  );
}

/** UpdatingDot marks a background refetch next to a chart description.
 * Purely visual — no layout impact, invisible when idle. */
function UpdatingDot({ show }: { show: boolean }) {
  if (!show) return null;
  return <span aria-hidden className="ml-1.5 inline-block size-1.5 animate-pulse rounded-full bg-[#5E6AD2] align-middle" />;
}

/** Performance: CPU, memory and network history collected by the endpoint
 *  device bound to this asset, from the ClickHouse metrics tier. Latest
 *  mode tails a window and refreshes; range mode shows a static span picked
 *  with the timeline. The interface table carries per-NIC sparklines. */
function AssetPerformance({
  points, latest, ifaces, loading, fetching, perf, onPerf, effective, assetId, assetLabel,
}: {
  points: AssetMetricPoint[];
  latest: AssetMetricLatest | null;
  ifaces: AssetIfaceSeries[];
  loading: boolean;
  fetching: boolean;
  perf: PerfPrefs;
  onPerf: (p: PerfPrefs) => void;
  effective: { from: string; to: string; bucket: number; tail: boolean } | null;
  assetId: string;
  assetLabel: string;
}) {
  const effFrom = effective?.from || perf.from || points[0]?.ts || "";
  const effTo = effective?.to || perf.to || points[points.length - 1]?.ts || "";
  const spanSecs =
    effFrom && effTo ? Math.max(1, (new Date(effTo).getTime() - new Date(effFrom).getTime()) / 1000) : 86400;
  const ts = points.map((p) => fmtTick(p.ts, spanSecs));
  const memPct = latest?.mem_total ? Math.round((latest.mem_used / latest.mem_total) * 100) : null;
  const windowLabel = perf.mode === "latest" ? `last ${formatWindowLabel(perf.window)}` : fmtRangeLabel(effFrom, effTo);
  const refreshLabel =
    perf.mode === "range"
      ? "static"
      : PERF_REFRESH_PRESETS.find((r) => r.value === perf.refreshMs)?.label?.toLowerCase() ?? `${Math.round(perf.refreshMs / 1000)}s`;
  const seriesByName = new Map(ifaces.map((s) => [s.name, s]));
  const rangeInvalid = perf.mode === "range" && !!perf.from && !!perf.to && new Date(perf.from).getTime() >= new Date(perf.to).getTime();
  const rangeReady = perf.mode === "latest" || (!!perf.from && !!perf.to && !rangeInvalid);
  // Background refetch marker: points keep rendering while fresh data
  // loads (keepPreviousData), so the pulsing dot — not a layout swap — is
  // the only visible change.
  const updating = fetching && !loading;
  // "Create alert" entry points: deep-link into the Alerts console trigger
  // editor with a prefilled device-metric draft scoped to this asset.
  const { navigate } = useRouter();
  const alertSeed = (metricField: string) => {
    const p = new URLSearchParams({ tab: "triggers", new: "metric", metric: metricField, asset: assetId });
    if (assetLabel) p.set("label", assetLabel);
    navigate(`/alerts?${p.toString()}`);
  };
  return (
    <>
      <PerfControls perf={perf} onPerf={onPerf} />
      {perf.mode === "range" && perf.from && perf.to && !rangeInvalid && (
        <RangeTimeline
          assetId={assetId}
          from={perf.from}
          to={perf.to}
          onChange={(from, to) => onPerf({ ...perf, from, to })}
        />
      )}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-0">
            <CardTitle>Current load</CardTitle>
            <CardDescription>Most recent sample from the endpoint collector</CardDescription>
            <CardAction>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" className="gap-1.5"><BellPlus /> Create alert</Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-64">
                  <DropdownMenuItem onClick={() => alertSeed("cpu_percent")}>
                    <Gauge /> CPU utilization above 90%…
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => alertSeed("mem_used_percent")}>
                    <MemoryStick /> Memory usage above 90%…
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => navigate("/alerts?tab=triggers")}>
                    <BellPlus /> Manage trigger rules…
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </CardAction>
          </CardHeader>
          <CardContent>
            {latest ? (
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">CPU</div>
                  <div className={cn("tabular text-2xl font-semibold", latest.cpu_percent > 85 ? "text-critical" : "text-foreground")}>
                    {latest.cpu_percent.toFixed(1)}%
                  </div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Memory</div>
                  <div className="tabular text-2xl font-semibold">{memPct !== null ? `${memPct}%` : "—"}</div>
                  <div className="text-[11px] text-muted-foreground">{fmtBytes(latest.mem_used)} of {fmtBytes(latest.mem_total)}</div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Network</div>
                  <div className="tabular text-sm font-semibold">↓ {fmtBps(latest.rx_bps)}</div>
                  <div className="tabular text-sm font-semibold">↑ {fmtBps(latest.tx_bps)}</div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Uptime</div>
                  <div className="tabular text-sm font-semibold">{latest.uptime_secs > 0 ? fmtUptime(latest.uptime_secs) : "—"}</div>
                  <div className="text-[11px] text-muted-foreground">sampled {timeAgo(latest.timestamp)}</div>
                </div>
              </div>
            ) : (
              <EmptyState compact icon={Activity} title="No samples yet" description="The first performance sample arrives about a minute after the endpoint collector connects." />
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-0">
            <CardTitle>CPU utilization</CardTitle>
            <CardDescription>Average and peak per bucket · {windowLabel} · {refreshLabel}<UpdatingDot show={updating} /></CardDescription>
          </CardHeader>
          <CardContent>
            {points.length === 0 || !rangeReady ? (
              <EmptyState compact icon={Activity} title={loading || !rangeReady ? "Loading metrics…" : "No history in this window"} />
            ) : (
              <Chart
                height={220}
                live={perf.mode === "latest"}
                option={{
                  xAxis: { type: "category", boundaryGap: false, data: ts, axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } }, axisLabel: { hideOverlap: true } },
                  yAxis: { type: "value", max: 100, axisLabel: { formatter: "{value}%" }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  tooltip: { trigger: "axis", valueFormatter: (v) => `${Number(v).toFixed(1)}%` },
                  series: [
                    { name: "avg", type: "line", data: points.map((p) => Number(p.cpu_avg.toFixed(2))), smooth: true, symbol: "none", lineStyle: { color: "#5E6AD2" }, areaStyle: { color: "#5E6AD222" } },
                    { name: "peak", type: "line", data: points.map((p) => Number(p.cpu_max.toFixed(2))), smooth: true, symbol: "none", lineStyle: { color: "#FB923C", type: "dashed" } },
                  ],
                  legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 11 } },
                }}
              />
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-0">
            <CardTitle>Memory</CardTitle>
            <CardDescription>Used vs. installed · {windowLabel} · {refreshLabel}<UpdatingDot show={updating} /></CardDescription>
          </CardHeader>
          <CardContent>
            {points.length === 0 || !rangeReady ? (
              <EmptyState compact icon={Activity} title={loading || !rangeReady ? "Loading metrics…" : "No history in this window"} />
            ) : (
              <Chart
                height={220}
                live={perf.mode === "latest"}
                option={{
                  xAxis: { type: "category", boundaryGap: false, data: ts, axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } }, axisLabel: { hideOverlap: true } },
                  yAxis: { type: "value", axisLabel: { formatter: (v: number) => fmtBytes(v) }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  tooltip: { trigger: "axis", valueFormatter: (v) => fmtBytes(Number(v)) },
                  series: [
                    { name: "used", type: "line", data: points.map((p) => p.mem_used), smooth: true, symbol: "none", lineStyle: { color: "#60A5FA" }, areaStyle: { color: "#60A5FA22" } },
                    { name: "total", type: "line", data: points.map((p) => p.mem_total), smooth: true, symbol: "none", lineStyle: { color: "#8A8F98", type: "dashed" } },
                  ],
                  legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 11 } },
                }}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-0">
            <CardTitle>Network throughput</CardTitle>
            <CardDescription>Receive/transmit rates · {windowLabel} · {refreshLabel}<UpdatingDot show={updating} /></CardDescription>
          </CardHeader>
          <CardContent>
            {points.length === 0 || !rangeReady ? (
              <EmptyState compact icon={Activity} title={loading || !rangeReady ? "Loading metrics…" : "No history in this window"} />
            ) : (
              <Chart
                height={220}
                live={perf.mode === "latest"}
                option={{
                  xAxis: { type: "category", boundaryGap: false, data: ts, axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } }, axisLabel: { hideOverlap: true } },
                  yAxis: { type: "value", axisLabel: { formatter: (v: number) => fmtBytes(v) }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  tooltip: { trigger: "axis", valueFormatter: (v) => fmtBps(Number(v)) },
                  series: [
                    { name: "in", type: "line", data: points.map((p) => Number(p.rx_bps.toFixed(1))), smooth: true, symbol: "none", lineStyle: { color: "#34D399" }, areaStyle: { color: "#34D39922" } },
                    { name: "out", type: "line", data: points.map((p) => Number(p.tx_bps.toFixed(1))), smooth: true, symbol: "none", lineStyle: { color: "#FBBF24" } },
                  ],
                  legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 11 } },
                }}
              />
            )}
          </CardContent>
        </Card>
      </div>

      {latest && latest.ifaces.length > 0 && (
        <Card className="py-0">
          <CardHeader>
            <CardTitle>Network interfaces</CardTitle>
            <CardDescription>Counters, rates and speed history ({windowLabel})</CardDescription>
          </CardHeader>
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Interface</TableHead>
                  <TableHead>MAC</TableHead>
                  <TableHead className="text-right">Receive</TableHead>
                  <TableHead className="text-right">Transmit</TableHead>
                  <TableHead className="w-44">Activity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {latest.ifaces.map((i) => {
                  const series = seriesByName.get(i.name);
                  const hasHistory = !!series && series.rx.length + series.tx.length > 0;
                  return (
                    <TableRow key={i.name}>
                      <TableCell className="pl-4 font-medium">{i.name}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{i.mac || "—"}</TableCell>
                      <TableCell className="text-right tabular text-xs">{fmtBytes(i.rx_bytes)} · {fmtBps(i.rx_bps)}</TableCell>
                      <TableCell className="text-right tabular text-xs">{fmtBytes(i.tx_bytes)} · {fmtBps(i.tx_bps)}</TableCell>
                      <TableCell className="w-44 py-1.5">
                        {hasHistory ? (
                          <Sparkline rx={series!.rx} tx={series!.tx} />
                        ) : (
                          <span className="text-xs text-muted-foreground">no history</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </>
  );
}

function fmtUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
