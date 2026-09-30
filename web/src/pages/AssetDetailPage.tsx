import * as React from "react";
import {
  ArrowLeft,
  FileText,
  Loader2,
  MoreHorizontal,
  Pencil,
  Radar,
  RefreshCw,
  ShieldAlert,
  Tag,
  Trash2,
  Waypoints,
} from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type { Trace } from "@/data/types";
import { VulnDiagnosticsSheet } from "@/components/vulns/VulnDiagnosticsSheet";
import {
  DEFAULT_PERF_PREFS, loadPerfPrefs, savePerfPrefs, type PerfPrefs,
} from "@/components/assets/perf-config";
import { useScope } from "@/components/layout/AppShell";
import {
  useAddNote, useAsset, useAssetFindings, useAssetMetrics, useAssetTraces, useAssets,
  useEvents, useRediscoverAsset, useSites, useSiteNetworks, useTopology, useUpdateAsset,
} from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsUnderlineList, TabsUnderlineTrigger } from "@/components/ui/tabs";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "@/components/ui/toaster";
import { AssetGroupCell } from "@/components/groups/GroupChip";
import { DeleteAssetDialog } from "@/components/assets/DeleteAssetDialog";
import {
  CriticalityBadge,
  EmptyState,
  ExposureBadge,
  Mono,
  RiskRing,
  StatusDot,
  usePagination,
} from "@/components/shared";
import { AssetOverviewTab } from "@/components/asset/AssetOverviewTab";
import { AssetNetworkTab } from "@/components/asset/AssetNetworkTab";
import { AssetServicesTab } from "@/components/asset/AssetServicesTab";
import { AssetSoftwareTab } from "@/components/asset/AssetSoftwareTab";
import { AssetFindingsTab } from "@/components/asset/AssetFindingsTab";
import { AssetTracesTab } from "@/components/asset/AssetTracesTab";
import { AssetPerformanceTab } from "@/components/asset/AssetPerformanceTab";
import { TagsNotesDialog } from "@/components/asset/AssetTagsNotesDialog";
import { IdentityOverrideDialog } from "@/components/asset/AssetIdentityOverrideDialog";

/**
 * Asset detail page shell — owns every query, mutation and piece of page
 * state, then composes the per-tab components from components/asset/* via
 * props. Route component and URL contract (?tab=…) are unchanged.
 */
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
          <AssetOverviewTab
            asset={asset}
            bundle={bundle}
            site={site}
            endpointDevice={endpointDevice}
            primaryIface={primaryIface}
            openPorts={openPorts}
            eventsForAsset={eventsForAsset}
            changeTab={changeTab}
            onCriticalityChange={(c) =>
              updateAsset.mutate(
                { id: asset.id, criticality: c },
                { onSuccess: () => toast({ title: "Criticality updated", variant: "success" }) },
              )
            }
          />
        </TabsContent>

        {/* ---------------- Network ---------------- */}
        <TabsContent value="network" className="grid gap-4 xl:grid-cols-3">
          <AssetNetworkTab
            asset={asset}
            interfaces={bundle.interfaces}
            trace={trace}
            siteNetworks={siteNetworksQ.data?.items ?? []}
            neighbors={neighbors}
          />
        </TabsContent>

        {/* ---------------- Services ---------------- */}
        <TabsContent value="services">
          <AssetServicesTab
            asset={asset}
            ports={bundle.ports}
            pagedPorts={pagedPorts}
            onOpenDiagnostics={() => setDiagOpen(true)}
          />
        </TabsContent>

        {/* ---------------- Software ---------------- */}
        <TabsContent value="software">
          <AssetSoftwareTab
            asset={asset}
            software={bundle.software}
            pagedSoftware={pagedSoftware}
            onOpenDiagnostics={() => setDiagOpen(true)}
          />
        </TabsContent>

        {/* ---------------- Findings ---------------- */}
        <TabsContent value="findings">
          <AssetFindingsTab assetFindings={assetFindings} />
        </TabsContent>

        {/* ---------------- Traces ---------------- */}
        <TabsContent value="traces">
          <AssetTracesTab trace={trace} assetIp={asset.ip} />
        </TabsContent>

        {/* ---------------- Performance ---------------- */}
        {endpointDevice && (
          <TabsContent value="performance" className="flex flex-col gap-4">
            <AssetPerformanceTab
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
