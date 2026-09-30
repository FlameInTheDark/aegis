import * as React from "react";
import { Activity, Cpu, Network as NetworkIcon } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type { Asset, AssetDetailBundle, Criticality, EndpointDevice, PlatformEvent, Port, Site } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  ConfidenceMeter,
  EmptyState,
  ExposureBadge,
  KeyValue,
  SeverityStack,
  StateBadge,
  StatusDot,
  severityMeta,
} from "@/components/shared";

/** Overview tab of the asset detail page: the identity card, security
 *  posture, detected ports & services summary and recent sensor activity. */
export function AssetOverviewTab({
  asset,
  bundle,
  site,
  endpointDevice,
  primaryIface,
  openPorts,
  eventsForAsset,
  changeTab,
  onCriticalityChange,
}: {
  asset: Asset;
  bundle: AssetDetailBundle;
  site?: Site;
  endpointDevice?: EndpointDevice;
  primaryIface?: AssetDetailBundle["interfaces"][number];
  openPorts: Port[];
  eventsForAsset: PlatformEvent[];
  changeTab: (t: string) => void;
  onCriticalityChange: (c: Criticality) => void;
}) {
  return (
    <>
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
              <CriticalitySelect value={asset.criticality} onChange={onCriticalityChange} />
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
    </>
  );
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
