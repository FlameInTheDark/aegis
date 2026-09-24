import * as React from "react";
import { Bell, Check, Crosshair, ShieldBan, Search, X, Waypoints } from "lucide-react";

import { cn, timeAgo, formatDateTime } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type { Detection, DetectionStatus } from "@/data/types";
import { useScope } from "@/components/layout/AppShell";
import { useAsset, useDetectionMatches, useUpdateMatchStatus } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { EmptyState, KeyValue, Mono, PageHeader, SeverityBadge, severityMeta, StateBadge, StatusDot } from "@/components/shared";
import { toast } from "@/components/ui/toaster";

const statusTone = (s: DetectionStatus) => (s === "new" ? "danger" : s === "investigating" ? "primary" : s === "contained" ? "warning" : "muted");

export function DetectionsPage() {
  const { query, navigate } = useRouter();
  const matchesQ = useDetectionMatches({ limit: 200 });
  const updateStatus = useUpdateMatchStatus();
  const [q, setQ] = React.useState("");
  const [sev, setSev] = React.useState("all");
  const [status, setStatus] = React.useState("all");
  const [selectedId, setSelectedId] = React.useState<string | null>(query.get("id"));

  React.useEffect(() => {
    if (query.get("id")) setSelectedId(query.get("id"));
  }, [query]);

  const items = matchesQ.data?.items ?? [];

  const list = React.useMemo(() => {
    const needle = q.toLowerCase();
    return items
      .filter((d) => {
        if (sev !== "all" && d.severity !== sev) return false;
        if (status !== "all" && d.status !== status) return false;
        if (!needle) return true;
        return [d.title, d.ruleType, d.description, d.srcIp, d.entity, ...d.indicators].some((s) => s?.toLowerCase().includes(needle));
      })
      .sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));
  }, [items, q, sev, status]);

  React.useEffect(() => {
    if (!selectedId && list.length > 0) setSelectedId(list[0].id);
  }, [list, selectedId]);

  const selected = items.find((d) => d.id === selectedId) ?? list[0] ?? null;

  const setStatusFor = (id: string, next: DetectionStatus, label: string) => {
    updateStatus.mutate(
      { id, status: next },
      {
        onSuccess: () => toast({ title: `Detection ${label}`, variant: "success" }),
        onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const counts = (s: DetectionStatus) => items.filter((d) => d.status === s).length;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Detections" description="Alerts produced by the correlation engine: detection rules evaluated against the sensor event stream. Triage each match through the workflow." />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {(["new", "investigating", "contained", "closed"] as DetectionStatus[]).map((s) => (
          <button
            key={s}
            onClick={() => setStatus(status === s ? "all" : s)}
            className={cn("flex items-center justify-between rounded-xl border bg-card px-4 py-3 text-left transition-colors hover:bg-accent/30 cursor-pointer", status === s && "border-primary")}
          >
            <div className="leading-tight">
              <div className="tabular text-lg font-semibold">{counts(s)}</div>
              <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{s}</div>
            </div>
            <StatusDot tone={statusTone(s)} pulse={s === "new" && counts(s) > 0} className="size-2.5" />
          </button>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, rule, indicator…" className="h-8 pl-8 text-[13px]" />
        </div>
        <Select value={sev} onValueChange={setSev}>
          <SelectTrigger size="sm" className="w-[150px]">
            <span className="text-muted-foreground">Severity:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        {(q || sev !== "all" || status !== "all") && (
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground"
            onClick={() => {
              setQ("");
              setSev("all");
              setStatus("all");
            }}
          >
            <X /> Clear
          </Button>
        )}
      </div>

      <div className="grid gap-4 lg:grid-cols-5">
        {/* List */}
        <div className="flex flex-col gap-2 lg:col-span-2">
          {list.length === 0 ? (
            <Card>
              <CardContent>
                <EmptyState icon={Bell} title="No detections" description="No rule matches yet — attach a network sensor or enroll an endpoint agent so the correlation engine has events to evaluate." />
              </CardContent>
            </Card>
          ) : (
            list.map((d) => {
              const active = selected?.id === d.id;
              return (
                <button
                  key={d.id}
                  onClick={() => {
                    setSelectedId(d.id);
                    if (query.get("id")) navigate("/detections", { replace: true });
                  }}
                  className={cn(
                    "relative flex w-full flex-col gap-1.5 overflow-hidden rounded-xl border bg-card p-3 text-left transition-colors hover:bg-accent/30 cursor-pointer",
                    active && "border-primary/60 bg-primary/5"
                  )}
                >
                  <span className={cn("absolute inset-y-0 left-0 w-1", severityMeta[d.severity].bg)} />
                  <div className="flex items-center gap-2 pl-2">
                    <SeverityBadge severity={d.severity} compact />
                    <StateBadge label={d.status} tone={statusTone(d.status)} className="px-1.5 text-[10px]" />
                    <span className="ml-auto tabular text-[11px] text-muted-foreground">{timeAgo(d.timestamp)}</span>
                  </div>
                  <div className="pl-2 text-sm font-medium leading-snug">{d.title}</div>
                  <div className="flex items-center gap-2 pl-2 text-[11px] text-muted-foreground">
                    <Waypoints className="size-3" /> correlation · {d.count} event{d.count === 1 ? "" : "s"} · <Mono className="text-[11px]">{d.srcIp ?? d.entity ?? "stream"}</Mono>
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Detail */}
        <Card className="self-start lg:col-span-3">
          {!selected ? (
            <CardContent>
              <EmptyState compact icon={Bell} title="Select a detection" />
            </CardContent>
          ) : (
            <DetectionDetail detection={selected} onStatus={setStatusFor} />
          )}
        </Card>
      </div>
    </div>
  );
}

function DetectionDetail({
  detection: selected,
  onStatus,
}: {
  detection: Detection;
  onStatus: (id: string, next: DetectionStatus, label: string) => void;
}) {
  const assetQ = useAsset(selected.assetId);
  const asset = assetQ.data?.asset;
  return (
    <CardContent className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={selected.severity} />
        <StateBadge label={selected.status} tone={statusTone(selected.status)} />
        <Badge variant="outline" className="capitalize">
          <Waypoints className="size-3" /> correlation
        </Badge>
        <span className="ml-auto font-mono text-xs text-muted-foreground">{selected.id.slice(0, 8)}</span>
      </div>
      <div>
        <h2 className="text-lg font-semibold leading-snug">{selected.title}</h2>
        <p className="mt-1 text-xs text-muted-foreground">{formatDateTime(selected.timestamp)}</p>
      </div>
      <p className="text-sm leading-relaxed text-foreground/85">{selected.description}</p>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="rounded-lg border bg-muted/30 p-3">
          <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Match volume</div>
          <div className="mt-1 text-sm font-medium">
            {selected.count} event{selected.count === 1 ? "" : "s"} correlated
          </div>
          <div className="text-xs text-muted-foreground">Rule fires aggregated into this match</div>
        </div>
        {asset && (
          <Link to={`/assets/${asset.id}`} className="flex items-center gap-3 rounded-lg border bg-muted/30 p-3 hover:bg-accent/40">
            <span className="flex size-8 items-center justify-center rounded-md border bg-card text-muted-foreground">
              {(() => {
                const Icon = assetTypeMeta[asset.type].icon;
                return <Icon className="size-4" />;
              })()}
            </span>
            <div className="min-w-0 leading-tight">
              <div className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Asset</div>
              <div className="truncate text-sm font-medium">{asset.hostname ?? asset.ip}</div>
              <div className="font-mono text-[11px] text-muted-foreground">{asset.ip}</div>
            </div>
          </Link>
        )}
      </div>

      <div>
        <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Indicators</div>
        <div className="flex flex-wrap gap-1.5">
          {selected.indicators.length > 0 ? (
            selected.indicators.map((i) => (
              <span key={i} className="rounded-md border bg-[oklch(0.11_0.01_262)] px-2 py-1 font-mono text-[11px]">
                {i}
              </span>
            ))
          ) : (
            <span className="text-xs text-muted-foreground">No concrete indicators on this match</span>
          )}
        </div>
      </div>

      <div className="divide-y rounded-lg border px-3">
        <KeyValue label="Source">correlation engine</KeyValue>
        <KeyValue label="Observed">{formatDateTime(selected.timestamp)}</KeyValue>
      </div>

      <Separator />
      <div className="flex flex-wrap gap-2">
        {selected.status === "new" && (
          <Button size="sm" onClick={() => onStatus(selected.id, "investigating", "under investigation")}>
            <Crosshair /> Investigate
          </Button>
        )}
        {(selected.status === "new" || selected.status === "investigating") && (
          <Button size="sm" variant="outline" onClick={() => onStatus(selected.id, "contained", "contained")}>
            <ShieldBan /> Mark contained
          </Button>
        )}
        {selected.status !== "closed" && (
          <Button size="sm" variant="outline" onClick={() => onStatus(selected.id, "closed", "closed")}>
            <Check /> Close
          </Button>
        )}
      </div>
    </CardContent>
  );
}
