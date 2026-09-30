import * as React from "react";
import { Check, ChevronDown, Copy, Radar, Route } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { useAssets } from "@/lib/queries";
import type { Trace } from "@/data/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, Mono, StateBadge } from "@/components/shared";

/** Traces tab of the asset detail page: the recorded network path from the
 *  scanner to this host (visual hop strip, hop table, raw probe output). */
export function AssetTracesTab({ trace, assetIp }: { trace?: Trace; assetIp: string }) {
  const { navigate } = useRouter();
  if (!trace) {
    return (
      <Card>
        <CardContent>
          <EmptyState
            icon={Route}
            title="No trace recorded"
            description="Run a trace scan against this host to record the network path from the scanner."
            action={
              <Button size="sm" onClick={() => navigate(`/scans?new=1&target=${assetIp}&preset=discovery`)}>
                <Radar /> Trace now
              </Button>
            }
          />
        </CardContent>
      </Card>
    );
  }
  return <TraceView trace={trace} assetIp={assetIp} />;
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
