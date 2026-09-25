import { Bell, BellOff, Clock, Send, ShieldCheck } from "lucide-react";

import { cn, timeAgo, formatDateTime } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Separator } from "@/components/ui/separator";
import { KeyValue, Mono, SectionTitle, StateBadge } from "@/components/shared";
import { useAckAlert, useAlertOccurrence, useResolveAlert, type AlertOccurrence } from "@/lib/queries.alerts";

// Occurrence detail: lifecycle badges, evidence snapshot, the immutable
// transition timeline and per-destination delivery attempts. Acknowledge
// and resolve act through the API and invalidate the affected caches.

const stateTone: Record<string, "danger" | "warning" | "success" | "muted" | "primary"> = {
  firing: "danger", acknowledged: "warning", recovered: "success", suppressed: "muted",
};

const deliveryTone: Record<string, "danger" | "warning" | "success" | "muted"> = {
  sent: "success", retry: "warning", pending: "muted", dead: "danger",
};

export function OccurrenceDetail({ occurrence, onClose }: { occurrence: AlertOccurrence; onClose: () => void }) {
  const detail = useAlertOccurrence(occurrence.id);
  const ack = useAckAlert();
  const resolve = useResolveAlert();
  const open = occurrence.state === "firing" || occurrence.state === "acknowledged";

  return (
    <Card className="self-start lg:col-span-3">
      <CardHeader className="pb-0">
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="flex items-center gap-2 text-base">
              {occurrence.title}
              <StateBadge label={occurrence.state} tone={stateTone[occurrence.state] ?? "muted"} pulse={occurrence.state === "firing"} />
            </CardTitle>
            <CardDescription>{occurrence.summary}</CardDescription>
          </div>
          <Button variant="ghost" size="icon-xs" onClick={onClose} aria-label="Close alert detail"><BellOff className="hidden" /><span aria-hidden>×</span></Button>
        </div>
        <div className="flex flex-wrap items-center gap-2 pt-1">
          {open && (
            <>
              <Button size="xs" variant="outline" onClick={() => ack.mutate(occurrence.id)} disabled={ack.isPending}>
                <Bell /> Acknowledge
              </Button>
              <Button size="xs" variant="outline" onClick={() => resolve.mutate(occurrence.id)} disabled={resolve.isPending}>
                <ShieldCheck /> Resolve
              </Button>
            </>
          )}
        </div>
      </CardHeader>
      <CardContent className="pt-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <KeyValue label="Severity"><span className="capitalize">{occurrence.severity}</span></KeyValue>
          <KeyValue label="Trigger"><Mono>{occurrence.triggerName}</Mono> <span className="text-xs text-muted-foreground">({occurrence.triggerId.slice(0, 8)})</span></KeyValue>
          <KeyValue label="Opened"><span title={formatDateTime(occurrence.openedAt)}>{timeAgo(occurrence.openedAt)}</span></KeyValue>
          <KeyValue label="Last update"><span title={formatDateTime(occurrence.updatedAt)}>{timeAgo(occurrence.updatedAt)}</span></KeyValue>
          <KeyValue label="Observations">{occurrence.occurrenceCount}</KeyValue>
          {occurrence.assetId && (
            <KeyValue label="Asset"><Mono>{occurrence.assetId.slice(0, 8)}</Mono></KeyValue>
          )}
          {occurrence.acknowledgedAt && (
            <KeyValue label="Acknowledged">{timeAgo(occurrence.acknowledgedAt)}</KeyValue>
          )}
          {occurrence.recoveredAt && (
            <KeyValue label="Recovered">{timeAgo(occurrence.recoveredAt)}</KeyValue>
          )}
        </div>

        {/* Snapshot: the immutable evaluation context at fire time. */}
        {occurrence.snapshot && Object.keys(occurrence.snapshot).length > 0 && (
          <>
            <Separator className="my-3" />
            <SectionTitle>Evidence snapshot</SectionTitle>
            <pre className="mt-1.5 max-h-44 overflow-auto rounded-lg border bg-muted/30 p-2 font-mono text-[11px] leading-relaxed text-muted-foreground">
              {JSON.stringify(occurrence.snapshot, null, 2)}
            </pre>
          </>
        )}

        {/* Transition timeline: append-only, never rewritten. */}
        <Separator className="my-3" />
        <SectionTitle>Timeline</SectionTitle>
        <div className="mt-2 grid gap-1.5">
          {(detail.data?.transitions ?? []).length === 0 && (
            <p className="text-xs text-muted-foreground">Loading transitions…</p>
          )}
          {(detail.data?.transitions ?? []).map((t, i) => (
            <div key={t.id} className="flex items-start gap-2.5">
              <div className="flex flex-col items-center">
                <span className={cn("mt-1 size-1.5 rounded-full", t.toState === "recovered" ? "bg-success" : t.toState === "acknowledged" ? "bg-warning" : "bg-critical")} />
                {i < (detail.data?.transitions.length ?? 0) - 1 && <span className="w-px flex-1 bg-border" />}
              </div>
              <div className="pb-1">
                <div className="text-xs">
                  <span className="font-medium">{t.toState}</span>
                  {t.fromState && t.fromState !== "normal" && <span className="text-muted-foreground"> · from {t.fromState}</span>}
                  {t.observedValue !== undefined && t.observedValue !== null && <span className="text-muted-foreground"> · value {t.observedValue.toFixed(1)}</span>}
                </div>
                <div className="text-[11px] text-muted-foreground">
                  {timeAgo(t.createdAt)} · {t.reason || t.actor}
                </div>
              </div>
            </div>
          ))}
        </div>

        {/* Delivery attempts per destination. */}
        {(detail.data?.deliveries ?? []).length > 0 && (
          <>
            <Separator className="my-3" />
            <SectionTitle>Deliveries</SectionTitle>
            <div className="mt-2 grid gap-1.5">
              {(detail.data?.deliveries ?? []).map((d) => (
                <div key={d.id} className="flex items-center justify-between rounded-lg border bg-muted/30 px-2.5 py-1.5">
                  <div className="flex items-center gap-2 text-xs">
                    <Send className="size-3.5 text-muted-foreground" />
                    <span className="font-medium">{d.destinationName}</span>
                    <Badge variant="outline" className="text-[10px]">{d.kind}</Badge>
                  </div>
                  <div className="flex items-center gap-2 text-[11px] text-muted-foreground">
                    {d.lastStatusCode ? <span className="tabular">HTTP {d.lastStatusCode}</span> : null}
                    {d.lastError && <span className="max-w-40 truncate text-destructive" title={d.lastError}>{d.lastError}</span>}
                    <span>{d.attempts} attempt{d.attempts === 1 ? "" : "s"}</span>
                    <StateBadge label={d.status} tone={deliveryTone[d.status] ?? "muted"} />
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
        <div className="mt-3 flex items-center gap-1.5 text-[11px] text-muted-foreground">
          <Clock className="size-3" /> Fingerprint <Mono>{occurrence.fingerprint}</Mono>
        </div>
      </CardContent>
    </Card>
  );
}
