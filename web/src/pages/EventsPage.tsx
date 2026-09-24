import * as React from "react";
import { Activity, Pause, Play, Search, X } from "lucide-react";

import { cn, formatDateTime } from "@/lib/utils";
import { Link } from "@/lib/router";
import type { EventLevel, PlatformEvent } from "@/data/types";
import { useEvents } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { EmptyState, Mono, PageHeader, StatusDot } from "@/components/shared";

const levelTone: Record<EventLevel, "muted" | "warning" | "danger"> = { info: "muted", warning: "warning", error: "danger", critical: "danger" };

export function EventsPage() {
  const [q, setQ] = React.useState("");
  const [level, setLevel] = React.useState("all");
  const [category, setCategory] = React.useState("all");
  const [live, setLive] = React.useState(true);
  const [expanded, setExpanded] = React.useState<string | null>(null);

  const eventsQ = useEvents({ severity: level === "all" ? undefined : level, limit: 200, cursor: undefined });
  // refetchInterval keeps the stream fresh; "Pause live" turns it off
  const items = eventsQ.data?.items ?? [];
  React.useEffect(() => {
    // toggle the query's polling by invalidating on resume
    if (live) void eventsQ.refetch();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [live]);

  const list = React.useMemo(() => {
    const needle = q.toLowerCase();
    return items.filter((e) => {
      if (category !== "all" && e.category !== category) return false;
      if (!needle) return true;
      return [e.message, e.srcIp, e.category, ...Object.values(e.meta ?? {})].some((s) => s?.toLowerCase().includes(needle));
    });
  }, [items, q, level, category]);

  // group by day
  const groups = React.useMemo(() => {
    const m = new Map<string, PlatformEvent[]>();
    list.forEach((e) => {
      const key = new Date(e.timestamp).toDateString();
      m.set(key, [...(m.get(key) ?? []), e]);
    });
    return Array.from(m.entries());
  }, [list]);

  const levelCount = (l: EventLevel) => items.filter((e) => e.level === l).length;
  const knownCategories = Array.from(new Set(items.map((e) => e.category))).sort();

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Events"
        description="Raw sensor event stream from network taps, agents and collectors — deduplicated and normalized. Retention follows the ClickHouse tiering policy."
        actions={
          <Button variant={live ? "default" : "outline"} size="sm" onClick={() => setLive((v) => !v)}>
            {live ? (
              <>
                <Pause /> Pause live
              </>
            ) : (
              <>
                <Play /> Resume live
              </>
            )}
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search message, source, address…" className="h-8 pl-8 text-[13px]" />
        </div>
        <Select value={level} onValueChange={setLevel}>
          <SelectTrigger size="sm" className="w-[140px]">
            <span className="text-muted-foreground">Level:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any</SelectItem>
            <SelectItem value="info">Info</SelectItem>
            <SelectItem value="warning">Warning</SelectItem>
            <SelectItem value="error">Error</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
          </SelectContent>
        </Select>
        <Select value={category} onValueChange={setCategory}>
          <SelectTrigger size="sm" className="w-[160px]">
            <span className="text-muted-foreground">Type:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All</SelectItem>
            {knownCategories.map((c) => (
              <SelectItem key={c} value={c} className="capitalize">
                {c.replace(/_/g, " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {(q || level !== "all" || category !== "all") && (
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground"
            onClick={() => {
              setQ("");
              setLevel("all");
              setCategory("all");
            }}
          >
            <X /> Clear
          </Button>
        )}
        <div className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <StatusDot tone="muted" className="size-1.5" /> {levelCount("info")} info
          </span>
          <span className="flex items-center gap-1.5">
            <StatusDot tone="warning" className="size-1.5" /> {levelCount("warning")} warn
          </span>
          <span className="flex items-center gap-1.5">
            <StatusDot tone="danger" className="size-1.5" /> {levelCount("error") + levelCount("critical")} error
          </span>
          {live && (
            <span className="flex items-center gap-1.5 text-success">
              <StatusDot tone="success" pulse className="size-1.5" /> live
            </span>
          )}
        </div>
      </div>

      <div className="overflow-hidden rounded-xl border bg-card">
        {groups.length === 0 ? (
          <EmptyState
            icon={Activity}
            title={eventsQ.isError ? "Event stream unavailable" : "No events match"}
            description={eventsQ.isError ? "The sensor event stream requires the ClickHouse backend to be running." : "Try a different level or type filter."}
          />
        ) : (
          groups.map(([day, evs]) => (
            <div key={day}>
              <div className="sticky top-0 z-10 border-b bg-muted/60 px-4 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground backdrop-blur">
                {day === new Date().toDateString() ? "Today" : day === new Date(Date.now() - 86_400_000).toDateString() ? "Yesterday" : day}
                <span className="ml-2 font-normal normal-case tracking-normal">{evs.length} events</span>
              </div>
              <ul className="divide-y">
                {evs.map((e) => {
                  const open = expanded === e.id;
                  return (
                    <li key={e.id} className={cn("group text-sm transition-colors hover:bg-accent/30", open && "bg-accent/20")}>
                      <button className="flex w-full items-start gap-3 px-4 py-2 text-left cursor-pointer" onClick={() => setExpanded(open ? null : e.id)}>
                        <span className="mt-0.5 shrink-0 font-mono text-[11px] tabular text-muted-foreground">{formatDateTime(e.timestamp).split(", ")[1] ?? formatDateTime(e.timestamp)}</span>
                        <StatusDot tone={levelTone[e.level]} className="mt-1.5 size-1.5" />
                        <Badge variant="muted" className="mt-0.5 w-24 justify-center truncate capitalize">
                          {e.category.replace(/_/g, " ")}
                        </Badge>
                        <span className={cn("min-w-0 flex-1 leading-snug", e.level === "critical" && "font-medium text-critical", e.level === "error" && "text-foreground")}>{e.message}</span>
                        <span className="hidden shrink-0 items-center gap-2 text-xs text-muted-foreground md:flex">
                          {e.srcIp && <Mono className="text-[11px]">{e.srcIp}</Mono>}
                        </span>
                      </button>
                      {open && (
                        <div className="grid gap-x-6 gap-y-1 border-t bg-[oklch(0.11_0.01_262)] px-4 py-3 font-mono text-[11.5px] text-muted-foreground sm:grid-cols-2">
                          <div>
                            id: <span className="text-foreground/80">{e.id}</span>
                          </div>
                          <div>
                            timestamp: <span className="text-foreground/80">{new Date(e.timestamp).toISOString()}</span>
                          </div>
                          <div>
                            level: <span className="text-foreground/80">{e.level}</span>
                          </div>
                          <div>
                            type: <span className="text-foreground/80">{e.category}</span>
                          </div>
                          {e.srcIp && (
                            <div>
                              src: <span className="text-foreground/80">{e.srcIp}</span>
                            </div>
                          )}
                          {Object.entries(e.meta ?? {}).map(([k, v]) => (
                            <div key={k}>
                              {k}: <span className="text-foreground/80">{v}</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
