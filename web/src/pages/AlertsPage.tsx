import * as React from "react";
import { BellRing, History, Search, Webhook, Workflow, X } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { useRouter } from "@/lib/router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsUnderlineList, TabsUnderlineTrigger } from "@/components/ui/tabs";
import { EmptyState, PageHeader, SeverityBadge, StatusDot, TableFooterBar } from "@/components/shared";
import { usePageSize } from "@/lib/pagination";
import { useAlertOccurrences, type AlertOccurrence } from "@/lib/queries.alerts";
import { OccurrenceDetail } from "@/components/alerts/OccurrenceDetail";
import { TriggerList } from "@/components/alerts/TriggerList";
import { DestinationManager } from "@/components/alerts/DestinationManager";

// Alerts: the four-view operator area (plan §5.11) — active occurrences
// (master/detail), history (server-paginated), trigger rules (visual
// builder) and destinations. Live updates arrive as post-commit WS hints
// (useNotificationStream) and the REST list stays the recovery path.

type Tab = "active" | "history" | "triggers" | "destinations";

export function AlertsPage() {
  const router = useRouter();
  const tabParam = router.query.get("tab") as Tab | null;
  const [tab, setTab] = React.useState<Tab>(tabParam ?? "active");

  React.useEffect(() => {
    if (tabParam && tabParam !== tab) setTab(tabParam);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tabParam]);

  const changeTab = (t: string) => {
    setTab(t as Tab);
    router.navigate(`/alerts?tab=${t}`, { replace: true });
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Alerts"
        description="Operational conditions, occurrences, and destinations"
      />
      <Tabs value={tab} onValueChange={changeTab}>
        <TabsUnderlineList>
          <TabsUnderlineTrigger value="active"><BellRing className="size-3.5" /> Active</TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="history"><History className="size-3.5" /> History</TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="triggers"><Workflow className="size-3.5" /> Trigger rules</TabsUnderlineTrigger>
          <TabsUnderlineTrigger value="destinations"><Webhook className="size-3.5" /> Destinations</TabsUnderlineTrigger>
        </TabsUnderlineList>
        <TabsContent value="active"><ActiveOccurrences /></TabsContent>
        <TabsContent value="history"><HistoryOccurrences /></TabsContent>
        <TabsContent value="triggers"><TriggerList /></TabsContent>
        <TabsContent value="destinations"><DestinationManager /></TabsContent>
      </Tabs>
    </div>
  );
}

// --- active occurrences ------------------------------------------------------

function ActiveOccurrences() {
  const router = useRouter();
  const [q, setQ] = React.useState("");
  const [severity, setSeverity] = React.useState("all");
  const list = useAlertOccurrences({ state: "active", q, severity, limit: 100 });
  const items = list.data?.items ?? [];
  const [selectedId, setSelectedId] = React.useState<string | null>(router.query.get("id"));

  React.useEffect(() => {
    if (!selectedId && items.length > 0) setSelectedId(items[0].id);
  }, [items, selectedId]);
  const selected = items.find((o) => o.id === selectedId) ?? null;

  const firing = items.filter((o) => o.state === "firing").length;
  const acknowledged = items.length - firing;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title…" className="h-8 pl-8 text-[13px]" aria-label="Search alerts" />
        </div>
        <Select value={severity} onValueChange={setSeverity}>
          <SelectTrigger size="sm" className="w-36" aria-label="Filter by severity"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            {["critical", "high", "medium", "low", "info"].map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {(q || severity !== "all") && (
          <Button variant="ghost" size="sm" onClick={() => { setQ(""); setSeverity("all"); }}><X /> Clear</Button>
        )}
        <div className="ml-auto flex items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5"><StatusDot tone="danger" pulse={firing > 0} /> {firing} firing</span>
          <span className="flex items-center gap-1.5"><StatusDot tone="warning" /> {acknowledged} acknowledged</span>
        </div>
      </div>

      {list.isLoading ? (
        <p className="py-10 text-center text-sm text-muted-foreground">Loading alerts…</p>
      ) : items.length === 0 ? (
        <EmptyState
          icon={BellRing}
          title={q || severity !== "all" ? "No alerts match these filters" : "No open alerts"}
          description={
            q || severity !== "all"
              ? "Adjust the filters to see more occurrences."
              : "Enabled triggers have not fired. When they do, occurrences appear here with evidence and delivery status."
          }
        />
      ) : (
        <div className="grid gap-4 lg:grid-cols-5">
          <div className="flex flex-col gap-2 lg:col-span-2">
            {items.map((o) => (
              <OccurrenceCard key={o.id} occurrence={o} active={o.id === selectedId} onClick={() => setSelectedId(o.id)} />
            ))}
          </div>
          {selected ? (
            <OccurrenceDetail occurrence={selected} onClose={() => setSelectedId(null)} />
          ) : (
            <Card className="self-start lg:col-span-3">
              <EmptyState compact title="Select an alert" description="Pick an occurrence to inspect its evidence and lifecycle." />
            </Card>
          )}
        </div>
      )}
    </div>
  );
}

function OccurrenceCard({ occurrence: o, active, onClick }: { occurrence: AlertOccurrence; active: boolean; onClick: () => void }) {
  return (
    <button type="button" onClick={onClick} className={cn("relative rounded-xl border bg-card p-3 text-left", active && "border-primary/60 bg-primary/5")}>
      <span className={`absolute inset-y-0 left-0 w-1 rounded-l-xl ${
        o.severity === "critical" ? "bg-critical" : o.severity === "high" ? "bg-high" : o.severity === "medium" ? "bg-medium" : o.severity === "low" ? "bg-low" : "bg-info"
      }`} />
      <div className="flex items-center justify-between gap-2 pl-1.5">
        <span className="truncate text-[13px] font-medium">{o.title}</span>
        <SeverityBadge severity={o.severity as never} compact />
      </div>
      <p className="mt-0.5 line-clamp-1 pl-1.5 text-xs text-muted-foreground">{o.summary}</p>
      <div className="mt-1.5 flex items-center gap-2 pl-1.5 text-[11px] text-muted-foreground">
        <StatusDot tone={o.state === "firing" ? "danger" : o.state === "acknowledged" ? "warning" : "muted"} pulse={o.state === "firing"} />
        <span className="capitalize">{o.state}</span>
        <span>· updated {timeAgo(o.updatedAt)}</span>
        {o.occurrenceCount > 1 && <span>· seen {o.occurrenceCount}×</span>}
      </div>
    </button>
  );
}

// --- history -------------------------------------------------------------------

function HistoryOccurrences() {
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSize] = usePageSize("alerts-history");
  const list = useAlertOccurrences({ state: "all", q: "", page, limit: pageSize });
  const items = (list.data?.items ?? []).filter((o) => o.state === "recovered" || o.state === "suppressed");
  const total = list.data?.total ?? 0;

  return (
    <div className="overflow-hidden rounded-xl border bg-card">
      {list.isLoading ? (
        <p className="py-10 text-center text-sm text-muted-foreground">Loading history…</p>
      ) : items.length === 0 ? (
        <EmptyState
          icon={History}
          title="No resolved alerts yet"
          description="Recovered and suppressed occurrences land here with their full transition timeline."
        />
      ) : (
        <div>
          {items.map((o) => (
            <div key={o.id} className="flex items-center justify-between border-b px-4 py-2.5 last:border-b-0">
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={o.severity as never} compact />
                  <span className="truncate text-[13px] font-medium">{o.title}</span>
                  <span className="text-[11px] uppercase tracking-wide text-muted-foreground">{o.state}</span>
                </div>
                <p className="mt-0.5 truncate text-xs text-muted-foreground">{o.summary}</p>
              </div>
              <div className="ml-3 shrink-0 text-right text-xs text-muted-foreground">
                <div>opened {timeAgo(o.openedAt)}</div>
                {o.recoveredAt && <div>recovered {timeAgo(o.recoveredAt)}</div>}
              </div>
            </div>
          ))}
          <TableFooterBar
            total={total}
            page={page}
            pageSize={pageSize}
            onPage={setPage}
            onPageSize={setPageSize}
            label="resolved alerts"
          />
        </div>
      )}
    </div>
  );
}
