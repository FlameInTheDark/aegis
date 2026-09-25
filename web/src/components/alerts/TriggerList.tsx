import * as React from "react";
import { Bell, Copy, Gauge, Loader2, MemoryStick, Pencil, Play, Plus, Search, Trash2, Workflow } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { useRouter } from "@/lib/router";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState, SectionTitle, SeverityBadge } from "@/components/shared";
import { ConfirmDialog } from "@/components/ui";
import {
  useAlertTriggers, useDeleteTrigger, useTestTrigger, useToggleTrigger, type AlertTrigger,
} from "@/lib/queries.alerts";
import { compileSummary, draftFromApi, seedMetricDraft, type TriggerDraft } from "@/lib/alert-draft";
import { TriggerEditor, type EditorTarget } from "./TriggerEditor";

// Trigger rules tab: server-paginated table with filters, per-row actions
// (edit, duplicate, enable/disable, test, delete) and the visual editor.
// A disabled rule stays visible — paused is a state, not an absence.

export function TriggerList() {
  const router = useRouter();
  const [q, setQ] = React.useState("");
  const [kind, setKind] = React.useState("all");
  const [enabled, setEnabled] = React.useState("all");
  const [page, setPage] = React.useState(1);
  const [editor, setEditor] = React.useState<EditorTarget | null>(null);
  const [editorOpen, setEditorOpen] = React.useState(false);
  const [seed, setSeed] = React.useState<TriggerDraft | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<AlertTrigger | null>(null);
  const test = useTestTrigger();
  const toggle = useToggleTrigger();
  const del = useDeleteTrigger();

  const list = useAlertTriggers({ q, kind, enabled, page, limit: 25 });
  const items = list.data?.items ?? [];
  const total = list.data?.total ?? 0;
  const pageSize = 25;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const openEditor = (t: EditorTarget, seedDraft: TriggerDraft | null = null) => {
    setSeed(seedDraft);
    setEditor(t);
    setEditorOpen(true);
  };

  // Deep link from the asset page (and presets elsewhere):
  // /alerts?tab=triggers&new=metric&metric=cpu_percent&asset=<id>&label=<name>
  // opens the editor with a prefilled device-metric draft, then the params
  // are stripped so a refresh does not re-open it.
  const bootstrapped = React.useRef(false);
  React.useEffect(() => {
    if (bootstrapped.current) return;
    bootstrapped.current = true;
    if (router.query.get("new") !== "metric") return;
    openEditor(
      { mode: "new" },
      seedMetricDraft({
        metricField: router.query.get("metric") ?? "cpu_percent",
        assetId: router.query.get("asset") ?? undefined,
        assetLabel: router.query.get("label") ?? undefined,
      }),
    );
    router.navigate("/alerts?tab=triggers", { replace: true });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => { setQ(e.target.value); setPage(1); }} placeholder="Search triggers…" className="h-8 pl-8 text-[13px]" aria-label="Search triggers" />
        </div>
        <Select value={kind} onValueChange={(v) => { setKind(v); setPage(1); }}>
          <SelectTrigger size="sm" className="w-36" aria-label="Filter by kind"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All kinds</SelectItem>
            <SelectItem value="event">Domain events</SelectItem>
            <SelectItem value="device_metric">Device metrics</SelectItem>
          </SelectContent>
        </Select>
        <Select value={enabled} onValueChange={(v) => { setEnabled(v); setPage(1); }}>
          <SelectTrigger size="sm" className="w-32" aria-label="Filter by state"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any state</SelectItem>
            <SelectItem value="true">Enabled</SelectItem>
            <SelectItem value="false">Paused</SelectItem>
          </SelectContent>
        </Select>
        <div className="ml-auto">
          <NewTriggerMenu onOpen={(s) => openEditor({ mode: "new" }, s)} />
        </div>
      </div>

      <Card className="overflow-hidden py-0">
        {list.isLoading ? (
          <p className="flex items-center gap-2 px-4 py-10 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> Loading triggers…</p>
        ) : items.length === 0 ? (
          <EmptyState
            icon={Bell}
            title={q || kind !== "all" || enabled !== "all" ? "No triggers match these filters" : "No trigger rules yet"}
            description={q || kind !== "all" || enabled !== "all" ? "Adjust the filters to see more rules." : "Create a trigger to fire alerts on domain events or device metric thresholds."}
            action={<NewTriggerMenu onOpen={(s) => openEditor({ mode: "new" }, s)} />}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-4">Trigger</TableHead>
                <TableHead>Definition</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead className="text-right">Firing</TableHead>
                <TableHead>Last evaluated</TableHead>
                <TableHead className="w-24 text-right">Enabled</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map(({ trigger: t, firing }) => (
                <TableRow key={t.id}>
                  <TableCell className="max-w-56 pl-4">
                    <div className="flex flex-col">
                      <button type="button" className="truncate text-left font-medium hover:text-primary" onClick={() => openEditor({ mode: "edit", trigger: toApi(t) })}>
                        {t.name}
                      </button>
                      <span className="truncate text-xs text-muted-foreground">
                        {t.kind === "device_metric" ? "Device metric" : "Domain event"}
                        {t.lastError && <span className="ml-1 text-destructive"> · {t.lastError}</span>}
                      </span>
                    </div>
                  </TableCell>
                  <TableCell className="max-w-96">
                    <span className="line-clamp-2 text-xs text-muted-foreground" title={compileSummary(draftFromApi(toApi(t)))}>
                      {compileSummary(draftFromApi(toApi(t)))}
                    </span>
                  </TableCell>
                  <TableCell><SeverityBadge severity={t.severity as never} compact /></TableCell>
                  <TableCell className="text-right tabular">
                    {firing > 0 ? <Badge className="text-[11px]">{firing} open</Badge> : <span className="text-muted-foreground">0</span>}
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{t.lastEvaluatedAt ? timeAgo(t.lastEvaluatedAt) : "never"}</TableCell>
                  <TableCell className="text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      <Switch checked={t.enabled} onCheckedChange={(v) => toggle.mutate({ id: t.id, enabled: v })} aria-label={`Enable ${t.name}`} />
                    </div>
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon-xs" aria-label={`Actions for ${t.name}`}>•••</Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => openEditor({ mode: "edit", trigger: toApi(t) })}><Pencil /> Edit</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => openEditor({ mode: "duplicate", trigger: toApi(t) })}><Copy /> Duplicate</DropdownMenuItem>
                        <DropdownMenuItem onClick={() => test.mutate(t.id)}><Play /> Test</DropdownMenuItem>
                        <DropdownMenuItem variant="destructive" onClick={() => setDeleteTarget(t)}><Trash2 /> Delete</DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
        {total > pageSize && (
          <div className="flex items-center justify-between border-t px-4 py-2 text-xs text-muted-foreground">
            <span className="tabular">{total} triggers</span>
            <div className="flex items-center gap-1.5">
              <Button variant="outline" size="xs" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>Previous</Button>
              <span className="tabular">Page {page} of {totalPages}</span>
              <Button variant="outline" size="xs" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>Next</Button>
            </div>
          </div>
        )}
      </Card>

      {/* Test result surface: distinct no-sample vs no-match vs error. */}
      {test.data && <TestResultCard result={test.data as { status: string; evaluated?: number; matched?: number; error?: string }} />}
      {test.isPending && (
        <p className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="size-3.5 animate-spin" /> Evaluating the recent sample…</p>
      )}

      <TriggerEditor open={editorOpen} onOpenChange={setEditorOpen} target={editor} seed={seed} />

      <ConfirmDialog
        open={!!deleteTarget}
        title={`Delete trigger “${deleteTarget?.name}”?`}
        body="Occurrences and history are kept; the rule simply stops evaluating and can no longer fire."
        confirmLabel="Delete trigger"
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => {
          if (deleteTarget) del.mutate(deleteTarget.id);
          setDeleteTarget(null);
        }}
      />
    </div>
  );
}

/** New-trigger split menu: blank editor or performance presets that open
 *  the editor with a prefilled device-metric draft (plan §5.11 editor). */
function NewTriggerMenu({ onOpen }: { onOpen: (seed: TriggerDraft | null) => void }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button size="sm"><Plus /> New trigger</Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-64">
        <DropdownMenuItem onClick={() => onOpen(null)}>
          <Workflow /> Blank trigger…
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuLabel>Performance presets</DropdownMenuLabel>
        <DropdownMenuItem onClick={() => onOpen(seedMetricDraft({ metricField: "cpu_percent" }))}>
          <Gauge /> High CPU utilization…
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => onOpen(seedMetricDraft({ metricField: "mem_used_percent" }))}>
          <MemoryStick /> High memory utilization…
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function TestResultCard({ result }: { result: { status: string; evaluated?: number; matched?: number; error?: string } }) {
  return (
    <Card className="py-3">
      <div className="px-4">
        <SectionTitle>Test result</SectionTitle>
        {result.status === "ok" && (
          <p className="mt-1 text-[13px]">
            Evaluated <span className="tabular">{result.evaluated}</span> sample{result.evaluated === 1 ? "" : "s"} ·{" "}
            <span className={cn((result.matched ?? 0) > 0 ? "text-warning" : "text-muted-foreground")}>
              {result.matched} matched
            </span>
            {(result.evaluated ?? 0) === 0 && <span className="ml-1 text-muted-foreground">(no sample available — this is not a pass)</span>}
            {(result.evaluated ?? 0) > 0 && (result.matched ?? 0) === 0 && <span className="ml-1 text-muted-foreground">(sample evaluated, condition did not match)</span>}
          </p>
        )}
        {result.status === "no_sample" && (
          <p className="mt-1 text-[13px] text-muted-foreground">No recent events of the selected types exist — the test could not run. This is not a successful match.</p>
        )}
        {result.status === "source_unavailable" && (
          <p className="mt-1 text-[13px] text-warning">The source (ClickHouse or the event stream) is unavailable; testing is disabled until it recovers.</p>
        )}
        {result.status === "error" && <p className="mt-1 text-[13px] text-destructive">{result.error}</p>}
      </div>
    </Card>
  );
}

/** toApi round-trips the UI model into the raw API shape the editor expects. */
function toApi(t: AlertTrigger) {
  return {
    id: t.id, organization_id: "", name: t.name, description: t.description,
    kind: t.kind, enabled: t.enabled, lifecycle: t.lifecycle as never, severity: t.severity,
    scope: { site_ids: t.scope.site_ids ?? [], asset_ids: t.scope.asset_ids ?? [], device_types: t.scope.device_types ?? [] },
    conditions: t.conditions as Record<string, unknown>,
    event_types: t.eventTypes, recovery_event_types: t.recoveryEventTypes,
    metric_field: t.metricField, aggregation: t.aggregation, operator: t.operator,
    threshold: t.threshold, window_secs: t.windowSecs, group_by: t.groupBy,
    activation_secs: t.activationSecs, recovery_secs: t.recoverySecs,
    recovery_threshold: t.recoveryThreshold, missing_data_policy: t.missingDataPolicy,
    cooldown_secs: t.cooldownSecs, repeat_secs: t.repeatSecs,
    destination_ids: t.destinationIds, revision: t.revision, created_by: t.createdBy,
    created_at: "", updated_at: t.updatedAt, last_evaluated_at: t.lastEvaluatedAt,
    last_error: t.lastError,
  };
}
