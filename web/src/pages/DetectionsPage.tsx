import * as React from "react";
import { Bell, Check, Crosshair, ShieldBan, Search, ShieldCheck, X, Waypoints, ListFilter, Plus, Lock } from "lucide-react";

import { cn, timeAgo, formatDateTime } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type { Detection, DetectionRule, DetectionStatus } from "@/data/types";
import { useScope } from "@/components/layout/AppShell";
import { useAsset, useDetectionMatches, useUpdateMatchStatus, useDetectionRules, useUpdateRule, useCreateRule } from "@/lib/queries";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Card, CardContent } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { EmptyState, KeyValue, Mono, PageHeader, SeverityBadge, severityMeta, StateBadge, StatusDot, TableFooterBar } from "@/components/shared";
import { usePageSize } from "@/lib/pagination";
import { toast } from "@/components/ui/toaster";

const statusTone = (s: DetectionStatus) =>
  (s === "new" ? "danger" : s === "investigating" ? "primary" : s === "contained" ? "warning" : "muted") as
    | "danger"
    | "primary"
    | "warning"
    | "muted";

export function DetectionsPage() {
  const { query, navigate } = useRouter();
  const { user } = useAuth();
  // Server-side filtering + pagination (Phase 1.2): the API already paged;
  // the console now drives it with q/level/status and pages through `total`
  // instead of holding 200 rows in the browser.
  const initialTab = query.get("tab") === "rules" ? "rules" : "matches";
  const [tab, setTab] = React.useState<"matches" | "rules">(initialTab as "matches" | "rules");
  const [q, setQ] = React.useState("");
  const [debouncedQ, setDebouncedQ] = React.useState("");
  const [sev, setSev] = React.useState("all");
  const [status, setStatus] = React.useState("all");
  const [mine, setMine] = React.useState(false);
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSizeRaw] = usePageSize("detections");
  const [selectedId, setSelectedId] = React.useState<string | null>(query.get("id"));

  React.useEffect(() => {
    const t = setTimeout(() => setDebouncedQ(q), 300);
    return () => clearTimeout(t);
  }, [q]);

  React.useEffect(() => {
    if (query.get("id")) setSelectedId(query.get("id"));
  }, [query]);

  React.useEffect(() => {
    setPage(1);
  }, [debouncedQ, sev, status, mine]);

  const setPageSize = React.useCallback(
    (n: number) => {
      setPageSizeRaw(n);
      setPage(1);
    },
    [setPageSizeRaw],
  );

  const matchesQ = useDetectionMatches({
    level: sev,
    status,
    search: debouncedQ || undefined,
    assignee: mine ? "me" : undefined,
    page,
    limit: pageSize,
    withCounts: true,
  });
  const updateStatus = useUpdateMatchStatus();
  const items = matchesQ.data?.items ?? [];
  const total = matchesQ.data?.total ?? 0;
  // Status counts come from the server (same filters minus status) so the
  // cards stay truthful under pagination.
  const counts = matchesQ.data?.counts;

  const list = items;

  React.useEffect(() => {
    if (!selectedId && list.length > 0) setSelectedId(list[0].id);
  }, [list, selectedId]);

  const selected = items.find((d) => d.id === selectedId) ?? null;

  const setStatusFor = (id: string, next: DetectionStatus, label: string) => {
    updateStatus.mutate(
      { id, status: next },
      {
        onSuccess: () => toast({ title: `Detection ${label}`, variant: "success" }),
        onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const assignToMe = (id: string) => {
    if (!user) return;
    updateStatus.mutate(
      { id, assignee: user.id },
      {
        onSuccess: () => toast({ title: "Assigned to you", variant: "success" }),
        onError: (e) => toast({ title: "Assign failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const countFor = (s: DetectionStatus) => counts?.[s] ?? 0;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Detections" description="Alerts produced by the correlation engine: detection rules evaluated against the sensor event stream. Triage each match through the workflow." />

      {/* Matches / Rules tabs (F1) */}
      <div className="flex w-fit items-center gap-1 rounded-lg border bg-card p-1">
        {(
          [
            { id: "matches", label: "Matches" },
            { id: "rules", label: "Rules" },
          ] as const
        ).map((t) => (
          <button
            key={t.id}
            onClick={() => {
              setTab(t.id);
              navigate(t.id === "rules" ? "/detections?tab=rules" : "/detections", { replace: true });
            }}
            className={cn(
              "rounded-md px-3 py-1.5 text-[13px] transition-colors cursor-pointer",
              tab === t.id ? "bg-primary/10 font-medium text-primary" : "text-muted-foreground hover:bg-accent/40",
            )}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "matches" ? (
        <>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {(["new", "investigating", "contained", "closed"] as DetectionStatus[]).map((s) => (
              <button
                key={s}
                onClick={() => setStatus(status === s ? "all" : s)}
                className={cn(
                  "flex items-center justify-between rounded-xl border bg-card px-4 py-3 text-left transition-colors hover:bg-accent/30 cursor-pointer",
                  status === s && "border-primary",
                )}
              >
                <div className="leading-tight">
                  <div className="tabular text-lg font-semibold">{countFor(s)}</div>
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{s}</div>
                </div>
                <StatusDot tone={statusTone(s)} pulse={s === "new" && countFor(s) > 0} className="size-2.5" />
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
            <Button variant={mine ? "secondary" : "outline"} size="sm" className="gap-1.5" onClick={() => setMine((m) => !m)}>
              <ListFilter className="size-3.5" /> My queue
            </Button>
            {(q || sev !== "all" || status !== "all" || mine) && (
              <Button
                variant="ghost"
                size="sm"
                className="text-muted-foreground"
                onClick={() => {
                  setQ("");
                  setSev("all");
                  setStatus("all");
                  setMine(false);
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
                        active && "border-primary/60 bg-primary/5",
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
              <TableFooterBar total={total} page={page} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} label="matches" />
            </div>

            {/* Detail */}
            <Card className="self-start lg:col-span-3">
              {!selected ? (
                <CardContent>
                  <EmptyState compact icon={Bell} title="Select a detection" />
                </CardContent>
              ) : (
                <DetectionDetail detection={selected} onStatus={setStatusFor} onAssignToMe={assignToMe} currentUserId={user?.id ?? null} />
              )}
            </Card>
          </div>
        </>
      ) : (
        <RulesTab />
      )}
    </div>
  );
}

function DetectionDetail({
  detection: selected,
  onStatus,
  onAssignToMe,
  currentUserId,
}: {
  detection: Detection;
  onStatus: (id: string, next: DetectionStatus, label: string) => void;
  onAssignToMe: (id: string) => void;
  currentUserId: string | null;
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
        {currentUserId && selected.assignee !== currentUserId && (
          <Button size="sm" variant="ghost" onClick={() => onAssignToMe(selected.id)}>
            Assign to me
          </Button>
        )}
        {selected.assignee && (
          <span className="ml-auto self-center text-xs text-muted-foreground">
            Assignee <Mono className="text-[11px]">{selected.assignee === currentUserId ? "you" : selected.assignee.slice(0, 8)}</Mono>
          </span>
        )}
      </div>
    </CardContent>
  );
}

/* ------------------------------------------------------------------ */
/* Rules tab (F1 first slice)                                          */
/* ------------------------------------------------------------------ */

const ruleTypes = ["single_event", "threshold", "temporal", "entity_agg"] as const;
const ruleLevels = ["info", "low", "medium", "high", "critical"] as const;
const conditionOperators = ["eq", "neq", "in", "gt", "gte", "lt", "lte", "contains", "regex", "exists"] as const;

interface DraftCondition {
  field: string;
  operator: (typeof conditionOperators)[number];
  values: string;
}

function RulesTab() {
  const rulesQ = useDetectionRules();
  const updateRule = useUpdateRule();
  const [createOpen, setCreateOpen] = React.useState(false);
  const rules = rulesQ.data ?? [];

  const toggle = (r: DetectionRule, enabled: boolean) => {
    updateRule.mutate(
      { id: r.id, enabled },
      {
        onSuccess: () => toast({ title: enabled ? "Rule enabled" : "Rule disabled", variant: "success" }),
        onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <p className="max-w-2xl text-xs leading-relaxed text-muted-foreground">
          Built-in rules are editable only for <b>enabled</b> — a seed rerun must not fight the operator. Custom rules use the four implemented
          rule types and the validated condition DSL (bounded regex, known fields, no nested quantifiers).
        </p>
        <Button size="sm" onClick={() => setCreateOpen(true)}>
          <Plus /> New rule
        </Button>
      </div>

      <div className="overflow-hidden rounded-xl border bg-card">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b text-left text-[11px] uppercase tracking-wider text-muted-foreground">
              <th className="px-4 py-2.5 font-semibold">Rule</th>
              <th className="px-3 py-2.5 font-semibold">Type</th>
              <th className="px-3 py-2.5 font-semibold">Window</th>
              <th className="px-3 py-2.5 font-semibold">Level</th>
              <th className="px-3 py-2.5 font-semibold">Status</th>
              <th className="px-3 py-2.5 font-semibold">Enabled</th>
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8">
                  <EmptyState icon={ShieldCheck} title="No rules" description="The seeded rule set appears here on first run." />
                </td>
              </tr>
            )}
            {rules.map((r) => {
              const builtin = r.author === "aegis" || r.identifier.startsWith("aegis-");
              return (
                <tr key={r.id} className="border-b last:border-0 hover:bg-accent/20">
                  <td className="max-w-sm px-4 py-3">
                    <div className="flex items-center gap-1.5 font-medium">
                      {r.title}
                      {builtin && (
                        <span title="Built-in rule: only the enabled flag is editable">
                          <Lock className="size-3 text-muted-foreground" />
                        </span>
                      )}
                    </div>
                    <div className="truncate text-xs text-muted-foreground">
                      <Mono className="text-[11px]">{r.identifier}</Mono>
                      {r.description ? ` · ${r.description}` : ""}
                    </div>
                  </td>
                  <td className="px-3 py-3">
                    <Badge variant="outline" className="font-mono text-[10px]">
                      {r.type}
                    </Badge>
                  </td>
                  <td className="px-3 py-3 tabular text-xs text-muted-foreground">{r.window || "—"}</td>
                  <td className="px-3 py-3">
                    <SeverityBadge severity={(r.level || "medium") as Detection["severity"]} compact />
                  </td>
                  <td className="px-3 py-3">
                    <StateBadge label={r.status || "stable"} tone={r.status === "experimental" ? "warning" : "muted"} className="px-1.5 text-[10px]" />
                  </td>
                  <td className="px-3 py-3">
                    <Switch checked={r.enabled} onCheckedChange={(v) => toggle(r, v)} />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <CreateRuleDialog open={createOpen} onOpenChange={setCreateOpen} />
    </div>
  );
}

function CreateRuleDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const createRule = useCreateRule();
  const [title, setTitle] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [type, setType] = React.useState<(typeof ruleTypes)[number]>("threshold");
  const [level, setLevel] = React.useState<(typeof ruleLevels)[number]>("medium");
  const [eventType, setEventType] = React.useState("");
  const [window_, setWindow] = React.useState("5m");
  const [count, setCount] = React.useState("10");
  const [distinct, setDistinct] = React.useState("");
  const [conditions, setConditions] = React.useState<DraftCondition[]>([{ field: "", operator: "eq", values: "" }]);

  const needsWindow = type !== "single_event";
  const needsThreshold = type === "threshold" || type === "entity_agg";
  const needsConditions = type === "single_event" || type === "temporal";

  // Client-side mirror of the server validation (internal/detections).
  // The server remains canonical — this only avoids a round trip.
  const clientIssues = React.useMemo(() => {
    const issues: string[] = [];
    if (!title.trim()) issues.push("Title is required.");
    if (needsWindow && !/^(\d+s|\d+m|\d+h)$/.test(window_)) issues.push("Window must look like 60s, 5m, 1h.");
    if (needsThreshold) {
      const n = Number(count);
      if (!Number.isInteger(n) || n < 2 || n > 100000) issues.push("Threshold count must be 2-100000.");
    }
    if (type === "temporal" && conditions.length < 2) issues.push("Temporal rules need at least two ordered conditions.");
    for (const c of conditions) {
      if (needsConditions && !c.field.trim()) issues.push("Every condition needs a field.");
      if (c.operator === "regex") {
        const re = c.values.trim();
        if (re.length > 128) issues.push("Regex must be at most 128 characters.");
        if (/((?:[^()\\]|\\.)*[+*}\d])\)\s*[+*{]/.test(re)) issues.push("Regex has a nested quantifier — the server rejects it.");
      }
      if ((c.operator === "gt" || c.operator === "gte" || c.operator === "lt" || c.operator === "lte") && Number.isNaN(Number(c.values))) {
        issues.push(`Operator ${c.operator} needs a numeric value.`);
      }
    }
    return issues;
  }, [title, type, window_, count, conditions, needsWindow, needsThreshold, needsConditions]);

  const submit = () => {
    const rule: Record<string, unknown> = {
      title: title.trim(),
      description: description.trim(),
      type,
      level,
      status: "experimental",
      author: "console",
      enabled: false,
    };
    if (eventType.trim()) rule.event_type = eventType.trim();
    if (needsWindow) rule.window = window_;
    if (needsThreshold) {
      rule.threshold = { count: Number(count), ...(distinct.trim() ? { distinct: distinct.trim() } : {}) };
    }
    if (needsConditions) {
      rule.conditions = conditions
        .filter((c) => c.field.trim())
        .map((c) => ({
          field: c.field.trim(),
          operator: c.operator,
          ...(c.operator === "exists" ? {} : { values: c.values.split(",").map((v) => v.trim()).filter(Boolean) }),
        }));
    }
    createRule.mutate(rule, {
      onSuccess: () => {
        toast({ title: "Rule created", description: "It is stored disabled — enable it when ready.", variant: "success" });
        onOpenChange(false);
        setTitle("");
        setDescription("");
        setConditions([{ field: "", operator: "eq", values: "" }]);
      },
      onError: (e) => toast({ title: "Create failed", description: (e as Error).message, variant: "error" }),
    });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>New detection rule</DialogTitle>
          <DialogDescription>Limited to the four implemented types and the validated condition DSL. New rules start disabled.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="grid gap-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Title</span>
              <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Lab subnet port scan" className="h-8 text-[13px]" />
            </label>
            <label className="grid gap-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Level</span>
              <Select value={level} onValueChange={(v) => setLevel(v as (typeof ruleLevels)[number])}>
                <SelectTrigger size="sm" className="w-full capitalize">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ruleLevels.map((l) => (
                    <SelectItem key={l} value={l} className="capitalize">
                      {l}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </label>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <label className="grid gap-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Type</span>
              <Select value={type} onValueChange={(v) => setType(v as (typeof ruleTypes)[number])}>
                <SelectTrigger size="sm" className="w-full font-mono">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {ruleTypes.map((t) => (
                    <SelectItem key={t} value={t} className="font-mono text-xs">
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </label>
            <label className="grid gap-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Event type</span>
              <Input value={eventType} onChange={(e) => setEventType(e.target.value)} placeholder="flow, dns, alert…" className="h-8 font-mono text-[13px]" />
            </label>
            <label className="grid gap-1.5">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Window {needsWindow ? "" : "(unused)"}</span>
              <Input value={window_} onChange={(e) => setWindow(e.target.value)} disabled={!needsWindow} placeholder="5m" className="h-8 font-mono text-[13px]" />
            </label>
          </div>
          <label className="grid gap-1.5">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Description</span>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="What does this rule catch, and what is it allowed to see?" className="h-8 text-[13px]" />
          </label>
          {needsThreshold && (
            <div className="grid grid-cols-2 gap-3">
              <label className="grid gap-1.5">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Threshold count (2-100000)</span>
                <Input value={count} onChange={(e) => setCount(e.target.value)} className="h-8 font-mono text-[13px]" />
              </label>
              <label className="grid gap-1.5">
                <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Count distinct of (optional)</span>
                <Input value={distinct} onChange={(e) => setDistinct(e.target.value)} placeholder="dst_port, dst_ip…" className="h-8 font-mono text-[13px]" />
              </label>
            </div>
          )}
          {needsConditions && (
            <div className="grid gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                Conditions {type === "temporal" ? "(ordered stages)" : "(all must match)"}
              </span>
              {conditions.map((c, i) => (
                <div key={i} className="grid grid-cols-[1fr_130px_1fr_auto] items-center gap-2">
                  <Input
                    value={c.field}
                    onChange={(e) => setConditions((cs) => cs.map((x, j) => (j === i ? { ...x, field: e.target.value } : x)))}
                    placeholder="field (severity, dst_port…)"
                    className="h-8 font-mono text-[12px]"
                  />
                  <Select value={c.operator} onValueChange={(v) => setConditions((cs) => cs.map((x, j) => (j === i ? { ...x, operator: v as DraftCondition["operator"] } : x)))}>
                    <SelectTrigger size="sm" className="w-full font-mono">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {conditionOperators.map((op) => (
                        <SelectItem key={op} value={op} className="font-mono text-xs">
                          {op}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Input
                    value={c.values}
                    onChange={(e) => setConditions((cs) => cs.map((x, j) => (j === i ? { ...x, values: e.target.value } : x)))}
                    placeholder={c.operator === "in" ? "comma-separated values" : "value"}
                    className="h-8 font-mono text-[12px]"
                  />
                  <Button
                    variant="ghost"
                    size="sm"
                    className="text-muted-foreground"
                    disabled={conditions.length === 1}
                    onClick={() => setConditions((cs) => cs.filter((_, j) => j !== i))}
                  >
                    <X />
                  </Button>
                </div>
              ))}
              <Button variant="outline" size="sm" className="w-fit" onClick={() => setConditions((cs) => [...cs, { field: "", operator: "eq", values: "" }])}>
                <Plus /> Add condition
              </Button>
            </div>
          )}
          {clientIssues.length > 0 && (
            <div className="rounded-lg border border-warning/40 bg-warning/10 p-2.5 text-xs leading-relaxed">
              {clientIssues.map((iss) => (
                <div key={iss}>{iss}</div>
              ))}
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={clientIssues.length > 0 || createRule.isPending}>
            Create rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
