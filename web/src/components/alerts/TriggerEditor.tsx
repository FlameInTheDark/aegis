import * as React from "react";
import { AlertTriangle, ArrowDown, ArrowUp, Check, Loader2, Plus, X } from "lucide-react";

import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { useAssets, useSites } from "@/lib/queries";
import {
  useAlertCapabilities, useAlertDestinations, useCreateTrigger, usePreviewTrigger, useUpdateTrigger,
} from "@/lib/queries.alerts";
import type { AlertCapabilities, AlertTrigger as ApiTrigger } from "@/lib/api-types";
import {
  clearDraft, compileSummary, draftFromApi, draftToPayload, emptyDraft, loadDraft, saveDraft,
  scopeSummary, type ConditionRow, type TriggerDraft,
} from "@/lib/alert-draft";
import { validateDraft } from "@/lib/alert-validation";

// The visual trigger editor: a large Radix dialog with a step rail, typed
// controls for every field the capability catalog advertises, a live
// compiled summary, preview/test separated from save, and an enable
// control separated from save. The server is the canonical validator;
// lib/alert-validation mirrors its rules so the editor can fail fast, and
// server errors render inline without ever dropping the draft.

export type EditorTarget =
  | { mode: "new" }
  | { mode: "edit"; trigger: ApiTrigger }
  | { mode: "duplicate"; trigger: ApiTrigger };

const STEPS = [
  { id: "basics", label: "Basics" },
  { id: "scope", label: "Scope" },
  { id: "trigger", label: "Trigger" },
  { id: "conditions", label: "Conditions" },
  { id: "behavior", label: "Behavior" },
  { id: "destinations", label: "Destinations" },
  { id: "review", label: "Review & test" },
] as const;

export function TriggerEditor({ open, onOpenChange, target, seed }: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  target: EditorTarget | null;
  /** Prefilled draft for { mode: "new" } — quick presets and deep links
   *  (high CPU / memory, asset-scoped). Takes precedence over the saved
   *  draft: an explicit "create X" action is the user's latest intent. */
  seed?: TriggerDraft | null;
}) {
  const [draft, setDraft] = React.useState<TriggerDraft>(() => emptyDraft());
  const [step, setStep] = React.useState<string>("basics");
  const [serverError, setServerError] = React.useState<string | null>(null);
  const [preview, setPreview] = React.useState<Record<string, unknown> | null>(null);
  const create = useCreateTrigger();
  const update = useUpdateTrigger();
  const previewMut = usePreviewTrigger();
  const caps = useAlertCapabilities();

  // Draft lifecycle: restore an unsaved draft (refresh/close recovery for
  // new triggers) or seed from the target. State resets per open.
  React.useEffect(() => {
    if (!open) return;
    setServerError(null);
    setPreview(null);
    setStep("basics");
    if (!target || target.mode === "new") {
      if (seed) {
        setDraft({ ...emptyDraft(seed.kind), ...seed });
        return;
      }
      const saved = loadDraft();
      setDraft(saved ? { ...emptyDraft(saved.kind), ...saved } : emptyDraft());
      return;
    }
    const d = draftFromApi(target.trigger);
    if (target.mode === "duplicate") {
      d.id = undefined;
      d.revision = undefined;
      d.name = `${d.name} (copy)`;
      d.enabled = false;
    }
    setDraft(d);
  }, [open, target, seed]);

  React.useEffect(() => {
    if (open) saveDraft(draft);
  }, [draft, open]);

  const errors = React.useMemo(() => validateDraft(draft), [draft]);
  const errFor = (field: string) => errors.errors.find((e) => e.field === field)?.message;
  const stepHasError = (s: string) => errors.errors.some((e) => e.step === s);
  const set = <K extends keyof TriggerDraft>(key: K, value: TriggerDraft[K]) => setDraft((d) => ({ ...d, [key]: value }));

  const handleSave = async () => {
    setServerError(null);
    const payload = draftToPayload(draft);
    if (draft.id) {
      payload.revision = draft.revision;
      await update.mutateAsync({ id: draft.id, payload });
    } else {
      await create.mutateAsync(payload);
    }
    clearDraft();
    onOpenChange(false);
  };

  const handlePreview = async () => {
    setServerError(null);
    try {
      const res = await previewMut.mutateAsync(draftToPayload(draft));
      setPreview(res as unknown as Record<string, unknown>);
    } catch (e) {
      setServerError((e as Error).message || "Preview failed");
    }
  };

  const pending = create.isPending || update.isPending;

  return (
    <Dialog open={open} onOpenChange={(o) => { if (!o && !draft.id) saveDraft(draft); onOpenChange(o); }}>
      <DialogContent className="flex max-h-[90vh] flex-col overflow-hidden p-0 sm:max-w-6xl">
        <DialogHeader className="border-b px-5 py-3.5">
          <DialogTitle className="flex items-center gap-2 text-sm font-semibold">
            {draft.id ? "Edit trigger" : "New trigger"}
            {draft.id && <Badge variant="outline" className="tabular">rev {draft.revision}</Badge>}
            <Badge variant="outline" className="capitalize">{draft.lifecycle}</Badge>
          </DialogTitle>
          <DialogDescription className="text-xs">
            The evaluator runs the server-compiled definition; the summary below is exactly that.
          </DialogDescription>
        </DialogHeader>

        <div className="flex min-h-0 flex-1 flex-col md:flex-row">
          <nav aria-label="Editor steps" className="flex shrink-0 gap-1 overflow-x-auto border-b p-2 md:w-48 md:flex-col md:overflow-y-auto md:border-b-0 md:border-r">
            {STEPS.map((s) => (
              <button
                key={s.id}
                type="button"
                onClick={() => setStep(s.id)}
                aria-current={step === s.id ? "step" : undefined}
                className={cn(
                  "flex items-center gap-2 whitespace-nowrap rounded-md px-2.5 py-1.5 text-left text-[13px] text-muted-foreground hover:bg-accent hover:text-foreground",
                  step === s.id && "bg-accent text-foreground",
                )}
              >
                {stepHasError(s.id) && <AlertTriangle className="size-3.5 text-warning" />}
                {s.label}
              </button>
            ))}
          </nav>

          <div className="min-h-0 flex-1 overflow-y-auto px-5 py-4">
            {step === "basics" && <BasicsStep draft={draft} set={set} errFor={errFor} />}
            {step === "scope" && <ScopeStep draft={draft} set={set} />}
            {step === "trigger" && <TriggerStep draft={draft} set={set} caps={caps.data} errFor={errFor} />}
            {step === "conditions" && <ConditionsStep draft={draft} set={set} caps={caps.data} errFor={errFor} />}
            {step === "behavior" && <BehaviorStep draft={draft} set={set} errFor={errFor} />}
            {step === "destinations" && <DestinationsStep draft={draft} set={set} />}
            {step === "review" && <ReviewStep draft={draft} preview={preview} previewing={previewMut.isPending} onPreview={handlePreview} />}
          </div>
        </div>

        <DialogFooter className="flex-col items-stretch gap-2 border-t px-5 py-3 sm:items-center">
          {serverError && (
            <Alert variant="destructive" className="py-2">
              <AlertDescription className="text-xs">{serverError} — your draft is preserved.</AlertDescription>
            </Alert>
          )}
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="text-xs text-muted-foreground" aria-live="polite">
              {errors.ok ? (
                <span className="flex items-center gap-1 text-success"><Check className="size-3.5" /> Draft is valid</span>
              ) : (
                <span className="flex items-center gap-1 text-warning">
                  <AlertTriangle className="size-3.5" /> {errors.errors.length} issue{errors.errors.length === 1 ? "" : "s"} to fix
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <div className="mr-1 flex items-center gap-1.5">
                <Switch id="editor-enabled" checked={draft.enabled} onCheckedChange={(v) => set("enabled", v)} />
                <Label htmlFor="editor-enabled" className="text-xs">Enabled</Label>
              </div>
              <Button type="button" variant="outline" size="sm" onClick={handlePreview} disabled={previewMut.isPending || !errors.ok}>
                {previewMut.isPending && <Loader2 className="size-3.5 animate-spin" />} Test / preview
              </Button>
              <Button type="button" size="sm" onClick={handleSave} disabled={pending || !errors.ok}>
                {pending && <Loader2 className="size-3.5 animate-spin" />} Save
              </Button>
            </div>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

type SetFn = <K extends keyof TriggerDraft>(key: K, value: TriggerDraft[K]) => void;

// --- steps ------------------------------------------------------------------

function BasicsStep({ draft, set, errFor }: { draft: TriggerDraft; set: SetFn; errFor: (f: string) => string | undefined }) {
  return (
    <div className="grid max-w-2xl gap-3">
      <div className="grid gap-1.5">
        <Label htmlFor="t-name">Name</Label>
        <Input id="t-name" value={draft.name} onChange={(e) => set("name", e.target.value)} aria-invalid={!!errFor("name")} placeholder="e.g. CPU saturation on servers" />
        {errFor("name") && <p className="text-xs text-destructive" role="alert">{errFor("name")}</p>}
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="t-desc">Description</Label>
        <Textarea id="t-desc" rows={2} value={draft.description} onChange={(e) => set("description", e.target.value)} placeholder="What this trigger protects and why it matters" />
      </div>
      <div className="grid gap-3 sm:grid-cols-3">
        <div className="grid gap-1.5">
          <Label>Severity</Label>
          <Select value={draft.severity} onValueChange={(v) => set("severity", v)}>
            <SelectTrigger aria-label="Severity"><SelectValue /></SelectTrigger>
            <SelectContent>{["info", "low", "medium", "high", "critical"].map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
            ))}</SelectContent>
          </Select>
        </div>
        <div className="grid gap-1.5">
          <Label>Lifecycle</Label>
          <Select value={draft.lifecycle} onValueChange={(v) => set("lifecycle", v)}>
            <SelectTrigger aria-label="Lifecycle"><SelectValue /></SelectTrigger>
            <SelectContent>{["stable", "experimental", "deprecated"].map((s) => (
              <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
            ))}</SelectContent>
          </Select>
        </div>
        <div className="grid gap-1.5">
          <Label>Trigger kind</Label>
          <Select value={draft.kind} onValueChange={(v) => set("kind", v as TriggerDraft["kind"])}>
            <SelectTrigger aria-label="Trigger kind"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="event">Domain event</SelectItem>
              <SelectItem value="device_metric">Device metric</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
}

function ScopeStep({ draft, set }: { draft: TriggerDraft; set: SetFn }) {
  const sitesQ = useSites();
  const assetsQ = useAssets({ limit: 200 });
  return (
    <div className="grid max-w-3xl gap-4">
      <p className="text-xs text-muted-foreground">
        Empty selection means the entire organization. Scoping happens at evaluation: events outside the scope never match.
      </p>
      <div className="grid gap-1.5">
        <Label>Sites</Label>
        <div className="flex max-h-40 flex-wrap gap-1.5 overflow-y-auto rounded-lg border bg-muted/30 p-2">
          {(sitesQ.data?.items ?? []).map((s) => {
            const on = draft.siteIds.includes(s.id);
            return (
              <button
                key={s.id} type="button"
                aria-pressed={on}
                onClick={() => set("siteIds", on ? draft.siteIds.filter((x) => x !== s.id) : [...draft.siteIds, s.id])}
                className={cn("rounded-md border px-2 py-1 text-xs", on ? "border-primary/60 bg-primary/10 text-foreground" : "text-muted-foreground hover:text-foreground")}
              >
                {s.name}
              </button>
            );
          })}
        </div>
      </div>
      <div className="grid gap-1.5">
        <Label>Assets</Label>
        <div className="max-h-48 overflow-y-auto rounded-lg border bg-muted/30 p-2">
          {(assetsQ.data?.items ?? []).map((a) => {
            const on = draft.assetIds.includes(a.id);
            return (
              <button
                key={a.id} type="button"
                aria-pressed={on}
                onClick={() => set("assetIds", on ? draft.assetIds.filter((x) => x !== a.id) : [...draft.assetIds, a.id])}
                className={cn("block w-full rounded-md px-2 py-1 text-left text-xs", on ? "bg-primary/10 text-foreground" : "text-muted-foreground hover:text-foreground")}
              >
                {a.hostname || a.ip || a.id}
              </button>
            );
          })}
        </div>
      </div>
      <p className="rounded-lg border bg-muted/30 px-3 py-2 text-xs text-muted-foreground" aria-live="polite">
        {scopeSummary(draft)}
      </p>
    </div>
  );
}

function TriggerStep({ draft, set, caps, errFor }: {
  draft: TriggerDraft; set: SetFn; caps?: AlertCapabilities; errFor: (f: string) => string | undefined;
}) {
  if (draft.kind === "event") {
    const events = caps?.event_types ?? [];
    return (
      <div className="grid max-w-3xl gap-4">
        <div className="grid gap-1.5">
          <Label>Fires on events</Label>
          <div className="grid max-h-64 gap-1 overflow-y-auto rounded-lg border bg-muted/30 p-2">
            {events.map((e) => {
              const on = draft.eventTypes.includes(e.type);
              return (
                <button
                  key={e.type} type="button" aria-pressed={on}
                  onClick={() => set("eventTypes", on ? draft.eventTypes.filter((x) => x !== e.type) : [...draft.eventTypes, e.type])}
                  className={cn("rounded-md px-2.5 py-1.5 text-left", on ? "bg-primary/10" : "hover:bg-accent")}
                >
                  <div className={cn("font-mono text-[13px]", on ? "text-foreground" : "text-muted-foreground")}>{e.type}</div>
                  <div className="text-xs text-muted-foreground">{e.description}</div>
                </button>
              );
            })}
          </div>
          {errFor("event_types") && <p className="text-xs text-destructive" role="alert">{errFor("event_types")}</p>}
        </div>
        <div className="grid gap-1.5">
          <Label>Recovered by events (optional)</Label>
          <div className="flex max-h-36 flex-wrap gap-1.5 overflow-y-auto rounded-lg border bg-muted/30 p-2">
            {events.map((e) => {
              const on = draft.recoveryEventTypes.includes(e.type);
              return (
                <button
                  key={e.type} type="button" aria-pressed={on}
                  onClick={() => set("recoveryEventTypes", on ? draft.recoveryEventTypes.filter((x) => x !== e.type) : [...draft.recoveryEventTypes, e.type])}
                  className={cn("rounded-md border px-2 py-1 font-mono text-xs", on ? "border-success/60 bg-success/10 text-foreground" : "text-muted-foreground hover:text-foreground")}
                >
                  {e.type}
                </button>
              );
            })}
          </div>
          <p className="text-xs text-muted-foreground">
            When one of these events arrives, the matching open occurrence is resolved automatically (e.g. feed.recovered resolves feed.stale).
          </p>
        </div>
      </div>
    );
  }
  const fields = caps?.metric_fields ?? [];
  const unit = fields.find((f) => f.field === draft.metricField)?.unit ?? "";
  return (
    <div className="grid max-w-2xl gap-4">
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label>Metric</Label>
          <Select value={draft.metricField} onValueChange={(v) => set("metricField", v)}>
            <SelectTrigger aria-label="Metric"><SelectValue /></SelectTrigger>
            <SelectContent>
              {fields.map((f) => (
                <SelectItem key={f.field} value={f.field}>
                  {f.description}{f.unit ? ` (${f.unit})` : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-1.5">
          <Label>Aggregation over the window</Label>
          <Select value={draft.aggregation} onValueChange={(v) => set("aggregation", v)}>
            <SelectTrigger aria-label="Aggregation"><SelectValue /></SelectTrigger>
            <SelectContent>{(caps?.aggregations ?? ["avg", "min", "max", "p95", "sum", "count"]).map((s) => (
              <SelectItem key={s} value={s}>{s.toUpperCase()}</SelectItem>
            ))}</SelectContent>
          </Select>
        </div>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label>Comparison</Label>
          <Select value={draft.operator} onValueChange={(v) => set("operator", v)}>
            <SelectTrigger aria-label="Comparison"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="gt">above</SelectItem>
              <SelectItem value="gte">at or above</SelectItem>
              <SelectItem value="lt">below</SelectItem>
              <SelectItem value="lte">at or below</SelectItem>
            </SelectContent>
          </Select>
        </div>
        <div className="grid gap-1.5">
          <Label htmlFor="t-threshold">Threshold {unit && <span className="text-muted-foreground">({unit})</span>}</Label>
          <Input id="t-threshold" inputMode="decimal" value={draft.threshold} onChange={(e) => set("threshold", e.target.value)} aria-invalid={!!errFor("threshold")} />
          {errFor("threshold") && <p className="text-xs text-destructive" role="alert">{errFor("threshold")}</p>}
        </div>
      </div>
      <div className="grid gap-1.5">
        <Label>Window</Label>
        <Select value={String(draft.windowSecs)} onValueChange={(v) => set("windowSecs", Number(v))}>
          <SelectTrigger aria-label="Window" className="w-56"><SelectValue /></SelectTrigger>
          <SelectContent>
            {(caps?.window_presets ?? []).map((w) => (
              <SelectItem key={w.secs} value={String(w.secs)}>{w.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  );
}

function ConditionsStep({ draft, set, caps, errFor }: {
  draft: TriggerDraft; set: SetFn; caps?: AlertCapabilities; errFor: (f: string) => string | undefined;
}) {
  if (draft.kind === "device_metric") {
    return (
      <div className="max-w-2xl rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">
        Metric triggers evaluate the single comparison defined in the Trigger step. Additional conditions apply to domain-event triggers only.
      </div>
    );
  }
  const selected = new Set(draft.eventTypes);
  const fieldOptions = (caps?.event_types ?? [])
    .filter((e) => selected.has(e.type))
    .flatMap((e) => e.fields.map((f) => ({ ...f, from: e.type })));
  const generic = [
    { field: "type", type: "string", from: "" }, { field: "source", type: "string", from: "" },
    { field: "entity_type", type: "string", from: "" }, { field: "severity", type: "string", from: "" },
  ];
  const options = [...generic, ...fieldOptions];
  const opOptions = caps?.operators ?? [];
  const operatorsFor = (type?: string) => opOptions.filter((o) =>
    type === "number" ? ["gt", "gte", "lt", "lte", "eq", "neq", "exists"].includes(o.op)
      : type === "boolean" ? ["eq", "neq", "exists"].includes(o.op)
      : ["eq", "neq", "in", "not_in", "contains", "starts_with", "ends_with", "exists", "regex"].includes(o.op));

  const updateRow = (i: number, patch: Partial<ConditionRow>) =>
    set("conditions", { ...draft.conditions, rows: draft.conditions.rows.map((r, j) => (j === i ? { ...r, ...patch } : r)) });
  const moveRow = (i: number, dir: -1 | 1) => {
    const rows = [...draft.conditions.rows];
    const j = i + dir;
    if (j < 0 || j >= rows.length) return;
    [rows[i], rows[j]] = [rows[j], rows[i]];
    set("conditions", { ...draft.conditions, rows });
  };

  return (
    <div className="grid max-w-3xl gap-3">
      <div className="flex items-center gap-2">
        <Select value={draft.conditions.kind} onValueChange={(v) => set("conditions", { ...draft.conditions, kind: v as "all" | "any" })}>
          <SelectTrigger aria-label="Boolean mode" className="w-44"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All conditions (AND)</SelectItem>
            <SelectItem value="any">Any condition (OR)</SelectItem>
          </SelectContent>
        </Select>
        <span className="text-xs text-muted-foreground">of the following match the event</span>
      </div>
      {draft.conditions.rows.length === 0 && (
        <p className="rounded-lg border bg-muted/30 px-3 py-4 text-center text-xs text-muted-foreground">
          No conditions — the trigger fires on every selected event. Add conditions to narrow it down.
        </p>
      )}
      {draft.conditions.rows.map((row, i) => {
        const type = options.find((o) => o.field === row.field)?.type;
        return (
          <div key={i} className="flex flex-wrap items-center gap-2 rounded-lg border bg-muted/30 p-2">
            <Select value={row.field || undefined} onValueChange={(v) => updateRow(i, { field: v })}>
              <SelectTrigger aria-label={`Condition ${i + 1} field`} className="w-48"><SelectValue placeholder="Field" /></SelectTrigger>
              <SelectContent>
                {options.map((o) => (
                  <SelectItem key={`${o.from || "base"}-${o.field}`} value={o.field}>
                    {o.field}{o.from ? ` · ${o.from}` : ""}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={row.op || undefined} onValueChange={(v) => updateRow(i, { op: v })}>
              <SelectTrigger aria-label={`Condition ${i + 1} operator`} className="w-40"><SelectValue placeholder="Operator" /></SelectTrigger>
              <SelectContent>
                {operatorsFor(type).map((o) => (
                  <SelectItem key={o.op} value={o.op}>{o.label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            {row.op !== "exists" && (
              <Input
                aria-label={`Condition ${i + 1} value`}
                value={row.values.join(", ")}
                onChange={(e) => updateRow(i, { values: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
                placeholder={type === "number" ? "42" : "value, value…"}
                className="w-44 flex-1"
              />
            )}
            <div className="ml-auto flex items-center gap-0.5">
              <Button type="button" variant="ghost" size="icon-xs" onClick={() => moveRow(i, -1)} aria-label={`Move condition ${i + 1} up`} disabled={i === 0}><ArrowUp /></Button>
              <Button type="button" variant="ghost" size="icon-xs" onClick={() => moveRow(i, 1)} aria-label={`Move condition ${i + 1} down`} disabled={i === draft.conditions.rows.length - 1}><ArrowDown /></Button>
              <Button type="button" variant="ghost" size="icon-xs" onClick={() => set("conditions", { ...draft.conditions, rows: draft.conditions.rows.filter((_, j) => j !== i) })} aria-label={`Remove condition ${i + 1}`}><X /></Button>
            </div>
          </div>
        );
      })}
      {errFor("rows") && <p className="text-xs text-destructive" role="alert">{errFor("rows")}</p>}
      <Button type="button" variant="outline" size="sm" className="w-fit"
        onClick={() => set("conditions", { ...draft.conditions, rows: [...draft.conditions.rows, { field: "", op: "eq", values: [] }] })}>
        <Plus /> Add condition
      </Button>
    </div>
  );
}

function BehaviorStep({ draft, set, errFor }: { draft: TriggerDraft; set: SetFn; errFor: (f: string) => string | undefined }) {
  const durations = [
    { v: 0, l: "immediately" }, { v: 60, l: "1 minute" }, { v: 120, l: "2 minutes" },
    { v: 300, l: "5 minutes" }, { v: 600, l: "10 minutes" }, { v: 1800, l: "30 minutes" }, { v: 3600, l: "1 hour" },
  ];
  const trigger = (label: string) => <SelectTrigger aria-label={label} className="w-44"><SelectValue /></SelectTrigger>;
  return (
    <div className="grid max-w-2xl gap-4">
      {draft.kind === "device_metric" && (
        <>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label>Activation: fire after the breach persists for</Label>
              <Select value={String(draft.activationSecs)} onValueChange={(v) => set("activationSecs", Number(v))}>
                {trigger("Activation duration")}
                <SelectContent>{durations.map((d) => <SelectItem key={d.v} value={String(d.v)}>{d.l}</SelectItem>)}</SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>Recovery: stay healthy for</Label>
              <Select value={String(draft.recoverySecs)} onValueChange={(v) => set("recoverySecs", Number(v))}>
                {trigger("Recovery duration")}
                <SelectContent>{durations.filter((d) => d.v > 0).map((d) => <SelectItem key={d.v} value={String(d.v)}>{d.l}</SelectItem>)}</SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor="t-hyst">Hysteresis threshold (optional)</Label>
              <Input id="t-hyst" inputMode="decimal" value={draft.recoveryThreshold} onChange={(e) => set("recoveryThreshold", e.target.value)} placeholder="e.g. 80 when alerting above 90" aria-invalid={!!errFor("recovery_threshold")} />
              <p className="text-xs text-muted-foreground">Recovery requires crossing this healthier bound, not just leaving the breach — stops flapping.</p>
              {errFor("recovery_threshold") && <p className="text-xs text-destructive" role="alert">{errFor("recovery_threshold")}</p>}
            </div>
            <div className="grid gap-1.5">
              <Label>Missing data policy</Label>
              <Select value={draft.missingDataPolicy} onValueChange={(v) => set("missingDataPolicy", v)}>
                {trigger("Missing data policy")}
                <SelectContent>
                  <SelectItem value="ignore">Ignore (keep state)</SelectItem>
                  <SelectItem value="trigger">Trigger (treat as breach)</SelectItem>
                  <SelectItem value="resolve">Resolve open alerts</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">A ClickHouse outage never resolves or fires anything by itself.</p>
            </div>
          </div>
        </>
      )}
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="grid gap-1.5">
          <Label>Cooldown before re-firing the same fingerprint</Label>
          <Select value={String(draft.cooldownSecs)} onValueChange={(v) => set("cooldownSecs", Number(v))}>
            {trigger("Cooldown")}
            <SelectContent>{durations.map((d) => <SelectItem key={d.v} value={String(d.v)}>{d.l}</SelectItem>)}</SelectContent>
          </Select>
        </div>
        <div className="grid gap-1.5">
          <Label>Repeat reminder while firing (0 = never)</Label>
          <Select value={String(draft.repeatSecs)} onValueChange={(v) => set("repeatSecs", Number(v))}>
            {trigger("Repeat interval")}
            <SelectContent>{[{ v: 0, l: "never" }, ...durations.filter((d) => d.v > 0)].map((d) => <SelectItem key={d.v} value={String(d.v)}>{d.l}</SelectItem>)}</SelectContent>
          </Select>
        </div>
      </div>
    </div>
  );
}

function DestinationsStep({ draft, set }: { draft: TriggerDraft; set: SetFn }) {
  const destsQ = useAlertDestinations();
  return (
    <div className="grid max-w-2xl gap-3">
      <p className="text-xs text-muted-foreground">
        Every alert is always visible under Alerts — destinations add signed webhook deliveries. Severity floors and event subscriptions are configured per destination.
      </p>
      {destsQ.isLoading && (
        <p className="flex items-center gap-2 text-xs text-muted-foreground"><Loader2 className="size-3.5 animate-spin" /> Loading destinations…</p>
      )}
      {destsQ.data && destsQ.data.length === 0 && (
        <p className="rounded-lg border bg-muted/30 px-3 py-4 text-center text-xs text-muted-foreground">
          No destinations yet — add a webhook under the Destinations tab.
        </p>
      )}
      <div className="grid gap-1.5">
        {(destsQ.data ?? []).map((d) => {
          const on = draft.destinationIds.includes(d.id);
          return (
            <button
              key={d.id} type="button" aria-pressed={on}
              onClick={() => set("destinationIds", on ? draft.destinationIds.filter((x) => x !== d.id) : [...draft.destinationIds, d.id])}
              className={cn("flex items-center justify-between rounded-lg border px-3 py-2 text-left", on ? "border-primary/60 bg-primary/5" : "hover:bg-accent")}
            >
              <span className="text-[13px]">{d.name} <span className="ml-1 text-xs text-muted-foreground">{d.kind === "webhook" ? "webhook" : "in-app"}</span></span>
              <span className="flex items-center gap-2 text-xs text-muted-foreground">
                min {d.minSeverity}
                {on && <Check className="size-3.5 text-success" />}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}

function ReviewStep({ draft, preview, previewing, onPreview }: {
  draft: TriggerDraft;
  preview: Record<string, unknown> | null;
  previewing: boolean;
  onPreview: () => void;
}) {
  return (
    <div className="grid max-w-3xl gap-4">
      <div className="rounded-lg border bg-muted/30 p-3">
        <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Compiled summary</div>
        <p className="mt-1 text-[13px]" aria-live="polite">{compileSummary(draft)}</p>
        <p className="mt-1 text-xs text-muted-foreground">Scope: {scopeSummary(draft)}</p>
      </div>

      {preview != null && (
        <div className="rounded-lg border p-3" aria-live="polite">
          <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Preview result</div>
          {preview.valid === false ? (
            <Alert variant="destructive" className="mt-2 py-2"><AlertDescription className="text-xs">{String(preview.error)}</AlertDescription></Alert>
          ) : (
            <>
              <p className="mt-1 text-[13px]">{String(preview.summary)}</p>
              {preview.metric_sample != null && <MetricPreview sample={preview.metric_sample as Record<string, unknown>} />}
            </>
          )}
        </div>
      )}

      {draft.kind === "event" && draft.eventTypes.length > 0 && (
        <div className="text-xs text-muted-foreground">
          Listens to <span className="font-mono">{draft.eventTypes.join(", ")}</span>
          {draft.recoveryEventTypes.length > 0 && <> · recovers on <span className="font-mono">{draft.recoveryEventTypes.join(", ")}</span></>}
        </div>
      )}

      <Button type="button" variant="outline" size="sm" className="w-fit" onClick={onPreview} disabled={previewing}>
        {previewing && <Loader2 className="size-3.5 animate-spin" />} Run server preview
      </Button>
      <p className="text-xs text-muted-foreground">
        Preview validates the draft against current data without creating alerts or notifications.
      </p>
    </div>
  );
}

function MetricPreview({ sample }: { sample: Record<string, unknown> }) {
  if (sample.available === false) {
    return (
      <Alert variant="warning" className="mt-2 py-2">
        <AlertDescription className="text-xs">ClickHouse is unavailable — metric preview and testing are disabled until it recovers. The rule can still be saved.</AlertDescription>
      </Alert>
    );
  }
  const evaluated = Number(sample.assets_evaluated ?? 0);
  const matched = Number(sample.matched ?? 0);
  return (
    <p className="mt-1 text-xs text-muted-foreground">
      {evaluated} device{evaluated === 1 ? "" : "s"} in scope over the current window · {matched} currently breaching
    </p>
  );
}
