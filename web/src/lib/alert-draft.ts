// Client-side draft model for the trigger editor: a typed draft lives
// outside react-query (server state) and survives refreshes via
// localStorage. The server remains the canonical validator — this module
// only shapes payloads and renders the human-readable summary the editor
// previews; alert-validation.ts mirrors the server's hard rules so the UI
// can fail fast without a round trip.

export interface ConditionRow {
  field: string;
  op: string;
  values: string[];
}

/** A group is "all" or "any"; NOT is a row-level toggle the server expands. */
export interface ConditionGroup {
  kind: "all" | "any";
  rows: ConditionRow[];
}

export interface TriggerDraft {
  id?: string;
  revision?: number;
  name: string;
  description: string;
  kind: "event" | "device_metric";
  enabled: boolean;
  lifecycle: string;
  severity: string;
  siteIds: string[];
  assetIds: string[];
  deviceTypes: string[];
  eventTypes: string[];
  recoveryEventTypes: string[];
  conditions: ConditionGroup;
  metricField: string;
  aggregation: string;
  operator: string;
  threshold: string;
  windowSecs: number;
  activationSecs: number;
  recoverySecs: number;
  recoveryThreshold: string;
  missingDataPolicy: string;
  cooldownSecs: number;
  repeatSecs: number;
  destinationIds: string[];
}

export function emptyDraft(kind: "event" | "device_metric" = "event"): TriggerDraft {
  return {
    name: "", description: "", kind, enabled: false, lifecycle: "stable",
    severity: "medium", siteIds: [], assetIds: [], deviceTypes: [],
    eventTypes: kind === "event" ? ["asset.discovered"] : [],
    recoveryEventTypes: [], conditions: { kind: "all", rows: [] },
    metricField: "cpu_percent", aggregation: "avg", operator: "gt",
    threshold: "90", windowSecs: 300, activationSecs: 120, recoverySecs: 300,
    recoveryThreshold: "", missingDataPolicy: "ignore",
    cooldownSecs: 300, repeatSecs: 0, destinationIds: [],
  };
}

export interface MetricSeedOptions {
  metricField: string; // a catalog metric field, e.g. "cpu_percent"
  assetId?: string; // scope the rule to a single asset when given
  assetLabel?: string; // display name woven into the default title
}

/** seedMetricDraft builds the prefilled device-metric draft behind the
 *  quick-create presets ("High CPU utilization", "High memory utilization")
 *  and the asset page's "Create alert" entry points. Defaults follow the
 *  plan's worked example: average utilization above 90% over a 5-minute
 *  window, sustained for 2 minutes, recovering after 5 minutes healthy. */
export function seedMetricDraft(opts: MetricSeedOptions): TriggerDraft {
  const d = emptyDraft("device_metric");
  d.metricField = opts.metricField;
  const label = METRIC_LABELS[opts.metricField] ?? opts.metricField;
  d.name = opts.assetLabel ? `High ${label} — ${opts.assetLabel}` : `High ${label}`;
  d.description =
    `Alerts when the device's average ${label} stays above 90% over a 5-minute window, ` +
    "recovering after 5 minutes back below the threshold.";
  if (opts.assetId) d.assetIds = [opts.assetId];
  return d;
}

/** draftFromApi maps a stored trigger into an editable draft. */
export function draftFromApi(t: {
  id: string; revision: number; name: string; description: string; kind: "event" | "device_metric";
  enabled: boolean; lifecycle: string; severity: string;
  scope: { site_ids?: string[]; asset_ids?: string[]; device_types?: string[] };
  conditions: Record<string, unknown>;
  event_types?: string[]; recovery_event_types?: string[];
  metric_field?: string; aggregation?: string; operator?: string; threshold?: number;
  window_secs?: number; activation_secs?: number; recovery_secs?: number;
  recovery_threshold?: number; missing_data_policy?: string;
  cooldown_secs?: number; repeat_secs?: number; destination_ids?: string[];
}): TriggerDraft {
  const d = emptyDraft(t.kind);
  d.id = t.id;
  d.revision = t.revision;
  d.name = t.name;
  d.description = t.description;
  d.enabled = t.enabled;
  d.lifecycle = t.lifecycle;
  d.severity = t.severity;
  d.siteIds = t.scope?.site_ids ?? [];
  d.assetIds = t.scope?.asset_ids ?? [];
  d.deviceTypes = t.scope?.device_types ?? [];
  d.eventTypes = t.event_types ?? [];
  d.recoveryEventTypes = t.recovery_event_types ?? [];
  d.metricField = t.metric_field || d.metricField;
  d.aggregation = t.aggregation || d.aggregation;
  d.operator = t.operator || d.operator;
  d.threshold = String(t.threshold ?? d.threshold);
  d.windowSecs = t.window_secs ?? d.windowSecs;
  d.activationSecs = t.activation_secs ?? d.activationSecs;
  d.recoverySecs = t.recovery_secs ?? d.recoverySecs;
  d.recoveryThreshold = t.recovery_threshold !== undefined && t.recovery_threshold !== null ? String(t.recovery_threshold) : "";
  d.missingDataPolicy = t.missing_data_policy || d.missingDataPolicy;
  d.cooldownSecs = t.cooldown_secs ?? d.cooldownSecs;
  d.repeatSecs = t.repeat_secs ?? d.repeatSecs;
  d.destinationIds = t.destination_ids ?? [];
  d.conditions = groupFromApi(t.conditions);
  return d;
}

function groupFromApi(raw: Record<string, unknown> | undefined): ConditionGroup {
  const d = emptyDraft().conditions;
  if (!raw || typeof raw !== "object") return d;
  const kind = Array.isArray(raw.any) ? "any" : "all";
  const list = (kind === "any" ? raw.any : raw.all) as unknown[];
  if (!Array.isArray(list)) return d;
  return {
    kind,
    rows: list.map((r) => {
      const row = r as { field?: string; op?: string; value?: unknown };
      let values: string[] = [];
      if (Array.isArray(row.value)) values = row.value.map((v) => String(v));
      else if (row.value !== undefined && row.value !== null) values = [String(row.value)];
      return { field: row.field ?? "", op: row.op ?? "eq", values };
    }),
  };
}

/** draftToPayload serializes the draft into the API request body. */
export function draftToPayload(d: TriggerDraft): Record<string, unknown> {
  const group = d.conditions.rows.map((r) => ({
    field: r.field,
    op: r.op,
    ...(r.values.length === 1 ? { value: coerceValue(r.values[0]) } : { value: r.values.map(coerceValue) }),
  }));
  const conditions = group.length === 0 ? {} : { [d.conditions.kind]: group };
  return {
    name: d.name.trim(),
    description: d.description.trim(),
    kind: d.kind,
    enabled: d.enabled,
    lifecycle: d.lifecycle,
    severity: d.severity,
    scope: {
      ...(d.siteIds.length ? { site_ids: d.siteIds } : {}),
      ...(d.assetIds.length ? { asset_ids: d.assetIds } : {}),
      ...(d.deviceTypes.length ? { device_types: d.deviceTypes } : {}),
    },
    conditions,
    event_types: d.kind === "event" ? d.eventTypes : [],
    recovery_event_types: d.kind === "event" ? d.recoveryEventTypes : [],
    metric_field: d.kind === "device_metric" ? d.metricField : "",
    aggregation: d.aggregation,
    operator: d.operator,
    threshold: numOr(d.threshold, 0),
    window_secs: d.windowSecs,
    group_by: "asset",
    activation_secs: d.activationSecs,
    recovery_secs: d.recoverySecs,
    ...(d.recoveryThreshold !== "" ? { recovery_threshold: numOr(d.recoveryThreshold, 0) } : {}),
    missing_data_policy: d.missingDataPolicy,
    cooldown_secs: d.cooldownSecs,
    repeat_secs: d.repeatSecs,
    destination_ids: d.destinationIds,
  };
}

function coerceValue(v: string): string | number | boolean {
  if (v === "true") return true;
  if (v === "false") return false;
  if (v !== "" && !Number.isNaN(Number(v))) return Number(v);
  return v;
}

function numOr(s: string, def: number): number {
  const n = Number(s);
  return Number.isFinite(n) ? n : def;
}

const OP_LABELS: Record<string, string> = {
  eq: "is", neq: "is not", ["in"]: "is one of", not_in: "is none of",
  gt: "above", gte: "at or above", lt: "below", lte: "at or below",
  contains: "contains", starts_with: "starts with", ends_with: "ends with",
  exists: "exists", regex: "matches",
};

const METRIC_LABELS: Record<string, string> = {
  cpu_percent: "CPU", mem_used_percent: "memory", rx_bps: "receive rate",
  tx_bps: "transmit rate", load1: "1-minute load", load5: "5-minute load", load15: "15-minute load",
};

function humanDuration(secs: number): string {
  if (secs >= 3600 && secs % 3600 === 0) return `${secs / 3600}h`;
  if (secs >= 60 && secs % 60 === 0) return `${secs / 60}m`;
  return `${secs}s`;
}

function rowText(r: ConditionRow): string {
  const vals = r.values.join(", ");
  return `${r.field.replace(/_/g, " ")} ${OP_LABELS[r.op] ?? r.op} ${vals || "…"}`;
}

/** compileSummary renders the plan's "Fire when ..." sentence for the draft. */
export function compileSummary(d: TriggerDraft): string {
  if (d.kind === "device_metric") {
    let s = `Fire when a device's ${d.aggregation} ${METRIC_LABELS[d.metricField] ?? d.metricField}` +
      ` is ${OP_LABELS[d.operator] ?? d.operator} ${d.threshold || "…"}` +
      ` over a ${humanDuration(d.windowSecs)} window`;
    if (d.activationSecs > 0) s += `, sustained for at least ${humanDuration(d.activationSecs)}`;
    if (d.recoveryThreshold !== "") s += `; recover when the value crosses ${d.recoveryThreshold} for ${humanDuration(Math.max(d.recoverySecs, 60))}`;
    else if (d.recoverySecs > 0) s += `; recover after staying below the threshold for ${humanDuration(d.recoverySecs)}`;
    return s;
  }
  let s = "Fire on " + (d.eventTypes.join(", ") || "…");
  if (d.conditions.rows.length > 0) {
    const joiner = d.conditions.kind === "any" ? " or " : " and ";
    s += " when " + d.conditions.rows.map(rowText).join(joiner);
  }
  if (d.recoveryEventTypes.length > 0) s += "; recover on " + d.recoveryEventTypes.join(", ");
  return s;
}

/** scopeSummary renders the "3 sites · 2 groups · 184 assets" style line. */
export function scopeSummary(d: TriggerDraft): string {
  const parts: string[] = [];
  if (d.siteIds.length === 0 && d.assetIds.length === 0) return "Entire organization";
  if (d.siteIds.length > 0) parts.push(`${d.siteIds.length} site${d.siteIds.length === 1 ? "" : "s"}`);
  if (d.assetIds.length > 0) parts.push(`${d.assetIds.length} asset${d.assetIds.length === 1 ? "" : "s"}`);
  if (d.deviceTypes.length > 0) parts.push(`${d.deviceTypes.join(", ")} devices`);
  return parts.join(" · ");
}

const DRAFT_KEY = "aegis-alert-draft";

/** Draft persistence: unsaved work survives an accidental close or refresh. */
export function saveDraft(draft: TriggerDraft): void {
  try {
    window.localStorage.setItem(DRAFT_KEY, JSON.stringify(draft));
  } catch {
    /* storage unavailable — draft simply does not persist */
  }
}

export function loadDraft(): TriggerDraft | null {
  try {
    const raw = window.localStorage.getItem(DRAFT_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as TriggerDraft;
    if (!parsed || typeof parsed !== "object" || !parsed.kind) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function clearDraft(): void {
  try {
    window.localStorage.removeItem(DRAFT_KEY);
  } catch {
    /* noop */
  }
}
