// Client-side validation for the trigger editor draft. These are the
// client mirror of the server's hard rules (internal/transport/http/
// handlers_alerts.go validateTrigger) — the server stays authoritative,
// this only exists so the editor can fail fast and mark the exact step.
// Pure functions, no react imports, fully unit-tested.

import type { TriggerDraft } from "./alert-draft";

export interface FieldError {
  step: "basics" | "trigger" | "conditions" | "behavior" | "destinations";
  field: string;
  message: string;
}

export interface ValidationResult {
  ok: boolean;
  errors: FieldError[];
}

const SEVERITIES = new Set(["info", "low", "medium", "high", "critical"]);
const LIFECYCLES = new Set(["stable", "experimental", "deprecated"]);
const METRIC_FIELDS = new Set(["cpu_percent", "mem_used_percent", "rx_bps", "tx_bps", "load1", "load5", "load15"]);
const AGGREGATIONS = new Set(["avg", "min", "max", "p95", "sum", "count"]);
const NUM_OPS = new Set(["gt", "gte", "lt", "lte"]);
const MISSING_DATA = new Set(["ignore", "trigger", "resolve"]);

function num(v: string): number | null {
  if (v.trim() === "") return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * validateDraft checks the draft and returns per-field errors. Checks the
 * same bounds the server enforces so a "valid" draft never 422s.
 */
export function validateDraft(d: TriggerDraft): ValidationResult {
  const errors: FieldError[] = [];

  // Basics.
  if (!d.name.trim()) errors.push({ step: "basics", field: "name", message: "Name is required" });
  if (d.name.trim().length > 120) errors.push({ step: "basics", field: "name", message: "Name must be at most 120 characters" });
  if (d.description.length > 2000) errors.push({ step: "basics", field: "description", message: "Description must be at most 2000 characters" });
  if (!SEVERITIES.has(d.severity)) errors.push({ step: "basics", field: "severity", message: "Pick a severity" });
  if (!LIFECYCLES.has(d.lifecycle)) errors.push({ step: "basics", field: "lifecycle", message: "Pick a lifecycle" });

  // Trigger definition.
  if (d.kind === "event") {
    if (d.eventTypes.length === 0) errors.push({ step: "trigger", field: "event_types", message: "Select at least one event" });
  } else {
    if (!METRIC_FIELDS.has(d.metricField)) errors.push({ step: "trigger", field: "metric_field", message: "Select a metric" });
    if (!AGGREGATIONS.has(d.aggregation)) errors.push({ step: "trigger", field: "aggregation", message: "Select an aggregation" });
    if (!NUM_OPS.has(d.operator)) errors.push({ step: "trigger", field: "operator", message: "Select a comparison" });
    const thr = num(d.threshold);
    if (thr === null) errors.push({ step: "trigger", field: "threshold", message: "Threshold must be a number" });
    if (d.windowSecs < 60 || d.windowSecs > 86400) errors.push({ step: "trigger", field: "window_secs", message: "Window must be 1 minute to 24 hours" });
  }

  // Conditions (event triggers): rows need field + op; numeric ops need a
  // parseable value.
  for (let i = 0; i < d.conditions.rows.length; i++) {
    const row = d.conditions.rows[i];
    if (!row.field) errors.push({ step: "conditions", field: `rows.${i}.field`, message: "Pick a field" });
    if (!row.op) errors.push({ step: "conditions", field: `rows.${i}.op`, message: "Pick an operator" });
    if (NUM_OPS.has(row.op) && row.values.length > 0 && num(row.values[0]) === null) {
      errors.push({ step: "conditions", field: `rows.${i}.values`, message: "Numeric operator needs a number" });
    }
  }
  if (d.conditions.rows.length > 20) {
    errors.push({ step: "conditions", field: "rows", message: "At most 20 conditions per group" });
  }

  // Behavior.
  if (d.cooldownSecs < 0 || d.cooldownSecs > 604800) errors.push({ step: "behavior", field: "cooldown_secs", message: "Cooldown must be 0 to 7 days" });
  if (d.repeatSecs < 0 || d.repeatSecs > 604800) errors.push({ step: "behavior", field: "repeat_secs", message: "Repeat must be 0 to 7 days" });
  if (d.activationSecs < 0 || d.activationSecs > 86400) errors.push({ step: "behavior", field: "activation_secs", message: "Activation must be 0 to 24 hours" });
  if (d.recoverySecs < 0 || d.recoverySecs > 86400) errors.push({ step: "behavior", field: "recovery_secs", message: "Recovery must be 0 to 24 hours" });
  if (d.recoveryThreshold !== "" && num(d.recoveryThreshold) === null) {
    errors.push({ step: "behavior", field: "recovery_threshold", message: "Recovery threshold must be a number" });
  }
  if (d.kind === "device_metric" && !MISSING_DATA.has(d.missingDataPolicy)) {
    errors.push({ step: "behavior", field: "missing_data_policy", message: "Pick a missing-data policy" });
  }

  // Destinations: every selected id must be non-empty (existence is the
  // server's check — the list comes from the API).
  if (d.destinationIds.some((id) => !id)) {
    errors.push({ step: "destinations", field: "destination_ids", message: "Destination selection is inconsistent; reopen the step" });
  }

  return { ok: errors.length === 0, errors };
}

/** stepOf maps an error to the editor step that owns it. */
export function stepOf(error: FieldError): string {
  return error.step;
}

/** firstErrorFor returns the message for one field, if any. */
export function firstErrorFor(errors: FieldError[], field: string): string | undefined {
  return errors.find((e) => e.field === field)?.message;
}
