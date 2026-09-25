import { describe, expect, it } from "vitest";

import {
  compileSummary, draftFromApi, draftToPayload, emptyDraft, loadDraft, saveDraft, clearDraft,
  scopeSummary, seedMetricDraft, type TriggerDraft,
} from "./alert-draft";

describe("draftToPayload", () => {
  it("serializes an event trigger with AND conditions", () => {
    const d = emptyDraft();
    d.name = "Finding floods";
    d.severity = "high";
    d.eventTypes = ["finding.created"];
    d.conditions = { kind: "all", rows: [{ field: "kev", op: "eq", values: ["true"] }] };
    d.siteIds = ["s1", "s2"];
    const p = draftToPayload(d) as Record<string, any>;
    expect(p.name).toBe("Finding floods");
    expect(p.kind).toBe("event");
    expect(p.enabled).toBe(false);
    expect(p.event_types).toEqual(["finding.created"]);
    expect(p.scope).toEqual({ site_ids: ["s1", "s2"] });
    expect(p.conditions).toEqual({ all: [{ field: "kev", op: "eq", value: true }] });
    expect(p.threshold).toBe(90); // default carries through as a number
  });

  it("serializes a metric trigger with hysteresis", () => {
    const d = emptyDraft("device_metric");
    d.metricField = "cpu_percent";
    d.operator = "gt";
    d.threshold = "90";
    d.windowSecs = 300;
    d.recoveryThreshold = "80";
    d.eventTypes = [];
    const p = draftToPayload(d) as Record<string, any>;
    expect(p.kind).toBe("device_metric");
    expect(p.metric_field).toBe("cpu_percent");
    expect(p.threshold).toBe(90);
    expect(p.recovery_threshold).toBe(80);
    expect(p.event_types).toEqual([]);
  });

  it("produces empty conditions when no rows exist", () => {
    const d = emptyDraft();
    const p = draftToPayload(d) as Record<string, any>;
    expect(p.conditions).toEqual({});
  });
});

describe("compileSummary", () => {
  it("renders the plan-style metric sentence", () => {
    const d = emptyDraft("device_metric");
    d.aggregation = "avg";
    d.threshold = "90";
    d.activationSecs = 120;
    d.recoveryThreshold = "80";
    const s = compileSummary(d);
    expect(s).toContain("avg CPU is above 90");
    expect(s).toContain("5m window");
    expect(s).toContain("sustained for at least 2m");
    expect(s).toContain("crosses 80");
  });

  it("renders the event sentence with conditions", () => {
    const d = emptyDraft();
    d.eventTypes = ["scan.state_changed"];
    d.conditions = { kind: "any", rows: [
      { field: "state", op: "eq", values: ["failed"] },
      { field: "kev", op: "eq", values: ["true"] },
    ] };
    const s = compileSummary(d);
    expect(s).toContain("Fire on scan.state_changed");
    expect(s).toContain("state is failed or kev is true");
  });
});

describe("scopeSummary", () => {
  it("reports organization-wide for empty scope", () => {
    expect(scopeSummary(emptyDraft())).toBe("Entire organization");
  });
  it("joins counts", () => {
    const d = emptyDraft();
    d.siteIds = ["a", "b", "c"];
    d.assetIds = ["x", "y"];
    expect(scopeSummary(d)).toBe("3 sites · 2 assets");
  });
});

describe("draft persistence", () => {
  it("round-trips through localStorage", () => {
    const store = new Map<string, string>();
    const win = { localStorage: {
      setItem: (k: string, v: string) => void store.set(k, v),
      getItem: (k: string) => store.get(k) ?? null,
      removeItem: (k: string) => void store.delete(k),
    } } as unknown as Window;
    const orig = (globalThis as Record<string, unknown>).window;
    (globalThis as Record<string, unknown>).window = win;
    try {
      const d = emptyDraft();
      d.name = "persisted";
      saveDraft(d);
      expect(loadDraft()?.name).toBe("persisted");
      clearDraft();
      expect(loadDraft()).toBeNull();
    } finally {
      (globalThis as Record<string, unknown>).window = orig;
    }
  });
});

describe("draftFromApi", () => {
  it("maps the stored trigger back into an editable draft", () => {
    const api = {
      id: "t1", revision: 3, name: "CPU", description: "", kind: "device_metric" as const,
      enabled: true, lifecycle: "stable", severity: "high",
      scope: { site_ids: ["s1"] }, conditions: { all: [{ field: "x", op: "eq", value: 5 }] },
      event_types: [] as string[], recovery_event_types: [] as string[],
      metric_field: "cpu_percent", aggregation: "p95", operator: "gte", threshold: 95,
      window_secs: 900, activation_secs: 300, recovery_secs: 600,
      recovery_threshold: 85, missing_data_policy: "resolve",
      cooldown_secs: 600, repeat_secs: 1800, destination_ids: ["d1"],
    };
    const d: TriggerDraft = draftFromApi(api as never);
    expect(d.id).toBe("t1");
    expect(d.revision).toBe(3);
    expect(d.metricField).toBe("cpu_percent");
    expect(d.threshold).toBe("95");
    expect(d.recoveryThreshold).toBe("85");
    expect(d.conditions).toEqual({ kind: "all", rows: [{ field: "x", op: "eq", values: ["5"] }] });
    expect(d.destinationIds).toEqual(["d1"]);
  });
});

describe("seedMetricDraft", () => {
  it("builds the plan's worked CPU example as a device-metric draft", () => {
    const d = seedMetricDraft({ metricField: "cpu_percent" });
    expect(d.kind).toBe("device_metric");
    expect(d.metricField).toBe("cpu_percent");
    expect(d.name).toBe("High CPU");
    expect(d.aggregation).toBe("avg");
    expect(d.operator).toBe("gt");
    expect(d.threshold).toBe("90");
    expect(d.windowSecs).toBe(300);
    expect(d.activationSecs).toBe(120);
    expect(d.recoverySecs).toBe(300);
    expect(d.assetIds).toEqual([]); // org-wide when unscoped
    const p = draftToPayload(d) as Record<string, any>;
    expect(p.kind).toBe("device_metric");
    expect(p.scope).toEqual({});
  });

  it("scopes to the asset and weaves the label into the title", () => {
    const d = seedMetricDraft({
      metricField: "mem_used_percent",
      assetId: "a-1",
      assetLabel: "web-01",
    });
    expect(d.name).toBe("High memory — web-01");
    expect(d.assetIds).toEqual(["a-1"]);
    expect(d.eventTypes).toEqual([]); // metric triggers carry no event types
    const p = draftToPayload(d) as Record<string, any>;
    expect(p.scope).toEqual({ asset_ids: ["a-1"] });
    expect(p.metric_field).toBe("mem_used_percent");
  });
});
