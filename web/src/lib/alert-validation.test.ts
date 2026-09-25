import { describe, expect, it } from "vitest";

import { validateDraft } from "./alert-validation";
import { emptyDraft } from "./alert-draft";

describe("validateDraft", () => {
  it("rejects a nameless draft and reports the step", () => {
    const res = validateDraft(emptyDraft());
    expect(res.ok).toBe(false);
    const nameErr = res.errors.find((e) => e.field === "name");
    expect(nameErr?.step).toBe("basics");
  });

  it("accepts a complete event trigger", () => {
    const d = emptyDraft();
    d.name = "New devices";
    d.eventTypes = ["asset.discovered"];
    expect(validateDraft(d).ok).toBe(true);
  });

  it("requires event types for event triggers", () => {
    const d = emptyDraft();
    d.name = "x";
    d.eventTypes = [];
    const res = validateDraft(d);
    expect(res.errors.some((e) => e.field === "event_types" && e.step === "trigger")).toBe(true);
  });

  it("validates metric bounds", () => {
    const d = emptyDraft("device_metric");
    d.name = "cpu";
    d.windowSecs = 10; // below 60s
    d.threshold = "abc";
    const res = validateDraft(d);
    expect(res.errors.some((e) => e.field === "window_secs")).toBe(true);
    expect(res.errors.some((e) => e.field === "threshold")).toBe(true);
    d.windowSecs = 300;
    d.threshold = "90";
    expect(validateDraft(d).ok).toBe(true);
  });

  it("flags numeric condition rows needing numeric values", () => {
    const d = emptyDraft();
    d.name = "x";
    d.conditions = { kind: "all", rows: [{ field: "findings_created", op: "gt", values: ["many"] }] };
    const res = validateDraft(d);
    expect(res.errors.some((e) => e.step === "conditions")).toBe(true);
  });

  it("rejects out-of-range cooldowns", () => {
    const d = emptyDraft();
    d.name = "x";
    d.cooldownSecs = 8 * 24 * 3600;
    const res = validateDraft(d);
    expect(res.errors.some((e) => e.field === "cooldown_secs" && e.step === "behavior")).toBe(true);
  });
});
