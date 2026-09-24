import { describe, expect, it } from "vitest";

import {
  DEFAULT_PERF_PREFS,
  fmtRangeLabel,
  fmtTick,
  formatWindowLabel,
  initialTimelineExtent,
  loadPerfPrefs,
  minuteFloor,
  nextTimelineExtent,
  parseCustomWindow,
  PERF_STORAGE_KEY,
  savePerfPrefs,
  splitWindow,
  windowSeconds,
} from "./perf-config";

function fakeStorage(initial?: Record<string, string>) {
  const data = new Map(Object.entries(initial ?? {}));
  return {
    getItem: (k: string) => data.get(k) ?? null,
    setItem: (k: string, v: string) => void data.set(k, v),
  } as Storage;
}

describe("windowSeconds", () => {
  it("resolves every accepted unit", () => {
    expect(windowSeconds("90")).toBe(90);
    expect(windowSeconds("30s")).toBe(30);
    expect(windowSeconds("5m")).toBe(300);
    expect(windowSeconds("2h")).toBe(7200);
    expect(windowSeconds("7d")).toBe(604800);
  });
  it("rejects junk", () => {
    expect(windowSeconds("0")).toBeNull();
    expect(windowSeconds("-5m")).toBeNull();
    expect(windowSeconds("5x")).toBeNull();
    expect(windowSeconds("")).toBeNull();
  });
});

describe("parseCustomWindow / formatWindowLabel", () => {
  it("builds API labels from value+unit", () => {
    expect(parseCustomWindow(90, "s")).toBe("90");
    expect(parseCustomWindow(45, "m")).toBe("45m");
    expect(parseCustomWindow(12, "h")).toBe("12h");
    expect(parseCustomWindow(30, "d")).toBe("30d");
    expect(parseCustomWindow(0, "m")).toBe("1m"); // floor at 1
  });
  it("formats labels compactly", () => {
    expect(formatWindowLabel("90")).toBe("90s");
    expect(formatWindowLabel("60")).toBe("1m");
    expect(formatWindowLabel("3600")).toBe("1h");
    expect(formatWindowLabel("86400")).toBe("1d");
    expect(formatWindowLabel("172800")).toBe("2d");
    expect(formatWindowLabel("45m")).toBe("45m");
  });
});

describe("splitWindow", () => {
  it("decomposes into the largest fitting unit", () => {
    expect(splitWindow("45m")).toEqual({ value: 45, unit: "m" });
    expect(splitWindow("7200")).toEqual({ value: 2, unit: "h" });
    expect(splitWindow("3d")).toEqual({ value: 3, unit: "d" });
    expect(splitWindow("90")).toEqual({ value: 90, unit: "s" });
    expect(splitWindow("junk")).toEqual({ value: 5, unit: "m" }); // default fallback (300s)
  });
  it("round-trips with parseCustomWindow (same duration)", () => {
    for (const w of ["30", "45m", "12h", "30d", "90s"]) {
      const { value, unit } = splitWindow(w);
      const rebuilt = parseCustomWindow(value, unit);
      expect(windowSeconds(rebuilt)).toBe(windowSeconds(w));
    }
  });
});

describe("perf prefs persistence", () => {
  it("returns defaults without storage or with junk", () => {
    expect(loadPerfPrefs(null)).toEqual(DEFAULT_PERF_PREFS);
    expect(loadPerfPrefs(fakeStorage({ [PERF_STORAGE_KEY]: "{not json" }))).toEqual(DEFAULT_PERF_PREFS);
  });
  it("round-trips valid prefs and drops invalid fields", () => {
    const storage = fakeStorage();
    savePerfPrefs(storage, { mode: "range", window: "5m", refreshMs: 10_000, from: "a", to: "b" });
    expect(loadPerfPrefs(storage)).toEqual({ mode: "range", window: "5m", refreshMs: 10_000, from: "a", to: "b" });
    savePerfPrefs(storage, { mode: "banana", window: "nope", refreshMs: 1234 } as never);
    expect(loadPerfPrefs(storage)).toEqual(DEFAULT_PERF_PREFS);
  });
  it("null storage save is a no-op", () => {
    expect(() => savePerfPrefs(null, DEFAULT_PERF_PREFS)).not.toThrow();
  });
});

describe("fmtTick", () => {
  it("renders hour:minute for short spans", () => {
    const ts = new Date(2026, 8, 24, 9, 5).toISOString();
    expect(fmtTick(ts, 3600)).toBe("09:05");
    expect(fmtTick(ts, 86400)).toBe("09:05"); // exactly one day still shows time
  });
  it("adds the date once the span crosses a day", () => {
    const ts = new Date(2026, 8, 24, 9, 5).toISOString();
    expect(fmtTick(ts, 2 * 86400)).toBe("09-24 09:05");
    expect(fmtTick(ts, 30 * 86400)).toBe("09-24");
  });
  it("falls back to the raw string for unparseable input", () => {
    expect(fmtTick("nonsense", 60)).toBe("nonsense");
  });
});

describe("fmtRangeLabel", () => {
  it("describes the span", () => {
    const from = new Date(2026, 8, 24, 12, 0).toISOString();
    const to = new Date(2026, 8, 24, 14, 0).toISOString();
    expect(fmtRangeLabel(from, to)).toBe("last 2h");
    expect(fmtRangeLabel(to, from)).toBe("selected range");
  });
});

describe("minuteFloor", () => {
  it("quantizes to the minute", () => {
    expect(minuteFloor(new Date(2026, 8, 24, 12, 0, 30, 500).getTime())).toBe(
      new Date(2026, 8, 24, 12, 0, 0, 0).getTime(),
    );
  });
});

describe("timeline extent", () => {
  const now = new Date(2026, 8, 24, 12, 0).getTime();
  // A 1h selection ending 30m before "now".
  const from = now - 90 * 60_000;
  const to = now - 30 * 60_000;
  const span = to - from;

  it("initial context is one span on each side, right edge clamped to now", () => {
    const e = initialTimelineExtent(from, to, now);
    expect(e.fromMs).toBe(from - span);
    expect(e.toMs).toBe(now); // to + span is in the future → clamped
  });

  it("keeps the extent stable while the selection stays away from the edges", () => {
    const e = initialTimelineExtent(from, to, now);
    // Drag the window 30m left and 10m right — both keep more than the
    // quarter-span (15m) margin from the extent edges.
    const movedLeft = nextTimelineExtent(e, from - 1800_000, to - 1800_000, now);
    const movedRight = nextTimelineExtent(e, from + 600_000, to + 600_000, now);
    expect(movedLeft).toBe(e);
    expect(movedRight).toBe(e);
  });

  it("grows (never shrinks) when the selection reaches an edge", () => {
    const e = initialTimelineExtent(from, to, now);
    // Drag flush to the left edge of the extent.
    const grown = nextTimelineExtent(e, e.fromMs, e.fromMs + span, now);
    expect(grown.fromMs).toBeLessThan(e.fromMs);
    expect(grown.toMs).toBeGreaterThanOrEqual(e.toMs);
    // Growing again from the grown extent keeps widening, never cutting.
    const again = nextTimelineExtent(grown, grown.fromMs, grown.fromMs + span, now);
    expect(again.fromMs).toBeLessThanOrEqual(grown.fromMs);
    expect(again.toMs).toBeGreaterThanOrEqual(grown.toMs);
  });

  it("returns the same reference when stable so React state and query keys do not churn", () => {
    const e = initialTimelineExtent(from, to, now);
    expect(nextTimelineExtent(e, from, to, now)).toBe(e);
  });
});
