// Pure configuration for the asset performance tab: persisted viewer
// preferences (mode, tail window, refresh cadence), the preset ladders the
// controls render, and the x-axis tick formatting shared by every chart.
// No React, no network — everything here is unit-testable.

export type PerfMode = "latest" | "range";

export interface PerfPrefs {
  mode: PerfMode;
  /** Tail window label ("30s", "5m", "24h", "7d" or bare seconds). */
  window: string;
  /** Refresh cadence in ms; 0 = off. Only meaningful in latest mode. */
  refreshMs: number;
  /** Range-mode bounds (RFC3339). */
  from?: string;
  to?: string;
}

export const PERF_WINDOW_PRESETS: { label: string; value: string }[] = [
  { label: "30 seconds", value: "30s" },
  { label: "1 minute", value: "1m" },
  { label: "5 minutes", value: "5m" },
  { label: "15 minutes", value: "15m" },
  { label: "1 hour", value: "1h" },
  { label: "6 hours", value: "6h" },
  { label: "24 hours", value: "24h" },
  { label: "7 days", value: "7d" },
];

export const PERF_REFRESH_PRESETS: { label: string; value: number }[] = [
  { label: "Off", value: 0 },
  { label: "5s", value: 5_000 },
  { label: "10s", value: 10_000 },
  { label: "30s", value: 30_000 },
  { label: "1m", value: 60_000 },
  { label: "5m", value: 300_000 },
];

export const DEFAULT_PERF_PREFS: PerfPrefs = {
  mode: "latest",
  window: "24h",
  refreshMs: 30_000,
};

export const PERF_STORAGE_KEY = "aegis.perf.v1";

const REFRESH_VALUES = new Set(PERF_REFRESH_PRESETS.map((r) => r.value));

/** parseCustomWindow turns the custom-value + unit pair into a window
 * label the API accepts ("90" seconds, "45m", "12h", "30d"). */
export function parseCustomWindow(value: number, unit: "s" | "m" | "h" | "d"): string {
  const n = Math.max(1, Math.floor(value || 0));
  if (unit === "s") return String(n);
  return `${n}${unit}`;
}

/** splitWindow decomposes a window label into the custom-value + unit pair
 * for the editor inputs (largest fitting unit first). */
export function splitWindow(window: string): { value: number; unit: "s" | "m" | "h" | "d" } {
  const secs = windowSeconds(window) ?? 300;
  if (secs >= 86400 && secs % 86400 === 0) return { value: secs / 86400, unit: "d" };
  if (secs >= 3600 && secs % 3600 === 0) return { value: secs / 3600, unit: "h" };
  if (secs >= 60 && secs % 60 === 0) return { value: secs / 60, unit: "m" };
  return { value: secs, unit: "s" };
}

/** formatWindowLabel renders a window label compactly ("90" → "90s",
 * "5m" → "5m", "86400" → "1d"). */
export function formatWindowLabel(window: string): string {
  const secs = windowSeconds(window);
  if (secs === null) return window;
  if (secs % 86400 === 0 && secs >= 86400) {
    const d = secs / 86400;
    return d === 1 ? "1d" : `${d}d`;
  }
  if (secs % 3600 === 0 && secs >= 3600) {
    const h = secs / 3600;
    return h === 1 ? "1h" : `${h}h`;
  }
  if (secs % 60 === 0 && secs >= 60) {
    const m = secs / 60;
    return m === 1 ? "1m" : `${m}m`;
  }
  return `${secs}s`;
}

/** windowSeconds resolves a window label to seconds (null when unknown). */
export function windowSeconds(window: string): number | null {
  const m = /^(\d+)(s|m|h|d)?$/.exec(window.trim());
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  switch (m[2]) {
    case "m": return n * 60;
    case "h": return n * 3600;
    case "d": return n * 86400;
    default: return n; // "s" or bare seconds
  }
}

/** loadPerfPrefs reads the persisted preferences, merging over the
 * defaults and discarding anything malformed (storage may hold junk). */
export function loadPerfPrefs(storage: Storage | null): PerfPrefs {
  const prefs: PerfPrefs = { ...DEFAULT_PERF_PREFS };
  if (!storage) return prefs;
  try {
    const raw = storage.getItem(PERF_STORAGE_KEY);
    if (!raw) return prefs;
    const saved = JSON.parse(raw) as Partial<PerfPrefs>;
    if (saved.mode === "latest" || saved.mode === "range") prefs.mode = saved.mode;
    if (typeof saved.window === "string" && windowSeconds(saved.window)) prefs.window = saved.window;
    if (typeof saved.refreshMs === "number" && REFRESH_VALUES.has(saved.refreshMs)) prefs.refreshMs = saved.refreshMs;
    if (typeof saved.from === "string" && saved.from) prefs.from = saved.from;
    if (typeof saved.to === "string" && saved.to) prefs.to = saved.to;
  } catch {
    // Malformed blob → defaults.
  }
  return prefs;
}

/** savePerfPrefs persists the preferences; failures are swallowed — the
 * perf tab works fine without persistence (private mode etc.). */
export function savePerfPrefs(storage: Storage | null, prefs: PerfPrefs): void {
  if (!storage) return;
  try {
    storage.setItem(PERF_STORAGE_KEY, JSON.stringify(prefs));
  } catch {
    // Storage full/unavailable — non-fatal.
  }
}

/** fmtTick renders one x-axis tick for a chart whose span is `spanSecs`:
 * hour-minute for tails and short ranges, month-day + time once the span
 * crosses a day so multi-day ranges stay unambiguous. */
export function fmtTick(ts: string, spanSecs: number): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const pad = (n: number) => String(n).padStart(2, "0");
  const hm = `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  if (spanSecs <= 86400) return hm;
  const md = `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
  if (spanSecs <= 7 * 86400) return `${md} ${hm}`;
  return md;
}

/** fmtRangeLabel renders the effective window for card descriptions. */
export function fmtRangeLabel(from: string, to: string): string {
  const ms = new Date(to).getTime() - new Date(from).getTime();
  if (!Number.isFinite(ms) || ms <= 0) return "selected range";
  return `last ${formatWindowLabel(String(Math.round(ms / 1000)))}`;
}

// ---------------------------------------------------------------------------

/** TimelineExtent is the fixed overview window the range timeline shows,
 * in epoch ms. It is held stable across drag commits so the overview strip
 * neither refetches nor rescales while the operator drags (a rescale
 * visually re-centers the selection and replays the strip), and only ever
 * grows when a selection comes close to an edge. */
export interface TimelineExtent {
  fromMs: number;
  toMs: number;
}

/** minuteFloor quantizes a timestamp to the minute so time-derived bounds
 * never change within the same minute (a raw Date.now() in render would
 * change the overview query key continuously and loop refetches). */
export function minuteFloor(ms: number): number {
  return Math.floor(ms / 60_000) * 60_000;
}

/** initialTimelineExtent builds the first overview window around a
 * selection: one span of context on each side, right edge clamped to
 * `nowMs` (pass minute-quantized). */
export function initialTimelineExtent(fromMs: number, toMs: number, nowMs: number): TimelineExtent {
  const spanMs = Math.max(60_000, toMs - fromMs);
  return { fromMs: fromMs - spanMs, toMs: Math.min(nowMs, toMs + spanMs) };
}

/** nextTimelineExtent resolves the overview window to keep after a
 * selection commit. While the selection keeps a quarter-span margin from
 * both edges — the common drag case — the extent object is returned
 * unchanged (same reference, so React state and the overview query key
 * stay stable: no refetch, no redraw, no recentering). Near an edge the
 * extent grows to two spans of context around the selection, unioned with
 * the previous window so it never shrinks mid-session. */
export function nextTimelineExtent(extent: TimelineExtent, fromMs: number, toMs: number, nowMs: number): TimelineExtent {
  const spanMs = Math.max(60_000, toMs - fromMs);
  const margin = spanMs / 4;
  if (fromMs - margin >= extent.fromMs && toMs + margin <= extent.toMs) return extent;
  return {
    fromMs: Math.min(extent.fromMs, fromMs - 2 * spanMs),
    toMs: Math.max(extent.toMs, Math.min(nowMs, toMs + 2 * spanMs)),
  };
}
