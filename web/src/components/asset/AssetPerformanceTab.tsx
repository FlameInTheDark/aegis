import * as React from "react";
import { Activity, BellPlus, Gauge, MemoryStick } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { useRouter } from "@/lib/router";
import { fmtBps, fmtBytes } from "@/lib/format";
import { Chart } from "@/components/charts/Chart";
import { Sparkline } from "@/components/charts/Sparkline";
import {
  PERF_REFRESH_PRESETS, PERF_WINDOW_PRESETS, fmtRangeLabel, fmtTick,
  formatWindowLabel, initialTimelineExtent, minuteFloor, nextTimelineExtent,
  parseCustomWindow, splitWindow, type PerfPrefs,
} from "@/components/assets/perf-config";
import { useAssetMetrics } from "@/lib/queries";
import type { AssetIfaceSeries, AssetMetricLatest, AssetMetricPoint } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { EmptyState } from "@/components/shared";

/** RFC3339 → datetime-local input value ("2026-09-24T14:30"), rendered in
 * the browser timezone so the input shows what the user expects. */
function isoToLocalInput(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "";
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/** datetime-local input value → RFC3339 (empty input → undefined). */
function localInputToIso(v: string): string | undefined {
  if (!v) return undefined;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? undefined : d.toISOString();
}

/** The initial range bounds when the viewer switches to range mode without
 * having picked dates: the trailing hour. */
function defaultRange(): { from: string; to: string } {
  const to = new Date();
  const from = new Date(to.getTime() - 3_600_000);
  return { from: from.toISOString(), to: to.toISOString() };
}

/** PerfControls — the viewer-facing control bar of the performance tab:
 * mode toggle (live tail vs. static range), the tail window presets plus a
 * custom value, the refresh cadence (latest mode only — a historical range
 * never changes, so polling would refetch identical data), and the range
 * bounds as datetime inputs. */
function PerfControls({ perf, onPerf }: { perf: PerfPrefs; onPerf: (p: PerfPrefs) => void }) {
  const isPreset = PERF_WINDOW_PRESETS.some((p) => p.value === perf.window);
  // Custom editor: initialized from the current window when it is already
  // custom, else from a non-colliding default — a colliding default (say
  // "5m") would make picking Custom… look like a no-op.
  const [custom, setCustom] = React.useState(() => splitWindow(isPreset ? "45m" : perf.window));
  const applyCustom = () => onPerf({ ...perf, window: parseCustomWindow(custom.value, custom.unit) });
  const setMode = (mode: "latest" | "range") => {
    if (mode === "range" && (!perf.from || !perf.to)) {
      onPerf({ ...perf, mode, ...defaultRange() });
    } else {
      onPerf({ ...perf, mode });
    }
  };
  const rangeInvalid = !!perf.from && !!perf.to && new Date(perf.from).getTime() >= new Date(perf.to).getTime();
  const modeBtn = (active: boolean) =>
    cn(
      "rounded px-3 py-1 text-xs font-medium transition-colors cursor-pointer",
      active ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground",
    );
  return (
    <Card>
      <CardContent className="flex flex-wrap items-center gap-x-6 gap-y-3 py-4">
        <div className="flex items-center gap-2.5">
          <span className="text-xs uppercase tracking-wider text-muted-foreground">Data range</span>
          <div className="flex rounded-md border p-0.5">
            <button type="button" className={modeBtn(perf.mode === "latest")} onClick={() => setMode("latest")}>
              Latest
            </button>
            <button type="button" className={modeBtn(perf.mode === "range")} onClick={() => setMode("range")}>
              Range
            </button>
          </div>
        </div>
        {perf.mode === "latest" ? (
          <>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Window</span>
              <Select
                value={isPreset ? perf.window : "custom"}
                onValueChange={(v) => {
                  if (v === "custom") {
                    const next = splitWindow(isPreset ? "45m" : perf.window);
                    setCustom(next);
                    onPerf({ ...perf, window: parseCustomWindow(next.value, next.unit) });
                  } else {
                    onPerf({ ...perf, window: v });
                  }
                }}
              >
                <SelectTrigger className="h-8 w-40">
                  <SelectValue>
                    {isPreset
                      ? PERF_WINDOW_PRESETS.find((p) => p.value === perf.window)?.label ?? perf.window
                      : `${formatWindowLabel(perf.window)} (custom)`}
                  </SelectValue>
                </SelectTrigger>
                <SelectContent>
                  {PERF_WINDOW_PRESETS.map((p) => (
                    <SelectItem key={p.value} value={p.value}>
                      {p.label}
                    </SelectItem>
                  ))}
                  <SelectSeparator />
                  <SelectItem value="custom">Custom…</SelectItem>
                </SelectContent>
              </Select>
            </div>
            {!isPreset && (
              <div className="flex items-center gap-1.5">
                <Input
                  type="number"
                  min={1}
                  value={custom.value}
                  onChange={(e) => setCustom({ ...custom, value: Math.max(1, Math.floor(Number(e.target.value) || 1)) })}
                  onKeyDown={(e) => e.key === "Enter" && applyCustom()}
                  className="h-8 w-20"
                  aria-label="Custom window value"
                />
                <Select value={custom.unit} onValueChange={(v) => setCustom({ ...custom, unit: v as "s" | "m" | "h" | "d" })}>
                  <SelectTrigger className="h-8 w-28" aria-label="Custom window unit">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="s">seconds</SelectItem>
                    <SelectItem value="m">minutes</SelectItem>
                    <SelectItem value="h">hours</SelectItem>
                    <SelectItem value="d">days</SelectItem>
                  </SelectContent>
                </Select>
                <Button size="sm" variant="outline" className="h-8" onClick={applyCustom}>
                  Apply
                </Button>
              </div>
            )}
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">Refresh</span>
              <Select value={String(perf.refreshMs)} onValueChange={(v) => onPerf({ ...perf, refreshMs: Number(v) })}>
                <SelectTrigger className="h-8 w-24" aria-label="Refresh interval">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {PERF_REFRESH_PRESETS.map((r) => (
                    <SelectItem key={r.value} value={String(r.value)}>
                      {r.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">From</span>
              <Input
                type="datetime-local"
                value={isoToLocalInput(perf.from)}
                onChange={(e) => onPerf({ ...perf, from: localInputToIso(e.target.value) })}
                className="h-8 w-56"
                aria-label="Range start"
              />
            </div>
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground">To</span>
              <Input
                type="datetime-local"
                value={isoToLocalInput(perf.to)}
                onChange={(e) => onPerf({ ...perf, to: localInputToIso(e.target.value) })}
                className="h-8 w-56"
                aria-label="Range end"
              />
            </div>
            <span className={cn("text-xs", rangeInvalid ? "text-critical" : "text-muted-foreground")}>
              {rangeInvalid ? "From must be before To" : "Static view — historical ranges do not update"}
            </span>
          </>
        )}
      </CardContent>
    </Card>
  );
}

/** RangeTimeline — the visual date picker for range mode. Shows a coarse
 * CPU/RAM/network overview of a fixed context window and a draggable slider
 * window; committing a drag re-queries the charts. The context window
 * (extent) is held stable across commits — it only grows when the selection
 * comes near an edge — so dragging never refetches or rescales the strip
 * (which used to redraw it and visually re-center the selection) and
 * keepPreviousData keeps the strip mounted while any expansion loads. The
 * overview query returns at most ~360 buckets, so the strip stays readable
 * instead of overloading with points. RAM rides the left percent axis as
 * used/total; throughput rides a separate right axis (bytes/s) — one axis
 * for both scales would flatten the percent lines into noise. */
function RangeTimeline({ assetId, from, to, onChange }: { assetId: string; from: string; to: string; onChange: (from: string, to: string) => void }) {
  const fromMs = new Date(from).getTime();
  const toMs = new Date(to).getTime();
  // Overview extent: initialized once from the incoming selection, then
  // only grown when a committed selection comes within a quarter-span of
  // an edge. Bounds are minute-quantized — a raw Date.now() would change
  // the query key on every render and loop the overview refetch forever.
  const [extent, setExtent] = React.useState(() => initialTimelineExtent(fromMs, toMs, minuteFloor(Date.now())));
  React.useEffect(() => {
    setExtent((prev) => nextTimelineExtent(prev, fromMs, toMs, minuteFloor(Date.now())));
  }, [fromMs, toMs]);
  const ctx = React.useMemo(
    () => ({ from: new Date(extent.fromMs).toISOString(), to: new Date(extent.toMs).toISOString() }),
    [extent.fromMs, extent.toMs],
  );
  const overviewQ = useAssetMetrics(assetId, { mode: "range", window: "", from: ctx.from, to: ctx.to, refreshMs: 0 });
  const commitRef = React.useRef<number | null>(null);
  React.useEffect(() => () => {
    if (commitRef.current) window.clearTimeout(commitRef.current);
  }, []);
  const onZoom = (start: number, end: number) => {
    if (commitRef.current) window.clearTimeout(commitRef.current);
    commitRef.current = window.setTimeout(() => {
      onChange(new Date(start).toISOString(), new Date(end).toISOString());
    }, 400);
  };
  const data = overviewQ.data?.points ?? [];
  // RAM as a percent of installed memory; null (gap) when a bucket carries
  // no memory reading, so a missing series never renders as a false 0%.
  const ramPct = (p: AssetMetricPoint): number | null =>
    p.mem_total > 0 ? Number(((p.mem_used / p.mem_total) * 100).toFixed(2)) : null;
  return (
    <Card>
      <CardHeader className="pb-0">
        <CardTitle>Timeline</CardTitle>
        <CardDescription>Drag the handles to set the range dates visually</CardDescription>
      </CardHeader>
      <CardContent>
        {data.length === 0 ? (
          <EmptyState compact icon={Activity} title={overviewQ.isLoading ? "Loading timeline…" : "No samples around this range"} />
        ) : (
          <Chart
            height={190}
            onDataZoom={onZoom}
            option={{
              // Legend row on top and right-axis labels on the side cost
              // vertical/horizontal room; bottom stays reserved for the slider.
              grid: { left: 44, right: 56, top: 26, bottom: 70 },
              xAxis: {
                type: "time",
                axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } },
                axisLabel: {
                  color: "#8A8F98",
                  fontSize: 10,
                  hideOverlap: true,
                  // Day-qualified labels with minutes — hour-only text made
                  // every intra-hour tick render the identical label.
                  formatter: (v: number) => {
                    const d = new Date(v);
                    const pad = (n: number) => String(n).padStart(2, "0");
                    return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
                  },
                },
              },
              yAxis: [
                {
                  type: "value",
                  max: 100,
                  axisLabel: { formatter: "{value}%", color: "#8A8F98", fontSize: 10 },
                  splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } },
                },
                {
                  type: "value",
                  axisLabel: { formatter: (v: number) => fmtBytes(v), color: "#8A8F98", fontSize: 10 },
                  splitLine: { show: false },
                  splitNumber: 4,
                },
              ],
              tooltip: {
                trigger: "axis",
                // Percent series and byte-rate series share the tooltip; a
                // single valueFormatter would mislabel one of them.
                formatter: (params: unknown) => {
                  const arr = (Array.isArray(params) ? params : [params]) as {
                    seriesName?: string; marker?: string; value?: unknown; axisValueLabel?: string;
                  }[];
                  if (arr.length === 0) return "";
                  const title = arr[0]?.axisValueLabel ?? "";
                  const rows = arr.map((p) => {
                    const raw = Array.isArray(p.value) ? p.value[1] : p.value;
                    const isBps = p.seriesName === "in" || p.seriesName === "out";
                    const val = raw === null || raw === undefined ? "—"
                      : isBps ? fmtBps(Number(raw)) : `${Number(raw).toFixed(1)}%`;
                    return `${p.marker ?? ""} ${p.seriesName} ${val}`;
                  });
                  return [title, ...rows].join("<br/>");
                },
              },
              dataZoom: [
                {
                  type: "slider",
                  xAxisIndex: 0,
                  height: 42,
                  bottom: 12,
                  startValue: fromMs,
                  endValue: toMs,
                  minSpan: 1,
                  brushSelect: false,
                  throttle: 200,
                  borderColor: "rgba(255,255,255,0.14)",
                  fillerColor: "rgba(94,106,210,0.28)",
                  dataBackground: {
                    lineStyle: { color: "rgba(255,255,255,0.18)" },
                    areaStyle: { color: "rgba(255,255,255,0.06)" },
                  },
                  selectedDataBackground: {
                    lineStyle: { color: "#5E6AD2" },
                    areaStyle: { color: "rgba(94,106,210,0.12)" },
                  },
                  handleStyle: { color: "#5E6AD2" },
                  moveHandleStyle: { color: "#5E6AD2" },
                  emphasis: { handleStyle: { borderColor: "#5E6AD2" } },
                  textStyle: { color: "#8A8F98", fontSize: 10 },
                  labelFormatter: (v: number) =>
                    new Date(v).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }),
                },
              ],
              legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 10 } },
              series: [
                {
                  name: "cpu",
                  type: "line",
                  data: data.map((p) => [new Date(p.ts).getTime(), Number(p.cpu_avg.toFixed(2))]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#5E6AD2", width: 1.5 },
                  areaStyle: { color: "#5E6AD222" },
                },
                {
                  name: "ram",
                  type: "line",
                  data: data.map((p) => [new Date(p.ts).getTime(), ramPct(p)]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#60A5FA", width: 1.25 },
                },
                {
                  name: "in",
                  type: "line",
                  yAxisIndex: 1,
                  data: data.map((p) => [new Date(p.ts).getTime(), Number(p.rx_bps.toFixed(1))]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#34D399", width: 1.25 },
                },
                {
                  name: "out",
                  type: "line",
                  yAxisIndex: 1,
                  data: data.map((p) => [new Date(p.ts).getTime(), Number(p.tx_bps.toFixed(1))]),
                  smooth: true,
                  symbol: "none",
                  lineStyle: { color: "#FBBF24", width: 1.25 },
                },
              ],
            }}
          />
        )}
      </CardContent>
    </Card>
  );
}

/** UpdatingDot marks a background refetch next to a chart description.
 * Purely visual — no layout impact, invisible when idle. */
function UpdatingDot({ show }: { show: boolean }) {
  if (!show) return null;
  return <span aria-hidden className="ml-1.5 inline-block size-1.5 animate-pulse rounded-full bg-[#5E6AD2] align-middle" />;
}

/** Performance: CPU, memory and network history collected by the endpoint
 *  device bound to this asset, from the ClickHouse metrics tier. Latest
 *  mode tails a window and refreshes; range mode shows a static span picked
 *  with the timeline. The interface table carries per-NIC sparklines. */
export function AssetPerformanceTab({
  points, latest, ifaces, loading, fetching, perf, onPerf, effective, assetId, assetLabel,
}: {
  points: AssetMetricPoint[];
  latest: AssetMetricLatest | null;
  ifaces: AssetIfaceSeries[];
  loading: boolean;
  fetching: boolean;
  perf: PerfPrefs;
  onPerf: (p: PerfPrefs) => void;
  effective: { from: string; to: string; bucket: number; tail: boolean } | null;
  assetId: string;
  assetLabel: string;
}) {
  const effFrom = effective?.from || perf.from || points[0]?.ts || "";
  const effTo = effective?.to || perf.to || points[points.length - 1]?.ts || "";
  const spanSecs =
    effFrom && effTo ? Math.max(1, (new Date(effTo).getTime() - new Date(effFrom).getTime()) / 1000) : 86400;
  const ts = points.map((p) => fmtTick(p.ts, spanSecs));
  const memPct = latest?.mem_total ? Math.round((latest.mem_used / latest.mem_total) * 100) : null;
  const windowLabel = perf.mode === "latest" ? `last ${formatWindowLabel(perf.window)}` : fmtRangeLabel(effFrom, effTo);
  const refreshLabel =
    perf.mode === "range"
      ? "static"
      : PERF_REFRESH_PRESETS.find((r) => r.value === perf.refreshMs)?.label?.toLowerCase() ?? `${Math.round(perf.refreshMs / 1000)}s`;
  const seriesByName = new Map(ifaces.map((s) => [s.name, s]));
  const rangeInvalid = perf.mode === "range" && !!perf.from && !!perf.to && new Date(perf.from).getTime() >= new Date(perf.to).getTime();
  const rangeReady = perf.mode === "latest" || (!!perf.from && !!perf.to && !rangeInvalid);
  // Background refetch marker: points keep rendering while fresh data
  // loads (keepPreviousData), so the pulsing dot — not a layout swap — is
  // the only visible change.
  const updating = fetching && !loading;
  // "Create alert" entry points: deep-link into the Alerts console trigger
  // editor with a prefilled device-metric draft scoped to this asset.
  const { navigate } = useRouter();
  const alertSeed = (metricField: string) => {
    const p = new URLSearchParams({ tab: "triggers", new: "metric", metric: metricField, asset: assetId });
    if (assetLabel) p.set("label", assetLabel);
    navigate(`/alerts?${p.toString()}`);
  };
  return (
    <>
      <PerfControls perf={perf} onPerf={onPerf} />
      {perf.mode === "range" && perf.from && perf.to && !rangeInvalid && (
        <RangeTimeline
          assetId={assetId}
          from={perf.from}
          to={perf.to}
          onChange={(from, to) => onPerf({ ...perf, from, to })}
        />
      )}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader className="pb-0">
            <CardTitle>Current load</CardTitle>
            <CardDescription>Most recent sample from the endpoint collector</CardDescription>
            <CardAction>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="sm" className="gap-1.5"><BellPlus /> Create alert</Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-64">
                  <DropdownMenuItem onClick={() => alertSeed("cpu_percent")}>
                    <Gauge /> CPU utilization above 90%…
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => alertSeed("mem_used_percent")}>
                    <MemoryStick /> Memory usage above 90%…
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => navigate("/alerts?tab=triggers")}>
                    <BellPlus /> Manage trigger rules…
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </CardAction>
          </CardHeader>
          <CardContent>
            {latest ? (
              <div className="grid grid-cols-2 gap-3">
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">CPU</div>
                  <div className={cn("tabular text-2xl font-semibold", latest.cpu_percent > 85 ? "text-critical" : "text-foreground")}>
                    {latest.cpu_percent.toFixed(1)}%
                  </div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Memory</div>
                  <div className="tabular text-2xl font-semibold">{memPct !== null ? `${memPct}%` : "—"}</div>
                  <div className="text-[11px] text-muted-foreground">{fmtBytes(latest.mem_used)} of {fmtBytes(latest.mem_total)}</div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Network</div>
                  <div className="tabular text-sm font-semibold">↓ {fmtBps(latest.rx_bps)}</div>
                  <div className="tabular text-sm font-semibold">↑ {fmtBps(latest.tx_bps)}</div>
                </div>
                <div className="rounded-lg border p-3">
                  <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Uptime</div>
                  <div className="tabular text-sm font-semibold">{latest.uptime_secs > 0 ? fmtUptime(latest.uptime_secs) : "—"}</div>
                  <div className="text-[11px] text-muted-foreground">sampled {timeAgo(latest.timestamp)}</div>
                </div>
              </div>
            ) : (
              <EmptyState compact icon={Activity} title="No samples yet" description="The first performance sample arrives about a minute after the endpoint collector connects." />
            )}
          </CardContent>
        </Card>

        <Card className="lg:col-span-2">
          <CardHeader className="pb-0">
            <CardTitle>CPU utilization</CardTitle>
            <CardDescription>Average and peak per bucket · {windowLabel} · {refreshLabel}<UpdatingDot show={updating} /></CardDescription>
          </CardHeader>
          <CardContent>
            {points.length === 0 || !rangeReady ? (
              <EmptyState compact icon={Activity} title={loading || !rangeReady ? "Loading metrics…" : "No history in this window"} />
            ) : (
              <Chart
                height={220}
                live={perf.mode === "latest"}
                option={{
                  xAxis: { type: "category", boundaryGap: false, data: ts, axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } }, axisLabel: { hideOverlap: true } },
                  yAxis: { type: "value", max: 100, axisLabel: { formatter: "{value}%" }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  tooltip: { trigger: "axis", valueFormatter: (v) => `${Number(v).toFixed(1)}%` },
                  series: [
                    { name: "avg", type: "line", data: points.map((p) => Number(p.cpu_avg.toFixed(2))), smooth: true, symbol: "none", lineStyle: { color: "#5E6AD2" }, areaStyle: { color: "#5E6AD222" } },
                    { name: "peak", type: "line", data: points.map((p) => Number(p.cpu_max.toFixed(2))), smooth: true, symbol: "none", lineStyle: { color: "#FB923C", type: "dashed" } },
                  ],
                  legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 11 } },
                }}
              />
            )}
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-0">
            <CardTitle>Memory</CardTitle>
            <CardDescription>Used vs. installed · {windowLabel} · {refreshLabel}<UpdatingDot show={updating} /></CardDescription>
          </CardHeader>
          <CardContent>
            {points.length === 0 || !rangeReady ? (
              <EmptyState compact icon={Activity} title={loading || !rangeReady ? "Loading metrics…" : "No history in this window"} />
            ) : (
              <Chart
                height={220}
                live={perf.mode === "latest"}
                option={{
                  xAxis: { type: "category", boundaryGap: false, data: ts, axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } }, axisLabel: { hideOverlap: true } },
                  yAxis: { type: "value", axisLabel: { formatter: (v: number) => fmtBytes(v) }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  tooltip: { trigger: "axis", valueFormatter: (v) => fmtBytes(Number(v)) },
                  series: [
                    { name: "used", type: "line", data: points.map((p) => p.mem_used), smooth: true, symbol: "none", lineStyle: { color: "#60A5FA" }, areaStyle: { color: "#60A5FA22" } },
                    { name: "total", type: "line", data: points.map((p) => p.mem_total), smooth: true, symbol: "none", lineStyle: { color: "#8A8F98", type: "dashed" } },
                  ],
                  legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 11 } },
                }}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-0">
            <CardTitle>Network throughput</CardTitle>
            <CardDescription>Receive/transmit rates · {windowLabel} · {refreshLabel}<UpdatingDot show={updating} /></CardDescription>
          </CardHeader>
          <CardContent>
            {points.length === 0 || !rangeReady ? (
              <EmptyState compact icon={Activity} title={loading || !rangeReady ? "Loading metrics…" : "No history in this window"} />
            ) : (
              <Chart
                height={220}
                live={perf.mode === "latest"}
                option={{
                  xAxis: { type: "category", boundaryGap: false, data: ts, axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } }, axisLabel: { hideOverlap: true } },
                  yAxis: { type: "value", axisLabel: { formatter: (v: number) => fmtBytes(v) }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  tooltip: { trigger: "axis", valueFormatter: (v) => fmtBps(Number(v)) },
                  series: [
                    { name: "in", type: "line", data: points.map((p) => Number(p.rx_bps.toFixed(1))), smooth: true, symbol: "none", lineStyle: { color: "#34D399" }, areaStyle: { color: "#34D39922" } },
                    { name: "out", type: "line", data: points.map((p) => Number(p.tx_bps.toFixed(1))), smooth: true, symbol: "none", lineStyle: { color: "#FBBF24" } },
                  ],
                  legend: { top: 0, right: 0, itemWidth: 14, itemHeight: 2, textStyle: { color: "#8A8F98", fontSize: 11 } },
                }}
              />
            )}
          </CardContent>
        </Card>
      </div>

      {latest && latest.ifaces.length > 0 && (
        <Card className="py-0">
          <CardHeader>
            <CardTitle>Network interfaces</CardTitle>
            <CardDescription>Counters, rates and speed history ({windowLabel})</CardDescription>
          </CardHeader>
          <CardContent className="px-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="pl-4">Interface</TableHead>
                  <TableHead>MAC</TableHead>
                  <TableHead className="text-right">Receive</TableHead>
                  <TableHead className="text-right">Transmit</TableHead>
                  <TableHead className="w-44">Activity</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {latest.ifaces.map((i) => {
                  const series = seriesByName.get(i.name);
                  const hasHistory = !!series && series.rx.length + series.tx.length > 0;
                  return (
                    <TableRow key={i.name}>
                      <TableCell className="pl-4 font-medium">{i.name}</TableCell>
                      <TableCell className="font-mono text-xs text-muted-foreground">{i.mac || "—"}</TableCell>
                      <TableCell className="text-right tabular text-xs">{fmtBytes(i.rx_bytes)} · {fmtBps(i.rx_bps)}</TableCell>
                      <TableCell className="text-right tabular text-xs">{fmtBytes(i.tx_bytes)} · {fmtBps(i.tx_bps)}</TableCell>
                      <TableCell className="w-44 py-1.5">
                        {hasHistory ? (
                          <Sparkline rx={series!.rx} tx={series!.tx} />
                        ) : (
                          <span className="text-xs text-muted-foreground">no history</span>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </>
  );
}

function fmtUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}
