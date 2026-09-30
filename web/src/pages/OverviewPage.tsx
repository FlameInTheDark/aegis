import * as React from "react";
import { ArrowRight, Bell, Bug, CalendarClock, Cpu, DoorOpen, Flame, Layers, ListTree, RefreshCw, ShieldAlert, Siren, Radar } from "lucide-react";

import { timeAgo } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import { useScope } from "@/components/layout/AppShell";
import {
  useAssets, useDetectionMatches, useFindings, useMetricsSummary, useMetricsTimeseries, useScans, useSites,
} from "@/lib/queries";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { EmptyState, KpiTile, RiskMeter, SeverityBadge, severityMeta, StateBadge } from "@/components/shared";
import type { Severity } from "@/data/types";
import { Chart } from "@/components/charts/Chart";

// zrender (ECharts' canvas renderer) does not parse oklch() colors, so the
// chart palette pins the SAME hex values the shared Chart theme maps — one
// visual language, one renderable color format.
function severityHex(s: "critical" | "high" | "medium" | "low" | "info" | string): string {
  const map: Record<string, string> = {
    critical: "#F87171",
    high: "#FB923C",
    medium: "#FBBF24",
    low: "#60A5FA",
    info: "#6B7280",
  };
  return map[s] ?? "#6B7280";
}

export function OverviewPage() {
  const { site } = useScope();
  const { navigate } = useRouter();
  const sites = useSites();
  const metrics = useMetricsSummary(site);
  const riskTrendQ = useMetricsTimeseries("risk", 30, site);
  const eventsQ = useMetricsTimeseries("events", 7, site);
  const assetsQ = useAssets({ site, limit: 200 });
  const scansQ = useScans({ site, limit: 50 });
  const findingsQ = useFindings({ site, limit: 200 });
  const detectionsQ = useDetectionMatches({ limit: 50 });

  const assets = assetsQ.data?.items ?? [];
  const bySeverity = metrics.data?.by_severity ?? {};
  const totals: Record<"critical" | "high" | "medium" | "low", number> = {
    critical: bySeverity.critical ?? 0,
    high: bySeverity.high ?? 0,
    medium: bySeverity.medium ?? 0,
    low: bySeverity.low ?? 0,
  };
  const runningScans = (scansQ.data?.items ?? []).filter((s) => s.state === "running");

  const donut = (["critical", "high", "medium", "low"] as const).map((k) => ({ name: k, value: totals[k], color: severityHex(k) }));
  const donutTotal = donut.reduce((n, d) => n + d.value, 0);

  const exposed = [...assets].sort((a, b) => b.risk - a.risk).slice(0, 6);
  const topFindings = (findingsQ.data?.items ?? [])
    .filter((f) => f.status !== "resolved" && f.status !== "accepted_risk" && f.status !== "false_positive" && f.status !== "suppressed")
    .sort((a, b) => ["critical", "high", "medium", "low", "info"].indexOf(a.severity) - ["critical", "high", "medium", "low", "info"].indexOf(b.severity))
    .slice(0, 5);
  const recentDetections = (detectionsQ.data?.items ?? []).slice(0, 5);

  const assetLabelOf = (id: string) => {
    const a = assets.find((x) => x.id === id);
    return a?.hostname ?? a?.ip ?? "asset";
  };

  // Event volume: backend returns per-day {ts, value, by_category}; stack the
  // top categories the way the sensor stream names them.
  const eventVolume = (eventsQ.data?.points ?? []).map((p) => {
    const cats = p.by_category ?? {};
    const pick = (prefix: string) => Object.entries(cats).filter(([k]) => k.startsWith(prefix)).reduce((n, [, v]) => n + v, 0);
    return {
      day: String(p.ts).slice(5),
      agent: pick("agent"),
      scans: pick("scan") + pick("nmap"),
      auth: pick("auth") + pick("ssh") + pick("login"),
      detections: pick("detection") + pick("rule") + pick("alert"),
    };
  });

  const riskTrend = (riskTrendQ.data?.points ?? []).map((p) => ({
    date: String(p.ts).slice(5),
    risk: Math.round(p.value),
    high: 0,
    critical: 0,
  }));

  return (
    <div className="flex flex-col gap-5">
      {/* Header */}
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">Overview</h1>
          <p className="mt-1 flex items-center gap-1.5 text-sm text-muted-foreground">
            <span>
              Security posture for <span className="text-foreground">{site === "all" ? "all sites" : sites.data?.items.find((s) => s.id === site)?.name ?? "site"}</span>
              {" \u00b7 "}
              {metrics.dataUpdatedAt ? `updated ${timeAgo(metrics.dataUpdatedAt)}` : "loading\u2026"}
            </span>
            <button
              type="button"
              aria-label="Refresh overview"
              title="Refresh"
              className="inline-flex size-5 items-center justify-center rounded text-muted-foreground transition-colors hover:text-foreground"
              onClick={() => metrics.refetch()}
            >
              <RefreshCw className={metrics.isFetching ? "size-3.5 animate-spin" : "size-3.5"} />
            </button>
          </p>
        </div>
        <div className="flex items-center gap-2">
          {runningScans.length > 0 && (
            <Link to="/scans" className="hidden sm:block">
              <StateBadge tone="primary" pulse label={`${runningScans.length} scan running`} />
            </Link>
          )}
          <Button variant="outline" size="sm" onClick={() => navigate("/reports?new=1")}>
            Generate report
          </Button>
          <Button size="sm" onClick={() => navigate("/scans?new=1")}>
            <Radar /> New scan
          </Button>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-8">
        <KpiTile label="Assets" value={metrics.data?.assets ?? "—"} hint="listening services" icon={Layers} onClick={() => navigate("/assets")} tone="primary" />
        <KpiTile label="Open ports" value={metrics.data?.open_ports ?? "—"} hint="listening services" icon={DoorOpen} onClick={() => navigate("/assets")} />
        <KpiTile label="Vulnerabilities" value={metrics.data?.vulnerabilities ?? "—"} hint="open findings" icon={Bug} onClick={() => navigate("/vulnerabilities")} />
        <KpiTile label="Critical" value={metrics.data?.critical ?? "—"} tone={totals.critical ? "critical" : "default"} hint="open findings" icon={Flame} onClick={() => navigate("/findings?severity=critical")} />
        <KpiTile label="KEV" value={metrics.data?.kev ?? "—"} tone={metrics.data?.kev ? "critical" : "default"} hint="known exploited" icon={Siren} onClick={() => navigate("/vulnerabilities?kev=1")} />
        <KpiTile label="High-risk assets" value={metrics.data?.high_risk_assets ?? "—"} tone={metrics.data?.high_risk_assets ? "high" : "default"} hint="risk ≥ 70" icon={ShieldAlert} onClick={() => navigate("/assets?sort=risk")} />
        <KpiTile label="Active alerts" value={metrics.data?.active_alerts ?? "—"} tone={metrics.data?.active_alerts ? "high" : "default"} hint="detection matches" icon={Bell} onClick={() => navigate("/detections")} />
        <KpiTile
          label="Overdue"
          value={metrics.data?.overdue_findings ?? "—"}
          tone={metrics.data?.overdue_findings ? "critical" : "default"}
          hint="past due date"
          icon={CalendarClock}
          onClick={() => navigate("/findings")}
        />
        <KpiTile
          label="Changes 7d"
          value={metrics.data?.changes_7d ?? "—"}
          tone={metrics.data?.changes_7d ? "high" : "default"}
          hint="scan changes this week"
          icon={ListTree}
          onClick={() => navigate("/changes")}
        />
      </div>

      {/* Row 2: trend + distribution */}
      <div className="grid gap-4 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader>
            <CardTitle>Risk trend</CardTitle>
            <CardDescription>Aggregate risk from finding history, last 30 days</CardDescription>
            <CardAction>
              <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                <span className="flex items-center gap-1.5">
                  <span className="size-2 rounded-sm bg-primary" /> Risk
                </span>
              </div>
            </CardAction>
          </CardHeader>
          <CardContent className="h-64">
            {riskTrend.length === 0 ? (
              <EmptyState compact icon={Radar} title="No risk history yet" description="Risk history builds up as findings are correlated over time." />
            ) : (
              <Chart
                option={{
                  grid: { left: 40, right: 12, top: 16, bottom: 28 },
                  xAxis: {
                    type: "category",
                    boundaryGap: false,
                    data: riskTrend.map((p) => p.date),
                    axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } },
                    axisTick: { show: false },
                    axisLabel: { interval: 4, color: "#8A8F98", fontSize: 10, margin: 12 },
                  },
                  yAxis: { type: "value", axisLabel: { color: "#8A8F98", fontSize: 10 }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  series: [
                    {
                      name: "Risk",
                      type: "line",
                      data: riskTrend.map((p) => p.risk),
                      smooth: true,
                      symbol: "none",
                      lineStyle: { color: "#5E6AD2", width: 2 },
                      areaStyle: { color: "rgba(94,106,210,0.18)" },
                    },
                  ],
                }}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Severity distribution</CardTitle>
            <CardDescription>{donutTotal} open findings across {metrics.data?.assets ?? 0} assets</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center gap-4">
            <div className="relative h-40 w-40 shrink-0">
              <Chart
                height={160}
                option={{
                  tooltip: { trigger: "item" },
                  series: [
                    {
                      type: "pie",
                      radius: ["58%", "80%"],
                      center: ["50%", "50%"],
                      padAngle: 2,
                      itemStyle: { borderWidth: 0 },
                      label: { show: false },
                      data: donut.map((d) => ({ name: d.name, value: d.value, itemStyle: { color: severityHex(d.name) } })),
                    },
                  ],
                }}
              />
              <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
                <span className="tabular text-2xl font-semibold">{donutTotal}</span>
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground">findings</span>
              </div>
            </div>
            <ul className="flex flex-1 flex-col gap-2">
              {donut.map((d) => (
                <li key={d.name}>
                  <button className="flex w-full items-center justify-between text-sm hover:text-foreground cursor-pointer" onClick={() => navigate(`/findings?severity=${d.name}`)}>
                    <span className="flex items-center gap-2 capitalize text-muted-foreground">
                      <span className="size-2 rounded-full" style={{ background: d.color }} /> {d.name}
                    </span>
                    <span className="tabular font-medium">{d.value}</span>
                  </button>
                  <Progress value={donutTotal ? (d.value / donutTotal) * 100 : 0} className="mt-1 h-1" indicatorClassName={severityMeta[d.name as Severity].bg} />
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      </div>

      {/* Row 3: event volume + exposed assets */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Event volume</CardTitle>
            <CardDescription>Sensor events by category, last 7 days</CardDescription>
            <CardAction>
              <Button variant="ghost" size="xs" asChild>
                <Link to="/events">
                  Open stream <ArrowRight />
                </Link>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="h-56">
            {eventVolume.length === 0 ? (
              <EmptyState compact icon={Bell} title="No event volume recorded" description="Sensor events require a running ClickHouse backend and active sensors." />
            ) : (
              <Chart
                height={220}
                option={{
                  grid: { left: 40, right: 12, top: 16, bottom: 28 },
                  xAxis: {
                    type: "category",
                    data: eventVolume.map((p) => p.day),
                    axisLine: { lineStyle: { color: "rgba(255,255,255,0.1)" } },
                    axisTick: { show: false },
                    axisLabel: { color: "#8A8F98", fontSize: 10, margin: 12 },
                  },
                  yAxis: { type: "value", axisLabel: { color: "#8A8F98", fontSize: 10 }, splitLine: { lineStyle: { color: "rgba(255,255,255,0.05)" } } },
                  series: (
                    [
                      { key: "agent", name: "agent", color: "#3F4254" },
                      { key: "scans", name: "scans", color: "#5E6AD2" },
                      { key: "auth", name: "auth", color: "#8FA8D9" },
                      { key: "detections", name: "detections", color: "#D2504B" },
                    ] as const
                  ).map((s) => ({
                    name: s.name,
                    type: "bar" as const,
                    stack: "events",
                    barWidth: 22,
                    itemStyle: { color: s.color },
                    data: eventVolume.map((p) => p[s.key]),
                  })),
                }}
              />
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Top exposed assets</CardTitle>
            <CardDescription>Ranked by risk score — exposure × criticality × findings</CardDescription>
            <CardAction>
              <Button variant="ghost" size="xs" asChild>
                <Link to="/assets?sort=risk">
                  All assets <ArrowRight />
                </Link>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="px-0">
            {exposed.length === 0 ? (
              <EmptyState compact icon={Layers} title="No assets in scope" description="Run a discovery scan to populate the inventory." />
            ) : (
              <ul className="divide-y">
                {exposed.map((a) => {
                  const Icon = assetTypeMeta[a.type].icon;
                  return (
                    <li key={a.id}>
                      <Link to={`/assets/${a.id}`} className="flex items-center gap-3 px-4 py-2 transition-colors hover:bg-accent/40">
                        <span className="flex size-7 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                          <Icon className="size-3.5" />
                        </span>
                        <div className="min-w-0 flex-1">
                          <div className="flex items-center gap-2 text-sm">
                            <span className="truncate font-medium">{a.hostname ?? a.ip}</span>
                            {a.hostname && <span className="font-mono text-xs text-muted-foreground">{a.ip}</span>}
                          </div>
                          <div className="truncate text-xs text-muted-foreground">
                            {assetTypeMeta[a.type].label} · {a.os ?? "OS unknown"}
                          </div>
                        </div>
                        <div className="hidden items-center gap-1 sm:flex">
                          {(a.findings?.critical ?? 0) > 0 && <Badge variant="critical" className="tabular px-1.5">{a.findings?.critical}C</Badge>}
                          {(a.findings?.high ?? 0) > 0 && <Badge variant="high" className="tabular px-1.5">{a.findings?.high}H</Badge>}
                        </div>
                        <RiskMeter value={a.risk} />
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Row 4: findings + detections */}
      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Top critical findings</CardTitle>
            <CardDescription>Highest severity, still open</CardDescription>
            <CardAction>
              <Button variant="ghost" size="xs" asChild>
                <Link to="/findings">
                  View all <ArrowRight />
                </Link>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="px-0">
            {topFindings.length === 0 ? (
              <EmptyState compact icon={ShieldAlert} title="No findings in scope" description="Nothing matched the selected scope. Run an inventory or vulnerability scan to populate findings." />
            ) : (
              <ul className="divide-y">
                {topFindings.map((f) => {
                  return (
                    <li key={f.id}>
                      <Link to={`/findings?id=${f.id}`} className="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-accent/40">
                        <SeverityBadge severity={f.severity} compact />
                        <div className="min-w-0 flex-1">
                          <div className="truncate text-sm">{f.title}</div>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <span className="font-mono">{assetLabelOf(f.assetId)}</span>
                            {f.cve && <span className="font-mono">{f.cve}</span>}
                            <span>· {f.category}</span>
                          </div>
                        </div>
                        <StateBadge label={f.status} tone={f.status === "open" ? "danger" : f.status === "in_progress" ? "primary" : "muted"} className="hidden sm:inline-flex" />
                      </Link>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Recent detections</CardTitle>
            <CardDescription>From network sensors and endpoint agents</CardDescription>
            <CardAction>
              <Button variant="ghost" size="xs" asChild>
                <Link to="/detections">
                  View all <ArrowRight />
                </Link>
              </Button>
            </CardAction>
          </CardHeader>
          <CardContent className="px-0">
            {recentDetections.length === 0 ? (
              <EmptyState
                compact
                icon={Bell}
                title="No detections yet"
                description="Attach a network sensor or connect an endpoint collector to start receiving detections."
                action={
                  <Button size="sm" variant="outline" asChild>
                    <Link to="/connections?create=agent">
                      <Cpu /> Connect endpoint
                    </Link>
                  </Button>
                }
              />
            ) : (
              <ul className="divide-y">
                {recentDetections.map((d) => (
                  <li key={d.id}>
                    <Link to={`/detections?id=${d.id}`} className="flex items-center gap-3 px-4 py-2.5 transition-colors hover:bg-accent/40">
                      <SeverityBadge severity={d.severity} compact />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-sm">{d.title}</div>
                        <div className="text-xs text-muted-foreground">
                          {d.ruleType ?? "correlation"} · <span className="font-mono">{d.srcIp ?? d.entity ?? ""}</span> · {assetLabelOf(d.assetId ?? "")}
                        </div>
                      </div>
                      <span className="tabular text-xs text-muted-foreground">{timeAgo(d.timestamp)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>

    </div>
  );
}
