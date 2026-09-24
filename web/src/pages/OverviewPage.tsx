import * as React from "react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip as RTooltip,
  XAxis,
  YAxis,
} from "recharts";
import { ArrowRight, Bell, Bug, Cpu, DoorOpen, Flame, Layers, ShieldAlert, Siren, Radar } from "lucide-react";

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

/* Recharts tooltip in our visual language */
export function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: { name: string; value: number; color?: string }[]; label?: string }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-md border bg-popover px-3 py-2 text-xs shadow-lg">
      <div className="mb-1 font-medium text-foreground">{label}</div>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center justify-between gap-4">
          <span className="flex items-center gap-1.5 capitalize text-muted-foreground">
            <span className="size-2 rounded-sm" style={{ background: p.color }} /> {p.name}
          </span>
          <span className="tabular font-medium text-foreground">{p.value}</span>
        </div>
      ))}
    </div>
  );
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

  const donut = (["critical", "high", "medium", "low"] as const).map((k) => ({ name: k, value: totals[k], color: severityMeta[k].hex }));
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
          <p className="mt-1 text-sm text-muted-foreground">
            Security posture for <span className="text-foreground">{site === "all" ? "all sites" : sites.data?.items.find((s) => s.id === site)?.name ?? "site"}</span> · updated{" "}
            {timeAgo(Date.now() - 45_000)}
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
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4 xl:grid-cols-7">
        <KpiTile label="Assets" value={metrics.data?.assets ?? "—"} hint="listening services" icon={Layers} onClick={() => navigate("/assets")} tone="primary" />
        <KpiTile label="Open ports" value={metrics.data?.open_ports ?? "—"} hint="listening services" icon={DoorOpen} onClick={() => navigate("/assets")} />
        <KpiTile label="Vulnerabilities" value={metrics.data?.vulnerabilities ?? "—"} hint="open findings" icon={Bug} onClick={() => navigate("/vulnerabilities")} />
        <KpiTile label="Critical" value={metrics.data?.critical ?? "—"} tone={totals.critical ? "critical" : "default"} hint="open findings" icon={Flame} onClick={() => navigate("/findings?severity=critical")} />
        <KpiTile label="KEV" value={metrics.data?.kev ?? "—"} tone={metrics.data?.kev ? "critical" : "default"} hint="known exploited" icon={Siren} onClick={() => navigate("/vulnerabilities?kev=1")} />
        <KpiTile label="High-risk assets" value={metrics.data?.high_risk_assets ?? "—"} tone={metrics.data?.high_risk_assets ? "high" : "default"} hint="risk ≥ 70" icon={ShieldAlert} onClick={() => navigate("/assets?sort=risk")} />
        <KpiTile label="Active alerts" value={metrics.data?.active_alerts ?? "—"} tone={metrics.data?.active_alerts ? "high" : "default"} hint="detection matches" icon={Bell} onClick={() => navigate("/detections")} />
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
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={riskTrend} margin={{ top: 4, right: 4, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="0%" stopColor="oklch(0.66 0.17 275)" stopOpacity={0.35} />
                      <stop offset="100%" stopColor="oklch(0.66 0.17 275)" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" />
                  <XAxis dataKey="date" tickLine={false} axisLine={false} interval={4} dy={6} />
                  <YAxis tickLine={false} axisLine={false} width={40} />
                  <RTooltip content={<ChartTooltip />} />
                  <Area type="monotone" dataKey="risk" stroke="oklch(0.66 0.17 275)" strokeWidth={2} fill="url(#riskFill)" />
                </AreaChart>
              </ResponsiveContainer>
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
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={donut} dataKey="value" innerRadius={52} outerRadius={72} paddingAngle={2} stroke="none" startAngle={90} endAngle={-270}>
                    {donut.map((d) => (
                      <Cell key={d.name} fill={d.color} />
                    ))}
                  </Pie>
                  <RTooltip content={<ChartTooltip />} />
                </PieChart>
              </ResponsiveContainer>
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
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={eventVolume} margin={{ top: 4, right: 4, left: -20, bottom: 0 }} barSize={22}>
                  <CartesianGrid vertical={false} strokeDasharray="3 3" />
                  <XAxis dataKey="day" tickLine={false} axisLine={false} dy={6} />
                  <YAxis tickLine={false} axisLine={false} width={40} />
                  <RTooltip content={<ChartTooltip />} />
                  <Bar dataKey="agent" stackId="a" fill="oklch(0.35 0.03 262)" radius={[0, 0, 2, 2]} />
                  <Bar dataKey="scans" stackId="a" fill="oklch(0.66 0.17 275)" />
                  <Bar dataKey="auth" stackId="a" fill="oklch(0.74 0.12 230)" />
                  <Bar dataKey="detections" stackId="a" fill="oklch(0.64 0.22 22)" radius={[2, 2, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
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
