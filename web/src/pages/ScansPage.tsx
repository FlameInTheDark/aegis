import * as React from "react";
import { Check, Clock, ListFilter, Loader2, MoreHorizontal, Radar, RotateCcw, Search, Square, X, XCircle, Package } from "lucide-react";

import { cn, timeAgo, formatDateTime } from "@/lib/utils";
import { useRouter } from "@/lib/router";
import type { Scan, ScanEngine, ScanState } from "@/data/types";
import { useScope } from "@/components/layout/AppShell";
import { useCancelScan, useCreateScan, useScans, useScan, useSites, type CreateScanInput } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { toast } from "@/components/ui/toaster";
import { NewScanDialog, engineMeta } from "@/components/scans/NewScanDialog";
import { JobLogPanel } from "@/components/scans/JobLogPanel";
import { useScanStateStream } from "@/lib/scanstream";
import { EmptyState, KeyValue, Mono, PageHeader, StateBadge, TableFooterBar, usePagination } from "@/components/shared";

const stateTone = (s: ScanState) => (s === "running" ? "primary" : s === "completed" ? "success" : s === "failed" ? "danger" : s === "queued" ? "warning" : "muted");

function EngineBadge({ engine }: { engine: string }) {
  const isSsh = engine === "ssh" || engine === "ssh_inventory";
  const m = engineMeta[isSsh ? "ssh" : "nmap"];
  const label = isSsh ? "ssh" : "nmap";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex w-fit items-center gap-1.5 rounded-md border bg-muted/40 px-1.5 py-0.5 text-[11px] font-medium">
          <m.icon className={cn("size-3", m.accent)} />
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent>{m.blurb}</TooltipContent>
    </Tooltip>
  );
}

export function ScansPage() {
  const { query, navigate } = useRouter();
  const { site } = useScope();
  const sites = useSites();
  const createScanM = useCreateScan();
  const cancelScanM = useCancelScan();
  const scansQ = useScans({ site, limit: 200 });
  const [q, setQ] = React.useState("");
  const [state, setState] = React.useState("all");
  const [engine, setEngine] = React.useState("all");
  const [openNew, setOpenNew] = React.useState(query.get("new") === "1");
  const [detailId, setDetailId] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (query.get("new") === "1") setOpenNew(true);
  }, [query]);

  const scans = scansQ.data?.items ?? [];

  const filtered = React.useMemo(() => {
    const needle = q.toLowerCase();
    return scans.filter((s) => {
      if (state !== "all" && s.state !== state) return false;
      const sEngine = s.profile === "ssh_inventory" ? "ssh" : "nmap";
      if (engine !== "all" && sEngine !== engine) return false;
      if (!needle) return true;
      return [s.name, s.targets, s.profile].some((v) => v.toLowerCase().includes(needle));
    });
  }, [scans, q, state, engine]);

  const { page, setPage, slice, pageSize, setPageSize, total } = usePagination(filtered, "scans");

  const counts = {
    running: scans.filter((s) => s.state === "running").length,
    queued: scans.filter((s) => s.state === "queued").length,
    completed: scans.filter((s) => s.state === "completed" && Date.now() - +new Date(s.createdAt) < 86_400_000).length,
    failed: scans.filter((s) => s.state === "failed").length,
  };

  const closeNew = () => {
    setOpenNew(false);
    if (query.get("new")) navigate("/scans", { replace: true });
  };

  const createScan = (input: CreateScanInput, opts: { scheduleCron?: string }) => {
    createScanM.mutate(input, {
      onSuccess: (res) => {
        closeNew();
        toast({
          title: res.scan.state === "queued" ? "Scan queued" : "Scan started",
          description: [res.scan.name, ...(res.warnings ?? [])].filter(Boolean).join(" · ") || "Dispatched to the scanner queue.",
          variant: res.scan.state === "queued" ? "warning" : "success",
        });
        if (res.scan) setDetailId(res.scan.id);
        void opts;
      },
      onError: (e) => toast({ title: "Scan rejected", description: (e as Error).message, variant: "error" }),
    });
  };

  const cancel = (id: string) => {
    cancelScanM.mutate(id, {
      onSuccess: () => toast({ title: `Scan cancelled`, description: "Partial results were kept.", variant: "warning" }),
      onError: (e) => toast({ title: "Cancel failed", description: (e as Error).message, variant: "error" }),
    });
  };

  const detailScan = scans.find((s) => s.id === detailId) ?? null;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Scans"
        description="Jobs dispatched to scanners. Network scans probe from the outside, authenticated scans log in, and agent tasks read from the endpoint itself."
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => navigate("/settings?tab=presets")}>
              <ListFilter /> Presets
            </Button>
            <Button size="sm" onClick={() => setOpenNew(true)}>
              <Radar /> New scan
            </Button>
          </>
        }
      />

      {/* Status strip */}
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        {[
          { label: "Running", key: "running", value: counts.running, tone: "primary" as const, icon: Loader2, spin: counts.running > 0 },
          { label: "Queued", key: "queued", value: counts.queued, tone: "warning" as const, icon: Clock },
          { label: "Completed (24h)", key: "completed", value: counts.completed, tone: "success" as const, icon: Check },
          { label: "Failed", key: "failed", value: counts.failed, tone: "danger" as const, icon: XCircle },
        ].map((c) => (
          <button
            key={c.label}
            onClick={() => setState(state === c.key ? "all" : c.key)}
            className={cn("flex items-center gap-3 rounded-xl border bg-card px-4 py-3 text-left transition-colors hover:bg-accent/30 cursor-pointer", state === c.key && "border-primary")}
          >
            <span
              className={cn(
                "flex size-8 items-center justify-center rounded-lg",
                c.tone === "primary" && "bg-primary/12 text-primary",
                c.tone === "warning" && "bg-medium/12 text-medium",
                c.tone === "success" && "bg-success/12 text-success",
                c.tone === "danger" && "bg-critical/12 text-critical"
              )}
            >
              <c.icon className={cn("size-4", c.spin && "animate-spin")} />
            </span>
            <div className="leading-tight">
              <div className="tabular text-lg font-semibold">{c.value}</div>
              <div className="text-[11px] uppercase tracking-wider text-muted-foreground">{c.label}</div>
            </div>
          </button>
        ))}
      </div>

      {/* Engine quick filter */}
      <div className="flex flex-wrap items-center gap-1.5">
        <button
          onClick={() => setEngine("all")}
          className={cn("rounded-md border px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer", engine === "all" ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent/50")}
        >
          All engines
        </button>
        {(Object.keys(engineMeta) as ScanEngine[]).map((e) => {
          const m = engineMeta[e];
          const active = engine === e;
          const n = scans.filter((s) => (s.profile === "ssh_inventory" ? "ssh" : "nmap") === e).length;
          return (
            <button
              key={e}
              onClick={() => setEngine(active ? "all" : e)}
              className={cn("inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer", active ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent/50")}
            >
              <m.icon className={cn("size-3", active ? "" : m.accent)} />
              {m.label}
              <span className="tabular opacity-70">{n}</span>
            </button>
          );
        })}
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search name, target, profile…" className="h-8 pl-8 text-[13px]" />
        </div>
        <Select value={state} onValueChange={setState}>
          <SelectTrigger size="sm" className="w-[150px]">
            <span className="text-muted-foreground">State:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All states</SelectItem>
            <SelectItem value="running">Running</SelectItem>
            <SelectItem value="queued">Queued</SelectItem>
            <SelectItem value="completed">Completed</SelectItem>
            <SelectItem value="failed">Failed</SelectItem>
            <SelectItem value="cancelled">Cancelled</SelectItem>
          </SelectContent>
        </Select>
        {(q || state !== "all" || engine !== "all") && (
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground"
            onClick={() => {
              setQ("");
              setState("all");
              setEngine("all");
            }}
          >
            <X /> Clear
          </Button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Scan</TableHead>
              <TableHead>Engine</TableHead>
              <TableHead>Profile</TableHead>
              <TableHead>State</TableHead>
              <TableHead className="w-40">Progress</TableHead>
              <TableHead className="text-right">Reachable</TableHead>
              <TableHead className="text-right">Ports</TableHead>
              <TableHead className="text-right">Services</TableHead>
              <TableHead className="text-right">Findings</TableHead>
              <TableHead>Created</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {slice.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={11}>
                  <EmptyState icon={Radar} title="No scans match" description="Start a discovery scan against an authorized site." action={<Button size="sm" onClick={() => setOpenNew(true)}>New scan</Button>} />
                </TableCell>
              </TableRow>
            ) : (
              slice.map((s) => (
                <TableRow key={s.id} className="cursor-pointer" onClick={() => setDetailId(s.id)}>
                  <TableCell className="pl-4">
                    <div className="leading-tight">
                      <div className="font-medium">{s.name}</div>
                      <div className="font-mono text-[11px] text-muted-foreground">
                        {s.targets} · {s.id.slice(0, 8)}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <EngineBadge engine={s.profile === "ssh_inventory" ? "ssh" : "nmap"} />
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="font-mono text-[11px]">
                      {s.profile}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <StateBadge label={s.state} tone={stateTone(s.state)} pulse={s.state === "running"} />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <Progress
                        value={s.progress}
                        className="h-1.5"
                        indicatorClassName={cn(s.state === "completed" && "bg-success", s.state === "failed" && "bg-critical", s.state === "cancelled" && "bg-muted-foreground")}
                      />
                      <span className="tabular w-9 text-right text-xs text-muted-foreground">{s.progress}%</span>
                    </div>
                  </TableCell>
                  <TableCell className="tabular text-right">
                    {s.reachable.up}
                    <span className="text-muted-foreground">/{s.reachable.total}</span>
                  </TableCell>
                  <TableCell className="tabular text-right">{s.ports}</TableCell>
                  <TableCell className="tabular text-right">{s.services}</TableCell>
                  <TableCell className={cn("tabular text-right font-medium", s.findings > 0 ? "text-high" : "text-muted-foreground")}>{s.findings}</TableCell>
                  <TableCell className="tabular text-xs text-muted-foreground">{timeAgo(s.createdAt)}</TableCell>
                  <TableCell onClick={(e) => e.stopPropagation()}>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon-xs" className="text-muted-foreground">
                          <MoreHorizontal />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => setDetailId(s.id)}>View details</DropdownMenuItem>
                        <DropdownMenuSeparator />
                        {(s.state === "running" || s.state === "queued") && (
                          <DropdownMenuItem variant="destructive" onClick={() => cancel(s.id)}>
                            <Square /> Cancel
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TableFooterBar total={total} page={page} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} label="scans" />
      </div>

      <NewScanDialog
        open={openNew}
        onOpenChange={(o) => (o ? setOpenNew(true) : closeNew())}
        onCreate={createScan}
        defaultTarget={query.get("target") ?? ""}
        defaultPreset={query.get("preset") ?? "inventory"}
      />
      <ScanDetailSheet scanId={detailId} fallback={detailScan} onClose={() => setDetailId(null)} onCancel={cancel} siteName={(id: string) => sites.data?.items.find((s) => s.id === id)?.name ?? "site"} />
    </div>
  );
}

/* ------------------------------------------------------------------ */
function ScanDetailSheet({
  scanId,
  fallback,
  onClose,
  onCancel,
  siteName,
}: {
  scanId: string | null;
  fallback: Scan | null;
  onClose: () => void;
  onCancel: (id: string) => void;
  siteName: (id: string) => string;
}) {
  const detailQ = useScan(scanId ?? undefined);
  const scan = detailQ.data?.scan ?? fallback;
  const tasks = detailQ.data?.tasks ?? [];
  const changes = detailQ.data?.changes ?? [];
  // Live progress/state for the open sheet (folded into the query cache);
  // the Job log panel streams its own channel.
  useScanStateStream(scanId ?? undefined);
  return (
    <Sheet open={!!scanId} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-2xl">
        {scan && (
          <>
            <SheetHeader>
              <div className="flex flex-wrap items-center gap-2">
                <StateBadge label={scan.state} tone={stateTone(scan.state)} pulse={scan.state === "running"} />
                <EngineBadge engine={scan.profile === "ssh_inventory" ? "ssh" : "nmap"} />
                <Badge variant="outline" className="font-mono text-[11px]">
                  {scan.profile}
                </Badge>
                <span className="font-mono text-xs text-muted-foreground">{scan.id.slice(0, 8)}</span>
              </div>
              <SheetTitle>{scan.name}</SheetTitle>
              <SheetDescription>
                <Mono>{scan.targets}</Mono> · {siteName(scan.site)}
                {scan.error ? ` · ${scan.error}` : ""}
              </SheetDescription>
            </SheetHeader>
            <div className="flex flex-col gap-4 overflow-y-auto px-5 pb-5">
              <div>
                <div className="mb-1 flex items-center justify-between text-xs text-muted-foreground">
                  <span>Progress {scan.phase ? `· ${scan.phase}` : ""}</span>
                  <span className="tabular">{scan.progress}%</span>
                </div>
                <Progress value={scan.progress} className="h-2" indicatorClassName={cn(scan.state === "completed" && "bg-success", scan.state === "failed" && "bg-critical")} />
              </div>

              <div className="grid grid-cols-4 gap-2">
                {[
                  { l: "Reachable", v: `${scan.reachable.up}/${scan.reachable.total}` },
                  { l: "Ports", v: scan.ports },
                  { l: "Services", v: scan.services },
                  { l: "Findings", v: scan.findings },
                ].map((m) => (
                  <div key={m.l} className="rounded-lg border bg-muted/30 px-3 py-2">
                    <div className="tabular text-lg font-semibold">{m.v}</div>
                    <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{m.l}</div>
                  </div>
                ))}
              </div>

              {scan.packages > 0 && (
                <div className="flex items-center gap-2 rounded-lg border bg-muted/30 px-3 py-2 text-sm">
                  <Package className="size-4 text-muted-foreground" />
                  <span className="tabular font-medium">{scan.packages}</span> packages collected
                </div>
              )}

              <div className="divide-y rounded-lg border px-3">
                <KeyValue label="Engine">{scan.profile === "ssh_inventory" ? "SSH inventory" : "Network (nmap)"}</KeyValue>
                <KeyValue label="Profile">
                  <Mono className="text-[11px]">{scan.profile}</Mono>
                </KeyValue>
                <KeyValue label="Tasks">
                  <span className="tabular">
                    {scan.tasks.done}/{scan.tasks.total} done{scan.tasks.failed > 0 ? ` · ${scan.tasks.failed} failed` : ""}
                  </span>
                </KeyValue>
                <KeyValue label="Created">{formatDateTime(scan.createdAt)}</KeyValue>
                <KeyValue label="Started">{scan.startedAt ? formatDateTime(scan.startedAt) : "—"}</KeyValue>
                <KeyValue label="Finished">{scan.finishedAt ? formatDateTime(scan.finishedAt) : "—"}</KeyValue>
              </div>

              <JobLogPanel
                scanId={scan.id}
                running={scan.state === "running" || scan.state === "queued"}
              />

              {scan.sshHosts && scan.sshHosts.length > 0 && (
                <div>
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">SSH hosts</div>
                  <div className="overflow-hidden rounded-lg border">
                    <Table>
                      <TableHeader>
                        <TableRow className="hover:bg-transparent">
                          <TableHead className="pl-3">Host</TableHead>
                          <TableHead>OS</TableHead>
                          <TableHead className="text-right">Packages</TableHead>
                          <TableHead className="text-right">Took</TableHead>
                          <TableHead>Status</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {scan.sshHosts.map((h) => (
                          <TableRow key={h.host}>
                            <TableCell className="pl-3">
                              <Mono className="text-[11px]">{h.user ? `${h.user}@` : ""}{h.host}{h.port ? `:${h.port}` : ""}</Mono>
                            </TableCell>
                            <TableCell className="text-xs text-muted-foreground">{h.os ?? "—"}</TableCell>
                            <TableCell className="tabular text-right text-xs">{h.packageCount}</TableCell>
                            <TableCell className="tabular text-right text-xs">{(h.durationMs / 1000).toFixed(1)}s</TableCell>
                            <TableCell>
                              <StateBadge label={h.error ? "error" : h.osOk ? "ok" : "partial"} tone={h.error ? "danger" : h.osOk ? "success" : "warning"} />
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </div>
              )}

              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Tasks</div>
                <div className="max-h-48 overflow-auto rounded-lg border">
                  {tasks.length === 0 ? (
                    <div className="px-3 py-4 text-center text-xs text-muted-foreground">No task records</div>
                  ) : (
                    <Table>
                      <TableBody>
                        {tasks.map((t) => (
                          <TableRow key={t.id}>
                            <TableCell className="py-1.5">
                              <div className="flex items-center gap-2">
                                <StateBadge label={t.state} tone={t.state === "done" ? "success" : t.state === "failed" ? "danger" : t.state === "running" ? "primary" : "muted"} />
                                <Mono className="text-[11px]">{t.type}</Mono>
                                <span className="truncate text-xs text-muted-foreground">{t.target}</span>
                                {t.attempt > 1 && <Badge variant="muted" className="px-1 text-[10px]">retry {t.attempt - 1}</Badge>}
                              </div>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  )}
                </div>
              </div>

              {changes.length > 0 && (
                <div>
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Changes recorded</div>
                  <div className="max-h-40 overflow-auto rounded-lg border bg-[oklch(0.11_0.01_262)] p-3 font-mono text-[11px] leading-relaxed">
                    {changes.map((c) => (
                      <div key={c.id} className="break-all text-foreground/85">
                        <span className="text-muted-foreground/60">{formatDateTime(c.createdAt)}</span>{" "}
                        <span className="uppercase text-muted-foreground">{c.type}</span> {c.entity ?? c.assetId?.slice(0, 8)} {c.before !== undefined ? `${c.before} → ` : ""}
                        {c.after}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="flex gap-2">
                {(scan.state === "running" || scan.state === "queued") && (
                  <Button size="sm" variant="destructive" onClick={() => onCancel(scan.id)}>
                    <Square /> Cancel job
                  </Button>
                )}
              </div>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
