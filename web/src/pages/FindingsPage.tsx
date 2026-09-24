import * as React from "react";
import { Check, Search, ShieldAlert, Ticket, X } from "lucide-react";

import { cn, timeAgo, formatDateTime } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type { Finding, FindingStatus, Severity } from "@/data/types";
import { useScope } from "@/components/layout/AppShell";
import { useAsset, useFindings, useFinding, useSuppressFinding, useUpdateFinding } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { EmptyState, KeyValue, Mono, PageHeader, SeverityBadge, severityMeta, StateBadge, TableFooterBar } from "@/components/shared";
import { usePageSize } from "@/lib/pagination";
import { toast } from "@/components/ui/toaster";

const statusTone = (s: FindingStatus) => (s === "open" ? "danger" : s === "in_progress" ? "primary" : s === "acknowledged" ? "warning" : s === "resolved" ? "success" : "muted");
const statuses: FindingStatus[] = ["open", "acknowledged", "in_progress", "resolved", "accepted_risk", "false_positive"];

export function FindingsPage() {
  const { query, navigate } = useRouter();
  const { site } = useScope();
  const [q, setQ] = React.useState(query.get("q") ?? "");
  const [sev, setSev] = React.useState(query.get("severity") ?? "all");
  const [status, setStatus] = React.useState("active");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSizeRaw] = usePageSize("findings");
  const [detailId, setDetailId] = React.useState<string | null>(query.get("id"));

  React.useEffect(() => {
    if (query.get("id")) setDetailId(query.get("id"));
    if (query.get("severity")) setSev(query.get("severity")!);
  }, [query]);

  React.useEffect(() => {
    setPage(1);
  }, [q, sev, status, site]);

  // a new page size always restarts at page 1 — the old page number has no
  // meaning under a different window
  const setPageSize = React.useCallback(
    (n: number) => {
      setPageSizeRaw(n);
      setPage(1);
    },
    [setPageSizeRaw],
  );

  const findingsQ = useFindings({
    site,
    status: status === "active" ? undefined : status === "all" ? undefined : status,
    severity: sev,
    search: q || undefined,
    page,
    limit: pageSize,
  });
  // "active" tab = everything unresolved; the backend has no negation filter,
  // so fetch the page unfiltered and keep the resolved out client-side.
  const items = (findingsQ.data?.items ?? []).filter((f) =>
    status === "active" ? !["resolved", "accepted_risk", "false_positive", "suppressed"].includes(f.status) : true,
  );
  const total = findingsQ.data?.total ?? 0;
  const activeQ = useFindings({ site, limit: 1 });
  const activeTotal = React.useMemo(() => {
    if (status !== "active") return total;
    return (activeQ.data?.items ?? []).length ? activeQ.data?.total ?? 0 : 0;
  }, [status, total, activeQ.data]);

  const bySevQ = useFindings({ site, limit: 200 });
  const activeItems = (bySevQ.data?.items ?? []).filter((f) => !["resolved", "accepted_risk", "false_positive", "suppressed"].includes(f.status));
  const bySev = (s: Severity) => activeItems.filter((f) => f.severity === s).length;

  const closeDetail = () => {
    setDetailId(null);
    if (query.get("id")) navigate("/findings", { replace: true });
  };

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Findings" description="Actionable issues correlated per asset from scans, agents and the CVE index. Each finding carries its evidence and a confidence score." />

      {/* Severity chips */}
      <div className="flex flex-wrap items-center gap-2">
        {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
          <button
            key={s}
            onClick={() => setSev(sev === s ? "all" : s)}
            className={cn(
              "flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm transition-colors cursor-pointer",
              sev === s ? "border-primary bg-primary/8" : "bg-card hover:bg-accent/40"
            )}
          >
            <span className={cn("size-2 rounded-full", severityMeta[s].dot)} />
            <span className="capitalize text-muted-foreground">{s}</span>
            <span className={cn("tabular font-semibold", bySev(s) > 0 ? severityMeta[s].text : "text-muted-foreground")}>{bySev(s)}</span>
          </button>
        ))}
        <span className="ml-2 text-xs text-muted-foreground">{activeTotal} active in scope</span>
      </div>

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search title, CVE, asset…" className="h-8 pl-8 text-[13px]" />
        </div>
        <Select value={status} onValueChange={setStatus}>
          <SelectTrigger size="sm" className="w-[160px]">
            <span className="text-muted-foreground">Status:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="all">All</SelectItem>
            {statuses.map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s.replace("_", " ")}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {(q || sev !== "all" || status !== "active") && (
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground"
            onClick={() => {
              setQ("");
              setSev("all");
              setStatus("active");
            }}
          >
            <X /> Clear
          </Button>
        )}
      </div>

      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Severity</TableHead>
              <TableHead>Finding</TableHead>
              <TableHead>Asset</TableHead>
              <TableHead>Category</TableHead>
              <TableHead>CVE</TableHead>
              <TableHead>Confidence</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Assignee</TableHead>
              <TableHead>Last seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={9}>
                  <EmptyState icon={ShieldAlert} title="No findings match" description="Adjust the filters, or run a vulnerability scan to correlate new findings." />
                </TableCell>
              </TableRow>
            ) : (
              items.map((f) => (
                <TableRow key={f.id} className="cursor-pointer" onClick={() => setDetailId(f.id)}>
                  <TableCell className="pl-4">
                    <SeverityBadge severity={f.severity} />
                  </TableCell>
                  <TableCell className="max-w-sm">
                    <div className="truncate font-medium">{f.title}</div>
                    <div className="text-xs text-muted-foreground">
                      {f.id.slice(0, 8)} · via {f.category}
                    </div>
                  </TableCell>
                  <TableCell>
                    <AssetLinkCell assetId={f.assetId} />
                  </TableCell>
                  <TableCell className="text-muted-foreground">{f.category}</TableCell>
                  <TableCell>
                    {f.cve ? (
                      <span className="inline-flex items-center gap-1">
                        <Mono>{f.cve}</Mono>
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex w-24 items-center gap-2">
                      <Progress value={f.confidence} className="h-1" />
                      <span className="tabular text-xs text-muted-foreground">{f.confidence}%</span>
                    </div>
                  </TableCell>
                  <TableCell>
                    <StateBadge label={f.status} tone={statusTone(f.status)} />
                  </TableCell>
                  <TableCell className="text-xs">
                    {f.assignee ? (
                      <span className="inline-flex items-center gap-1.5">
                        <span className="flex size-5 items-center justify-center rounded-full bg-primary/15 text-[9px] font-semibold text-primary">
                          {f.assignee
                            .split(" ")
                            .map((p) => p[0])
                            .join("")
                            .slice(0, 2)}
                        </span>
                        {f.assignee}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">unassigned</span>
                    )}
                  </TableCell>
                  <TableCell className="tabular text-xs text-muted-foreground">{timeAgo(f.lastSeen)}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TableFooterBar total={total} page={page} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} label="findings" />
      </div>

      {/* Detail sheet */}
      {detailId && <FindingDetailSheet findingId={detailId} onClose={closeDetail} />}
    </div>
  );
}

function AssetLinkCell({ assetId }: { assetId: string }) {
  const q = useAsset(assetId);
  const a = q.data?.asset;
  if (!a) return <span className="text-xs text-muted-foreground">{assetId.slice(0, 8)}</span>;
  const Icon = assetTypeMeta[a.type].icon;
  return (
    <span className="inline-flex items-center gap-1.5">
      <Icon className="size-3.5 text-muted-foreground" />
      <span>{a.hostname ?? a.ip}</span>
    </span>
  );
}

function FindingDetailSheet({ findingId, onClose }: { findingId: string; onClose: () => void }) {
  const detailQ = useFinding(findingId);
  const detail = detailQ.data?.finding;
  const evidence = detailQ.data?.evidence ?? [];
  const history = detailQ.data?.history ?? [];
  const assetQ = useAsset(detail?.assetId);
  const asset = assetQ.data?.asset;
  const update = useUpdateFinding();
  const suppress = useSuppressFinding();
  const [suppressOpen, setSuppressOpen] = React.useState(false);
  const [reason, setReason] = React.useState("");

  const setStatus = (status: string) => {
    if (!detail) return;
    update.mutate(
      { id: detail.id, status, reason: `status set to ${status}` },
      {
        onSuccess: () => toast({ title: "Finding updated", description: `Status set to ${status.replace("_", " ")}.`, variant: "success" }),
        onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-xl">
        {detail && (
          <>
            <SheetHeader>
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={detail.severity} />
                <StateBadge label={detail.status} tone={statusTone(detail.status)} />
                <span className="font-mono text-xs text-muted-foreground">{detail.id.slice(0, 8)}</span>
              </div>
              <SheetTitle>{detail.title}</SheetTitle>
              <SheetDescription>
                {detail.category} · confidence {detail.confidence}%
              </SheetDescription>
            </SheetHeader>
            <div className="flex flex-col gap-4 overflow-y-auto px-5 pb-5">
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Status</span>
                  <Select value={detail.status} onValueChange={setStatus}>
                    <SelectTrigger size="sm" className="w-full capitalize">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {statuses.map((s) => (
                        <SelectItem key={s} value={s} className="capitalize">
                          {s.replace("_", " ")}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-1.5">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Owner</span>
                  <Input
                    defaultValue={detail.assignee ?? ""}
                    placeholder="unassigned"
                    className="h-8 text-[13px]"
                    onBlur={(e) => {
                      const v = e.target.value.trim();
                      if (v !== (detail.assignee ?? "")) {
                        update.mutate({ id: detail.id, owner: v });
                      }
                    }}
                  />
                </div>
              </div>

              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Affected asset</div>
                {asset && (
                  <Link to={`/assets/${asset.id}`} className="flex items-center gap-3 rounded-lg border p-2.5 hover:bg-accent/40">
                    <span className="flex size-8 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                      {(() => {
                        const Icon = assetTypeMeta[asset.type].icon;
                        return <Icon className="size-4" />;
                      })()}
                    </span>
                    <div className="min-w-0 flex-1 leading-tight">
                      <div className="text-sm font-medium">{asset.hostname ?? asset.ip}</div>
                      <div className="text-xs text-muted-foreground">
                        <Mono>{asset.ip}</Mono> · {asset.os ?? "OS unknown"}
                      </div>
                    </div>
                    <span className="text-xs text-primary">Open →</span>
                  </Link>
                )}
              </div>

              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Evidence</div>
                {evidence.length === 0 ? (
                  <p className="rounded-lg border bg-muted/30 p-3 text-xs text-muted-foreground">No evidence records stored for this finding.</p>
                ) : (
                  <div className="grid gap-2">
                    {evidence.map((e) => (
                      <div key={e.id} className="rounded-lg border p-2.5">
                        <div className="mb-1 flex items-center gap-2 text-[10px] uppercase tracking-wider text-muted-foreground">
                          <Badge variant="muted" className="px-1 font-mono text-[10px]">{e.kind}</Badge>
                          <span>via {e.source}</span>
                          <span className="ml-auto">{timeAgo(e.createdAt)}</span>
                        </div>
                        <div className="text-[13px]">{e.statement}</div>
                        {Object.keys(e.detail ?? {}).length > 0 && (
                          <pre className="mt-1.5 overflow-x-auto rounded border bg-[oklch(0.11_0.01_262)] p-2 font-mono text-[10.5px] leading-relaxed text-foreground/80">{JSON.stringify(e.detail, null, 2)}</pre>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {detail.remediation && (
                <div>
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Remediation</div>
                  <p className="rounded-lg border border-success/25 bg-success/6 p-3 text-sm leading-relaxed">{detail.remediation}</p>
                </div>
              )}

              <div className="divide-y rounded-lg border px-3">
                <KeyValue label="CVE">
                  {detail.cve ? (
                    <Link to={`/vulnerabilities?q=${detail.cve}`} className="font-mono text-xs text-primary hover:underline">
                      {detail.cve}
                    </Link>
                  ) : (
                    "—"
                  )}
                </KeyValue>
                <KeyValue label="First seen">{formatDateTime(detail.firstSeen)}</KeyValue>
                <KeyValue label="Last seen">{formatDateTime(detail.lastSeen)}</KeyValue>
              </div>

              {history.length > 0 && (
                <div>
                  <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Status history</div>
                  <ul className="divide-y rounded-lg border px-3 text-xs">
                    {history.map((h, i) => (
                      <li key={i} className="flex items-center justify-between gap-2 py-1.5">
                        <span className="capitalize">
                          {h.from.replace(/_/g, " ")} → <b>{h.to.replace(/_/g, " ")}</b>
                        </span>
                        <span className="text-muted-foreground">
                          {h.changedBy.slice(0, 8)} · {timeAgo(h.createdAt)}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <div className="flex flex-wrap gap-2">
                <Button size="sm" onClick={() => setStatus("resolved")} disabled={detail.status === "resolved"}>
                  <Check /> Mark resolved
                </Button>
                <Button size="sm" variant="outline" onClick={() => setStatus("in_progress")} disabled={detail.status === "in_progress"}>
                  <Ticket /> Work on it
                </Button>
                <Button size="sm" variant="ghost" onClick={() => setStatus("accepted_risk")} disabled={detail.status === "accepted_risk"}>
                  Accept risk
                </Button>
                <Button size="sm" variant="ghost" className="text-destructive" onClick={() => setSuppressOpen(true)}>
                  Suppress
                </Button>
              </div>

              {suppressOpen && (
                <div className="grid gap-2 rounded-lg border border-destructive/30 p-3">
                  <span className="text-sm font-medium">Suppress this finding</span>
                  <Input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Reason (audited)…" className="h-8 text-[13px]" />
                  <div className="flex justify-end gap-2">
                    <Button size="sm" variant="ghost" onClick={() => setSuppressOpen(false)}>Cancel</Button>
                    <Button
                      size="sm"
                      variant="destructive"
                      disabled={!reason.trim()}
                      onClick={() =>
                        suppress.mutate(
                          { id: detail.id, reason },
                          {
                            onSuccess: () => {
                              toast({ title: "Finding suppressed", variant: "warning" });
                              setSuppressOpen(false);
                              onClose();
                            },
                            onError: (e) => toast({ title: "Suppress failed", description: (e as Error).message, variant: "error" }),
                          },
                        )
                      }
                    >
                      Suppress permanently
                    </Button>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
