import * as React from "react";
import { ArrowDown, ArrowUp, Bug, CalendarRange, ExternalLink, Link as LinkIcon, Search, Siren, X, Layers } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import { useScope } from "@/components/layout/AppShell";
import { useMetricsSummary, useVulnerabilities, useVulnerability } from "@/lib/queries";
import type { Severity, Vulnerability } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { EmptyState, KeyValue, KpiTile, Mono, PageHeader, SeverityBadge, severityMeta, TableFooterBar } from "@/components/shared";
import { usePageSize } from "@/lib/pagination";

function CvssBar({ score }: { score: number }) {
  const tone = score >= 9 ? severityMeta.critical.bg : score >= 7 ? severityMeta.high.bg : score >= 4 ? severityMeta.medium.bg : severityMeta.low.bg;
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-14 overflow-hidden rounded-full bg-muted">
        <div className={cn("h-full rounded-full", tone)} style={{ width: `${score * 10}%` }} />
      </div>
      <span className="tabular text-xs font-semibold">{score.toFixed(1)}</span>
    </div>
  );
}

export function VulnerabilitiesPage() {
  const { query } = useRouter();
  const [q, setQ] = React.useState(query.get("q") ?? "");
  const [sev, setSev] = React.useState("all");
  const [source, setSource] = React.useState("all");
  const [publishedFrom, setPublishedFrom] = React.useState("");
  const [publishedTo, setPublishedTo] = React.useState("");
  const [kevOnly, setKevOnly] = React.useState(query.get("kev") === "1");
  const [sort, setSort] = React.useState("published_at");
  const [sortDir, setSortDir] = React.useState<"asc" | "desc">("desc");
  const [page, setPage] = React.useState(1);
  const [pageSize, setPageSizeRaw] = usePageSize("vulns");
  const [detailId, setDetailId] = React.useState<string | null>(null);

  React.useEffect(() => {
    setPage(1);
  }, [q, sev, source, publishedFrom, publishedTo, kevOnly, sort, sortDir]);

  // a new page size always restarts at page 1 — the old page number has no
  // meaning under a different window
  const setPageSize = React.useCallback(
    (n: number) => {
      setPageSizeRaw(n);
      setPage(1);
    },
    [setPageSizeRaw],
  );

  const listQ = useVulnerabilities({
    search: q || undefined,
    severity: sev,
    source,
    publishedFrom: publishedFrom || undefined,
    publishedTo: publishedTo || undefined,
    kev: kevOnly,
    sort,
    order: sortDir,
    page,
    limit: pageSize,
  });
  const items = listQ.data?.items ?? [];
  const total = listQ.data?.total ?? 0;

  const kevQ = useVulnerabilities({ kev: true, limit: 1 });
  const matchedQ = useVulnerabilities({ limit: 1, sort: "published_at" });
  const metrics = useMetricsSummary("all");

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Vulnerabilities" description="CVE index entries ingested from NVD / CVE List v5 and matched against fingerprinted software. Prioritise by KEV membership and EPSS, not CVSS alone." />

      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <KpiTile label="Index size" value={matchedQ.data?.total ?? "—"} hint="live CVE records in the database" icon={Bug} />
        <KpiTile label="Known exploited" value={kevQ.data?.total ?? "—"} tone="critical" hint="CISA KEV" icon={Siren} onClick={() => setKevOnly(true)} />
        <KpiTile label="Open findings" value={metrics.data?.vulnerabilities ?? "—"} hint="correlated matches" icon={Layers} />
        <KpiTile label="High risk" value={metrics.data?.critical ?? "—"} tone={metrics.data?.critical ? "high" : "default"} hint="critical findings open" icon={Siren} />
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="CVE id, product, keyword…" className="h-8 pl-8 text-[13px]" />
        </div>
        <Select value={sev} onValueChange={setSev}>
          <SelectTrigger size="sm" className="w-[150px]">
            <span className="text-muted-foreground">Severity:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any</SelectItem>
            {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
              <SelectItem key={s} value={s} className="capitalize">
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={source} onValueChange={setSource}>
          <SelectTrigger size="sm" className="w-[150px]">
            <span className="text-muted-foreground">Source:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any feed</SelectItem>
            <SelectItem value="nvd">NVD</SelectItem>
            <SelectItem value="cvelistv5">CVE List v5</SelectItem>
          </SelectContent>
        </Select>
        <div className="flex h-8 items-center rounded-md border bg-transparent shadow-xs">
          <span className="flex items-center gap-1.5 border-r px-2 text-[11px] text-muted-foreground">
            <CalendarRange className="size-3.5" /> Published
          </span>
          <Input
            type="date"
            value={publishedFrom}
            onChange={(e) => setPublishedFrom(e.target.value)}
            aria-label="Published from"
            title="Published from"
            className="h-7 w-[124px] rounded-none border-0 px-2 text-[11px] shadow-none focus-visible:ring-0"
          />
          <span className="text-[10px] text-muted-foreground">to</span>
          <Input
            type="date"
            value={publishedTo}
            min={publishedFrom || undefined}
            onChange={(e) => setPublishedTo(e.target.value)}
            aria-label="Published to"
            title="Published to"
            className="h-7 w-[124px] rounded-none border-0 px-2 text-[11px] shadow-none focus-visible:ring-0"
          />
        </div>
        <Select value={sort} onValueChange={setSort}>
          <SelectTrigger size="sm" className="w-[165px]">
            <span className="text-muted-foreground">Sort:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {/* Values are the backend's whitelist sort keys (vulnOrderClause).
                The UI used to send "published"/"name"/"cvss"/"kev" — unknown
                to the whitelist, every option silently kept the default
                relevance order and sorting appeared dead. The backend also
                accepts those aliases now, but send the contract keys. */}
            <SelectItem value="published_at">Date published</SelectItem>
            <SelectItem value="cve_id">Name</SelectItem>
            <SelectItem value="cvss_score">CVSS score</SelectItem>
            <SelectItem value="known_exploited">KEV first</SelectItem>
          </SelectContent>
        </Select>
        <Button
          variant="outline"
          size="icon-sm"
          onClick={() => setSortDir((d) => (d === "asc" ? "desc" : "asc"))}
          title={sortDir === "asc" ? "Ascending" : "Descending"}
          aria-label={`Sort ${sortDir === "asc" ? "ascending" : "descending"}`}
        >
          {sortDir === "asc" ? <ArrowUp /> : <ArrowDown />}
        </Button>
        <label className="flex h-8 items-center gap-2 rounded-md border px-3 text-xs">
          <Switch checked={kevOnly} onCheckedChange={setKevOnly} /> KEV only
        </label>
        {(q || sev !== "all" || source !== "all" || publishedFrom || publishedTo || kevOnly) && (
          <Button
            variant="ghost"
            size="sm"
            className="text-muted-foreground"
            onClick={() => {
              setQ("");
              setSev("all");
              setSource("all");
              setPublishedFrom("");
              setPublishedTo("");
              setKevOnly(false);
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
              <TableHead className="pl-4">CVE</TableHead>
              <TableHead>Description</TableHead>
              <TableHead>Severity</TableHead>
              <TableHead>CVSS</TableHead>
              <TableHead>EPSS</TableHead>
              <TableHead>Affected</TableHead>
              <TableHead>Findings</TableHead>
              <TableHead>Published</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={8}>
                  <EmptyState icon={Bug} title="No vulnerabilities match" description="Nothing in the CVE index matched the current filters and scope." />
                </TableCell>
              </TableRow>
            ) : (
              items.map((v) => (
                <TableRow key={v.id} className="cursor-pointer" onClick={() => setDetailId(v.id)}>
                  <TableCell className="pl-4">
                    <div className="flex items-center gap-1.5">
                      <Mono className="font-medium">{v.id}</Mono>
                      {v.source === "cvelistv5" && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Badge variant="muted" className="px-1 text-[10px] uppercase">
                              v5
                            </Badge>
                          </TooltipTrigger>
                          <TooltipContent>Ingested from CVE List v5</TooltipContent>
                        </Tooltip>
                      )}
                      {v.kev && (
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Badge variant="critical" className="px-1 text-[10px]">
                              KEV
                            </Badge>
                          </TooltipTrigger>
                          <TooltipContent>Listed in CISA Known Exploited Vulnerabilities</TooltipContent>
                        </Tooltip>
                      )}
                    </div>
                  </TableCell>
                  <TableCell className="max-w-md">
                    <div className="truncate text-muted-foreground">{v.summary.slice(0, 140)}</div>
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={v.severity} />
                  </TableCell>
                  <TableCell>
                    <CvssBar score={v.cvss} />
                  </TableCell>
                  <TableCell>
                    <span className={cn("tabular text-xs font-medium", (v.epss ?? 0) >= 0.5 ? "text-critical" : (v.epss ?? 0) >= 0.1 ? "text-high" : "text-muted-foreground")}>
                      {v.epss !== undefined ? `${(v.epss * 100).toFixed(0)}%` : "—"}
                    </span>
                  </TableCell>
                  <TableCell>
                    <span className={cn("tabular text-sm", v.affectedAssetCount > 0 ? "font-medium" : "text-muted-foreground")}>{v.affectedAssetCount}</span>
                  </TableCell>
                  <TableCell>
                    <span className={cn("tabular text-sm", v.openFindings > 0 ? "font-medium text-high" : "text-muted-foreground")}>{v.openFindings}</span>
                  </TableCell>
                  <TableCell className="tabular text-xs text-muted-foreground">{v.publishedAt ? timeAgo(v.publishedAt) : "—"}</TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        <TableFooterBar total={total} page={page} pageSize={pageSize} onPage={setPage} onPageSize={setPageSize} label="CVEs" />
      </div>

      {detailId && <VulnDetailSheet cveId={detailId} onClose={() => setDetailId(null)} />}
    </div>
  );
}

function VulnDetailSheet({ cveId, onClose }: { cveId: string; onClose: () => void }) {
  const q = useVulnerability(cveId);
  const detail = q.data;
  const [assetTypes, setAssetTypes] = React.useState<Record<string, string>>({});
  void assetTypes;

  if (!detail) {
    return (
      <Sheet open onOpenChange={(o) => !o && onClose()}>
        <SheetContent className="sm:max-w-2xl">
          <EmptyState icon={Bug} title="Loading CVE…" />
        </SheetContent>
      </Sheet>
    );
  }

  return (
    <Sheet open onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-2xl">
        <>
          <SheetHeader>
            <div className="flex flex-wrap items-center gap-2">
              <SeverityBadge severity={detail.severity} />
              {detail.kev && <Badge variant="critical">KEV</Badge>}
              <Badge variant="muted" className="font-mono text-[10px] uppercase">
                {detail.source}
              </Badge>
              {(detail.cwe ?? []).slice(0, 3).map((w) => (
                <Badge key={w} variant="outline" className="font-mono text-[10px]">
                  {w}
                </Badge>
              ))}
            </div>
            <SheetTitle className="font-mono">{detail.id}</SheetTitle>
            <SheetDescription>{detail.state} · {detail.publishedAt ? `published ${new Date(detail.publishedAt).toLocaleDateString()}` : "publish date unknown"}</SheetDescription>
          </SheetHeader>
          <div className="flex flex-col gap-4 overflow-y-auto px-5 pb-5">
            <div className="grid grid-cols-3 gap-2">
              <div className="rounded-lg border bg-muted/30 px-3 py-2">
                <div className="tabular text-lg font-semibold">{detail.cvss.toFixed(1)}</div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">CVSS</div>
              </div>
              <div className="rounded-lg border bg-muted/30 px-3 py-2">
                <div className="tabular text-lg font-semibold">{detail.epss !== undefined ? `${(detail.epss * 100).toFixed(0)}%` : "—"}</div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">EPSS 30d</div>
              </div>
              <div className="rounded-lg border bg-muted/30 px-3 py-2">
                <div className="tabular text-lg font-semibold">{detail.affectedAssets?.length ?? 0}</div>
                <div className="text-[10px] uppercase tracking-wider text-muted-foreground">Assets</div>
              </div>
            </div>
            {detail.cvssVector && (
              <div className="rounded-lg border bg-[oklch(0.11_0.01_262)] p-2.5">
                <Mono className="block break-all text-[11px] leading-relaxed text-foreground/85">{detail.cvssVector}</Mono>
              </div>
            )}
            <p className="text-sm leading-relaxed text-foreground/85">{detail.summary}</p>

            {(detail.affectedProducts ?? []).length > 0 && (
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  Affected products <span className="tabular font-normal normal-case tracking-normal">({detail.affectedProducts!.length})</span>
                </div>
                <div className="overflow-hidden rounded-lg border">
                  <table className="w-full text-[12px]">
                    <thead className="bg-muted/40">
                      <tr className="border-b text-left text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
                        <th className="px-3 py-1.5">Vendor / product</th>
                        <th className="px-3 py-1.5">Versions</th>
                        <th className="px-3 py-1.5 text-right">Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {detail.affectedProducts!.map((p, i) => (
                        <tr key={i} className="border-b last:border-0">
                          <td className="px-3 py-2 align-top">
                            <div className="font-medium leading-tight">{p.product}</div>
                            <div className="text-[11px] text-muted-foreground">{p.vendor}</div>
                            {p.platforms && p.platforms.length > 0 && (
                              <div className="mt-1 flex flex-wrap gap-1">
                                {p.platforms.map((pl) => (
                                  <span key={pl} className="rounded border bg-muted/40 px-1 py-px font-mono text-[9px] text-muted-foreground">
                                    {pl}
                                  </span>
                                ))}
                              </div>
                            )}
                          </td>
                          <td className="px-3 py-2 align-top">
                            <Mono className="text-[11px] leading-snug">{p.versionStatement}</Mono>
                          </td>
                          <td className="px-3 py-2 text-right align-top">
                            <Badge variant={p.status === "affected" ? "critical" : p.status === "unaffected" ? "success" : "muted"} className="capitalize">
                              {p.status}
                            </Badge>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {(detail.cpeMatches ?? []).length > 0 && (
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">CPE ranges</div>
                <ul className="divide-y rounded-lg border">
                  {detail.cpeMatches!.map((m, i) => (
                    <li key={i} className="px-3 py-2">
                      <Mono className="block break-all text-[11px] text-foreground/85">{m.cpe}</Mono>
                      {m.ranges.length > 0 && <span className="mt-0.5 block text-[11px] text-muted-foreground">{m.ranges.join(" · ")}</span>}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div>
              <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Affected assets</div>
              {(detail.affectedAssets ?? []).length === 0 ? (
                <p className="text-xs text-muted-foreground">No inventory asset currently matches this CVE.</p>
              ) : (
                <ul className="divide-y rounded-lg border">
                  {detail.affectedAssets!.map((a) => (
                    <li key={a.findingId}>
                      <Link to={`/assets/${a.assetId}?tab=findings`} className="flex items-center gap-3 px-3 py-2 text-sm hover:bg-accent/40">
                        <Layers className="size-4 text-muted-foreground" />
                        <span className="font-medium">{a.hostname ?? a.assetId.slice(0, 8)}</span>
                        <Badge variant="muted" className="ml-auto capitalize">{a.status}</Badge>
                      </Link>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            {(detail.references ?? []).length > 0 && (
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
                  References <span className="tabular font-normal normal-case tracking-normal">({detail.references!.length})</span>
                </div>
                <ul className="divide-y rounded-lg border">
                  {detail.references!.map((r) => (
                    <li key={r.url}>
                      <a href={r.url} target="_blank" rel="noreferrer" className="group flex items-start gap-2.5 px-3 py-2 transition-colors hover:bg-accent/40">
                        <LinkIcon className="mt-1 size-3 shrink-0 text-muted-foreground" />
                        <span className="min-w-0 flex-1 truncate font-mono text-[11px] text-muted-foreground group-hover:text-primary">{r.url}</span>
                        <ExternalLink className="mt-1 size-3 shrink-0 text-muted-foreground opacity-0 transition-opacity group-hover:opacity-100" />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="divide-y rounded-lg border px-3">
              <KeyValue label="Published">{detail.publishedAt ? new Date(detail.publishedAt).toLocaleDateString() : "—"}</KeyValue>
              <KeyValue label="Feed source">
                <Mono className="text-xs">{detail.source}</Mono>
              </KeyValue>
            </div>

            <div className="flex flex-wrap gap-2">
              <Button size="sm" variant="outline" asChild>
                <a href={`https://nvd.nist.gov/vuln/detail/${detail.id}`} target="_blank" rel="noreferrer">
                  <ExternalLink /> NVD
                </a>
              </Button>
              <Button size="sm" variant="ghost" asChild>
                <Link to={`/findings?q=${detail.id}`}>Related findings</Link>
              </Button>
            </div>
          </div>
        </>
      </SheetContent>
    </Sheet>
  );
}
