import * as React from "react";
import { Download, FileBarChart, FileText, Layers, Loader2, MoreHorizontal, Plus, FileSpreadsheet, FileCode2, Route, ShieldAlert, Activity, MonitorSmartphone, GitCompareArrows, Building2 } from "lucide-react";

import { timeAgo } from "@/lib/utils";
import { useRouter } from "@/lib/router";
import { api } from "@/lib/api";
import { useAssets, useCreateReport, useReportJobs, useSites } from "@/lib/queries";
import type { Report } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { toast } from "@/components/ui/toaster";
import { EmptyState, PageHeader, StateBadge, TableFooterBar, usePagination } from "@/components/shared";

/** The backend's report catalogue (domain.ReportType) with UI metadata. */
const templates: { type: string; title: string; blurb: string; icon: React.ElementType }[] = [
  { type: "executive_security", title: "Executive security", blurb: "Risk trend, top exposures and remediation posture for leadership.", icon: FileBarChart },
  { type: "technical_vulnerability", title: "Technical vulnerability", blurb: "Every finding with evidence, remediation and affected services.", icon: FileText },
  { type: "network_inventory", title: "Network inventory", blurb: "Complete asset and service inventory across the scoped sites.", icon: Layers },
  { type: "topology", title: "Topology", blurb: "Inferred network graph with gateway and L2 evidence.", icon: Route },
  { type: "security_event", title: "Security events", blurb: "Sensor event digest for the reporting window.", icon: Activity },
  { type: "asset_risk", title: "Asset risk", blurb: "Per-asset risk scores ranked with contributing findings.", icon: ShieldAlert },
  { type: "scan_comparison", title: "Scan comparison", blurb: "Differential between two scans — new hosts, ports, software.", icon: GitCompareArrows },
  { type: "site_detail", title: "Site detail", blurb: "Fully detailed report about one site.", icon: Building2 },
  { type: "device_detail", title: "Device detail", blurb: "Full profile of a single asset: identity, services, software, findings.", icon: MonitorSmartphone },
];

const formatIcon = { pdf: FileText, html: FileCode2, csv: FileSpreadsheet } as const;

export function ReportsPage() {
  const { query, navigate } = useRouter();
  const jobsQ = useReportJobs();
  const createReport = useCreateReport();
  const [open, setOpen] = React.useState(query.get("new") === "1");
  const [type, setType] = React.useState(query.get("asset") ? "device_detail" : "executive_security");

  React.useEffect(() => {
    if (query.get("new") === "1") {
      setOpen(true);
      if (query.get("asset")) setType("device_detail");
    }
  }, [query]);

  const items = jobsQ.data ?? [];
  const paged = usePagination(items, "reports");

  const close = () => {
    setOpen(false);
    if (query.get("new")) navigate("/reports", { replace: true });
  };

  const create = (req: { type: string; format: string; site_id?: string; asset_id?: string }) => {
    createReport.mutate(req, {
      onSuccess: () => {
        close();
        toast({ title: "Report generation started", description: "The job runs in the background — download it from the list when ready.", variant: "success" });
      },
      onError: (e) => toast({ title: "Report rejected", description: (e as Error).message, variant: "error" }),
    });
  };

  const download = async (r: Report) => {
    try {
      await api.download(`/reports/jobs/${r.jobId}/download`, `aegis-report-${r.type}.${r.format}`);
      toast({ title: "Download started", variant: "success" });
    } catch (e) {
      toast({ title: "Download failed", description: (e as Error).message, variant: "error" });
    }
  };

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="Reports"
        description="Point-in-time documents generated from the current inventory and findings. Reports are immutable and retained for audit."
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus /> Generate report
          </Button>
        }
      />

      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Report</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Scope</TableHead>
              <TableHead>Format</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>By</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={8}>
                  <EmptyState
                    icon={FileText}
                    title="No reports yet"
                    description="Generate a report and choose its type, scope and format."
                    action={
                      <Button size="sm" onClick={() => setOpen(true)}>
                        <Plus /> Generate report
                      </Button>
                    }
                  />
                </TableCell>
              </TableRow>
            ) : (
              paged.slice.map((r) => {
                const FIcon = formatIcon[r.format] ?? FileText;
                return (
                  <TableRow key={r.id}>
                    <TableCell className="pl-4">
                      <div className="flex items-center gap-2.5">
                        <span className="flex size-7 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                          <FIcon className="size-3.5" />
                        </span>
                        <div className="leading-tight">
                          <div className="font-medium">{r.name}</div>
                          <div className="text-[11px] text-muted-foreground">{r.format.toUpperCase()}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="capitalize">
                        {r.type.replace(/_/g, " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{r.scope}</TableCell>
                    <TableCell className="font-mono text-xs uppercase text-muted-foreground">{r.format}</TableCell>
                    <TableCell>
                      {r.status === "generating" || r.status === "queued" ? (
                        <span className="inline-flex items-center gap-1.5 text-xs text-primary">
                          <Loader2 className="size-3 animate-spin" /> {r.status === "queued" ? "queued" : "generating"} {r.progress ? `${r.progress}%` : ""}
                        </span>
                      ) : (
                        <StateBadge label={r.status} tone={r.status === "ready" ? "success" : "danger"} />
                      )}
                    </TableCell>
                    <TableCell className="tabular text-xs text-muted-foreground">{timeAgo(r.createdAt)}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{r.createdBy ? r.createdBy.slice(0, 8) : "—"}</TableCell>
                    <TableCell>
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="xs" disabled={r.status !== "ready"} onClick={() => download(r)}>
                          <Download /> Download
                        </Button>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon-xs" className="text-muted-foreground">
                              <MoreHorizontal />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => toast({ title: "Retention policy governs deletion", description: "Reports are immutable and expire with the audit retention window.", variant: "warning" })}>
                              <Layers /> Retention info
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
        {paged.slice.length > 0 && <TableFooterBar total={paged.total} page={paged.page} pageSize={paged.pageSize} onPage={paged.setPage} onPageSize={paged.setPageSize} label="reports" />}
      </div>

      <GenerateDialog open={open} onOpenChange={(o) => (o ? setOpen(true) : close())} type={type} setType={setType} onCreate={create} defaultAsset={query.get("asset") ?? undefined} />
    </div>
  );
}

function GenerateDialog({
  open,
  onOpenChange,
  type,
  setType,
  onCreate,
  defaultAsset,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  type: string;
  setType: (t: string) => void;
  onCreate: (req: { type: string; format: string; site_id?: string; asset_id?: string }) => void;
  defaultAsset?: string;
}) {
  const sites = useSites();
  const assetsQ = useAssets({ limit: 200 });
  const [scope, setScope] = React.useState("all");
  const [asset, setAsset] = React.useState(defaultAsset ?? "");
  const [format, setFormat] = React.useState<Report["format"]>("pdf");

  React.useEffect(() => {
    if (defaultAsset) setAsset(defaultAsset);
  }, [defaultAsset]);

  const tpl = templates.find((t) => t.type === type) ?? templates[0];
  const assets = assetsQ.data?.items ?? [];
  const scopeLabel = type === "device_detail" ? (assets.find((a) => a.id === asset)?.hostname ?? "asset") : scope === "all" ? "All sites" : (sites.data?.items.find((s) => s.id === scope)?.name ?? "");

  const submit = () =>
    onCreate({
      type,
      format,
      site_id: type === "device_detail" ? undefined : scope === "all" ? undefined : scope,
      asset_id: type === "device_detail" ? asset : undefined,
    });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Generate report</DialogTitle>
          <DialogDescription>Reports snapshot the current state. Generation runs in the background — you'll find it in the list when ready.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label>Report type</Label>
            <Select value={type} onValueChange={setType}>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {templates.map((t) => (
                  <SelectItem key={t.type} value={t.type}>
                    {t.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">{tpl.blurb}</p>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label>{type === "device_detail" ? "Asset" : "Scope"}</Label>
              {type === "device_detail" ? (
                <Select value={asset} onValueChange={setAsset}>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Choose an asset" />
                  </SelectTrigger>
                  <SelectContent>
                    {assets.map((a) => (
                      <SelectItem key={a.id} value={a.id}>
                        {a.hostname ?? a.ip} <span className="font-mono text-xs text-muted-foreground">{a.ip}</span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              ) : (
                <Select value={scope} onValueChange={setScope}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All sites</SelectItem>
                    {(sites.data?.items ?? []).map((s) => (
                      <SelectItem key={s.id} value={s.id}>
                        {s.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              )}
            </div>
            <div className="grid gap-1.5">
              <Label>Format</Label>
              <Select value={format} onValueChange={(v) => setFormat(v as Report["format"])}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="pdf">PDF</SelectItem>
                  <SelectItem value="html">HTML</SelectItem>
                  <SelectItem value="csv">CSV (data only)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={type === "device_detail" && !asset}>
            <FileText /> Generate
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
