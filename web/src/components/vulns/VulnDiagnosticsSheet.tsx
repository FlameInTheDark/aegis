import { Loader2, Microscope } from "lucide-react";

import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { EmptyState, KeyValue, Mono, SectionTitle } from "@/components/shared";
import { useAssetVulnDiagnostics } from "@/lib/queries.vulnsearch";

// Target-bound match workbench (plan §6.4): shows, for every service and
// software row of the asset, the observed identity, the normalized version,
// the effective operator-curated alias, the automatic matches (existing
// findings) and how many matches the configured search actions contribute.
// Read-only — nothing here creates or changes data.

export function VulnDiagnosticsSheet({ assetId, open, onClose }: {
  assetId: string;
  open: boolean;
  onClose: () => void;
}) {
  const q = useAssetVulnDiagnostics(open ? assetId : undefined);
  const d = q.data;

  return (
    <Sheet open={open} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="sm:max-w-2xl">
        <SheetHeader>
          <SheetTitle className="flex items-center gap-2 text-base">
            <Microscope className="size-4" /> Match diagnostics
          </SheetTitle>
          <SheetDescription>
            How automatic matching and configured search actions see this asset's inventory.
          </SheetDescription>
        </SheetHeader>

        <div className="grid gap-4">
          {q.isLoading && (
            <p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> Evaluating identities…</p>
          )}
          {q.isError && (
            <Alert variant="destructive" className="py-2">
              <AlertDescription className="text-xs">{(q.error as Error).message}</AlertDescription>
            </Alert>
          )}
          {d && (
            <>
              <div className="flex flex-wrap gap-2 text-xs text-muted-foreground">
                <KeyValue label="Enabled actions">{d.enabled_actions}</KeyValue>
                <KeyValue label="Local sources">
                  <span className="flex gap-1.5">
                    <Badge variant={d.sources.cpe ? "success" : "muted"} className="text-[10px]">cpe</Badge>
                    <Badge variant={d.sources.osv ? "success" : "muted"} className="text-[10px]">osv</Badge>
                    <Badge variant={d.sources.oval ? "success" : "muted"} className="text-[10px]">oval</Badge>
                  </span>
                </KeyValue>
              </div>

              {d.diagnostics.length === 0 && (
                <EmptyState compact title="No inventory rows" description="This asset has no services or software to diagnose yet." />
              )}

              {d.diagnostics.map((row) => (
                <div key={`${row.type}-${row.id}`} className="rounded-lg border p-3">
                  <div className="flex items-center justify-between gap-2">
                    <div className="min-w-0">
                      <div className="flex items-center gap-1.5">
                        <Badge variant="muted" className="text-[10px]">{row.type}</Badge>
                        <span className="truncate text-[13px] font-medium">{row.name}</span>
                      </div>
                      <div className="mt-0.5 text-xs text-muted-foreground">
                        vendor {row.vendor || "—"} · version <Mono className="text-[11px]">{row.version || "—"}</Mono>
                        {row.raw_version && row.raw_version !== row.version && <> (raw <Mono className="text-[11px]">{row.raw_version}</Mono>)</>}
                        {row.ecosystem && <> · {row.ecosystem}</>}
                      </div>
                    </div>
                    <div className="shrink-0 text-right text-xs">
                      <div className="tabular">{row.findings.length} automatic</div>
                      <div className="tabular text-muted-foreground">{row.configured_matches} configured</div>
                    </div>
                  </div>
                  {row.alias_applied && (
                    <p className="mt-1.5 text-[11px] text-muted-foreground">
                      Alias applied → <span className="font-mono">{row.alias_applied}</span>
                    </p>
                  )}
                  {row.findings.length > 0 && (
                    <div className="mt-1.5 flex flex-wrap gap-1">
                      {row.findings.map((f) => (
                        <Badge key={f} variant="outline" className="font-mono text-[10px]">{f}</Badge>
                      ))}
                    </div>
                  )}
                </div>
              ))}

              <SectionTitle>Reading this view</SectionTitle>
              <p className="text-xs text-muted-foreground">
                Automatic matches come from the standard local matcher (CPE identity, distro advisories, OSV).
                Configured matches are contributed by your enabled search actions — open one under
                Vulnerabilities → Search actions to preview or run it against this inventory.
                A missing source badge means that index has no local rows yet; matches relying on it will be absent.
              </p>
            </>
          )}
        </div>
      </SheetContent>
    </Sheet>
  );
}
