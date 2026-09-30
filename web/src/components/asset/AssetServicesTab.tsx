import { Network as NetworkIcon } from "lucide-react";

import { useRouter } from "@/lib/router";
import type { Asset, Port } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { VersionCell } from "@/components/ui/VersionCell";
import { EmptyState, Mono, StateBadge, TableFooterBar } from "@/components/shared";
import type { Paged } from "@/components/asset/shared";

/** Services tab of the asset detail page: the paginated port/service table. */
export function AssetServicesTab({
  asset,
  ports,
  pagedPorts,
  onOpenDiagnostics,
}: {
  asset: Asset;
  ports: Port[];
  pagedPorts: Paged<Port>;
  onOpenDiagnostics: () => void;
}) {
  const { navigate } = useRouter();
  return (
    <Card className="py-0">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="pl-4">Port</TableHead>
            <TableHead>State</TableHead>
            <TableHead>Service</TableHead>
            <TableHead>Product / version</TableHead>
            <TableHead>Confidence</TableHead>
            <TableHead className="text-right pr-4">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {ports.length === 0 ? (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={6}>
                <EmptyState icon={NetworkIcon} title="No services detected" description="Run an inventory scan to enumerate listening services." action={<Button size="sm" onClick={() => navigate(`/scans?new=1&target=${asset.ip}`)}>Scan host</Button>} />
              </TableCell>
            </TableRow>
          ) : (
            pagedPorts.slice.map((p) => (
              <TableRow key={`${p.proto}${p.port}`}>
                <TableCell className="pl-4">
                  <Mono className="font-semibold">
                    {p.port}
                    <span className="font-normal text-muted-foreground">/{p.proto}</span>
                  </Mono>
                </TableCell>
                <TableCell>
                  <StateBadge label={p.state} tone={p.state === "open" ? "success" : "muted"} />
                </TableCell>
                <TableCell className="font-medium">{p.service}</TableCell>
                <TableCell className="text-muted-foreground">
                  {p.product ?? "—"} {p.version && <VersionCell version={p.version} meta={p.versionMeta} />}
                </TableCell>
                <TableCell>
                  <div className="flex w-24 items-center gap-2">
                    <Progress value={p.confidence ?? 0} className="h-1" />
                    <span className="tabular text-xs text-muted-foreground">{p.confidence ?? 0}%</span>
                  </div>
                </TableCell>
                <TableCell className="text-right pr-4">
                  <div className="flex justify-end gap-1">
                    <Button variant="ghost" size="xs" onClick={onOpenDiagnostics}>
                      Diagnostics
                    </Button>
                    <Button variant="ghost" size="xs" onClick={() => navigate(`/vulnerabilities?q=${encodeURIComponent(p.product ?? p.service)}`)}>
                      Search CVEs
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
      {pagedPorts.slice.length > 0 && <TableFooterBar total={pagedPorts.total} page={pagedPorts.page} pageSize={pagedPorts.pageSize} onPage={pagedPorts.setPage} onPageSize={pagedPorts.setPageSize} label="services" />}
    </Card>
  );
}
