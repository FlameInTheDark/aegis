import { Package } from "lucide-react";

import { Link, useRouter } from "@/lib/router";
import type { Asset, Software } from "@/data/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { VersionCell } from "@/components/ui/VersionCell";
import { EmptyState, TableFooterBar } from "@/components/shared";
import type { Paged } from "@/components/asset/shared";

/** Software tab of the asset detail page: the paginated package inventory. */
export function AssetSoftwareTab({
  asset,
  software,
  pagedSoftware,
  onOpenDiagnostics,
}: {
  asset: Asset;
  software: Software[];
  pagedSoftware: Paged<Software>;
  onOpenDiagnostics: () => void;
}) {
  const { navigate } = useRouter();
  return (
    <Card className="py-0">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="pl-4">Package</TableHead>
            <TableHead>Version</TableHead>
            <TableHead>Ecosystem</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {software.length === 0 ? (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={5}>
                <EmptyState
                  icon={Package}
                  title="No software inventory"
                  description="Connect a collector to this asset's connector or run an ssh_inventory scan to collect installed packages."
                  action={
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" asChild>
                        <Link to="/connections?create=agent">Connect endpoint</Link>
                      </Button>
                      <Button size="sm" onClick={() => navigate(`/scans?new=1&target=${asset.ip}&preset=ssh_inventory`)}>
                        SSH inventory
                      </Button>
                    </div>
                  }
                />
              </TableCell>
            </TableRow>
          ) : (
            pagedSoftware.slice.map((s) => (
              <TableRow key={s.id}>
                <TableCell className="pl-4 font-medium">{s.name}</TableCell>
                <TableCell>
                  <VersionCell version={s.version} meta={s.versionMeta} />
                </TableCell>
                <TableCell>
                  {s.ecosystem ? <Badge variant="muted">{s.ecosystem}</Badge> : <span className="text-xs text-muted-foreground">—</span>}
                </TableCell>
                <TableCell>
                  <Badge variant="muted">{s.source ?? "—"}</Badge>
                  {s.osvStatus && s.osvStatus !== "not_queried" && (
                    <Badge variant={s.osvStatus === "queried_findings" ? "destructive" : "outline"} className="text-[10px]">
                      {s.osvStatus === "queried_findings" ? "OSV: findings" : "OSV: clean"}
                    </Badge>
                  )}
                </TableCell>
                <TableCell>
                  <div className="flex justify-end gap-1">
                    <Button variant="ghost" size="xs" onClick={onOpenDiagnostics}>
                      Diagnostics
                    </Button>
                    <Button variant="ghost" size="xs" onClick={() => navigate(`/vulnerabilities?q=${encodeURIComponent(s.name)}`)}>
                      Search CVEs
                    </Button>
                  </div>
                </TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
      {pagedSoftware.slice.length > 0 && <TableFooterBar total={pagedSoftware.total} page={pagedSoftware.page} pageSize={pagedSoftware.pageSize} onPage={pagedSoftware.setPage} onPageSize={pagedSoftware.setPageSize} label="packages" />}
    </Card>
  );
}
