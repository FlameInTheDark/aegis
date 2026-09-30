import { ShieldAlert } from "lucide-react";

import { timeAgo } from "@/lib/utils";
import { useRouter } from "@/lib/router";
import type { Finding } from "@/data/types";
import { Card } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { EmptyState, Mono, SeverityBadge, StateBadge } from "@/components/shared";

const findingTone = (s: string) => (s === "open" ? "danger" : s === "in_progress" ? "primary" : s === "acknowledged" ? "warning" : s === "resolved" ? "success" : "muted");

/** Findings tab of the asset detail page: every finding correlated against
 *  this asset, rows linking into the findings queue. */
export function AssetFindingsTab({ assetFindings }: { assetFindings: Finding[] }) {
  const { navigate } = useRouter();
  return (
    <Card className="py-0">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="pl-4">Severity</TableHead>
            <TableHead>Finding</TableHead>
            <TableHead>Category</TableHead>
            <TableHead>CVE</TableHead>
            <TableHead>Confidence</TableHead>
            <TableHead>Status</TableHead>
            <TableHead>Last seen</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {assetFindings.length === 0 ? (
            <TableRow className="hover:bg-transparent">
              <TableCell colSpan={7}>
                <EmptyState icon={ShieldAlert} title="No findings for this asset" description="Nothing correlated against the current CVE index. Rediscover after feed updates to re-match." />
              </TableCell>
            </TableRow>
          ) : (
            assetFindings.map((f) => (
              <TableRow key={f.id} className="cursor-pointer" onClick={() => navigate(`/findings?id=${f.id}`)}>
                <TableCell className="pl-4">
                  <SeverityBadge severity={f.severity} />
                </TableCell>
                <TableCell className="max-w-md">
                  <div className="truncate font-medium">{f.title}</div>
                  <div className="truncate text-xs text-muted-foreground">{f.id.slice(0, 8)} · {f.category}</div>
                </TableCell>
                <TableCell className="text-muted-foreground">{f.category}</TableCell>
                <TableCell>
                  {f.cve ? (
                    <span className="inline-flex items-center gap-1.5">
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
                  <StateBadge label={f.status} tone={findingTone(f.status)} />
                </TableCell>
                <TableCell className="tabular text-xs text-muted-foreground">{timeAgo(f.lastSeen)}</TableCell>
              </TableRow>
            ))
          )}
        </TableBody>
      </Table>
    </Card>
  );
}
