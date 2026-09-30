import * as React from "react";
import { GitCompare, History, Loader2 } from "lucide-react";

import { cn, formatDateTime } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import type { Change } from "@/lib/api-types";
import { useScope } from "@/components/layout/AppShell";
import { useChanges } from "@/lib/queries";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared";

// F7 (change timeline): "what appeared on this site since Tuesday" without
// diffing two scan rows by hand. Every row links back to the scan that
// produced it and, when known, the asset it touched.

const CHANGE_TYPES = [
  "NEW_ASSET", "REMOVED_ASSET", "IP_CHANGED", "MAC_CHANGED", "OS_CHANGED",
  "SERVICE_OPENED", "SERVICE_CLOSED", "SERVICE_CHANGED", "VERSION_CHANGED",
  "SOFTWARE_INSTALLED", "SOFTWARE_REMOVED", "VULNERABILITY_NEW",
  "VULNERABILITY_RESOLVED", "VULNERABILITY_CHANGED", "TOPOLOGY_CHANGED",
  "AGENT_MISSING", "SECURITY_POSTURE_CHANGED",
];

const PAGE_SIZE = 50;

export function ChangesPage() {
  const { query, navigate } = useRouter();
  const { site: scopeSite } = useScope();
  const [type, setType] = React.useState(query.get("type") ?? "all");
  const [from, setFrom] = React.useState("");
  const [offset, setOffset] = React.useState(0);
  const site = query.get("site_id") ?? scopeSite ?? "";

  const params = React.useMemo(() => {
    const p: Parameters<typeof useChanges>[0] = { limit: PAGE_SIZE, offset };
    // "all" is the site-scope sentinel, not a site id — never send it.
    if (site && site !== "all") p.site_id = site;
    if (type !== "all") p.type = type;
    if (from) p.from = new Date(from).toISOString();
    return p;
  }, [site, type, from, offset]);

  const changesQ = useChanges(params);
  const items = changesQ.data?.items ?? [];
  const total = changesQ.data?.total ?? 0;

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Changes"
        description="What scans and agents observed changing across the estate — new assets, opened services, version shifts. Each row links to the scan that produced it."
        actions={
          <Button variant="outline" size="sm" onClick={() => changesQ.refetch()}>
            {changesQ.isFetching ? <Loader2 className="size-4 animate-spin" /> : <History className="size-4" />} Refresh
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <Select value={type} onValueChange={(v) => { setType(v); setOffset(0); }}>
          <SelectTrigger size="sm" className="h-8 w-56 text-xs"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All change types</SelectItem>
            {CHANGE_TYPES.map((t) => (
              <SelectItem key={t} value={t}>{t.replaceAll("_", " ").toLowerCase()}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Input
          type="date"
          value={from}
          onChange={(e) => { setFrom(e.target.value); setOffset(0); }}
          className="h-8 w-44 text-xs"
          aria-label="From date"
        />
        <Badge variant="outline">{total} total</Badge>
      </div>

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-44">When</TableHead>
              <TableHead className="w-52">Change</TableHead>
              <TableHead>Entity</TableHead>
              <TableHead>Before → After</TableHead>
              <TableHead className="w-24">Scan</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((c) => (
              <ChangeRow key={c.id} change={c} />
            ))}
            {!changesQ.isFetching && items.length === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-10 text-center text-sm text-muted-foreground">
                  <GitCompare className="mx-auto mb-2 size-6 opacity-40" />
                  No change records match. Changes appear when scheduled or manual scans discover differences.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>

      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>
          Showing {items.length === 0 ? 0 : offset + 1}–{offset + items.length} of {total}
        </span>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
            Previous
          </Button>
          <Button variant="outline" size="sm" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
            Next
          </Button>
        </div>
      </div>
    </div>
  );
}

function ChangeRow({ change }: { change: Change }) {
  return (
    <TableRow>
      <TableCell className="text-xs text-muted-foreground">{formatDateTime(change.created_at)}</TableCell>
      <TableCell>
        <Badge variant="outline" className={cn("font-mono text-[10px]")}>{change.type}</Badge>
      </TableCell>
      <TableCell className="text-xs">
        {change.entity || (change.asset_id ? (
          <Link to={`/assets/${change.asset_id}`} className="underline-offset-2 hover:underline">
            {change.asset_id.slice(0, 8)}…
          </Link>
        ) : null)}
      </TableCell>
      <TableCell className="max-w-64 truncate text-xs text-muted-foreground">
        {change.before || change.after ? `${change.before || "—"} → ${change.after || "—"}` : ""}
      </TableCell>
      <TableCell>
        <Link to={`/scans?scan=${change.scan_id}`} className="text-xs underline-offset-2 hover:underline">view scan</Link>
      </TableCell>
    </TableRow>
  );
}
