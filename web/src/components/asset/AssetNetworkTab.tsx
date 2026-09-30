import { Waypoints } from "lucide-react";

import { Link } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type { Network } from "@/lib/api-types";
import type { Asset, AssetDetailBundle, Trace } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ExposureBadge, KeyValue, Mono } from "@/components/shared";

/** Network tab of the asset detail page: interfaces, path & exposure and
 *  topology neighbors. */
export function AssetNetworkTab({
  asset,
  interfaces,
  trace,
  siteNetworks,
  neighbors,
}: {
  asset: Asset;
  interfaces: AssetDetailBundle["interfaces"];
  trace?: Trace;
  siteNetworks: Network[];
  neighbors: (Asset | undefined)[];
}) {
  return (
    <>
      <Card className="xl:col-span-2">
        <CardHeader>
          <CardTitle>Interfaces</CardTitle>
          <CardDescription>Addresses observed on this host</CardDescription>
        </CardHeader>
        <CardContent className="px-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-4">Interface</TableHead>
                <TableHead>Address</TableHead>
                <TableHead>MAC</TableHead>
                <TableHead>MAC vendor</TableHead>
                <TableHead>VLAN</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {interfaces.length === 0 ? (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={5} className="text-center text-sm text-muted-foreground">No interfaces recorded</TableCell>
                </TableRow>
              ) : (
                interfaces.map((i) => (
                  <TableRow key={i.name + i.ip}>
                    <TableCell className="pl-4 font-medium">{i.name}</TableCell>
                    <TableCell>
                      {/* Every address the endpoint/scan ever observed on
                          this NIC (agent inventory records IPv4 AND IPv6);
                          the primary is the management-facing one picked by
                          the hub. Fallback keeps old payloads readable. */}
                      {i.addresses.length > 0 ? (
                        <div className="flex flex-col items-start gap-0.5">
                          {i.addresses.map((a) => (
                            <span key={a.ip} className="flex items-center gap-1.5">
                              <Mono className={a.is_primary ? "" : "text-muted-foreground"}>{a.ip}</Mono>
                              {a.is_primary && (
                                <span className="rounded bg-muted px-1 py-px text-[10px] uppercase tracking-wide text-muted-foreground">
                                  primary
                                </span>
                              )}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <Mono className="text-muted-foreground">{i.ip || "—"}</Mono>
                      )}
                    </TableCell>
                    <TableCell>
                      <Mono className="text-muted-foreground">{i.mac ?? "—"}</Mono>
                    </TableCell>
                    <TableCell className="text-muted-foreground">{i.vendor ?? "—"}</TableCell>
                    <TableCell className="tabular text-muted-foreground">{i.vlan ?? "—"}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Path &amp; exposure</CardTitle>
        </CardHeader>
        <CardContent className="divide-y">
          <KeyValue label="Hops from scanner">{trace ? trace.hops.length : "—"}</KeyValue>
          <KeyValue label="Exposure">
            <ExposureBadge value={asset.exposure} />
          </KeyValue>
          <KeyValue label="DNS names">{asset.fqdn ?? "—"}</KeyValue>
          <KeyValue label="Site networks" mono>
            {siteNetworks.map((n) => n.cidr).join(", ") || "—"}
          </KeyValue>
          <KeyValue label="Notes">
            <span className="line-clamp-3 whitespace-pre-wrap text-left text-xs">{asset.notes ?? "—"}</span>
          </KeyValue>
        </CardContent>
      </Card>

      <Card className="xl:col-span-3">
        <CardHeader>
          <CardTitle>Topology neighbors</CardTitle>
          <CardDescription>Assets adjacent to this host in the inferred network graph</CardDescription>
          <CardAction>
            <Button variant="ghost" size="xs" asChild>
              <Link to={`/topology?focus=${asset.id}`}>
                <Waypoints /> Open topology
              </Link>
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            {neighbors.length === 0 ? (
              <p className="text-sm text-muted-foreground">No inferred neighbors yet — run discovery scans to build the topology graph.</p>
            ) : (
              neighbors.slice(0, 8).map((n) => {
                if (!n) return null;
                const NIcon = assetTypeMeta[n.type].icon;
                return (
                  <Link key={n.id} to={`/assets/${n.id}`} className="flex items-center gap-2.5 rounded-lg border p-2 transition-colors hover:bg-accent/40">
                    <span className="flex size-7 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                      <NIcon className="size-3.5" />
                    </span>
                    <div className="min-w-0 leading-tight">
                      <div className="truncate text-sm font-medium">{n.hostname ?? n.ip}</div>
                      <div className="font-mono text-[11px] text-muted-foreground">{n.ip}</div>
                    </div>
                  </Link>
                );
              })
            )}
          </div>
        </CardContent>
      </Card>
    </>
  );
}
