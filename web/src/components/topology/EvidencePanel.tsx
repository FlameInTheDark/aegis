import { Crosshair, ExternalLink, Focus, LayoutGrid, Pin, PinOff, X } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { Link } from "@/lib/router";
import { assetTypeMeta } from "@/lib/domain";
import type { GraphNode } from "@/components/topology/TopologyGraph";
import { useAsset } from "@/lib/queries";
import type { AssetGroup } from "@/data/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { GroupChip } from "@/components/groups/GroupChip";
import { CriticalityBadge, ExposureBadge, Mono, RiskMeter, SeverityCountsInline, StatusDot } from "@/components/shared";

/**
 * EvidencePanel — the floating node detail card of the topology graph view:
 * identity, badges, groups, risk/findings summary, open ports and the
 * per-node actions (open asset, center, pin trace, collapse branch).
 * Renders as a slide-in overlay; without a selection it stays off-canvas.
 */
export function EvidencePanel({
  selNode,
  pinned,
  trace,
  collapsed,
  groupsOf,
  onClose,
  onCenter,
  onToggleTrace,
  onToggleCollapse,
  onSelectGroup,
}: {
  selNode: GraphNode | undefined;
  /** the selected node has an analyst-pinned parent (migration 0032) */
  pinned: boolean;
  trace: string[];
  collapsed: Set<string>;
  groupsOf: (assetId: string) => AssetGroup[];
  onClose: () => void;
  onCenter: (id: string) => void;
  onToggleTrace: (id: string) => void;
  onToggleCollapse: (id: string) => void;
  onSelectGroup: (id: string) => void;
}) {
  return (
    <div className={cn("pointer-events-none absolute right-3 top-14 z-20 w-80 transition-all duration-300 ease-[cubic-bezier(0.32,0.72,0,1)]", selNode ? "translate-x-0 opacity-100" : "translate-x-6 opacity-0")}>
      {selNode && (
        <Card className="pointer-events-auto gap-3 border-primary/30 bg-popover/95 shadow-2xl backdrop-blur-md">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 pr-6">
              {selNode.asset.hostname ?? selNode.asset.ip}
              {selNode.hub && <Badge variant="primary">hub</Badge>}
              {pinned && (
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Badge variant="medium" className="gap-1">
                      <Pin className="size-3" /> pinned parent
                    </Badge>
                  </TooltipTrigger>
                  <TooltipContent>
                    An analyst pinned this node's topology parent (Edit identity on the asset page) — the amber
                    link overrides the observed evidence.
                  </TooltipContent>
                </Tooltip>
              )}
            </CardTitle>
            <Button variant="ghost" size="icon-xs" className="absolute right-3 top-3 text-muted-foreground" onClick={onClose}>
              <X />
            </Button>
          </CardHeader>
          <CardContent className="flex max-h-[calc(100vh-18rem)] flex-col gap-3 overflow-y-auto text-sm">
            <div className="flex items-center gap-2">
              <Mono>{selNode.asset.ip}</Mono>
              <span className="text-muted-foreground">·</span>
              <span className="text-muted-foreground">{assetTypeMeta[selNode.asset.type].label}</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              <ExposureBadge value={selNode.asset.exposure} />
              <CriticalityBadge value={selNode.asset.criticality} />
            </div>
            {groupsOf(selNode.asset.id).length > 0 && (
              <div className="flex flex-wrap gap-1">
                {groupsOf(selNode.asset.id).map((g) => (
                  <GroupChip key={g.id} group={g} size="sm" onClick={() => onSelectGroup(g.id)} />
                ))}
              </div>
            )}
            <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted/30 p-2.5 text-xs">
              <div>
                <div className="text-muted-foreground">Risk</div>
                <RiskMeter value={selNode.asset.risk} className="mt-1" />
              </div>
              <div>
                <div className="text-muted-foreground">Findings</div>
                <SeverityCountsInline counts={selNode.asset.findings ?? { critical: 0, high: 0, medium: 0, low: 0 }} className="mt-1.5" />
              </div>
              <div className="min-w-0">
                <div className="text-muted-foreground">OS</div>
                <div className="truncate">{selNode.asset.os ?? "Unknown"}</div>
              </div>
              <div>
                <div className="text-muted-foreground">Last seen</div>
                <div className="flex items-center gap-1.5">
                  <StatusDot tone="success" className="size-1.5" /> {timeAgo(selNode.asset.lastSeen)}
                </div>
              </div>
            </div>
            <NodePorts assetId={selNode.asset.id} />
            <div className="grid grid-cols-2 gap-2 pt-1">
              <Button size="sm" asChild>
                <Link to={`/assets/${selNode.asset.id}`}>
                  <ExternalLink /> Open asset
                </Link>
              </Button>
              <Button size="sm" variant="outline" onClick={() => onCenter(selNode.asset.id)}>
                <Crosshair /> Center
              </Button>
              <Button size="sm" variant={trace.includes(selNode.asset.id) ? "default" : "outline"} onClick={() => onToggleTrace(selNode.asset.id)}>
                {trace.includes(selNode.asset.id) ? <PinOff /> : <Pin />} {trace.includes(selNode.asset.id) ? "Unpin" : "Pin trace"}
              </Button>
              <Button size="sm" variant="outline" onClick={() => onToggleCollapse(selNode.asset.id)}>
                <LayoutGrid /> {collapsed.has(selNode.asset.id) ? "Expand" : "Collapse"}
              </Button>
            </div>
            <Button size="sm" variant="ghost" className="text-muted-foreground" asChild>
              <Link to={`/assets/${selNode.asset.id}?tab=traces`}>
                <Focus /> View trace path
              </Link>
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

/** Side-panel open ports line fed by the asset bundle query. */
function NodePorts({ assetId }: { assetId: string }) {
  const bundleQ = useAsset(assetId);
  const open = (bundleQ.data?.ports ?? []).filter((p) => p.state === "open");
  return (
    <div className="text-xs text-muted-foreground">
      Open ports:{" "}
      {open.length ? (
        <span className="font-mono text-foreground">{open.map((p) => p.port).join(", ")}</span>
      ) : bundleQ.isLoading ? (
        "…"
      ) : (
        "none"
      )}
    </div>
  );
}
