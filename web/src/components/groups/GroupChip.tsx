import * as React from "react";
import { Plus, X } from "lucide-react";

import { cn } from "@/lib/utils";
import { colorOf, iconOf, useGroups } from "@/lib/groups";
import type { AssetGroup } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuLabel, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";

export function GroupChip({
  group,
  onRemove,
  onClick,
  size = "default",
  className,
}: {
  group: AssetGroup;
  onRemove?: () => void;
  onClick?: () => void;
  size?: "sm" | "default";
  className?: string;
}) {
  const c = colorOf(group.color);
  const Icon = iconOf(group.icon);
  const Comp: React.ElementType = onClick ? "button" : "span";
  return (
    <Comp
      onClick={onClick}
      style={{ backgroundColor: c.soft, borderColor: c.border, color: c.solid }}
      className={cn(
        "inline-flex w-fit items-center gap-1 rounded-md border font-medium whitespace-nowrap",
        size === "sm" ? "px-1.5 py-0 text-[10px]" : "px-2 py-0.5 text-xs",
        onClick && "cursor-pointer transition-opacity hover:opacity-80",
        className
      )}
    >
      <Icon className={size === "sm" ? "size-2.5" : "size-3"} />
      {group.name}
      {onRemove && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onRemove();
          }}
          className="ml-0.5 cursor-pointer opacity-60 hover:opacity-100"
        >
          <X className="size-3" />
        </button>
      )}
    </Comp>
  );
}

/** Compact list of an asset's groups with an inline add/remove menu. */
export function AssetGroupCell({ assetId, editable = true, max = 2 }: { assetId: string; editable?: boolean; max?: number }) {
  const { groups, groupsOf, toggle } = useGroups();
  const mine = groupsOf(assetId);
  const shown = mine.slice(0, max);
  const rest = mine.length - shown.length;

  return (
    <div className="flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
      {shown.map((g) => (
        <GroupChip key={g.id} group={g} size="sm" />
      ))}
      {rest > 0 && <span className="tabular text-[10px] text-muted-foreground">+{rest}</span>}
      {mine.length === 0 && !editable && <span className="text-xs text-muted-foreground">—</span>}
      {editable && (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button variant="ghost" size="icon-xs" className={cn("size-5 text-muted-foreground", mine.length === 0 && "opacity-60")}>
              <Plus className="size-3" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-56">
            <DropdownMenuLabel>Groups</DropdownMenuLabel>
            <DropdownMenuSeparator />
            {groups.map((g) => {
              const c = colorOf(g.color);
              const Icon = iconOf(g.icon);
              return (
                <DropdownMenuItem key={g.id} onSelect={(e) => e.preventDefault()} onClick={() => toggle(g.id, assetId)} className="gap-2">
                  <Checkbox checked={g.assetIds.includes(assetId)} className="pointer-events-none" />
                  <Icon className="size-3.5" style={{ color: c.solid }} />
                  <span className="truncate">{g.name}</span>
                </DropdownMenuItem>
              );
            })}
            {groups.length === 0 && <div className="px-2 py-3 text-center text-xs text-muted-foreground">No groups yet</div>}
          </DropdownMenuContent>
        </DropdownMenu>
      )}
    </div>
  );
}
