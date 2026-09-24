import * as React from "react";
import { Boxes, Check, FolderPlus, Settings2 } from "lucide-react";

import { cn } from "@/lib/utils";
import { colorOf, iconOf, UNGROUPED_ID, useGroups } from "@/lib/groups";
import { useAssets } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

/**
 * Compact group filter dropdown — replaces long wrapping chip rails.
 */
export function GroupFilterButton({
  value,
  onChange,
  site = "all",
  onManage,
  onNew,
  className,
}: {
  value: string;
  onChange: (id: string) => void;
  site?: string;
  onManage?: () => void;
  onNew?: () => void;
  className?: string;
}) {
  const { groups } = useGroups();
  const assetsQ = useAssets({ site, limit: 200 });
  const assets = assetsQ.data?.items ?? [];
  const selected = value === "all" ? undefined : groups.find((g) => g.id === value);
  const selColor = selected ? colorOf(selected.color) : undefined;
  const SelIcon = selected ? iconOf(selected.icon) : Boxes;

  const countFor = (gids: string[] | "all" | "ungrouped") =>
    assets.filter((a) => {
      const mine = groups.filter((g) => g.assetIds.includes(a.id));
      if (gids === "all") return true;
      if (gids === "ungrouped") return mine.length === 0;
      return mine.some((g) => gids.includes(g.id));
    }).length;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" className={cn("gap-2 font-normal", className)}>
          <SelIcon className="size-3.5" style={selColor ? { color: selColor.solid } : undefined} />
          <span className="max-w-44 truncate">{selected ? selected.name : "All groups"}</span>
          {selected && (
            <span
              role="button"
              tabIndex={0}
              aria-label="Clear group filter"
              onClick={(e) => {
                e.stopPropagation();
                onChange("all");
              }}
              className="ml-0.5 rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-foreground"
            >
              ×
            </span>
          )}
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuLabel>Filter by group</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <FilterItem label="All groups" icon={Boxes} active={value === "all"} count={countFor("all")} onClick={() => onChange("all")} />
        <FilterItem label="Ungrouped" icon={Boxes} muted active={value === UNGROUPED_ID} count={countFor("ungrouped")} onClick={() => onChange(UNGROUPED_ID)} />
        <DropdownMenuSeparator />
        {groups.map((g) => {
          const c = colorOf(g.color);
          const Icon = iconOf(g.icon);
          return (
            <FilterItem
              key={g.id}
              label={g.name}
              icon={Icon}
              iconColor={c.solid}
              active={value === g.id}
              count={g.assetIds.length}
              onClick={() => onChange(g.id)}
            />
          );
        })}
        <DropdownMenuSeparator />
        {onNew && <FilterItem label="New group…" icon={FolderPlus} onClick={onNew} />}
        {onManage && <FilterItem label="Manage groups" icon={Settings2} onClick={onManage} />}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function FilterItem({
  label,
  icon: Icon,
  iconColor,
  active,
  muted,
  count,
  onClick,
}: {
  label: string;
  icon: React.ElementType;
  iconColor?: string;
  active?: boolean;
  muted?: boolean;
  count?: number;
  onClick?: () => void;
}) {
  return (
    <DropdownMenuItem onSelect={onClick} className={cn("gap-2", muted && "text-muted-foreground")}>
      <Icon className="size-3.5" style={iconColor ? { color: iconColor } : undefined} />
      <span className="flex-1 truncate">{label}</span>
      {count !== undefined && <span className="tabular text-xs text-muted-foreground">{count}</span>}
      {active && <Check className="size-3.5 text-primary" />}
    </DropdownMenuItem>
  );
}
