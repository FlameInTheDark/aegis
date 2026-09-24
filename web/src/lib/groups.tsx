import * as React from "react";
import {
  Boxes, Briefcase, Building2, Cpu, FlaskConical, Globe, HardDrive, Home,
  Network, Printer, Router, Server, Shield, Video, Warehouse, Wifi, type LucideIcon,
} from "lucide-react";

import type { AssetGroup } from "@/data/types";
import { useAssetGroups, useCreateGroup, useDeleteGroup, useGroupMembership, useUpdateGroup } from "@/lib/queries";

/* ------------------------------------------------------------------ */
/* Palette                                                             */
/* ------------------------------------------------------------------ */
export interface GroupColor {
  id: string;
  label: string;
  solid: string;
  soft: string;
  border: string;
}

export const groupPalette: GroupColor[] = [
  { id: "indigo", label: "Indigo", solid: "oklch(0.66 0.17 275)", soft: "oklch(0.66 0.17 275 / 0.16)", border: "oklch(0.66 0.17 275 / 0.42)" },
  { id: "cyan", label: "Cyan", solid: "oklch(0.75 0.13 210)", soft: "oklch(0.75 0.13 210 / 0.16)", border: "oklch(0.75 0.13 210 / 0.42)" },
  { id: "emerald", label: "Emerald", solid: "oklch(0.74 0.16 160)", soft: "oklch(0.74 0.16 160 / 0.16)", border: "oklch(0.74 0.16 160 / 0.42)" },
  { id: "amber", label: "Amber", solid: "oklch(0.8 0.16 85)", soft: "oklch(0.8 0.16 85 / 0.16)", border: "oklch(0.8 0.16 85 / 0.42)" },
  { id: "orange", label: "Orange", solid: "oklch(0.72 0.18 45)", soft: "oklch(0.72 0.18 45 / 0.16)", border: "oklch(0.72 0.18 45 / 0.42)" },
  { id: "rose", label: "Rose", solid: "oklch(0.68 0.19 12)", soft: "oklch(0.68 0.19 12 / 0.16)", border: "oklch(0.68 0.19 12 / 0.42)" },
  { id: "violet", label: "Violet", solid: "oklch(0.68 0.19 305)", soft: "oklch(0.68 0.19 305 / 0.16)", border: "oklch(0.68 0.19 305 / 0.42)" },
  { id: "slate", label: "Slate", solid: "oklch(0.62 0.02 262)", soft: "oklch(0.62 0.02 262 / 0.16)", border: "oklch(0.62 0.02 262 / 0.42)" },
];

export const colorOf = (id: string): GroupColor => groupPalette.find((c) => c.id === id) ?? groupPalette[7];

/** Keys are the canonical STORED icon ids — lowercase, because the API
 *  sanitizes group metadata with a lowercase pass before persisting. The
 *  picker used to iterate PascalCase keys ("Boxes"), so everything round-
 *  tripped through the DB as "boxes" and every lookup missed, rendering
 *  the same fallback icon on every group. */
export const groupIcons: Record<string, LucideIcon> = {
  server: Server, network: Network, router: Router, video: Video,
  building2: Building2, briefcase: Briefcase, flaskconical: FlaskConical,
  globe: Globe, home: Home, boxes: Boxes, warehouse: Warehouse, wifi: Wifi,
  printer: Printer, cpu: Cpu, harddrive: HardDrive, shield: Shield,
};

export const iconOf = (id?: string): LucideIcon =>
  groupIcons[(id ?? "").toLowerCase()] ?? Boxes;

/* ------------------------------------------------------------------ */
/* Store — server-backed (persisted in Postgres via /asset-groups)     */
/* ------------------------------------------------------------------ */
interface GroupsContextValue {
  groups: AssetGroup[];
  byId: (id: string) => AssetGroup | undefined;
  groupsOf: (assetId: string) => AssetGroup[];
  primaryOf: (assetId: string) => AssetGroup | undefined;
  loading: boolean;
  /** opts.onSuccess fires after the server accepted the change (errors toast globally). */
  create: (g: Omit<AssetGroup, "id"> & { id?: string }, opts?: { onSuccess?: () => void }) => void;
  update: (id: string, patch: Partial<Omit<AssetGroup, "id">>, opts?: { onSuccess?: () => void }) => void;
  remove: (id: string) => void;
  assign: (groupId: string, assetIds: string[], opts?: { onSuccess?: () => void }) => void;
  unassign: (groupId: string, assetIds: string[], opts?: { onSuccess?: () => void }) => void;
  toggle: (groupId: string, assetId: string) => void;
}

const GroupsContext = React.createContext<GroupsContextValue | null>(null);

export function GroupsProvider({ children }: { children: React.ReactNode }) {
  const { data: groups = [], isLoading } = useAssetGroups();
  // useAssetGroups maps kind to the union; the generic infers string, pin it.
  const typedGroups = groups as AssetGroup[];
  const createGroup = useCreateGroup();
  const updateGroup = useUpdateGroup();
  const deleteGroup = useDeleteGroup();
  const membership = useGroupMembership();

  const value = React.useMemo<GroupsContextValue>(() => {
    const byId = (id: string) => typedGroups.find((g) => g.id === id);
    const groupsOf = (assetId: string) => typedGroups.filter((g) => g.assetIds.includes(assetId));
    return {
      groups: typedGroups,
      byId,
      groupsOf,
      primaryOf: (assetId) => groupsOf(assetId)[0],
      loading: isLoading,
      // assetIds ride along so a group can be created WITH its members and
      // edited with replace-all membership — previously they were dropped,
      // which is why ticking assets in the dialog never persisted anything.
      create: (g, opts) =>
        createGroup.mutate(
          { name: g.name, description: g.description, color: g.color, icon: g.icon, kind: g.kind, asset_ids: g.assetIds },
          opts,
        ),
      update: (id, patch, opts) => {
        const { assetIds, ...rest } = patch;
        updateGroup.mutate({ id, ...rest, asset_ids: assetIds }, opts);
      },
      remove: (id) => deleteGroup.mutate(id),
      assign: (groupId, assetIds, opts) => membership.mutate({ id: groupId, add: assetIds }, opts),
      unassign: (groupId, assetIds, opts) => membership.mutate({ id: groupId, remove: assetIds }, opts),
      toggle: (groupId, assetId) => {
        const g = groups.find((x) => x.id === groupId);
        if (!g) return;
        if (g.assetIds.includes(assetId)) membership.mutate({ id: groupId, remove: [assetId] });
        else membership.mutate({ id: groupId, add: [assetId] });
      },
    };
  }, [typedGroups, isLoading, createGroup, updateGroup, deleteGroup, membership]);

  return <GroupsContext.Provider value={value}>{children}</GroupsContext.Provider>;
}

export function useGroups() {
  const ctx = React.useContext(GroupsContext);
  if (!ctx) throw new Error("useGroups must be used inside GroupsProvider");
  return ctx;
}

export const UNGROUPED_ID = "__ungrouped__";
