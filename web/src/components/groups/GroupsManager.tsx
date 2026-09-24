import * as React from "react";
import { Boxes, Check, ChevronLeft, Pencil, Plus, Search, Trash2, Users } from "lucide-react";

import { cn } from "@/lib/utils";
import { colorOf, groupIcons, groupPalette, iconOf, useGroups } from "@/lib/groups";
import { useAssets } from "@/lib/queries";
import { assetTypeMeta } from "@/lib/domain";
import type { AssetGroup } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { toast } from "@/components/ui/toaster";
import { EmptyState, Mono, RiskMeter } from "@/components/shared";

type Draft = Omit<AssetGroup, "id"> & { id?: string };

const emptyDraft: Draft = { name: "", description: "", color: "indigo", icon: "boxes", kind: "custom", assetIds: [] };

export function GroupsManager({
  open,
  onOpenChange,
  initialGroupId,
  preselectAssetIds,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  initialGroupId?: string;
  /** when opened from a bulk selection, a new group starts with these members */
  preselectAssetIds?: string[];
}) {
  const { groups, create, update, remove } = useGroups();
  const [q, setQ] = React.useState("");
  const assetsQ = useAssets({ search: q || undefined, limit: 200 });
  const allAssetsQ = useAssets({ limit: 200 });
  const assets = allAssetsQ.data?.items ?? [];
  const [editing, setEditing] = React.useState<Draft | null>(null);

  React.useEffect(() => {
    if (!open) {
      setEditing(null);
      setQ("");
      return;
    }
    if (initialGroupId) {
      const g = groups.find((x) => x.id === initialGroupId);
      if (g) setEditing({ ...g });
    } else if (preselectAssetIds?.length) {
      setEditing({ ...emptyDraft, assetIds: [...preselectAssetIds] });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, initialGroupId]);

  const save = () => {
    if (!editing || !editing.name.trim()) return;
    const name = editing.name.trim();
    if (editing.id) {
      const { id, ...patch } = editing;
      // Success/error toasts fire from the mutation result (onSuccess here,
      // onError globally per-mutation) — never before the request resolves.
      update(id, patch, {
        onSuccess: () => toast({ title: `Group “${name}” updated`, variant: "success" }),
      });
    } else {
      const count = editing.assetIds.length;
      create(editing, {
        onSuccess: () =>
          toast({
            title: `Group “${name}” created`,
            description: `${count} asset${count === 1 ? "" : "s"} assigned.`,
            variant: "success",
          }),
      });
    }
    setEditing(null);
  };

  const filteredAssets = assetsQ.data?.items ?? [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[86vh] flex-col overflow-hidden sm:max-w-3xl">
        {!editing ? (
          <>
            <DialogHeader>
              <DialogTitle>Asset groups</DialogTitle>
              <DialogDescription>
                Organise the inventory into rooms, functions or owners. Groups appear as filters in Assets and as clusters in Topology.
              </DialogDescription>
            </DialogHeader>
            <div className="min-h-0 flex-1 overflow-y-auto">
              {groups.length === 0 ? (
                <EmptyState icon={Boxes} title="No groups yet" description="Create your first group to organise assets by room, function or owner." />
              ) : (
                <div className="grid gap-2 sm:grid-cols-2">
                  {groups.map((g) => {
                    const c = colorOf(g.color);
                    const Icon = iconOf(g.icon);
                    const members = assets.filter((a) => g.assetIds.includes(a.id));
                    const risk = members.length ? Math.round(members.reduce((n, a) => n + a.risk, 0) / members.length) : 0;
                    return (
                      <div key={g.id} className="flex flex-col gap-2 rounded-lg border p-3" style={{ borderColor: c.border }}>
                        <div className="flex items-start gap-2.5">
                          <span className="flex size-8 shrink-0 items-center justify-center rounded-md" style={{ backgroundColor: c.soft, color: c.solid }}>
                            <Icon className="size-4" />
                          </span>
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm font-medium">{g.name}</div>
                            <div className="text-[11px] capitalize text-muted-foreground">
                              {g.kind} · {g.assetIds.length} asset{g.assetIds.length === 1 ? "" : "s"}
                            </div>
                          </div>
                          <div className="flex gap-0.5">
                            <Button variant="ghost" size="icon-xs" onClick={() => setEditing({ ...g })}>
                              <Pencil />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon-xs"
                              className="text-muted-foreground hover:text-destructive"
                              onClick={() => {
                                remove(g.id);
                                toast({ title: `Group “${g.name}” deleted`, description: "Assets were not modified.", variant: "warning" });
                              }}
                            >
                              <Trash2 />
                            </Button>
                          </div>
                        </div>
                        {g.description && <p className="line-clamp-2 text-xs text-muted-foreground">{g.description}</p>}
                        <div className="flex items-center justify-between border-t pt-2 text-xs">
                          <span className="text-muted-foreground">avg. risk</span>
                          <RiskMeter value={risk} />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
            <DialogFooter className="border-t pt-4">
              <Button variant="ghost" onClick={() => onOpenChange(false)}>
                Close
              </Button>
              <Button onClick={() => setEditing({ ...emptyDraft, assetIds: preselectAssetIds ? [...preselectAssetIds] : [] })}>
                <Plus /> New group
              </Button>
            </DialogFooter>
          </>
        ) : (
          <>
            <DialogHeader>
              <DialogTitle className="flex items-center gap-2">
                <Button variant="ghost" size="icon-xs" onClick={() => setEditing(null)}>
                  <ChevronLeft />
                </Button>
                {editing.id ? "Edit group" : "New group"}
              </DialogTitle>
              <DialogDescription>Pick a colour and icon — they are used for the topology clusters and inventory chips.</DialogDescription>
            </DialogHeader>

            <div className="grid min-h-0 flex-1 gap-4 overflow-hidden sm:grid-cols-2">
              <div className="flex flex-col gap-3 overflow-y-auto pr-1">
                <div className="grid gap-1.5">
                  <Label htmlFor="g-name">Name</Label>
                  <Input id="g-name" value={editing.name} onChange={(e) => setEditing({ ...editing, name: e.target.value })} placeholder="Room 1, IoT devices, DMZ…" autoFocus />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="g-desc">Description</Label>
                  <Textarea id="g-desc" value={editing.description ?? ""} onChange={(e) => setEditing({ ...editing, description: e.target.value })} className="min-h-16" placeholder="Optional context for other analysts" />
                </div>
                <div className="grid gap-1.5">
                  <Label>Kind</Label>
                  <Select value={editing.kind} onValueChange={(v) => setEditing({ ...editing, kind: v as AssetGroup["kind"] })}>
                    <SelectTrigger className="w-full capitalize">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="location">Location — room, floor, site area</SelectItem>
                      <SelectItem value="function">Function — role on the network</SelectItem>
                      <SelectItem value="owner">Owner — team or business unit</SelectItem>
                      <SelectItem value="custom">Custom</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-1.5">
                  <Label>Colour</Label>
                  <div className="flex flex-wrap gap-1.5">
                    {groupPalette.map((c) => (
                      <button
                        key={c.id}
                        onClick={() => setEditing({ ...editing, color: c.id })}
                        style={{ backgroundColor: c.soft, borderColor: editing.color === c.id ? c.solid : "transparent" }}
                        className="flex size-8 items-center justify-center rounded-md border-2 cursor-pointer"
                        title={c.label}
                      >
                        <span className="size-3.5 rounded-full" style={{ backgroundColor: c.solid }} />
                      </button>
                    ))}
                  </div>
                </div>
                <div className="grid gap-1.5">
                  <Label>Icon</Label>
                  <div className="flex flex-wrap gap-1.5">
                    {Object.keys(groupIcons).map((k) => {
                      const Icon = groupIcons[k];
                      const active = editing.icon === k;
                      return (
                        <button
                          key={k}
                          onClick={() => setEditing({ ...editing, icon: k })}
                          className={cn("flex size-8 items-center justify-center rounded-md border transition-colors cursor-pointer", active ? "border-primary bg-primary/10 text-primary" : "text-muted-foreground hover:bg-accent")}
                        >
                          <Icon className="size-4" />
                        </button>
                      );
                    })}
                  </div>
                </div>
              </div>

              {/* Members */}
              <div className="flex min-h-0 flex-col gap-2">
                <div className="flex items-center justify-between">
                  <Label className="flex items-center gap-1.5">
                    <Users className="size-3.5" /> Members
                  </Label>
                  <Badge variant="muted" className="tabular">
                    {editing.assetIds.length} selected
                  </Badge>
                </div>
                <div className="relative">
                  <Search className="pointer-events-none absolute left-2.5 top-1/2 size-3.5 -translate-y-1/2 text-muted-foreground" />
                  <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Filter assets…" className="h-8 pl-8 text-[13px]" />
                </div>
                <ScrollArea className="min-h-0 flex-1 rounded-lg border">
                  <ul className="divide-y">
                    {filteredAssets.map((a) => {
                      const Icon = assetTypeMeta[a.type].icon;
                      const checked = editing.assetIds.includes(a.id);
                      return (
                        <li key={a.id}>
                          <label className="flex cursor-pointer items-center gap-2.5 px-2.5 py-1.5 text-sm transition-colors hover:bg-accent/40">
                            <Checkbox
                              checked={checked}
                              onCheckedChange={(v) =>
                                setEditing({
                                  ...editing,
                                  assetIds: v ? [...editing.assetIds, a.id] : editing.assetIds.filter((x) => x !== a.id),
                                })
                              }
                            />
                            <Icon className="size-3.5 shrink-0 text-muted-foreground" />
                            <span className="min-w-0 flex-1 truncate">{a.hostname ?? a.ip}</span>
                            <Mono className="text-[11px] text-muted-foreground">{a.ip}</Mono>
                          </label>
                        </li>
                      );
                    })}
                  </ul>
                </ScrollArea>
              </div>
            </div>

            <DialogFooter className="border-t pt-4">
              <Button variant="ghost" onClick={() => setEditing(null)}>
                Cancel
              </Button>
              <Button onClick={save} disabled={!editing.name.trim()}>
                <Check /> {editing.id ? "Save changes" : "Create group"}
              </Button>
            </DialogFooter>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
