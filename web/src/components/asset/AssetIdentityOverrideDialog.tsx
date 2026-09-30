import * as React from "react";

import { assetTypeMeta } from "@/lib/domain";
import type { AssetType } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

const SCANNED_TYPE = "__scanned__";
const NO_PARENT = "__none__";

/**
 * IdentityOverrideDialog — non-destructive analyst corrections for the
 * asset's display name, device type and topology parent. Detection
 * occasionally mislabels a host (a router fingerprinted as a workstation)
 * or misses its wiring entirely (a transparent L2 switch never shows up as
 * a routable hop, so hosts behind it are wired straight to the router);
 * overrides live in dedicated columns (migrations 0031/0032) and are never
 * applied to the scanned data itself, so clearing them restores exactly
 * what the scanner reported.
 */
export function IdentityOverrideDialog({
  open,
  onOpenChange,
  asset,
  onSave,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  asset: {
    id: string;
    label: string;
    nameOverride: string | null;
    typeOverride: string | null;
    effectiveType: AssetType;
    parentOverride: string | null;
    /** human label of the currently pinned parent, resolved by the page */
    parentLabel: string | null;
    /** selectable parent candidates (same site, this asset excluded) */
    candidates: { id: string; label: string }[];
  };
  onSave: (nameOverride: string | null, deviceTypeOverride: string | null, parentOverride: string | null) => void;
}) {
  const [name, setName] = React.useState(asset.nameOverride ?? "");
  const [type, setType] = React.useState(asset.typeOverride ?? SCANNED_TYPE);
  const [parent, setParent] = React.useState(asset.parentOverride ?? NO_PARENT);
  React.useEffect(() => {
    if (open) {
      setName(asset.nameOverride ?? "");
      setType(asset.typeOverride ?? SCANNED_TYPE);
      setParent(asset.parentOverride ?? NO_PARENT);
    }
  }, [open, asset.nameOverride, asset.typeOverride, asset.parentOverride]);
  const dirty =
    (name.trim() || null) !== asset.nameOverride ||
    (type === SCANNED_TYPE ? null : type) !== asset.typeOverride ||
    (parent === NO_PARENT ? null : parent) !== asset.parentOverride;
  // the current parent stays selectable even when it is not among the page's
  // candidates (beyond the 200-asset window, or in another site)
  const options =
    asset.parentOverride && !asset.candidates.some((c) => c.id === asset.parentOverride)
      ? [{ id: asset.parentOverride, label: asset.parentLabel ?? asset.parentOverride }, ...asset.candidates]
      : asset.candidates;
  const typeOptions = Object.entries(assetTypeMeta) as [AssetType, { label: string }][];
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit identity</DialogTitle>
          <DialogDescription>{asset.label}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label htmlFor="asset-name-override">Display name</Label>
            <Input
              id="asset-name-override"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Leave empty to show the scanned name"
              className="h-8"
            />
            <p className="text-[11px] text-muted-foreground">
              Shown everywhere instead of the scanned hostname. Clear it to reveal the scanned value again.
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label>Device type</Label>
            <Select value={type} onValueChange={setType}>
              <SelectTrigger className="w-full text-xs capitalize">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={SCANNED_TYPE} className="capitalize">
                  Scanned value ({assetTypeMeta[asset.effectiveType].label})
                </SelectItem>
                {typeOptions.map(([k, m]) => (
                  <SelectItem key={k} value={k} className="capitalize">
                    {m.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">
              Use this when detection mislabels the host — a router read as a workstation, for example.
            </p>
          </div>
          <div className="grid gap-1.5">
            <Label>Topology parent</Label>
            <Select value={parent} onValueChange={setParent}>
              <SelectTrigger className="w-full text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={NO_PARENT}>Observed evidence (no pin)</SelectItem>
                {options.map((c) => (
                  <SelectItem key={c.id} value={c.id}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-[11px] text-muted-foreground">
              Pin this asset beneath another node on the topology map — for hosts sitting behind a transparent switch
              that a network scan cannot see as a hop.
            </p>
          </div>
          <p className="rounded-md border bg-muted/30 px-2.5 py-2 text-[11px] leading-relaxed text-muted-foreground">
            Overrides are non-destructive: the scanned data is kept untouched and comes back the moment the
            override is cleared.
          </p>
        </div>
        <DialogFooter>
          {(asset.nameOverride || asset.typeOverride || asset.parentOverride) && (
            <Button
              variant="outline"
              className="mr-auto"
              onClick={() => {
                onSave(null, null, null);
                onOpenChange(false);
              }}
            >
              Restore scanned data
            </Button>
          )}
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            disabled={!dirty}
            onClick={() => {
              onSave(name.trim() || null, type === SCANNED_TYPE ? null : type, parent === NO_PARENT ? null : parent);
              onOpenChange(false);
            }}
          >
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
