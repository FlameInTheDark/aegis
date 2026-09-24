import { TriangleAlert } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useDeleteAsset } from "@/lib/queries";
import { toast } from "@/components/ui/toaster";

interface DeleteAssetDialogProps {
  /** the asset to remove (null = nothing to mount) */
  asset: { id: string; hostname?: string; ip: string } | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** called after the row was deleted (navigate away, clear selection…) */
  onDeleted?: () => void;
}

// Confirmation for the destructive asset delete (DELETE /assets/{id}).
// Deletion drops the asset with its services, software, findings and group
// memberships — unlike the other one-click removals (sites, groups,
// profiles) this one destroys collected evidence, so it asks first.
// Rediscovery is the recovery path, not an undo: a matching scan re-creates
// the asset and an installed endpoint re-links on its next report, but the
// collected history does not come back.
export function DeleteAssetDialog({ asset, open, onOpenChange, onDeleted }: DeleteAssetDialogProps) {
  const deleteM = useDeleteAsset();
  if (!asset) return null;

  const name = asset.hostname ?? asset.ip;

  const confirm = () => {
    deleteM.mutate(asset.id, {
      onSuccess: () => {
        toast({
          title: `${name} deleted`,
          description: "It will be rediscovered by the next scan or endpoint report.",
          variant: "warning",
        });
        onOpenChange(false);
        onDeleted?.();
      },
      onError: (e) => toast({ title: "Delete failed", description: (e as Error).message, variant: "error" }),
    });
  };

  return (
    <Dialog open={open} onOpenChange={(o) => !deleteM.isPending && onOpenChange(o)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <TriangleAlert className="size-4 text-destructive" /> Delete {name}?
          </DialogTitle>
          <DialogDescription>
            The asset is removed with its services, software, findings and group
            memberships. This cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          If the device is still on the network it will be rediscovered: a
          matching scan re-creates it, and an installed endpoint re-links on its
          next report.
        </p>
        <DialogFooter>
          <Button variant="outline" size="sm" onClick={() => onOpenChange(false)} disabled={deleteM.isPending}>
            Cancel
          </Button>
          <Button variant="destructive" size="sm" onClick={confirm} disabled={deleteM.isPending}>
            {deleteM.isPending ? "Deleting…" : "Delete asset"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
