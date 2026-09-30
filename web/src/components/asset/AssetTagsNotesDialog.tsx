import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

/** TagsNotesDialog — editor for the asset's analyst tags and notes. */
export function TagsNotesDialog({
  open,
  onOpenChange,
  asset,
  onSave,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  asset: { id: string; tags: string[]; notes?: string; label: string };
  onSave: (tags: string[], notes: string) => void;
}) {
  const [tags, setTags] = React.useState<string[]>(asset.tags);
  const [notes, setNotes] = React.useState(asset.notes ?? "");
  const [draft, setDraft] = React.useState("");
  React.useEffect(() => {
    if (open) {
      setTags(asset.tags);
      setNotes(asset.notes ?? "");
    }
  }, [open, asset.tags, asset.notes]);
  const add = () => {
    const t = draft.trim();
    if (t && !tags.includes(t)) setTags([...tags, t]);
    setDraft("");
  };
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Edit tags &amp; notes</DialogTitle>
          <DialogDescription>{asset.label}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">Tags</span>
            <div className="flex flex-wrap gap-1.5">
              {tags.map((t) => (
                <Badge key={t} variant="muted" className="gap-1">
                  {t}
                  <button onClick={() => setTags(tags.filter((x) => x !== t))} className="text-muted-foreground hover:text-foreground cursor-pointer">×</button>
                </Badge>
              ))}
            </div>
            <div className="flex gap-2">
              <Input
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") {
                    e.preventDefault();
                    add();
                  }
                }}
                placeholder="Add a tag…"
                className="h-8"
              />
              <Button variant="outline" size="sm" onClick={add}>
                Add
              </Button>
            </div>
          </div>
          <div className="grid gap-1.5">
            <span className="text-sm font-medium">Notes</span>
            <textarea
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              className="min-h-24 rounded-md border bg-transparent px-3 py-2 text-sm"
              placeholder="Analyst notes for this asset…"
            />
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button onClick={() => { onSave(tags, notes); onOpenChange(false); }}>Save</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
