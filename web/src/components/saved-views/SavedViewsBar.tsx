import * as React from "react";
import { BookmarkPlus, Bookmark, Trash2 } from "lucide-react";

import { useRouter } from "@/lib/router";
import { useCreateSavedView, useDeleteSavedView, useSavedViews } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { toast } from "@/components/ui/toaster";

// F12 (saved views): a named query string per user, per page. Save captures
// the current hash-router query exactly; apply restores it in one click.
// Sharing inside the org is a later flag on the same row.

export function SavedViewsBar({ page }: { page: "assets" | "findings" | "alerts" }) {
  const { query, navigate } = useRouter();
  const viewsQ = useSavedViews(page);
  const createM = useCreateSavedView(page);
  const deleteM = useDeleteSavedView(page);
  const [naming, setNaming] = React.useState(false);
  const [name, setName] = React.useState("");

  const currentQuery = new URLSearchParams(query).toString();
  const views = viewsQ.data ?? [];

  const save = () => {
    const trimmed = name.trim();
    if (!trimmed) return;
    createM.mutate(
      { name: trimmed, query: currentQuery },
      {
        onSuccess: () => {
          toast({ title: `View "${trimmed}" saved`, variant: "success" });
          setName("");
          setNaming(false);
        },
        onError: (e) => toast({ title: "Save failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" aria-label="Saved views">
          <Bookmark className="size-4" /> Views
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        {views.length === 0 && (
          <div className="px-2 py-3 text-center text-xs text-muted-foreground">No saved views yet.</div>
        )}
        {views.map((v) => (
          <div key={v.id} className="flex items-center gap-1">
            <DropdownMenuItem
              className="flex-1 cursor-pointer"
              onClick={() => navigate(`/${page}${v.query ? `?${v.query}` : ""}`)}
            >
              <span className="truncate">{v.name}</span>
            </DropdownMenuItem>
            <Button
              variant="ghost" size="icon-xs" aria-label={`Delete view ${v.name}`}
              className="mr-1" onClick={() => deleteM.mutate(v.id)}
            >
              <Trash2 className="size-3.5" />
            </Button>
          </div>
        ))}
        {views.length > 0 && <DropdownMenuSeparator />}
        {naming ? (
          <div className="flex items-center gap-1 p-1">
            <input
              autoFocus
              value={name}
              onChange={(e) => setName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") save();
                if (e.key === "Escape") setNaming(false);
              }}
              placeholder="View name…"
              className="h-7 w-full rounded border bg-transparent px-2 text-xs"
            />
            <Button size="xs" onClick={save} disabled={!name.trim() || createM.isPending}>Save</Button>
          </div>
        ) : (
          <DropdownMenuItem className="cursor-pointer" onClick={() => setNaming(true)}>
            <BookmarkPlus className="size-4" /> Save current view
          </DropdownMenuItem>
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
