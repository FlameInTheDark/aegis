import * as React from "react";
import { Bug, Loader2, Pencil, Play, Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ConfirmDialog } from "@/components/ui";
import { EmptyState, SectionTitle } from "@/components/shared";
import {
  useCreateSearchAction, useDeleteSearchAction, usePreviewSearchAction, useRunSearchAction,
  useUpdateSearchAction, useVulnSearchActions, useVulnSearchCapabilities,
} from "@/lib/queries.vulnsearch";
import type { VulnSearchAction } from "@/lib/api-types";

// Search actions: declarative local vulnerability search plans. Shadow
// mode evaluates without creating findings; augment writes findings with
// provenance. The editor is a simple typed form — the server validates the
// DSL and rejects anything URL/command/SQL-shaped.

interface Row {
  field: string;
  op: string;
  values: string;
}

export function SearchActions() {
  const list = useVulnSearchActions();
  const caps = useVulnSearchCapabilities();
  const create = useCreateSearchAction();
  const update = useUpdateSearchAction();
  const del = useDeleteSearchAction();
  const run = useRunSearchAction();
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editTarget, setEditTarget] = React.useState<VulnSearchAction | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<VulnSearchAction | null>(null);

  // form state
  const [name, setName] = React.useState("");
  const [description, setDescription] = React.useState("");
  const [targetKind, setTargetKind] = React.useState("software");
  const [mode, setMode] = React.useState("shadow");
  const [enabled, setEnabled] = React.useState(false);
  const [rows, setRows] = React.useState<Row[]>([{ field: "name", op: "in", values: "" }]);
  const [formError, setFormError] = React.useState<string | null>(null);

  const openCreate = () => {
    setEditTarget(null);
    setName(""); setDescription(""); setTargetKind("software"); setMode("shadow");
    setEnabled(false); setRows([{ field: "name", op: "in", values: "" }]);
    setFormError(null);
    setDialogOpen(true);
  };
  const openEdit = (a: VulnSearchAction) => {
    setEditTarget(a);
    setName(a.name); setDescription(a.description); setTargetKind(a.target_kind);
    setMode(a.mode); setEnabled(a.enabled); setFormError(null);
    setRows(rowsFromSelector(a.selector));
    setDialogOpen(true);
  };

  const buildSelector = () => {
    const all = rows
      .filter((r) => r.field && r.values.trim())
      .map((r) => ({ field: r.field, op: r.op, values: r.values.split(",").map((s) => s.trim()).filter(Boolean) }));
    return all.length > 0 ? { all } : null;
  };

  const actionPayload = (): Record<string, unknown> => {
    const selector = buildSelector() ?? { all: [] };
    return {
      name, description, target_kind: targetKind, mode, enabled, selector,
      priority: 100, confidence_cap: 0.8,
      version_policy: { input: "normalized", projection: "auto" },
    };
  };

  const submit = async () => {
    setFormError(null);
    if (!buildSelector()) {
      setFormError("At least one complete condition row is required");
      return;
    }
    try {
      if (editTarget) {
        await update.mutateAsync({ id: editTarget.id, payload: { ...actionPayload(), revision: editTarget.revision } });
      } else {
        await create.mutateAsync(actionPayload());
      }
      setDialogOpen(false);
    } catch (e) {
      setFormError((e as Error).message || "Save failed");
    }
  };

  const items = list.data?.items ?? [];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted-foreground">
          Local-only search over the synchronized indexes — no external calls, no scripts. Shadow mode explains matches without writing findings.
          {caps.data && caps.data.sources.some((s) => !s.available) && (
            <span className="ml-1 text-warning">
              ({caps.data.sources.filter((s) => !s.available).map((s) => s.source).join(", ")} have no local data yet)
            </span>
          )}
        </p>
        <div className="ml-auto">
          <Button size="sm" onClick={openCreate}><Plus /> New action</Button>
        </div>
      </div>

      <Card className="overflow-hidden py-0">
        {list.isLoading ? (
          <p className="flex items-center gap-2 px-4 py-10 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> Loading actions…</p>
        ) : items.length === 0 ? (
          <EmptyState
            icon={Bug}
            title="No search actions yet"
            description="Create a declarative action to match inventory against the local NVD/CVE/OSV/OVAL indexes — e.g. map openssh-server to openbsd:openssh."
            action={<Button size="sm" onClick={openCreate}><Plus /> New action</Button>}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-4">Action</TableHead>
                <TableHead>Target</TableHead>
                <TableHead>Mode</TableHead>
                <TableHead>Selector</TableHead>
                <TableHead className="text-right">Enabled</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="max-w-56 pl-4">
                    <button type="button" className="truncate text-left font-medium hover:text-primary" onClick={() => openEdit(a)}>{a.name}</button>
                    <div className="truncate text-xs text-muted-foreground">{a.description || `rev ${a.revision}`}</div>
                  </TableCell>
                  <TableCell className="text-xs capitalize">{a.target_kind}</TableCell>
                  <TableCell>
                    <Badge variant={a.mode === "shadow" ? "outline" : a.mode === "augment" ? "default" : "secondary"} className="text-[11px]">{a.mode}</Badge>
                  </TableCell>
                  <TableCell className="max-w-80">
                    <span className="line-clamp-1 font-mono text-xs text-muted-foreground">{selectorText(a.selector)}</span>
                  </TableCell>
                  <TableCell className="text-right">
                    <Switch checked={a.enabled} onCheckedChange={(v) => update.mutate({ id: a.id, payload: { enabled: v, revision: a.revision } })} aria-label={`Enable ${a.name}`} />
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-0.5">
                      <Button variant="ghost" size="icon-xs" title="Run now" aria-label={`Run ${a.name}`} onClick={() => run.mutate(a.id)} disabled={!a.enabled || run.isPending}>
                        <Play />
                      </Button>
                      <Button variant="ghost" size="icon-xs" title="Edit" aria-label={`Edit ${a.name}`} onClick={() => openEdit(a)}>
                        <Pencil />
                      </Button>
                      <Button variant="ghost" size="icon-xs" title="Delete" aria-label={`Delete ${a.name}`} onClick={() => setDeleteTarget(a)}>
                        <Trash2 />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Card>

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="text-sm">{editTarget ? "Edit search action" : "New search action"}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3">
            {formError && <Alert variant="destructive" className="py-2"><AlertDescription className="text-xs">{formError}</AlertDescription></Alert>}
            <div className="grid gap-1.5">
              <Label htmlFor="sa-name">Name</Label>
              <Input id="sa-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. OpenSSH package aliases" />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="sa-desc">Description</Label>
              <Input id="sa-desc" value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Why this identity mapping exists" />
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              <div className="grid gap-1.5">
                <Label>Target</Label>
                <Select value={targetKind} onValueChange={setTargetKind}>
                  <SelectTrigger aria-label="Target kind"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="software">Software packages</SelectItem>
                    <SelectItem value="service">Network services</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label>Mode</Label>
                <Select value={mode} onValueChange={setMode}>
                  <SelectTrigger aria-label="Mode"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="shadow">Shadow (no findings)</SelectItem>
                    <SelectItem value="augment">Augment (write findings)</SelectItem>
                    <SelectItem value="fallback_only">Fallback only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
            <div className="grid gap-1.5">
              <Label>Selector — match targets by</Label>
              {rows.map((row, i) => (
                <div key={i} className="flex flex-wrap items-center gap-2">
                  <Select value={row.field} onValueChange={(v) => setRows(rows.map((r, j) => (j === i ? { ...r, field: v } : r)))}>
                    <SelectTrigger aria-label={`Field ${i + 1}`} className="w-36"><SelectValue /></SelectTrigger>
                    <SelectContent>{(caps.data?.fields ?? ["name", "vendor", "product", "ecosystem", "version", "source"]).map((f) => (
                      <SelectItem key={f} value={f}>{f}</SelectItem>
                    ))}</SelectContent>
                  </Select>
                  <Select value={row.op} onValueChange={(v) => setRows(rows.map((r, j) => (j === i ? { ...r, op: v } : r)))}>
                    <SelectTrigger aria-label={`Operator ${i + 1}`} className="w-36"><SelectValue /></SelectTrigger>
                    <SelectContent>{(caps.data?.operators ?? ["eq", "in", "not_in", "contains", "starts_with"]).map((o) => (
                      <SelectItem key={o} value={o}>{o}</SelectItem>
                    ))}</SelectContent>
                  </Select>
                  <Input
                    value={row.values}
                    onChange={(e) => setRows(rows.map((r, j) => (j === i ? { ...r, values: e.target.value } : r)))}
                    placeholder="comma, separated, values"
                    aria-label={`Values ${i + 1}`}
                    className="flex-1"
                  />
                  <Button variant="ghost" size="icon-xs" aria-label={`Remove row ${i + 1}`} onClick={() => setRows(rows.filter((_, j) => j !== i))}>
                    <Trash2 />
                  </Button>
                </div>
              ))}
              <Button variant="outline" size="sm" className="w-fit" onClick={() => setRows([...rows, { field: "ecosystem", op: "in", values: "" }])}>
                <Plus /> Add condition
              </Button>
            </div>
            {editTarget && <PreviewPanel payloadGetter={actionPayload} />}
            <div className="flex items-center justify-between rounded-lg border bg-muted/30 px-3 py-2">
              <span className="text-xs text-muted-foreground">Shadow actions never write findings; augment actions create findings with full provenance.</span>
              <Switch checked={enabled} onCheckedChange={setEnabled} aria-label="Enable action" />
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={submit} disabled={!name || create.isPending || update.isPending}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleteTarget}
        title={`Delete action “${deleteTarget?.name}”?`}
        body="Runs and provenance are kept; the action stops contributing matches."
        confirmLabel="Delete action"
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => {
          if (deleteTarget) del.mutate(deleteTarget.id);
          setDeleteTarget(null);
        }}
      />
    </div>
  );
}

function PreviewPanel({ payloadGetter }: { payloadGetter: () => Record<string, unknown> }) {
  const preview = usePreviewSearchAction();
  const [busy, setBusy] = React.useState(false);
  const runPreview = async () => {
    setBusy(true);
    try {
      await preview.mutateAsync(payloadGetter());
    } finally {
      setBusy(false);
    }
  };
  const res = preview.data;
  return (
    <div className="rounded-lg border bg-muted/30 p-3">
      <div className="flex items-center justify-between">
        <SectionTitle>Preview (read-only)</SectionTitle>
        <Button variant="outline" size="xs" onClick={runPreview} disabled={busy}>
          {busy && <Loader2 className="size-3 animate-spin" />} Run preview
        </Button>
      </div>
      {preview.isError && <p className="mt-1 text-xs text-destructive">{(preview.error as Error).message}</p>}
      {res && (
        <div className="mt-1.5 text-xs">
          <p>
            <span className="tabular">{res.targets}</span> target{res.targets === 1 ? "" : "s"} selected{res.truncated ? " (capped)" : ""} ·{" "}
            <span className="tabular">{res.matches}</span> match{res.matches === 1 ? "" : "es"}
          </p>
          {(res.rows ?? []).slice(0, 5).map((r) => (
            <p key={`${r.target.id}-${r.cve_id}`} className="mt-1 font-mono text-[11px] text-muted-foreground">
              {r.cve_id} · {r.match_type} · {r.target.name} {r.target.version}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function rowsFromSelector(selector: Record<string, unknown>): Row[] {
  const all = (selector as { all?: { field: string; op: string; values?: string[] }[] }).all;
  if (!Array.isArray(all) || all.length === 0) return [{ field: "name", op: "in", values: "" }];
  return all.map((c) => ({ field: c.field, op: c.op, values: (c.values ?? []).join(", ") }));
}

function selectorText(selector: Record<string, unknown>): string {
  const rows = rowsFromSelector(selector);
  return rows.map((r) => `${r.field} ${r.op} [${r.values}]`).join(" AND ");
}
