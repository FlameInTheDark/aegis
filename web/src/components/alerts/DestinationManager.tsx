import * as React from "react";
import { Loader2, Play, Plus, RotateCcw, Trash2, Webhook } from "lucide-react";

import { timeAgo } from "@/lib/utils";
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
import { EmptyState, SectionTitle, StateBadge } from "@/components/shared";
import {
  useAlertDestinations, useCreateDestination, useDeleteDestination, useReplayDeadDeliveries,
  useTestDestination, useUpdateDestination, type AlertDestination,
} from "@/lib/queries.alerts";

// Destinations: in-app (built-in) and webhook channels. Secrets are never
// rendered — only the masked reference — and rotation replaces the secret
// server-side. Test posts a signed synthetic delivery; delivery health and
// dead-letter replay live here too.

export function DestinationManager() {
  const list = useAlertDestinations();
  const create = useCreateDestination();
  const update = useUpdateDestination();
  const del = useDeleteDestination();
  const test = useTestDestination();
  const replay = useReplayDeadDeliveries();

  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [editTarget, setEditTarget] = React.useState<AlertDestination | null>(null);
  const [name, setName] = React.useState("");
  const [url, setUrl] = React.useState("");
  const [minSeverity, setMinSeverity] = React.useState("low");
  const [deleteTarget, setDeleteTarget] = React.useState<AlertDestination | null>(null);
  const [formError, setFormError] = React.useState<string | null>(null);

  const openCreate = () => {
    setEditTarget(null);
    setName("");
    setUrl("");
    setMinSeverity("low");
    setFormError(null);
    setDialogOpen(true);
  };
  const openEdit = (d: AlertDestination) => {
    setEditTarget(d);
    setName(d.name);
    setUrl(d.url);
    setMinSeverity(d.minSeverity);
    setFormError(null);
    setDialogOpen(true);
  };

  const submit = async () => {
    setFormError(null);
    try {
      if (editTarget) {
        await update.mutateAsync({ id: editTarget.id, payload: { name, url, min_severity: minSeverity } });
      } else {
        await create.mutateAsync({ name, url, kind: "webhook", min_severity: minSeverity, events: ["fired", "recovered", "repeat"], enabled: true });
      }
      setDialogOpen(false);
    } catch (e) {
      setFormError((e as Error).message || "Save failed");
    }
  };

  const items = list.data ?? [];

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-xs text-muted-foreground">
          Webhooks receive every alert as a signed JSON payload (HMAC-SHA256 in <code className="font-mono text-[11px]">X-Aegis-Signature</code>).
          Secrets are stored server-side and only shown masked.
        </p>
        <div className="ml-auto">
          <Button size="sm" onClick={openCreate}><Plus /> New webhook</Button>
        </div>
      </div>

      <Card className="overflow-hidden py-0">
        {list.isLoading ? (
          <p className="flex items-center gap-2 px-4 py-10 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" /> Loading destinations…</p>
        ) : items.length === 0 ? (
          <EmptyState
            icon={Webhook}
            title="No destinations yet"
            description="Add a webhook to forward alerts — every alert is also always visible in the console."
            action={<Button size="sm" onClick={openCreate}><Plus /> New webhook</Button>}
          />
        ) : (
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="pl-4">Destination</TableHead>
                <TableHead>URL / kind</TableHead>
                <TableHead>Min severity</TableHead>
                <TableHead>Delivery health</TableHead>
                <TableHead>Last success</TableHead>
                <TableHead className="w-20 text-right">Enabled</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((d) => {
                const dead = d.deliveries["dead"] ?? 0;
                return (
                  <TableRow key={d.id}>
                    <TableCell className="max-w-48 pl-4">
                      <button type="button" className="truncate font-medium hover:text-primary" onClick={() => openEdit(d)}>{d.name}</button>
                      {d.lastError && <div className="truncate text-xs text-destructive" title={d.lastError}>{d.lastError}</div>}
                    </TableCell>
                    <TableCell className="max-w-72">
                      {d.kind === "webhook" ? (
                        <span className="block truncate font-mono text-xs text-muted-foreground" title={d.url}>{d.url}</span>
                      ) : (
                        <Badge variant="outline" className="text-[11px]">in-app</Badge>
                      )}
                    </TableCell>
                    <TableCell className="capitalize text-xs">{d.minSeverity}</TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <span className="tabular text-success">{d.deliveries["sent"] ?? 0} sent</span>
                        {(d.deliveries["retry"] ?? 0) > 0 && <span className="tabular text-warning">{d.deliveries["retry"]} retrying</span>}
                        {dead > 0 && <span className="tabular text-destructive">{dead} dead</span>}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{d.lastSuccessAt ? timeAgo(d.lastSuccessAt) : "never"}</TableCell>
                    <TableCell className="text-right">
                      <Switch checked={d.enabled} onCheckedChange={(v) => update.mutate({ id: d.id, payload: { enabled: v } })} aria-label={`Enable ${d.name}`} />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-0.5">
                        <Button variant="ghost" size="icon-xs" title="Send test delivery" aria-label={`Test ${d.name}`} onClick={() => test.mutate(d.id)} disabled={d.kind !== "webhook"}>
                          <Play />
                        </Button>
                        {dead > 0 && (
                          <Button variant="ghost" size="icon-xs" title="Replay dead deliveries" aria-label={`Replay dead deliveries for ${d.name}`} onClick={() => replay.mutate(d.id)}>
                            <RotateCcw />
                          </Button>
                        )}
                        <Button variant="ghost" size="icon-xs" title="Delete" aria-label={`Delete ${d.name}`} onClick={() => setDeleteTarget(d)}>
                          <Trash2 />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        )}
      </Card>

      {test.data && (
        <Alert className="py-2">
          <AlertDescription className="text-xs">
            Test delivery <span className="font-mono">{String(test.data.delivery_id).slice(0, 8)}</span> enqueued — watch its attempts under the next alert or in delivery health above.
          </AlertDescription>
        </Alert>
      )}

      <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle className="text-sm">{editTarget ? "Edit webhook destination" : "New webhook destination"}</DialogTitle>
          </DialogHeader>
          <div className="grid gap-3">
            {formError && <Alert variant="destructive" className="py-2"><AlertDescription className="text-xs">{formError}</AlertDescription></Alert>}
            <div className="grid gap-1.5">
              <Label htmlFor="d-name">Name</Label>
              <Input id="d-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. SOC chatops relay" />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="d-url">HTTPS endpoint</Label>
              <Input id="d-url" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://hooks.example.com/aegis" />
              <p className="text-xs text-muted-foreground">
                HTTPS only in production; private/loopback targets are rejected. Redirects are never followed.
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label>Minimum severity</Label>
              <Select value={minSeverity} onValueChange={setMinSeverity}>
                <SelectTrigger aria-label="Minimum severity"><SelectValue /></SelectTrigger>
                <SelectContent>{["info", "low", "medium", "high", "critical"].map((s) => (
                  <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>
                ))}</SelectContent>
              </Select>
            </div>
            {editTarget?.secretMasked && (
              <div className="rounded-lg border bg-muted/30 p-2.5">
                <SectionTitle>Signing secret</SectionTitle>
                <p className="font-mono text-xs text-muted-foreground">{editTarget.secretMasked}</p>
                <p className="mt-1 text-[11px] text-muted-foreground">Stored server-side, returned only masked. Rotation happens through the API (PUT with a new secret).</p>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" size="sm" onClick={() => setDialogOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={submit} disabled={!name || (editTarget?.kind !== "in_app" && !url) || create.isPending || update.isPending}>Save</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <ConfirmDialog
        open={!!deleteTarget}
        title={`Delete destination “${deleteTarget?.name}”?`}
        body="Delivery history is kept, but no new notifications will be sent here. Triggers referencing it keep their other destinations."
        confirmLabel="Delete destination"
        onCancel={() => setDeleteTarget(null)}
        onConfirm={() => {
          if (deleteTarget) del.mutate(deleteTarget.id);
          setDeleteTarget(null);
        }}
      />
    </div>
  );
}
