import * as React from "react";
import { AlertTriangle, Ban, Check, CheckCircle2, Copy, Cpu, MoreHorizontal, Pencil, Plus, Radar, RefreshCw, RotateCcw, Settings2, Trash2 } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import type { Connection } from "@/data/types";
import { useConnections, useCreateConnection, useDeleteConnection, useRevokeConnection, useRotateConnectionToken, useSites, useUpdateConnection, useUpdateConnectionConfig } from "@/lib/queries";
import type { ConnectorConfig } from "@/components/connections/ConnectorDialogs";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { ConfigureConnectorDialog, ConfirmConnectorDialog, EditConnectorDialog, connectionFunctions } from "@/components/connections/ConnectorDialogs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { toast } from "@/components/ui/toaster";
import { Link, useRouter } from "@/lib/router";
import { EmptyState, Mono, PageHeader, StateBadge, StatusDot, TableFooterBar, usePagination } from "@/components/shared";

type ConnectorKind = "agent" | "scanner" | "collector";

const kindMeta = {
  agent: { label: "Agent", icon: Cpu, blurb: "Installed on a device to collect local software, patches, processes and event logs." },
  scanner: { label: "Scanner", icon: Radar, blurb: "Deployed on a device inside the network to run nmap scans against authorized ranges." },
  collector: { label: "Collector", icon: Radar, blurb: "Forwards sensor telemetry from the network segment into the platform event stream." },
} as const;

const statusTone = (s: Connection["status"]) =>
  s === "active" ? "success" : s === "pending" ? "warning" : s === "revoked" ? "danger" : "muted";

const formatHeartbeat = (sec?: number) => {
  if (!sec) return "—";
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.round(sec / 60)}m`;
  return `${Math.round(sec / 3600)}h`;
};

export function ConnectionsPage() {
  const sites = useSites();
  const connectionsQ = useConnections();
  const createConn = useCreateConnection();
  const updateConn = useUpdateConnection();
  const updateCfg = useUpdateConnectionConfig();
  const revokeConn = useRevokeConnection();
  const deleteConn = useDeleteConnection();
  const rotateTok = useRotateConnectionToken();

  const items = connectionsQ.data ?? [];
  const [q, setQ] = React.useState("");
  const [typeFilter, setTypeFilter] = React.useState<"all" | ConnectorKind>("all");
  const [dialogOpen, setDialogOpen] = React.useState(false);
  const [step, setStep] = React.useState<"form" | "command">("form");
  const [kind, setKind] = React.useState<ConnectorKind>("scanner");
  const [name, setName] = React.useState("");
  const [site, setSite] = React.useState("");
  const [issued, setIssued] = React.useState<{ token: string; command: string; expires_at: string } | null>(null);
  const [copied, setCopied] = React.useState(false);
  const [editing, setEditing] = React.useState<Connection | null>(null);
  const [configuring, setConfiguring] = React.useState<Connection | null>(null);
  const [confirm, setConfirm] = React.useState<{ connector: Connection; action: "revoke" | "delete" } | null>(null);

  // Deep link: the Agents page sends operators here to enroll an
  // endpoint — ?create=agent opens the create dialog with the kind preset.
  const { query, navigate } = useRouter();
  React.useEffect(() => {
    const create = query.get("create");
    if (create === "agent" || create === "scanner" || create === "collector") {
      setKind(create as ConnectorKind);
      setDialogOpen(true);
      navigate("/connections", { replace: true });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const siteName = (id?: string) => (id ? sites.data?.items.find((s) => s.id === id)?.name ?? "site" : "—");

  const saveEdit = (id: string, patch: { name?: string; site_id?: string }) => {
    updateConn.mutate(
      { id, ...patch },
      {
        onSuccess: () => toast({ title: "Connector updated", description: `${patch.name ?? ""} saved.`, variant: "success" }),
        onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
      },
    );
    setEditing(null);
  };

  const saveConfig = (id: string, config: ConnectorConfig) => {
    updateCfg.mutate(
      { id, config: config as unknown as Record<string, unknown> },
      {
        onSuccess: () => {
          setConfiguring(null);
          toast({
            title: "Configuration applied",
            description: `Heartbeat ${formatHeartbeat(config.heartbeat_secs)} — pushed on the next watch stream sync.`,
            variant: "success",
          });
        },
        onError: (e) => toast({ title: "Configuration rejected", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const runConfirm = (id: string, action: "revoke" | "delete") => {
    const c = items.find((x) => x.id === id);
    if (action === "delete") {
      deleteConn.mutate(id, {
        onSuccess: () => toast({ title: `${c?.name ?? "Connector"} deleted`, variant: "warning" }),
        onError: (e) => toast({ title: "Delete failed", description: (e as Error).message, variant: "error" }),
      });
    } else {
      revokeConn.mutate(id, {
        onSuccess: () => toast({ title: `${c?.name ?? "Connector"} credentials revoked`, description: "Re-enroll with a new one-liner to reconnect.", variant: "warning" }),
        onError: (e) => toast({ title: "Revoke failed", description: (e as Error).message, variant: "error" }),
      });
    }
    setConfirm(null);
  };

  const rotate = (id: string) => {
    rotateTok.mutate(id, {
      onSuccess: (res) => {
        setIssued({ token: res.token, command: res.connect_command, expires_at: res.expires_at });
        setKind((items.find((x) => x.id === id)?.kind as ConnectorKind) ?? "scanner");
        setStep("command");
        setDialogOpen(true);
      },
      onError: (e) => toast({ title: "Token rotation failed", description: (e as Error).message, variant: "error" }),
    });
  };

  const filtered = React.useMemo(() => {
    const needle = q.trim().toLowerCase();
    return items.filter((c) => {
      if (typeFilter !== "all" && c.kind !== typeFilter) return false;
      if (!needle) return true;
      return [c.name, c.provider, c.site, siteName(c.site)].some((v) => v?.toLowerCase().includes(needle));
    });
  }, [items, q, typeFilter, sites.data]);

  const paged = usePagination(filtered, "connectors");

  const openCreate = (nextKind: ConnectorKind = "scanner") => {
    setKind(nextKind);
    setName("");
    setIssued(null);
    setStep("form");
    setDialogOpen(true);
  };

  const create = () => {
    createConn.mutate(
      { kind, name: name.trim() || (kind === "scanner" ? "scanner-new" : "agent-new"), site_id: site },
      {
        onSuccess: (res) => {
          setIssued({ token: res.token, command: res.connect_command, expires_at: res.expires_at });
          setStep("command");
        },
        onError: (e) => toast({ title: "Create failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(issued?.command ?? "");
      setCopied(true);
      setTimeout(() => setCopied(false), 1600);
    } catch {
      /* clipboard unavailable */
    }
  };

  const problems = items.filter((c) => c.status !== "revoked" && !c.online);

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Connections"
        description="Connectors are deployed into your environment: agents collect data on devices, scanners run network scans. Pick a type, choose a site, then run the generated one-liner."
        actions={
          <Button size="sm" onClick={() => openCreate("scanner")}>
            <Plus /> Connect connector
          </Button>
        }
      />

      {problems.map((c) => (
        <Alert key={c.id} variant="destructive">
          <RefreshCwIcon />
          <AlertTitle>{c.name} is not reporting</AlertTitle>
          <AlertDescription>
            Last heartbeat {c.lastSync ? timeAgo(c.lastSync) : "never"}. Re-run the connector one-liner on the device to restore enrollment.
          </AlertDescription>
        </Alert>
      ))}

      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex rounded-md border p-0.5">
          {(["all", "scanner", "agent"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTypeFilter(t)}
              className={cn(
                "flex items-center gap-1.5 rounded px-2.5 py-1 text-xs font-medium capitalize transition-colors cursor-pointer",
                typeFilter === t ? "bg-accent text-foreground" : "text-muted-foreground hover:text-foreground"
              )}
            >
              {t === "all" ? "All" : kindMeta[t].label}
              <span className="tabular text-[10px] opacity-70">{t === "all" ? items.length : items.filter((c) => c.kind === t).length}</span>
            </button>
          ))}
        </div>
        <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search connectors…" className="h-8 w-56 text-[13px]" />
        <div className="flex items-center gap-3 ml-auto text-[11px] text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-success" /> {items.filter((c) => c.online).length} online
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-medium" /> {items.filter((c) => c.status === "pending").length} pending
          </span>
          <span className="flex items-center gap-1.5">
            <span className="size-1.5 rounded-full bg-critical" /> {problems.length} offline
          </span>
        </div>
      </div>

      {/* Single unified table */}
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Name</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Site</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Device / engine</TableHead>
              <TableHead>Heartbeat</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead>Version</TableHead>
              <TableHead className="w-[130px] text-right pr-4">Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paged.slice.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={9}>
                  <EmptyState
                    icon={Radar}
                    title="No connectors yet"
                    description="Connect an agent to collect data from a device, or a scanner to run network scans inside a site."
                    action={
                      <Button size="sm" onClick={() => openCreate("scanner")}>
                        <Plus /> Connect connector
                      </Button>
                    }
                  />
                </TableCell>
              </TableRow>
            ) : (
              paged.slice.map((c) => {
                const k = (c.kind === "agent" ? "agent" : c.kind === "collector" ? "collector" : "scanner") as ConnectorKind;
                const Meta = kindMeta[k];
                const cfg = (c.config ?? {}) as Record<string, unknown>;
                const fns = connectionFunctions(c.kind, c.config);
                const scanSec = cfg["scanner"] && typeof cfg["scanner"] === "object" ? (cfg["scanner"] as Record<string, unknown>) : undefined;
                const engine = (scanSec?.engine as string) ?? (cfg["engine"] as string) ?? "auto";
                const nmapPath = (scanSec?.nmap_path as string) ?? (cfg["nmap_path"] as string) ?? "";
                return (
                  <TableRow key={c.id}>
                    <TableCell className="pl-4">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={cn(
                            "flex size-8 shrink-0 items-center justify-center rounded-lg border",
                            c.online ? "bg-success/10 text-success" : c.status === "revoked" ? "bg-critical/10 text-critical" : "bg-muted/40 text-muted-foreground"
                          )}
                        >
                          <Meta.icon className="size-4" />
                        </span>
                        <div className="min-w-0 leading-tight">
                          <div className="truncate text-sm font-medium">{c.name}</div>
                          <div className="truncate text-[11px] text-muted-foreground">{c.endpoint ?? c.platform ?? "aegis-connector"}</div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div className="flex flex-wrap items-center gap-1">
                        {c.kind === "collector" ? (
                          <Badge variant="muted" className="gap-1">
                            <Meta.icon className="size-3" /> {Meta.label}
                          </Badge>
                        ) : (
                          fns.map((fn) => {
                            const m = fn === "agent" ? kindMeta.agent : kindMeta.scanner;
                            return (
                              <Badge key={fn} variant={fn === "agent" ? "low" : "primary"} className="gap-1">
                                <m.icon className="size-3" /> {m.label}
                              </Badge>
                            );
                          })
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{siteName(c.site)}</TableCell>
                    <TableCell>
                      <StateBadge
                        label={c.status === "active" ? (c.connState === "shutting_down" ? "stopping" : c.online ? "online" : "offline") : c.status}
                        tone={statusTone(c.status)}
                        pulse={c.online}
                      />
                    </TableCell>
                    <TableCell>
                      {fns.includes("agent") && c.device ? (
                        <div className="leading-tight">
                          <div className="flex items-center gap-1.5 text-xs font-medium">
                            <StatusDot tone={c.device.status === "online" ? "success" : c.device.status === "degraded" ? "warning" : "muted"} className="size-1.5" />
                            {c.device.hostname || "device"}
                          </div>
                          {c.device.assetId && (
                            <Link to={`/assets/${c.device.assetId}`} className="text-[10px] text-primary hover:underline">
                              view asset
                            </Link>
                          )}
                          {fns.includes("scanner") && (
                            <div className="font-mono text-[10px] text-muted-foreground">
                              {engine}
                              {nmapPath ? ` · ${nmapPath}` : ""}
                            </div>
                          )}
                        </div>
                      ) : fns.includes("scanner") ? (
                        <div className="leading-tight">
                          <Mono className="text-[11px]">{engine}</Mono>
                          <div className="truncate font-mono text-[10px] text-muted-foreground" title={nmapPath}>
                            {nmapPath || "—"}
                          </div>
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="tabular text-xs text-muted-foreground">{formatHeartbeat(typeof cfg["heartbeat_secs"] === "number" ? (cfg["heartbeat_secs"] as number) : undefined)}</TableCell>
                    <TableCell className={cn("tabular text-xs", c.lastSync && Date.now() - +new Date(c.lastSync) > 15 * 60_000 && c.status === "active" ? "text-critical" : "text-muted-foreground")}>
                      {c.lastSync ? timeAgo(c.lastSync) : "—"}
                    </TableCell>
                    <TableCell className="tabular text-xs text-muted-foreground">{c.version ? `v${c.version}` : "—"}</TableCell>
                    <TableCell className="pr-4">
                      <div className="flex items-center justify-end gap-1">
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon-xs" className="text-muted-foreground">
                              <MoreHorizontal />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end" className="w-44">
                            <DropdownMenuItem onClick={() => setEditing(c)}>
                              <Pencil /> Edit
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => setConfiguring(c)}>
                              <Settings2 /> Configure
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => rotate(c.id)}>
                              <RotateCcw /> New one-liner
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem disabled={c.status === "revoked"} onClick={() => setConfirm({ connector: c, action: "revoke" })}>
                              <Ban /> Revoke
                            </DropdownMenuItem>
                            <DropdownMenuItem variant="destructive" onClick={() => setConfirm({ connector: c, action: "delete" })}>
                              <Trash2 /> Delete
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
        {paged.slice.length > 0 && <TableFooterBar total={paged.total} page={paged.page} pageSize={paged.pageSize} onPage={paged.setPage} onPageSize={paged.setPageSize} label="connectors" />}
      </div>

      {/* Create connector dialog */}
      <Dialog
        open={dialogOpen}
        onOpenChange={(o) => {
          setDialogOpen(o);
        }}
      >
        <DialogContent className="sm:max-w-lg">
          <DialogHeader>
            <DialogTitle>Connect connector</DialogTitle>
            <DialogDescription>Choose the connector type and site, then run the generated one-liner on the target device.</DialogDescription>
          </DialogHeader>

          {step === "form" ? (
            <div className="grid gap-4">
              <div className="grid grid-cols-2 gap-2">
                {(["scanner", "agent"] as ConnectorKind[]).map((k) => {
                  const m = kindMeta[k];
                  const active = kind === k;
                  return (
                    <button
                      key={k}
                      onClick={() => setKind(k)}
                      className={cn("flex items-start gap-2.5 rounded-lg border p-3 text-left transition-colors cursor-pointer", active ? "border-primary bg-primary/8" : "hover:bg-accent/40")}
                    >
                      <m.icon className={cn("mt-0.5 size-4 shrink-0", active ? "text-primary" : "text-muted-foreground")} />
                      <span className="min-w-0">
                        <span className="block text-sm font-medium">{m.label}</span>
                        <span className="block text-[11px] leading-snug text-muted-foreground">{k === "agent" ? "Collects data on the device" : "Runs nmap in the network"}</span>
                      </span>
                    </button>
                  );
                })}
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label htmlFor="conn-name">Name</Label>
                  <Input id="conn-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={kind === "scanner" ? "scanner-branch-01" : "agent-srv-web-01"} autoFocus />
                </div>
                <div className="grid gap-1.5">
                  <Label>Site</Label>
                  {sites.isPending ? (
                    <div className="flex h-9 items-center gap-2 rounded-md border px-3 text-sm text-muted-foreground">
                      <RefreshCw className="size-3.5 animate-spin" /> Loading sites…
                    </div>
                  ) : sites.isError ? (
                    <div className="rounded-md border border-destructive/40 bg-destructive/5 px-3 py-2">
                      <div className="flex items-start gap-2">
                        <AlertTriangle className="mt-0.5 size-3.5 text-destructive" />
                        <div className="min-w-0 flex-1">
                          <p className="text-xs font-medium text-destructive">Failed to load sites</p>
                          <p className="mt-0.5 break-words text-[11px] text-muted-foreground">{(sites.error as Error)?.message || "The sites API request failed."}</p>
                          <Button size="xs" variant="outline" className="mt-1.5" onClick={() => sites.refetch()}>
                            <RefreshCw /> Retry
                          </Button>
                        </div>
                      </div>
                    </div>
                  ) : (sites.data?.items.length ?? 0) === 0 ? (
                    <div className="rounded-md border bg-muted/30 px-3 py-2 text-xs text-muted-foreground">
                      No sites yet. Create one in <Link to="/settings?tab=sites" className="underline underline-offset-2">Settings → Sites</Link> — connectors attach to a site.
                    </div>
                  ) : (
                    <Select value={site} onValueChange={setSite}>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Choose a site" />
                      </SelectTrigger>
                      <SelectContent>
                        {(sites.data?.items ?? []).map((s) => (
                          <SelectItem key={s.id} value={s.id}>
                            {s.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                </div>
              </div>

              <p className="rounded-lg border bg-muted/30 px-3 py-2 text-[11px] leading-relaxed text-muted-foreground">{kindMeta[kind].blurb}</p>
            </div>
          ) : (
            <div className="grid gap-3">
              <Alert variant="info">
                <CheckCircle2 className="size-4" />
                <AlertTitle>{name || `New ${kindMeta[kind].label}`} registered</AlertTitle>
                <AlertDescription>Run this command on the device. The one-time token is burned on first connect; the token expires {issued ? timeAgo(issued.expires_at) : "soon"}.</AlertDescription>
              </Alert>
              <div className="relative rounded-lg border bg-[oklch(0.11_0.01_262)] p-3 pr-10">
                <Mono className="block break-all text-[11.5px] leading-relaxed text-foreground/85">{issued?.command}</Mono>
                <Button variant="ghost" size="icon-xs" className="absolute right-1.5 top-1.5" onClick={copy}>
                  {copied ? <Check className="text-success" /> : <Copy />}
                </Button>
              </div>
              <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                <span>
                  Type: <span className="text-foreground">{kindMeta[kind].label}</span> · Site:{" "}
                  <span className="text-foreground">{siteName(site)}</span>
                </span>
              </div>
            </div>
          )}

          <DialogFooter>
            {step === "form" ? (
              <>
                <Button variant="ghost" onClick={() => setDialogOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={create} disabled={!site || createConn.isPending}>
                  {createConn.isPending ? "Registering…" : "Generate one-liner"}
                </Button>
              </>
            ) : (
              <Button onClick={() => setDialogOpen(false)}>Done</Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <EditConnectorDialog connector={editing} onClose={() => setEditing(null)} onSave={saveEdit} />
      <ConfigureConnectorDialog connector={configuring} onClose={() => setConfiguring(null)} onSave={saveConfig} />
      <ConfirmConnectorDialog connector={confirm?.connector ?? null} action={confirm?.action ?? null} onClose={() => setConfirm(null)} onConfirm={runConfirm} />
    </div>
  );
}

function RefreshCwIcon() {
  return <Radar className="size-4" />;
}
