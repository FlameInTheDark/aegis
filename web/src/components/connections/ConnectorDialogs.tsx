import * as React from "react";
import { AlertTriangle, Ban, Cpu, Radar, Save, Trash2 } from "lucide-react";

import { cn } from "@/lib/utils";
import { useSites } from "@/lib/queries";
import type { Connection } from "@/data/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Mono } from "@/components/shared";

import {
  connectionFunctions,
  defaultConnectorConfig,
  formatRate,
  DEFAULT_NMAP_PATH,
  HEARTBEAT_PRESETS,
  PROBE_RATE_PRESETS,
  PULL_RATE_PRESETS,
  type ConnectorAgentConfig,
  type ConnectorConfig,
  type ConnectorScannerConfig,
} from "./connector-config";

// Public re-exports: existing consumers import the model from this module.
export { connectionFunctions } from "./connector-config";
export type { ConnectorAgentConfig, ConnectorConfig, ConnectorScannerConfig } from "./connector-config";

/* ------------------------------------------------------------------ */
/* Edit — name + site                                                  */
/* ------------------------------------------------------------------ */
export function EditConnectorDialog({
  connector,
  onClose,
  onSave,
}: {
  connector: Connection | null;
  onClose: () => void;
  onSave: (id: string, patch: { name?: string; site_id?: string }) => void;
}) {
  const sites = useSites();
  const [name, setName] = React.useState("");
  const [site, setSite] = React.useState("");

  React.useEffect(() => {
    if (connector) {
      setName(connector.name);
      setSite(connector.site ?? "");
    }
  }, [connector]);

  if (!connector) return null;
  const Icon = connector.kind === "agent" ? Cpu : Radar;

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icon className="size-4 text-muted-foreground" /> Edit connector
          </DialogTitle>
          <DialogDescription>Rename the connector or move it to a different site. The connector keeps its enrollment.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label htmlFor="edit-name">Name</Label>
            <Input id="edit-name" value={name} onChange={(e) => setName(e.target.value)} autoFocus />
          </div>
          <div className="grid gap-1.5">
            <Label>Site</Label>
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
            {site !== connector.site && (
              <p className="text-[11px] text-medium">Moving a connector re-scopes which ranges it is allowed to scan.</p>
            )}
          </div>
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => onSave(connector.id, { name: name.trim() || connector.name, site_id: site })} disabled={!name.trim()}>
            <Save /> Save changes
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Shared field blocks                                                 */
/* ------------------------------------------------------------------ */

/** withCurrent keeps a stored non-preset value selectable in a preset list. */
function withCurrent(presets: { value: number; label: string }[], v?: number) {
  return v && !presets.some((p) => p.value === v) ? [...presets, { value: v, label: formatRate(v) }] : presets;
}

function HeartbeatField({ value, onChange }: { value?: number; onChange: (v: number) => void }) {
  return (
    <div className="grid gap-1.5">
      <Label>Heartbeat interval</Label>
      <Select value={String(value ?? 60)} onValueChange={(v) => onChange(Number(v))}>
        <SelectTrigger className="w-full">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {HEARTBEAT_PRESETS.map((h) => (
            <SelectItem key={h.value} value={String(h.value)}>
              {h.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      <p className="text-[11px] text-muted-foreground">
        A connector is marked offline after 3 missed heartbeats (~{Math.round(((value ?? 60) * 3) / 60) || 1} min).
      </p>
    </div>
  );
}

function DisabledFunctionNote({ title }: { title: string }) {
  return (
    <p className="rounded-lg border bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground">
      {title} is currently disabled. The settings below are remembered and take effect when the function is enabled.
    </p>
  );
}

/* ------------------------------------------------------------------ */
/* Configure — tabs: General / Agent / Scanner                         */
/* ------------------------------------------------------------------ */
export function ConfigureConnectorDialog({
  connector,
  onClose,
  onSave,
}: {
  connector: Connection | null;
  onClose: () => void;
  onSave: (id: string, config: ConnectorConfig) => void;
}) {
  const [cfg, setCfg] = React.useState<ConnectorConfig>({});
  const [pathTouched, setPathTouched] = React.useState(false);

  React.useEffect(() => {
    if (connector) {
      setCfg(defaultConnectorConfig(connector.kind, connector.config as Record<string, unknown> | undefined));
      setPathTouched(false);
    }
  }, [connector]);

  if (!connector) return null;
  const isScanner = connector.kind === "scanner";
  const isEndpointKind = connector.kind === "agent" || isScanner; // hybrid-capable kinds
  const agent = cfg.agent ?? { enabled: connector.kind === "agent" };
  const scanner = cfg.scanner ?? { enabled: isScanner };
  const Icon = isScanner ? Radar : Cpu;

  const setAgent = (patch: Partial<ConnectorAgentConfig>) => setCfg((c) => ({ ...c, agent: { ...(c.agent ?? {}), ...patch } }));
  const setScanner = (patch: Partial<ConnectorScannerConfig>) => setCfg((c) => ({ ...c, scanner: { ...(c.scanner ?? {}), ...patch } }));

  const setEngine = (engine: string) => {
    setScanner({
      engine,
      // keep a custom path if the operator edited it, otherwise follow the engine default
      nmap_path: pathTouched ? scanner.nmap_path : engine === "simulated" ? undefined : DEFAULT_NMAP_PATH,
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Icon className="size-4 text-muted-foreground" /> Configure {connector.name}
          </DialogTitle>
          <DialogDescription>
            Choose what this connector can do and how. Settings are pushed to the connector on its next heartbeat;
            toggling a function on or off starts or stops it without a restart.
          </DialogDescription>
        </DialogHeader>

        {isEndpointKind ? (
          <Tabs defaultValue="general">
            <TabsList className="w-full">
              <TabsTrigger value="general">General</TabsTrigger>
              <TabsTrigger value="agent" className="gap-1.5">
                <Cpu className="size-3.5" /> Agent
              </TabsTrigger>
              <TabsTrigger value="scanner" className="gap-1.5">
                <Radar className="size-3.5" /> Scanner
              </TabsTrigger>
            </TabsList>

            {/* ---------------- General: functions + heartbeat ---------------- */}
            <TabsContent value="general" className="grid gap-4">
              <div className="grid gap-2">
                <div className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">What this connector can do</div>
                <label className="flex cursor-pointer items-center justify-between rounded-lg border px-3 py-2.5 text-sm">
                  <span>
                    <span className="inline-flex items-center gap-1.5"><Cpu className="size-3.5" /> Endpoint collection</span>
                    <span className="block text-[11px] text-muted-foreground">Collects inventory and security posture from the host it runs on.</span>
                  </span>
                  <Switch checked={!!agent.enabled} onCheckedChange={(v) => setAgent({ enabled: v })} />
                </label>
                <label className="flex cursor-pointer items-center justify-between rounded-lg border px-3 py-2.5 text-sm">
                  <span>
                    <span className="inline-flex items-center gap-1.5"><Radar className="size-3.5" /> Remote scanning</span>
                    <span className="block text-[11px] text-muted-foreground">Runs network scans dispatched by the hub against authorized ranges.</span>
                  </span>
                  <Switch checked={!!scanner.enabled} onCheckedChange={(v) => setScanner({ enabled: v })} />
                </label>
                {agent.enabled && scanner.enabled && (
                  <p className="text-[11px] text-muted-foreground">Both functions run side by side in one process (hybrid mode). Disable one to free the host.</p>
                )}
                {!agent.enabled && !scanner.enabled && (
                  <p className="rounded-lg border bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground">
                    Both functions are off: the connector stays enrolled and heartbeats, but performs no work.
                  </p>
                )}
              </div>
              <HeartbeatField value={cfg.heartbeat_secs} onChange={(v) => setCfg((c) => ({ ...c, heartbeat_secs: v }))} />
            </TabsContent>

            {/* ---------------- Agent: collection + metrics cadence ---------------- */}
            <TabsContent value="agent" className="grid gap-3">
              {!agent.enabled && <DisabledFunctionNote title="Endpoint collection" />}
              <div className="grid gap-1.5">
                <Label>Collection level</Label>
                <Select value={agent.collection_level ?? "basic"} onValueChange={(v) => setAgent({ collection_level: v })}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="basic">basic — hardware + OS overview</SelectItem>
                    <SelectItem value="standard">standard — + installed software and network state</SelectItem>
                    <SelectItem value="full">full — everything incl. security posture</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-[11px] text-muted-foreground">Applied by the connector on its next config reload, no restart needed.</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label>Probe rate</Label>
                  <Select
                    value={String(agent.probe_rate_ms ?? 5000)}
                    onValueChange={(v) => setAgent({ probe_rate_ms: Number(v) })}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {withCurrent(PROBE_RATE_PRESETS, agent.probe_rate_ms).map((p) => (
                        <SelectItem key={p.value} value={String(p.value)}>
                          {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-[11px] text-muted-foreground">How often a performance sample is taken from the system.</p>
                </div>
                <div className="grid gap-1.5">
                  <Label>Pull rate</Label>
                  <Select
                    value={String(agent.pull_rate_ms ?? 30000)}
                    onValueChange={(v) => setAgent({ pull_rate_ms: Number(v) })}
                  >
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {withCurrent(PULL_RATE_PRESETS, agent.pull_rate_ms).map((p) => (
                        <SelectItem key={p.value} value={String(p.value)}>
                          {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <p className="text-[11px] text-muted-foreground">How often buffered samples are sent to the hub in one batch.</p>
                </div>
              </div>
              <p className="rounded-lg border bg-muted/30 px-3 py-2 text-[11px] text-muted-foreground">
                Samples are collected at the probe rate and flushed together at the pull rate, so a fast probe does not
                spam the network with per-sample requests. A pull faster than the probe would carry nothing and is
                clamped on the agent. Changes apply within one loop iteration — no restart.
              </p>
            </TabsContent>

            {/* ---------------- Scanner: engine + SSH ---------------- */}
            <TabsContent value="scanner" className="grid gap-3">
              {!scanner.enabled && <DisabledFunctionNote title="Remote scanning" />}
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label>Scan engine</Label>
                  <Select value={scanner.engine ?? "auto"} onValueChange={setEngine}>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="auto">auto — prefer nmap</SelectItem>
                      <SelectItem value="nmap">nmap — full featured</SelectItem>
                      <SelectItem value="simulated">simulated — safe demo mode</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="grid gap-1.5">
                  <Label>nmap binary path</Label>
                  <Input
                    value={scanner.nmap_path ?? ""}
                    onChange={(e) => {
                      setPathTouched(true);
                      setScanner({ nmap_path: e.target.value });
                    }}
                    className="font-mono text-xs"
                    placeholder={DEFAULT_NMAP_PATH}
                  />
                </div>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Absolute path on the connector host, verified at the next heartbeat — an invalid path marks the scanner degraded ("simulated" skips nmap entirely).
              </p>

              <div>
                <div className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">SSH inventory credentials (optional)</div>
                <div className="grid gap-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="ssh-user">User</Label>
                      <Input id="ssh-user" value={scanner.ssh_user ?? ""} onChange={(e) => setScanner({ ssh_user: e.target.value })} placeholder="scan" className="font-mono text-xs" />
                    </div>
                    <div className="grid gap-1.5">
                      <Label htmlFor="ssh-key-path">Key path</Label>
                      <Input id="ssh-key-path" value={scanner.ssh_key_path ?? ""} onChange={(e) => setScanner({ ssh_key_path: e.target.value })} placeholder="/home/scan/.ssh/id_ed25519" className="font-mono text-xs" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="grid gap-1.5">
                      <Label htmlFor="ssh-password">Password</Label>
                      <Input id="ssh-password" type="password" value={scanner.ssh_password ?? ""} onChange={(e) => setScanner({ ssh_password: e.target.value })} className="font-mono text-xs" />
                    </div>
                    <div className="grid gap-1.5">
                      <Label htmlFor="ssh-timeout">Timeout (seconds)</Label>
                      <Input
                        id="ssh-timeout"
                        type="number"
                        min={1}
                        max={3600}
                        value={scanner.ssh_timeout_secs ?? 30}
                        onChange={(e) => setScanner({ ssh_timeout_secs: Math.max(1, Number(e.target.value) || 1) })}
                      />
                    </div>
                  </div>
                  <label className="flex cursor-pointer items-center justify-between rounded-lg border px-3 py-2.5 text-sm">
                    <span>
                      Accept any host key (lab only)
                      <span className="block text-[11px] text-muted-foreground">Skips host-key verification for SSH inventory runs.</span>
                    </span>
                    <Switch checked={!!scanner.ssh_insecure} onCheckedChange={(v) => setScanner({ ssh_insecure: v })} />
                  </label>
                  <div className="grid gap-1.5">
                    <Label htmlFor="ssh-pinned">Pinned host key (authorized_keys format)</Label>
                    <Input id="ssh-pinned" value={scanner.ssh_pinned_key ?? ""} onChange={(e) => setScanner({ ssh_pinned_key: e.target.value })} className="font-mono text-[11px]" placeholder="ssh-ed25519 AAAA…" />
                    <p className="text-[11px] text-muted-foreground">When set, the handshake must match exactly — stronger than disabling verification.</p>
                  </div>
                </div>
              </div>
            </TabsContent>
          </Tabs>
        ) : (
          <div className="grid gap-1.5">
            <HeartbeatField value={cfg.heartbeat_secs} onChange={(v) => setCfg((c) => ({ ...c, heartbeat_secs: v }))} />
          </div>
        )}

        <div className="rounded-lg border bg-[oklch(0.11_0.01_262)] p-2.5">
          <div className="mb-1 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">Effective configuration</div>
          <Mono className="block break-all text-[11px] leading-relaxed text-foreground/85">
            heartbeat_secs={cfg.heartbeat_secs}
            {agent.enabled
              ? ` agent=on collection_level=${agent.collection_level ?? "basic"} probe=${formatRate(agent.probe_rate_ms)} pull=${formatRate(agent.pull_rate_ms)}`
              : " agent=off"}
            {scanner.enabled
              ? ` scanner=on engine=${scanner.engine ?? "auto"} nmap_path=${scanner.nmap_path || "-"}${scanner.ssh_user ? ` ssh_user=${scanner.ssh_user}` : ""} ssh_insecure=${String(!!scanner.ssh_insecure)}`
              : " scanner=off"}
          </Mono>
        </div>

        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button onClick={() => onSave(connector.id, cfg)}>
            <Save /> Apply configuration
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
/* Destructive confirmations — revoke / delete                         */
/* ------------------------------------------------------------------ */
export function ConfirmConnectorDialog({
  connector,
  action,
  onClose,
  onConfirm,
}: {
  connector: Connection | null;
  action: "revoke" | "delete" | null;
  onClose: () => void;
  onConfirm: (id: string, action: "revoke" | "delete") => void;
}) {
  const sites = useSites();
  if (!connector || !action) return null;
  const isRevoke = action === "revoke";

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <span className={cn("flex size-7 items-center justify-center rounded-md", isRevoke ? "bg-medium/15 text-medium" : "bg-critical/15 text-critical")}>
              {isRevoke ? <Ban className="size-4" /> : <Trash2 className="size-4" />}
            </span>
            {isRevoke ? "Revoke credentials" : "Delete connector"}
          </DialogTitle>
          <DialogDescription>
            {isRevoke
              ? "The connector stays listed but its enrollment token is invalidated. It will disconnect immediately and must be re-enrolled with a new one-liner."
              : "The connector and its history are permanently removed. Any scheduled scans assigned to it must be reassigned."}
          </DialogDescription>
        </DialogHeader>

        <div className="flex items-center gap-3 rounded-lg border bg-muted/30 px-3 py-2.5">
          <span className="flex size-8 items-center justify-center rounded-lg border bg-card text-muted-foreground">
            {connector.kind === "agent" ? <Cpu className="size-4" /> : <Radar className="size-4" />}
          </span>
          <div className="min-w-0 leading-tight">
            <div className="truncate text-sm font-medium">{connector.name}</div>
            <div className="truncate text-[11px] text-muted-foreground">
              {sites.data?.items.find((s) => s.id === connector.site)?.name ?? "—"} · <Mono className="text-[11px]">{connector.endpoint ?? "endpoint unknown"}</Mono>
            </div>
          </div>
          <Badge variant={connector.kind === "agent" ? "low" : "primary"} className="ml-auto capitalize">
            {connector.kind}
          </Badge>
        </div>

        {!isRevoke && (
          <div className="flex items-start gap-2 rounded-lg border border-critical/30 bg-critical/8 px-3 py-2 text-[11px] text-muted-foreground">
            <AlertTriangle className="mt-0.5 size-3.5 shrink-0 text-critical" />
            <span>This cannot be undone. To temporarily disable the connector instead, use Revoke.</span>
          </div>
        )}

        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant={isRevoke ? "outline" : "destructive"} onClick={() => onConfirm(connector.id, action)}>
            {isRevoke ? (
              <>
                <Ban /> Revoke credentials
              </>
            ) : (
              <>
                <Trash2 /> Delete permanently
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
