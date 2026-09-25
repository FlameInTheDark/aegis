import * as React from "react";
import { CalendarClock, Check, ChevronDown, Copy, Cpu, HelpCircle, KeyRound, Play, Radar, ShieldQuestion, TriangleAlert, Plus, Trash2 } from "lucide-react";

import { cn } from "@/lib/utils";
import { colorOf, iconOf, useGroups } from "@/lib/groups";
import type { ScanEngine } from "@/data/types";
import type * as A from "@/lib/api-types";
import { useAssets, type CreateScanInput, useProfiles, useScanners, useSiteNetworks, useSites } from "@/lib/queries";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { Mono, StatusDot } from "@/components/shared";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

export const engineMeta: Record<ScanEngine, { label: string; icon: typeof Radar; blurb: string; accent: string }> = {
  nmap: { label: "Network scan", icon: Radar, blurb: "Unauthenticated nmap probing — discovery, ports, services, OS fingerprint and path trace.", accent: "text-primary" },
  ssh: { label: "SSH scan", icon: KeyRound, blurb: "Logs in over SSH to read installed packages, services, users and configuration.", accent: "text-success" },
};

interface SshHostDraft {
  host: string;
  port: string;
  username: string;
  auth: "password" | "key";
  password: string;
  key_pem: string;
}

const emptySshHost: SshHostDraft = { host: "", port: "22", username: "", auth: "password", password: "", key_pem: "" };

const SCHEDULE_PRESETS = [
  { value: "0 3 * * 1", label: "Weekly — Monday 03:00" },
  { value: "0 3 * * *", label: "Daily — 03:00" },
  { value: "0 3 1 * *", label: "Monthly — 1st 03:00" },
];

export function NewScanDialog({
  open,
  onOpenChange,
  onCreate,
  defaultTarget,
  defaultPreset,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  /** Receives the assembled POST /scans payload — the page owns the mutation. */
  onCreate: (input: CreateScanInput, opts: { scheduleCron?: string }) => void;
  defaultTarget: string;
  defaultPreset: string;
}) {
  const { groups } = useGroups();
  const profiles = useProfiles();
  const sites = useSites();
  const scanners = useScanners();
  const assetList = useAssets({ limit: 200 });

  const [engine, setEngine] = React.useState<ScanEngine>("nmap");
  const [profile, setProfile] = React.useState(defaultPreset || "inventory");
  const [name, setName] = React.useState("");
  const [site, setSite] = React.useState("");
  const [scanner, setScanner] = React.useState("");
  const [targets, setTargets] = React.useState(defaultTarget);
  const [denylist, setDenylist] = React.useState("");
  const [schedule, setSchedule] = React.useState(false);
  const [cron, setCron] = React.useState(SCHEDULE_PRESETS[0].value);
  const [advanced, setAdvanced] = React.useState(false);
  const [copied, setCopied] = React.useState(false);
  const [confirmElevated, setConfirmElevated] = React.useState(false);
  const [sshHosts, setSshHosts] = React.useState<SshHostDraft[]>([{ ...emptySshHost }]);
  const [sshInsecure, setSshInsecure] = React.useState(false);
  const [pickedGroups, setPickedGroups] = React.useState<string[]>([]);

  const rawProfiles = profiles.data?.raw;
  const allProfiles = [...(rawProfiles?.builtin ?? []), ...(rawProfiles?.custom ?? [])].filter(
    (p): p is A.ProfileDef => !!p && typeof p.name === "string" && p.name.length > 0,
  );
  const siteNetworksQ = useSiteNetworks(site || undefined);
  const siteNetworks = siteNetworksQ.data?.items ?? [];

  React.useEffect(() => {
    if (!open) return;
    setProfile(defaultPreset || "inventory");
    setTargets(defaultTarget);
    setName("");
    setDenylist("");
    setSshHosts([{ ...emptySshHost }]);
    setSshInsecure(false);
    setPickedGroups([]);
    setAdvanced(false);
    setConfirmElevated(false);
    setSchedule(false);
  }, [open, defaultPreset, defaultTarget]);

  React.useEffect(() => {
    if (!site && sites.data?.items.length) setSite(sites.data.items[0].id);
  }, [sites.data, site]);

  const profileDef = allProfiles.find((p) => p.name === profile);
  const activePreset = allProfiles.find((p) => p.name === profile);

  // Effective nmap arguments the scanner will run for this profile —
  // mirrors internal/scanner/engine.go phase argv construction (display
  // only; the backend stays the single source of truth).
  const nmapArgs = React.useMemo(() => {
    if (!profileDef) return "";
    const a: string[] = ["-Pn", "-n", "-sS", "--open"];
    a.push(profileDef.full_port_scan ? "-p-" : `--top-ports ${profileDef.top_tcp_ports || 1000}`);
    if (profileDef.max_packet_rate) a.push(`--max-rate ${profileDef.max_packet_rate}`);
    if (profileDef.service_detect) a.push("-sV", "--version-intensity 5");
    if (profileDef.service_lite) a.push("-sV --version-light");
    if (profileDef.os_detect) a.push("-O");
    if (profileDef.safe_nse) a.push("--script safe");
    if (profileDef.traceroute) a.push("--traceroute");
    if (profileDef.extra_args?.length) a.push(...profileDef.extra_args);
    return a.join(" ");
  }, [profileDef]);

  const appendGroupIps = (gid: string) => {
    const g = groups.find((x) => x.id === gid);
    if (!g) return;
    const ips = g.assetIds
      .map((id) => (assetList.data?.items ?? []).find((a) => a.id === id)?.ip)
      .filter((v): v is string => !!v);
    if (!ips.length) return;
    setTargets((t) => (t.trim() ? `${t.replace(/,?\s*$/, "")}, ${ips.join(", ")}` : ips.join(", ")));
    setPickedGroups((p) => [...p, gid]);
  };

  const targetList = targets.split(/[\s,;]+/).filter((t) => /[0-9a-z]/i.test(t));
  const sshHostList = sshHosts.filter((h) => h.host.trim());
  const canSubmit = engine === "nmap" ? targetList.length > 0 : sshHostList.length > 0;
  const needsConfirm = profile === "active_validation" || profile === "full_audit";

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(
        engine === "ssh"
          ? `ssh_inventory: ${sshHostList.map((h) => `${h.username}@${h.host}:${h.port}`).join(", ")}${sshInsecure ? " (accept any host key)" : ""}`
          : `nmap ${nmapArgs}${denylist ? ` --exclude ${denylist}` : ""} ${targetList.join(" ")}`.trim(),
      );
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* noop */
    }
  };

  const submit = () => {
    if (!canSubmit || !site) return;
    const input: CreateScanInput = {
      site_id: site,
      scanner_id: scanner || undefined,
      name: name || `${activePreset?.name ?? profile} scan`,
      profile,
      targets: engine === "nmap" ? targetList : [],
      denylist: denylist.split(/[\s,;]+/).filter(Boolean),
      engine: "nmap",
      confirm_elevated: needsConfirm ? confirmElevated : undefined,
    };
    if (engine === "ssh") {
      input.profile = "ssh_inventory";
      input.name = name || "ssh_inventory scan";
      input.ssh_hosts = sshHostList.map((h) => ({
        host: h.host.trim(),
        port: Number(h.port) || undefined,
        username: h.username.trim(),
        auth: h.auth,
        password: h.auth === "password" ? h.password : undefined,
        key_pem: h.auth === "key" ? h.key_pem : undefined,
      }));
      input.ssh_insecure_host_key = sshInsecure || undefined;
    }
    onCreate(input, { scheduleCron: schedule ? cron : undefined });
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="flex max-h-[92vh] flex-col gap-4 overflow-hidden sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>New scan</DialogTitle>
          <DialogDescription>Network scans probe targets with nmap; SSH scans authenticate to read host-level data. Path tracing is included in network scans.</DialogDescription>
        </DialogHeader>

        {/* Engine segmented control */}
        <div className="grid grid-cols-2 gap-2 rounded-lg border bg-muted/30 p-1">
          {(Object.keys(engineMeta) as ScanEngine[]).map((e) => {
            const m = engineMeta[e];
            const active = engine === e;
            return (
              <button
                key={e}
                onClick={() => {
                  setEngine(e);
                  setProfile(e === "ssh" ? "ssh_inventory" : "inventory");
                }}
                className={cn(
                  "flex items-center justify-center gap-2 rounded-md px-3 py-2 text-sm font-medium transition-colors cursor-pointer",
                  active ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground"
                )}
              >
                <m.icon className={cn("size-4", active ? m.accent : "")} />
                {m.label}
              </button>
            );
          })}
        </div>

        <div className="grid min-h-0 flex-1 gap-4 overflow-y-auto pr-1">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="grid gap-1.5">
              <Label htmlFor="scan-name">Name</Label>
              <Input id="scan-name" value={name} onChange={(e) => setName(e.target.value)} placeholder={`${activePreset?.name ?? profile} scan`} />
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
            </div>
          </div>

          {engine === "nmap" && (
            <>
              <div className="grid grid-cols-2 items-start gap-3">
                <div className="grid content-start gap-1.5">
                  <Label className="flex items-center gap-1">
                    Profile
                    {profileDef?.description && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            aria-label="About this profile"
                            className="cursor-pointer text-muted-foreground/60 transition-colors hover:text-foreground"
                          >
                            <HelpCircle className="size-3.5" />
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side="bottom" align="start" className="max-w-[300px] leading-relaxed">
                          {profileDef.description}
                        </TooltipContent>
                      </Tooltip>
                    )}
                  </Label>
                  <Select value={profile} onValueChange={setProfile}>
                    <SelectTrigger className="w-full font-mono text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {(profiles.data?.builtin ?? []).map((p) => (
                        <SelectItem key={p.name} value={p.name} className="font-mono">
                          {p.name}
                        </SelectItem>
                      ))}
                      {(profiles.data?.custom ?? []).map((p) => (
                        <SelectItem key={p.name} value={p.name} className="font-mono">
                          {p.name} (custom)
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  {profileDef?.warning && (
                    <p className="flex items-start gap-1 text-[11px] text-medium">
                      <TriangleAlert className="mt-0.5 size-3 shrink-0" /> {profileDef.warning}
                    </p>
                  )}
                </div>
                <div className="grid content-start gap-1.5">
                  <Label>Scanner</Label>
                  <Select value={scanner} onValueChange={setScanner}>
                    <SelectTrigger className="w-full">
                      <SelectValue placeholder="Default scanner" />
                    </SelectTrigger>
                    <SelectContent>
                      {(scanners.data ?? [])
                        .filter((s) => !site || s.siteId === site)
                        .map((s) => (
                          <SelectItem key={s.id} value={s.id} disabled={s.health === "offline"}>
                            <span className="flex items-center gap-2">
                              <StatusDot tone={s.health === "healthy" ? "success" : s.health === "degraded" ? "warning" : "muted"} className="size-1.5" />
                              {s.name}
                              {s.isDefault ? " · default" : ""}
                            </span>
                          </SelectItem>
                        ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <Collapsible open={advanced} onOpenChange={setAdvanced}>
                <CollapsibleTrigger asChild>
                  <button className="mb-2 flex items-center gap-1.5 text-xs font-medium text-muted-foreground hover:text-foreground cursor-pointer">
                    <ChevronDown className={cn("size-3.5 transition-transform", advanced && "rotate-180")} />
                    Advanced options
                  </button>
                </CollapsibleTrigger>
                <CollapsibleContent className="grid gap-3 rounded-lg border bg-muted/20 p-3">
                  <div className="grid gap-1.5">
                    <Label className="text-xs">Denylist — never touched</Label>
                    <Textarea value={denylist} onChange={(e) => setDenylist(e.target.value)} placeholder={"10.10.0.1, 192.168.1.0/28"} className="min-h-12 font-mono text-xs" />
                  </div>
                  {profileDef && (
                    <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-[11px] text-muted-foreground">
                      <span>top TCP ports: <span className="tabular text-foreground">{profileDef.full_port_scan ? "all" : profileDef.top_tcp_ports || 100}</span></span>
                      <span>full port scan: <span className="text-foreground">{profileDef.full_port_scan ? "yes" : "no"}</span></span>
                      <span>service detect: <span className="text-foreground">{profileDef.service_detect ? "intensity 5" : profileDef.service_lite ? "version-light" : "no"}</span></span>
                      <span>OS detect: <span className="text-foreground">{profileDef.os_detect ? "yes" : "no"}</span></span>
                      <span>safe NSE: <span className="text-foreground">{profileDef.safe_nse ? "yes" : "no"}</span></span>
                      <span>traceroute: <span className="text-foreground">{profileDef.traceroute ? "yes" : "no"}</span></span>
                      <span>max targets: <span className="tabular text-foreground">{profileDef.max_targets}</span></span>
                      <span>max packet rate: <span className="tabular text-foreground">{profileDef.max_packet_rate}/s</span></span>
                    </div>
                  )}
                </CollapsibleContent>
              </Collapsible>
            </>
          )}

          {engine === "ssh" && (
            <>
              <div className="flex items-center justify-between">
                <div>
                  <div className="text-sm font-medium">ssh_inventory</div>
                  <p className="text-[11px] text-muted-foreground">Read-only package/service collection over SSH. Credentials travel to the scanner and are redacted afterwards.</p>
                </div>
              </div>

              <div className="grid gap-2">
                {sshHosts.map((h, i) => (
                  <div key={i} className="grid gap-2 rounded-lg border bg-muted/20 p-3">
                    <div className="grid grid-cols-[1fr_5rem_1fr_auto] gap-2">
                      <Input
                        value={h.host}
                        onChange={(e) => setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, host: e.target.value } : x)))}
                        placeholder="host or IP"
                        className="h-8 font-mono text-xs"
                      />
                      <Input
                        value={h.port}
                        onChange={(e) => setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, port: e.target.value } : x)))}
                        placeholder="22"
                        className="h-8 font-mono text-xs"
                      />
                      <Input
                        value={h.username}
                        onChange={(e) => setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, username: e.target.value } : x)))}
                        placeholder="username"
                        className="h-8 font-mono text-xs"
                      />
                      <Button variant="ghost" size="icon-sm" disabled={sshHosts.length === 1} onClick={() => setSshHosts((l) => l.filter((_, j) => j !== i))} className="text-muted-foreground">
                        <Trash2 className="size-3.5" />
                      </Button>
                    </div>
                    <div className="grid grid-cols-[10rem_1fr] gap-2">
                      <Select value={h.auth} onValueChange={(v) => setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, auth: v as SshHostDraft["auth"] } : x)))}>
                        <SelectTrigger size="sm" className="h-8 w-full text-xs"><SelectValue /></SelectTrigger>
                        <SelectContent>
                          <SelectItem value="password">Password</SelectItem>
                          <SelectItem value="key">Private key (PEM)</SelectItem>
                        </SelectContent>
                      </Select>
                      {h.auth === "password" ? (
                        <Input
                          type="password"
                          value={h.password}
                          onChange={(e) => setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, password: e.target.value } : x)))}
                          placeholder="password"
                          className="h-8 font-mono text-xs"
                        />
                      ) : (
                        <div className="flex items-start gap-2">
                          {/* Multi-line PEM input: private keys do not fit a
                              single-line input, so a monospace textarea plus a
                              .pem file picker (drag-and-drop friendly). */}
                          <Textarea
                            rows={5}
                            value={h.key_pem}
                            onChange={(e) => setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, key_pem: e.target.value } : x)))}
                            onDrop={async (e) => {
                              const file = e.dataTransfer.files?.[0];
                              if (file) {
                                e.preventDefault();
                                const text = await file.text();
                                setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, key_pem: text } : x)));
                              }
                            }}
                            placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n...\n-----END OPENSSH PRIVATE KEY-----"}
                            spellCheck={false}
                            className="min-h-0 font-mono text-xs"
                          />
                          <label className="flex h-8 shrink-0 cursor-pointer items-center gap-1.5 rounded-md border border-input bg-transparent px-2.5 text-xs font-medium shadow-sm transition-colors hover:bg-accent hover:text-accent-foreground">
                            Upload .pem
                            <input
                              type="file"
                              accept=".pem,.key,.txt,application/x-pem-file"
                              className="sr-only"
                              onChange={async (e) => {
                                const file = e.target.files?.[0];
                                if (file) {
                                  const text = await file.text();
                                  setSshHosts((l) => l.map((x, j) => (j === i ? { ...x, key_pem: text } : x)));
                                }
                                e.target.value = "";
                              }}
                            />
                          </label>
                        </div>
                      )}
                    </div>
                  </div>
                ))}
                <Button variant="outline" size="sm" className="w-fit gap-1.5" onClick={() => setSshHosts((l) => [...l, { ...emptySshHost }])}>
                  <Plus className="size-3.5" /> Add host
                </Button>
              </div>

              <label className="flex cursor-pointer items-center justify-between rounded-lg border px-3 py-2.5 text-sm">
                <span>
                  Accept any host key
                  <span className="block text-[11px] text-muted-foreground">Skips host-key verification — lab use only.</span>
                </span>
                <Switch checked={sshInsecure} onCheckedChange={setSshInsecure} />
              </label>
            </>
          )}

          {engine === "nmap" && (
            <div className="grid gap-1.5">
              <div className="flex items-center justify-between">
                <Label htmlFor="targets">
                  Targets{" "}
                  <span className="font-normal text-muted-foreground">— IPs, ranges or CIDR subnets</span>
                </Label>
                <span className="tabular text-[11px] text-muted-foreground">
                  {targetList.length} target{targetList.length === 1 ? "" : "s"}
                </span>
              </div>
              <Textarea
                id="targets"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                placeholder={"192.168.1.5, 192.168.1.10-25, 10.0.0.0/24, host.example"}
                className="min-h-20 font-mono text-xs"
              />
              <div className="flex flex-wrap items-center gap-1.5">
                {siteNetworks.length > 0 && (
                  <button
                    type="button"
                    onClick={() => setTargets(siteNetworks.map((n) => n.cidr).join(", "))}
                    className="rounded border bg-muted/40 px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground hover:bg-accent cursor-pointer"
                  >
                    insert site ranges
                  </button>
                )}
                {groups.map((g) => {
                  const c = colorOf(g.color);
                  const Icon = iconOf(g.icon);
                  const on = pickedGroups.includes(g.id);
                  return (
                    <button
                      key={g.id}
                      type="button"
                      onClick={() => appendGroupIps(g.id)}
                      disabled={on}
                      className="inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] disabled:opacity-50 cursor-pointer"
                      style={{ borderColor: c.border, color: c.solid }}
                    >
                      <Icon className="size-2.5" />+ {g.name}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {needsConfirm && (
            <div className="flex items-start gap-2 rounded-lg border border-medium/40 bg-medium/8 px-3 py-2 text-[11px] text-muted-foreground">
              <ShieldQuestion className="mt-0.5 size-3.5 shrink-0 text-medium" />
              <label className="flex flex-1 cursor-pointer items-center gap-2">
                <Checkbox checked={confirmElevated} onCheckedChange={(v) => setConfirmElevated(!!v)} />
                <span>
                  <b className="text-foreground">{profile}</b> performs active validation against live hosts. I confirm the targets are authorized for intrusive testing.
                </span>
              </label>
            </div>
          )}

          <div className="rounded-lg border px-3 py-2.5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 text-sm">
                <CalendarClock className="size-4 text-muted-foreground" /> Recurring schedule
              </div>
              <Switch checked={schedule} onCheckedChange={setSchedule} />
            </div>
            {schedule && (
              <div className="mt-2 grid gap-1.5">
                <Select value={cron} onValueChange={setCron}>
                  <SelectTrigger size="sm" className="h-8 w-full text-xs"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {SCHEDULE_PRESETS.map((p) => (
                      <SelectItem key={p.value} value={p.value}>
                        {p.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <p className="text-[11px] text-muted-foreground">Also creates a schedule that re-runs this profile on the chosen cadence (site + current targets as scope).</p>
              </div>
            )}
          </div>
        </div>

        {/* Summary */}
        <div className="shrink-0 rounded-lg border bg-[oklch(0.11_0.01_262)] p-2.5">
          <div className="mb-1 flex items-center justify-between">
            <span className="flex items-center gap-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
              <Cpu className="size-3" /> Summary
            </span>
            <Button variant="ghost" size="xs" onClick={copy} className="text-muted-foreground">
              {copied ? <Check className="text-success" /> : <Copy />} {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <Mono className="block max-h-14 overflow-y-auto break-all text-[11px] leading-relaxed text-foreground/85">
            {engine === "ssh"
              ? `ssh_inventory: ${sshHostList.map((h) => `${h.username || "?"}@${h.host}:${h.port || 22}`).join(", ")}${sshInsecure ? " (accept any host key)" : ""}`
              : `nmap ${nmapArgs}${denylist ? ` --exclude ${denylist}` : ""} ${targetList.join(" ")}`.trim()}
          </Mono>
        </div>

        <DialogFooter className="shrink-0">
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!canSubmit || (needsConfirm && !confirmElevated)}>
            <Play /> Start scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Toggle({ label, checked, onChange }: { label: string; checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <label className="flex cursor-pointer items-center justify-between gap-3 rounded-md border px-2.5 py-1.5 text-[13px]">
      {label}
      <Switch checked={checked} onCheckedChange={onChange} />
    </label>
  );
}
