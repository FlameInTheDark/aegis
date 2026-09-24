import * as React from "react";
import {
  Building2,
  Check,
  Copy,
  Database,
  Download,
  Globe,
  Info,
  KeyRound,
  ListFilter,
  MoreHorizontal,
  Plus,
  Radar,
  RefreshCw,
  Rss,
  ScrollText,
  Search,
  ShieldCheck,
  Star,
  Trash2,
  TriangleAlert,
  UserRound,
  Users as UsersIcon,
  type LucideIcon,
} from "lucide-react";

import { cn, timeAgo, formatDateTime, formatNumber } from "@/lib/utils";
import { Link, useRouter } from "@/lib/router";
import type { Feed, Scanner, Site, User } from "@/data/types";
import {
  useAuditLog, useCreateProfile, useCreateSite, useCreateUser, useDeleteProfile, useRunMetricsCleanup,
  useEnrollScanner, useFeeds, useMe, useProfiles, useResetUserPassword, useScanners, useSettings,
  useSetDefaultScanner, useSites, useTriggerFeedSync, useUpdateProfile, useUpdateSettings, useUpdateSite,
  useUpdateUser, useUsers, useChangeOwnPassword, useRenameOrg, useCreateNetwork, useDeleteSite, useSiteNetworks,
} from "@/lib/queries";
import { useAuth } from "@/lib/auth";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectSeparator, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { toast } from "@/components/ui/toaster";
import { EmptyState, Mono, PageHeader, StateBadge, TableFooterBar, usePagination } from "@/components/shared";

type Section = "sites" | "account" | "presets" | "users" | "scanners" | "feeds" | "metrics" | "audit";

const sections: { id: Section; label: string; icon: LucideIcon; blurb: string }[] = [
  { id: "sites", label: "Sites", icon: Building2, blurb: "Sites, networks and address ranges" },
  { id: "account", label: "My account", icon: UserRound, blurb: "Profile, organization and password" },
  { id: "presets", label: "Presets", icon: ListFilter, blurb: "Reusable scan profiles" },
  { id: "users", label: "Users", icon: UsersIcon, blurb: "Members, roles and access" },
  { id: "scanners", label: "Scanners", icon: Radar, blurb: "Scan engines and defaults" },
  { id: "feeds", label: "Feeds", icon: Rss, blurb: "CVE, KEV, EPSS and OVAL sources" },
  { id: "metrics", label: "Metrics", icon: Database, blurb: "Performance data retention and storage" },
  { id: "audit", label: "Audit log", icon: ScrollText, blurb: "Immutable record of all actions" },
];

export function SettingsPage() {
  const { query, navigate } = useRouter();
  const tab = (query.get("tab") as Section) || "sites";
  const active = sections.find((s) => s.id === tab) ?? sections[0];

  return (
    <div className="flex flex-col gap-5">
      <PageHeader title="Settings" description="Tenant-wide configuration. Changes are audited and take effect immediately." />
      <div className="grid gap-6 lg:grid-cols-[220px_1fr]">
        <nav className="flex gap-1 overflow-x-auto lg:flex-col">
          {sections.map((s) => (
            <button
              key={s.id}
              onClick={() => navigate(`/settings?tab=${s.id}`)}
              className={cn(
                "flex shrink-0 items-center gap-2.5 rounded-md px-3 py-2 text-left text-sm transition-colors cursor-pointer",
                active.id === s.id ? "bg-accent text-foreground" : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
              )}
            >
              <s.icon className={cn("size-4", active.id === s.id && "text-primary")} />
              {s.label}
            </button>
          ))}
        </nav>
        <div className="min-w-0">
          <div className="mb-4">
            <h2 className="text-base font-semibold">{active.label}</h2>
            <p className="text-sm text-muted-foreground">{active.blurb}</p>
          </div>
          {tab === "sites" && <SitesSection />}
          {tab === "account" && <AccountSection />}
          {tab === "presets" && <PresetsSection />}
          {tab === "users" && <UsersSection />}
          {tab === "scanners" && <ScannersSection />}
          {tab === "feeds" && <FeedsSection />}
          {tab === "metrics" && <MetricsSection />}
          {tab === "audit" && <AuditSection />}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function SitesSection() {
  const sitesQ = useSites();
  const deleteSite = useDeleteSite();
  // One dialog for everything site-related: null = closed, "new" = create
  // form, Site = edit. The old UI kept a separate Networks dialog that
  // mounted *on top of* the edit dialog (both opened on "Edit site").
  const [dlg, setDlg] = React.useState<Site | "new" | null>(null);

  const sites = sitesQ.data?.items ?? [];

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          <Badge variant="outline" className="tabular">{sites.length} sites</Badge>
          <Badge variant="outline" className="tabular">{sites.reduce((n, s) => n + s.networks.length, 0)} networks</Badge>
        </div>
        <Button size="sm" onClick={() => setDlg("new")}>
          <Plus /> Add site
        </Button>
      </div>

      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Site</TableHead>
              <TableHead>Type</TableHead>
              <TableHead>Networks</TableHead>
              <TableHead className="text-right">Assets</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {sitesQ.isPending ? (
              // While the query is in flight the honest answer is "loading",
              // not "no sites" — an empty list here would be a lie.
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={5}>
                  <div className="flex items-center justify-center gap-2 py-6 text-sm text-muted-foreground">
                    <RefreshCw className="size-3.5 animate-spin" /> Loading sites…
                  </div>
                </TableCell>
              </TableRow>
            ) : sitesQ.isError ? (
              // Surface WHY the list could not load (auth blip, proxy error,
              // malformed response) instead of rendering it as an empty table.
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={5}>
                  <Alert variant="destructive" className="border-none bg-destructive/5">
                    <TriangleAlert />
                    <AlertTitle>Failed to load sites</AlertTitle>
                    <AlertDescription>
                      <p>{(sitesQ.error as Error)?.message || "The sites API request failed."}</p>
                      <Button size="sm" variant="outline" className="mt-1" onClick={() => sitesQ.refetch()}>
                        <RefreshCw /> Retry
                      </Button>
                    </AlertDescription>
                  </Alert>
                </TableCell>
              </TableRow>
            ) : sites.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={5}>
                  <EmptyState icon={Globe} title="No sites yet" description="Create a site to scope networks and scanners." />
                </TableCell>
              </TableRow>
            ) : (
              sites.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="pl-4">
                    <div className="flex items-center gap-2.5">
                      <span className="flex size-7 shrink-0 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground">
                        <Globe className="size-3.5" />
                      </span>
                      <div className="min-w-0 leading-tight">
                        <div className="truncate font-medium">{s.name}</div>
                        <div className="text-[11px] text-muted-foreground">{s.description ?? "—"}</div>
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="capitalize">{s.kind}</Badge>
                  </TableCell>
                  <TableCell>
                    <div className="flex max-w-md flex-wrap gap-1">
                      {s.networks.map((n) => (
                        <Badge key={n.id} variant="outline" className="font-mono text-[10px]">
                          {n.cidr}
                        </Badge>
                      ))}
                      {s.networks.length === 0 && <span className="text-xs text-muted-foreground">No ranges</span>}
                    </div>
                  </TableCell>
                  <TableCell className="tabular text-right font-medium">{s.assets}</TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="icon-xs" className="text-muted-foreground">
                          <MoreHorizontal />
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem onClick={() => setDlg(s)}>Edit site</DropdownMenuItem>
                        <DropdownMenuSeparator />
                        <DropdownMenuItem
                          variant="destructive"
                          onClick={() =>
                            deleteSite.mutate(s.id, {
                              onSuccess: () => toast({ title: `${s.name} removed`, variant: "warning" }),
                              onError: (e) => toast({ title: "Delete failed", description: (e as Error).message, variant: "error" }),
                            })
                          }
                        >
                          Remove site
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {dlg && <SiteDialog initial={dlg} onClose={() => setDlg(null)} />}
    </div>
  );
}

/* Exposure values accepted by the networks.exposure CHECK constraint
 * (migrations/postgres/0001_tenancy.up.sql). The old dialog offered
 * internal/dmz/internet — values the backend silently dropped and the
 * database would have rejected with a 500. */
const NETWORK_EXPOSURES = [
  { value: "internal_only", label: "Internal only" },
  { value: "vpn_only", label: "VPN only" },
  { value: "publicly_reachable", label: "Publicly reachable" },
  { value: "unknown", label: "Unknown" },
] as const;

function exposureLabel(v: string): string {
  return NETWORK_EXPOSURES.find((e) => e.value === v)?.label ?? v;
}

/**
 * SiteDialog — the single site editor. Site fields live at the top; the
 * Networks section appears as soon as the site exists (edit mode, or
 * immediately after a create flips the dialog in place), backed by the live
 * per-site networks query so every Add is reflected without reopening.
 */
function SiteDialog({ initial, onClose }: { initial: Site | "new"; onClose: () => void }) {
  const sitesQ = useSites();
  const createSite = useCreateSite();
  const updateSite = useUpdateSite();
  const createNetwork = useCreateNetwork();

  // After a successful create the raw site comes back from the API; the
  // dialog switches to edit mode and networks become addable at once.
  const [createdId, setCreatedId] = React.useState<string | null>(null);
  const site = initial === "new" ? null : initial;
  const liveId = site?.id ?? createdId;

  // Prefer the freshly invalidated row over the snapshot the table handed
  // us, so a rename elsewhere is reflected on reopen within the session.
  const live = sitesQ.data?.items.find((s) => s.id === liveId) ?? site;

  const [name, setName] = React.useState(site?.name ?? "");
  const [siteType, setSiteType] = React.useState(site?.kind ?? "branch");
  const [description, setDescription] = React.useState(site?.description ?? "");
  const [cidr, setCidr] = React.useState("");
  const [exposure, setExposure] = React.useState<string>("internal_only");

  const netsQ = useSiteNetworks(liveId ?? undefined);
  const networks = netsQ.data?.items ?? [];

  const saveSite = () => {
    if (liveId) {
      updateSite.mutate(
        { id: liveId, name: name.trim() || live?.name, description, site_type: siteType },
        {
          onSuccess: () => toast({ title: `${name || live?.name} updated`, variant: "success" }),
          onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
        },
      );
    } else {
      createSite.mutate(
        { name: name.trim() || "New site", site_type: siteType, description },
        {
          onSuccess: (created) => {
            setCreatedId(created.id);
            toast({ title: `${created.name} created`, description: "Add the network ranges the site scanner may touch.", variant: "success" });
          },
          onError: (e) => toast({ title: "Create failed", description: (e as Error).message, variant: "error" }),
        },
      );
    }
  };

  const addNetwork = () => {
    if (!liveId || !cidr.trim()) return;
    createNetwork.mutate(
      { siteId: liveId, cidr: cidr.trim(), exposure },
      {
        onSuccess: () => {
          setCidr("");
          toast({ title: "Network added", variant: "success" });
        },
        onError: (e) => toast({ title: "Invalid network", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>{liveId ? "Edit site" : "Add site"}</DialogTitle>
          <DialogDescription>
            {liveId
              ? "Scope, context and the address ranges this site covers."
              : "A site groups address ranges under one scope. Networks can be added right after creation."}
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-4">
          <div className="grid gap-1.5">
            <Label>Name</Label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Branch — Munich" autoFocus />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label>Type</Label>
              <Select value={siteType} onValueChange={setSiteType}>
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {["hq", "datacenter", "cloud", "branch", "home", "lab"].map((t) => (
                    <SelectItem key={t} value={t} className="capitalize">
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label>Description</Label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Optional context" />
          </div>

          {liveId && (
            <div className="grid gap-2">
              <Separator />
              <div className="flex items-center gap-2">
                <Label className="text-xs text-muted-foreground">Networks</Label>
                <Badge variant="outline" className="tabular text-[10px]">{networks.length}</Badge>
              </div>
              <ul className="divide-y rounded-lg border text-xs">
                {netsQ.isLoading ? (
                  <li className="px-3 py-2 text-center text-muted-foreground">Loading networks…</li>
                ) : netsQ.isError ? (
                  <li className="flex items-center justify-between gap-2 px-3 py-2">
                    <span className="text-destructive">{(netsQ.error as Error)?.message || "Failed to load networks."}</span>
                    <Button size="icon-xs" variant="ghost" aria-label="Retry" onClick={() => netsQ.refetch()}>
                      <RefreshCw />
                    </Button>
                  </li>
                ) : networks.length === 0 ? (
                  <li className="px-3 py-2 text-center text-muted-foreground">No networks yet</li>
                ) : (
                  networks.map((n) => (
                    <li key={n.id} className="flex items-center justify-between px-3 py-1.5">
                      <Mono className="text-[11px]">{n.cidr}</Mono>
                      <span className="text-muted-foreground">{exposureLabel(n.exposure)}</span>
                    </li>
                  ))
                )}
              </ul>
              <div className="grid grid-cols-[1fr_10rem_auto] gap-2">
                <Input
                  value={cidr}
                  onChange={(e) => setCidr(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addNetwork()}
                  placeholder="10.30.0.0/16"
                  className="font-mono text-xs"
                />
                <Select value={exposure} onValueChange={setExposure}>
                  <SelectTrigger size="sm" className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {NETWORK_EXPOSURES.map((e) => (
                      <SelectItem key={e.value} value={e.value}>{e.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button size="sm" disabled={!cidr.trim() || createNetwork.isPending} onClick={addNetwork}>
                  <Plus /> Add
                </Button>
              </div>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={onClose}>{liveId ? "Close" : "Cancel"}</Button>
          <Button
            onClick={saveSite}
            disabled={!name.trim() || createSite.isPending || updateSite.isPending}
          >
            {liveId ? "Save changes" : "Create site"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

/* ------------------------------------------------------------------ */
function AccountSection() {
  const { user } = useAuth();
  const me = useMe();
  const changePw = useChangeOwnPassword();
  const renameOrg = useRenameOrg();
  const [current, setCurrent] = React.useState("");
  const [next, setNext] = React.useState("");
  const [repeat, setRepeat] = React.useState("");
  const [orgName, setOrgName] = React.useState("");

  const role = me.data?.organizations?.find((o) => o.id === me.data?.current_organization_id)?.role;
  const org = me.data?.organizations?.find((o) => o.id === me.data?.current_organization_id);

  const submitPassword = () => {
    if (next !== repeat) {
      toast({ title: "Passwords do not match", variant: "error" });
      return;
    }
    changePw.mutate(
      { current, next },
      {
        onSuccess: () => {
          toast({ title: "Password changed", description: "Use the new password on your next sign-in.", variant: "success" });
          setCurrent("");
          setNext("");
          setRepeat("");
        },
        onError: (e) => toast({ title: "Password change failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const initials = (user?.name ?? user?.email ?? "U").split(/[^\w]+/).filter(Boolean).slice(0, 2).map((p) => p[0]?.toUpperCase()).join("");

  return (
    <div className="grid gap-4 xl:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Profile</CardTitle>
          <CardDescription>How you appear in audit entries and assignments</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3">
          <div className="flex items-center gap-3">
            <span className="flex size-12 items-center justify-center rounded-lg bg-primary/15 text-base font-semibold text-primary">{initials}</span>
            <div>
              <div className="font-medium">{user?.name}</div>
              <div className="text-xs text-muted-foreground capitalize">
                {role?.replace("_", " ")} · {user?.email}
              </div>
            </div>
          </div>
          <Separator />
          <div className="grid gap-1.5">
            <Label>Organization</Label>
            <div className="flex gap-2">
              <Input value={orgName || org?.name || ""} onChange={(e) => setOrgName(e.target.value)} className="h-8 text-[13px]" />
              <Button
                size="sm"
                variant="outline"
                disabled={!orgName.trim() || orgName === org?.name}
                onClick={() =>
                  renameOrg.mutate(orgName.trim(), {
                    onSuccess: () => toast({ title: "Organization renamed", variant: "success" }),
                    onError: (e) => toast({ title: "Rename failed", description: (e as Error).message, variant: "error" }),
                  })
                }
              >
                <Check /> Rename
              </Button>
            </div>
            <p className="text-[11px] text-muted-foreground">Members see this name in the sidebar and audit log.</p>
          </div>
        </CardContent>
      </Card>

      <div className="flex flex-col gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Security</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex items-center justify-between rounded-lg border px-3 py-2.5">
              <div className="flex items-center gap-3">
                <KeyRound className="size-4 text-muted-foreground" />
                <div>
                  <div className="text-sm font-medium">Password</div>
                  <div className="text-xs text-muted-foreground">Argon2id-hashed; sessions survive on rotating refresh tokens</div>
                </div>
              </div>
            </div>
            <div className="grid gap-2 rounded-lg border p-3">
              <Input type="password" placeholder="Current password" value={current} onChange={(e) => setCurrent(e.target.value)} className="h-8 text-[13px]" />
              <Input type="password" placeholder="New password" value={next} onChange={(e) => setNext(e.target.value)} className="h-8 text-[13px]" />
              <Input type="password" placeholder="Repeat new password" value={repeat} onChange={(e) => setRepeat(e.target.value)} className="h-8 text-[13px]" />
              <div className="flex justify-end">
                <Button size="sm" onClick={submitPassword} disabled={!current || !next || changePw.isPending}>
                  <ShieldCheck className="size-3.5" /> Change password
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Sessions</CardTitle>
            <CardDescription>The SPA keeps the access token in memory only; sessions persist through an HttpOnly rotating cookie that JavaScript can never read.</CardDescription>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-muted-foreground">
              Signing out revokes the whole session family server-side. Tokens rotate on every refresh; reuse of a retired token beyond the grace window revokes the family as theft protection.
            </p>
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
type AProfileDef = {
  name: string
  description: string
  top_tcp_ports: number
  full_port_scan: boolean
  service_detect: boolean
  service_lite?: boolean
  os_detect: boolean
  traceroute: boolean
  max_targets: number
  max_packet_rate: number
  extra_args?: string[]
  builtin?: boolean
}

interface ProfileDraft {
  name: string;
  description: string;
  top_tcp_ports: number;
  full_port_scan: boolean;
  service_detect: boolean;
  service_lite?: boolean;
  os_detect: boolean;
  traceroute: boolean;
  max_targets: number;
  max_packet_rate: number;
  extra_args?: string[];
  builtin?: boolean;
}

function PresetsSection() {
  const navigate = useRouter().navigate;
  const profiles = useProfiles();
  const createProfile = useCreateProfile();
  const updateProfile = useUpdateProfile();
  const deleteProfile = useDeleteProfile();
  const [draft, setDraft] = React.useState<ProfileDraft | null>(null);
  const [editingName, setEditingName] = React.useState<string | null>(null);
  // free-text form of draft.extra_args — kept separate so typing whitespace
  // is not destroyed by re-parsing on every keystroke
  const [extraArgsText, setExtraArgsText] = React.useState("");
  const custom = profiles.data?.raw?.custom ?? [];
  const builtin = profiles.data?.raw?.builtin ?? [];

  const openNew = () => {
    setExtraArgsText("");
    setDraft({
      name: "",
      description: "",
      top_tcp_ports: 1000,
      full_port_scan: false,
      service_detect: true,
      os_detect: true,
      traceroute: true,
      max_targets: 8192,
      max_packet_rate: 300,
    });
  };
  const openEdit = (p: AProfileDef) => {
    setEditingName(p.name);
    setExtraArgsText((p.extra_args ?? []).join(" "));
    setDraft({ ...p });
  };
  const save = () => {
    if (!draft) return;
    const extraArgs = extraArgsText.trim().split(/\s+/).filter(Boolean);
    if (editingName) {
      updateProfile.mutate(
        { ...draft, extra_args: extraArgs, name: draft.name || editingName },
        {
          onSuccess: () => {
            toast({ title: "Profile updated", variant: "success" });
            setDraft(null);
            setEditingName(null);
          },
          onError: (e) => toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
        },
      );
    } else {
      createProfile.mutate(
        { ...draft, extra_args: extraArgs },
        {
          onSuccess: () => {
            toast({ title: "Profile created", variant: "success" });
            setDraft(null);
          },
        onError: (e) => toast({ title: "Create failed", description: (e as Error).message, variant: "error" }),
      });
    }
  };

  const renderCard = (p: AProfileDef, isBuiltin: boolean) => (
    <Card key={p.name} className="gap-3">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 font-mono">
          {p.name}
          {isBuiltin ? <Badge variant="muted">built-in</Badge> : <Badge variant="primary">custom</Badge>}
        </CardTitle>
        <CardDescription>{p.description}</CardDescription>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        <div className="grid grid-cols-3 gap-2 text-xs">
          <div className="rounded-md border bg-muted/30 px-2 py-1.5">
            <div className="text-muted-foreground">Ports</div>
            <Mono className="text-xs">{p.full_port_scan ? "full" : `top ${p.top_tcp_ports}`}</Mono>
          </div>
          <div className="rounded-md border bg-muted/30 px-2 py-1.5">
            <div className="text-muted-foreground">Max rate</div>
            <Mono className="text-xs">{p.max_packet_rate}/s</Mono>
          </div>
          <div className="rounded-md border bg-muted/30 px-2 py-1.5">
            <div className="text-muted-foreground">Max targets</div>
            <span className="text-xs tabular">{p.max_targets}</span>
          </div>
        </div>
        <div className="flex flex-wrap gap-1">
          {[
            p.service_detect && "service detection",
            p.os_detect && "OS detection",
            p.traceroute && "traceroute",
            p.full_port_scan && "full port range",
          ]
            .filter(Boolean)
            .map((s) => (
              <Badge key={s as string} variant="outline" className="font-mono text-[10px]">
                {s}
              </Badge>
            ))}
        </div>
        {!!p.extra_args?.length && (
          <div className="break-all rounded-md border bg-muted/30 px-2 py-1.5 font-mono text-[10.5px] text-muted-foreground">
            + {p.extra_args.join(" ")}
          </div>
        )}
        <div className="flex items-center justify-between border-t pt-3">
          <div className="flex gap-1">
            {!isBuiltin && (
              <>
                <Button size="xs" variant="ghost" className="text-muted-foreground" onClick={() => openEdit(p)}>
                  Edit
                </Button>
                <Button
                  size="xs"
                  variant="ghost"
                  className="text-muted-foreground hover:text-destructive"
                  onClick={() =>
                    deleteProfile.mutate(p.name, {
                      onSuccess: () => toast({ title: "Profile deleted", variant: "warning" }),
                      onError: (e) => toast({ title: "Delete failed", description: (e as Error).message, variant: "error" }),
                    })
                  }
                >
                  <Trash2 /> Delete
                </Button>
              </>
            )}
          </div>
          <Button size="xs" variant="outline" onClick={() => navigate(`/scans?new=1&preset=${p.name}`)}>
            <Radar /> Use preset
          </Button>
        </div>
      </CardContent>
    </Card>
  );

  return (
    <div className="flex flex-col gap-5">
      <div className="flex justify-end">
        <Button size="sm" onClick={openNew}>
          <Plus /> New preset
        </Button>
      </div>
      <section className="flex flex-col gap-2">
        <div className="flex items-center gap-2">
          <h3 className="text-sm font-semibold">Built-in profiles</h3>
          <Badge variant="muted" className="tabular">{builtin.length}</Badge>
        </div>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{builtin.map((p) => renderCard(p, true))}</div>
      </section>
      {custom.length > 0 && (
        <section className="flex flex-col gap-2">
          <div className="flex items-center gap-2">
            <h3 className="text-sm font-semibold">Custom profiles</h3>
            <Badge variant="muted" className="tabular">{custom.length}</Badge>
          </div>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{custom.map((p) => renderCard(p, false))}</div>
        </section>
      )}

      {draft && (
        <Dialog open onOpenChange={(o) => !o && setDraft(null)}>
          <DialogContent className="sm:max-w-lg">
            <DialogHeader>
              <DialogTitle>{editingName ? "Edit profile" : "New profile"}</DialogTitle>
              <DialogDescription>Profiles define the safety envelope for scans: what is scanned, how loud, and how far.</DialogDescription>
            </DialogHeader>
            <div className="grid gap-3">
              <div className="grid gap-1.5">
                <Label>Name</Label>
                <Input value={draft.name} onChange={(e) => setDraft({ ...draft, name: e.target.value })} placeholder="perimeter_weekly" className="font-mono text-xs" />
              </div>
              <div className="grid gap-1.5">
                <Label>Description</Label>
                <Input value={draft.description} onChange={(e) => setDraft({ ...draft, description: e.target.value })} placeholder="Low-rate perimeter sweep" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label>Top TCP ports</Label>
                  <Input type="number" value={draft.top_tcp_ports} onChange={(e) => setDraft({ ...draft, top_tcp_ports: Number(e.target.value) || 1000 })} />
                </div>
                <div className="grid gap-1.5">
                  <Label>Max packet rate</Label>
                  <Input type="number" value={draft.max_packet_rate} onChange={(e) => setDraft({ ...draft, max_packet_rate: Number(e.target.value) || 300 })} />
                </div>
                <div className="grid gap-1.5">
                  <Label>Max targets</Label>
                  <Input type="number" value={draft.max_targets} onChange={(e) => setDraft({ ...draft, max_targets: Number(e.target.value) || 4096 })} />
                </div>
              </div>
              <div className="grid gap-1.5">
                {[
                  ["full_port_scan", "Full port range (1-65535)"],
                  ["service_detect", "Service / version detection"],
                  ["os_detect", "OS fingerprinting"],
                  ["traceroute", "Path tracing"],
                ].map(([k, label]) => (
                  <label key={k} className="flex cursor-pointer items-center justify-between rounded-md border px-2.5 py-1.5 text-[13px]">
                    {label}
                    <Switch checked={Boolean(draft[k as keyof ProfileDraft])} onCheckedChange={(v) => setDraft({ ...draft, [k]: v })} />
                  </label>
                ))}
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="profile-extra-args">Extra nmap arguments</Label>
                <Input
                  id="profile-extra-args"
                  value={extraArgsText}
                  onChange={(e) => setExtraArgsText(e.target.value)}
                  placeholder="--max-retries 2 -T4"
                  className="font-mono text-xs"
                />
                <p className="text-[11px] leading-relaxed text-muted-foreground">
                  Appended to every nmap phase, space-separated. Allowed flags: --max-rate, --min-rate,
                  --max-retries, --top-ports, -p, -T1…-T5, -F, -Pn, -n, --system-dns,
                  --defeat-rst-ratelimit, --disable-arp-ping, --send-eth, --send-ip, --unprivileged.
                  Everything else (scripts, file inputs) is rejected by the server.
                </p>
                {extraArgsText.trim() && (
                  <p className="break-all rounded-md border bg-muted/30 px-2 py-1.5 font-mono text-[10.5px] text-muted-foreground">
                    preview: nmap -Pn -n -sS --open {draft.full_port_scan ? "-p-" : `--top-ports ${draft.top_tcp_ports || 1000}`}
                    {draft.service_detect ? " -sV --version-intensity 5" : ""}
                    {draft.service_lite ? " -sV --version-light" : ""}
                    {draft.os_detect ? " -O" : ""}
                    {draft.traceroute ? " --traceroute" : ""} {extraArgsText.trim()}
                  </p>
                )}
              </div>
            </div>
            <DialogFooter>
              <Button variant="ghost" onClick={() => setDraft(null)}>
                Cancel
              </Button>
              <Button onClick={save} disabled={!draft.name.trim()}>
                {editingName ? "Save changes" : "Create profile"}
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
function UsersSection() {
  const me = useMe();
  const usersQ = useUsers();
  const createUser = useCreateUser();
  const updateUser = useUpdateUser();
  const resetPw = useResetUserPassword();
  const [invite, setInvite] = React.useState(false);
  const [email, setEmail] = React.useState("");
  const [name, setName] = React.useState("");
  const [role, setRole] = React.useState("operator");
  const [password, setPassword] = React.useState("");
  const [resetTarget, setResetTarget] = React.useState<User | null>(null);
  const [resetPwValue, setResetPwValue] = React.useState("");

  const users = usersQ.data ?? [];
  const pagedUsers = usePagination(users, "users");
  const myId = me.data?.user?.id;

  const inviteUser = () => {
    createUser.mutate(
      { email, name, role, password },
      {
        onSuccess: () => {
          toast({ title: "User created", description: `${name || email} can sign in now.`, variant: "success" });
          setInvite(false);
          setEmail("");
          setName("");
          setPassword("");
        },
        onError: (e) => toast({ title: "Invite failed", description: (e as Error).message, variant: "error" }),
      },
    );
  };

  const roleTone: Record<string, "primary" | "high" | "low" | "info"> = {
    owner: "primary",
    administrator: "primary",
    security_analyst: "low",
    operator: "high",
    viewer: "info",
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <div className="flex gap-2 text-xs">
          <Badge variant="outline" className="py-1">
            {users.filter((u) => u.status === "active").length} active
          </Badge>
          <Badge variant="outline" className="py-1">
            {users.filter((u) => u.status === "disabled").length} disabled
          </Badge>
        </div>
        <Button size="sm" onClick={() => setInvite(true)}>
          <Plus /> Add user
        </Button>
      </div>
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">User</TableHead>
              <TableHead>Role</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Last active</TableHead>
              <TableHead className="w-10" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {pagedUsers.slice.map((u) => (
              <TableRow key={u.id}>
                <TableCell className="pl-4">
                  <div className="flex items-center gap-2.5">
                    <span className="flex size-7 items-center justify-center rounded-full bg-primary/15 text-[10px] font-semibold text-primary">
                      {u.name
                        .split(" ")
                        .map((p) => p[0])
                        .join("")
                        .slice(0, 2)}
                    </span>
                    <div className="leading-tight">
                      <div className="font-medium">
                        {u.name} {u.id === myId && <span className="text-xs text-muted-foreground">(you)</span>}
                      </div>
                      <div className="text-[11px] text-muted-foreground">{u.email}</div>
                    </div>
                  </div>
                </TableCell>
                <TableCell>
                  <Select
                    value={u.role}
                    onValueChange={(v) =>
                      updateUser.mutate(
                        { id: u.id, role: v },
                        {
                          onSuccess: () => toast({ title: "Role updated", variant: "success" }),
                          onError: (e) => toast({ title: "Role change failed", description: (e as Error).message, variant: "error" }),
                        },
                      )
                    }
                    disabled={u.id === myId}
                  >
                    <SelectTrigger size="sm" className="h-7 w-36 border-transparent bg-transparent text-xs hover:bg-accent/50">
                      <Badge variant={roleTone[u.role] ?? "info"} className="capitalize">
                        {u.role.replace("_", " ")}
                      </Badge>
                    </SelectTrigger>
                    <SelectContent>
                      {["owner", "administrator", "security_analyst", "operator", "viewer"].map((r) => (
                        <SelectItem key={r} value={r} className="capitalize">
                          {r.replace("_", " ")}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </TableCell>
                <TableCell>
                  <StateBadge label={u.status} tone={u.status === "active" ? "success" : "muted"} />
                </TableCell>
                <TableCell className="tabular text-xs text-muted-foreground">{u.lastActive ? timeAgo(u.lastActive) : "—"}</TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button variant="ghost" size="icon-xs" className="text-muted-foreground">
                        <MoreHorizontal />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem
                        onClick={() => {
                          setResetTarget(u);
                          setResetPwValue("");
                        }}
                      >
                        <KeyRound /> Reset password
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      {u.status === "disabled" ? (
                        <DropdownMenuItem
                          onClick={() =>
                            updateUser.mutate(
                              { id: u.id, disabled: false },
                              { onSuccess: () => toast({ title: "Account re-enabled", variant: "success" }) },
                            )
                          }
                        >
                          Re-enable
                        </DropdownMenuItem>
                      ) : (
                        <DropdownMenuItem
                          variant="destructive"
                          disabled={u.id === myId}
                          onClick={() =>
                            updateUser.mutate(
                              { id: u.id, disabled: true },
                              { onSuccess: () => toast({ title: "Account disabled", variant: "warning" }) },
                            )
                          }
                        >
                          Disable account
                        </DropdownMenuItem>
                      )}
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {pagedUsers.slice.length > 0 && <TableFooterBar total={pagedUsers.total} page={pagedUsers.page} pageSize={pagedUsers.pageSize} onPage={pagedUsers.setPage} onPageSize={pagedUsers.setPageSize} label="users" />}
      </div>

      <Dialog open={invite} onOpenChange={setInvite}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add user</DialogTitle>
            <DialogDescription>Creates the account with a temporary password. The user should change it after first sign-in.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label>Email</Label>
              <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="name@company.example" />
            </div>
            <div className="grid gap-1.5">
              <Label>Name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Full name" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label>Role</Label>
                <Select value={role} onValueChange={setRole}>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="administrator">Administrator — full access incl. settings</SelectItem>
                    <SelectItem value="security_analyst">Analyst — triage findings &amp; detections</SelectItem>
                    <SelectItem value="operator">Operator — run scans, manage assets</SelectItem>
                    <SelectItem value="viewer">Viewer — read-only</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="grid gap-1.5">
                <Label>Temporary password</Label>
                <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setInvite(false)}>
              Cancel
            </Button>
            <Button onClick={inviteUser} disabled={!email.trim() || !password || createUser.isPending}>
              Create user
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={!!resetTarget} onOpenChange={(o) => !o && setResetTarget(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Reset password — {resetTarget?.name}</DialogTitle>
            <DialogDescription>Sets a new temporary password. All existing sessions keep working until their tokens expire.</DialogDescription>
          </DialogHeader>
          <Input type="password" value={resetPwValue} onChange={(e) => setResetPwValue(e.target.value)} placeholder="New temporary password" />
          <DialogFooter>
            <Button variant="ghost" onClick={() => setResetTarget(null)}>
              Cancel
            </Button>
            <Button
              disabled={!resetPwValue}
              onClick={() =>
                resetPw.mutate(
                  { id: resetTarget!.id, password: resetPwValue },
                  {
                    onSuccess: () => {
                      toast({ title: "Password reset", variant: "success" });
                      setResetTarget(null);
                    },
                    onError: (e) => toast({ title: "Reset failed", description: (e as Error).message, variant: "error" }),
                  },
                )
              }
            >
              Reset
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function ScannersSection() {
  const scannersQ = useScanners();
  const sitesQ = useSites();
  const setDefault = useSetDefaultScanner();
  const enroll = useEnrollScanner();
  const [enrollOpen, setEnrollOpen] = React.useState(false);
  const [name, setName] = React.useState("");
  const [siteId, setSiteId] = React.useState("");
  const [issued, setIssued] = React.useState<{ scanner_id: string; token: string } | null>(null);

  const scanners = scannersQ.data ?? [];

  return (
    <div className="flex flex-col gap-4">
      <Alert variant="info">
        <Info />
        <AlertTitle>Prefer a scanner connection</AlertTitle>
        <AlertDescription>
          <p>
            Add new scan engines as a <Mono className="text-xs">scanner</Mono> connection under{" "}
            <Link to="/connections" className="text-primary hover:underline">
              Connections
            </Link>
            . The dialog below enrolls a legacy hub agent and is kept for compatibility.
          </p>
        </AlertDescription>
      </Alert>
      <div className="flex justify-end">
        <Button size="sm" variant="outline" onClick={() => setEnrollOpen(true)}>
          <Plus /> Enroll scanner (legacy)
        </Button>
      </div>
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Scanner</TableHead>
              <TableHead>Transport</TableHead>
              <TableHead>Health</TableHead>
              <TableHead>Capabilities</TableHead>
              <TableHead>Last seen</TableHead>
              <TableHead className="text-right pr-4">Default</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {scanners.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6}>
                  <EmptyState icon={Radar} title="No scanners registered" description="Enroll the embedded scanner or connect a scanner connector." />
                </TableCell>
              </TableRow>
            ) : (
              scanners.map((s) => (
                <TableRow key={s.id}>
                  <TableCell className="pl-4">
                    <div className="leading-tight">
                      <div className="flex items-center gap-2 font-medium">
                        {s.name}
                        {s.isDefault && (
                          <Badge variant="primary" className="gap-1">
                            <Star className="size-3" /> default
                          </Badge>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-1 text-[11px] text-muted-foreground">
                        <Mono className="text-[11px]">{s.version}</Mono> · {s.capabilities.join(", ")}
                      </div>
                    </div>
                  </TableCell>
                  <TableCell>
                    <Badge variant="muted" className="capitalize">
                      {s.transport}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <StateBadge label={s.health} tone={s.health === "healthy" ? "success" : s.health === "degraded" ? "warning" : "danger"} pulse={s.health === "healthy"} />
                  </TableCell>
                  <TableCell className="text-xs text-muted-foreground">{s.capabilities.length}</TableCell>
                  <TableCell className={cn("tabular text-xs", s.health === "offline" ? "text-critical" : "text-muted-foreground")}>{timeAgo(s.lastSeen)}</TableCell>
                  <TableCell className="text-right pr-4">
                    <Button
                      size="xs"
                      variant={s.isDefault ? "ghost" : "outline"}
                      disabled={s.isDefault || s.health === "offline"}
                      onClick={() =>
                        setDefault.mutate(
                          { id: s.id, is_default: true },
                          {
                            onSuccess: () => toast({ title: `${s.name} is now the default scanner`, description: "New scans without an explicit scanner will use it.", variant: "success" }),
                            onError: (e) => toast({ title: "Failed", description: (e as Error).message, variant: "error" }),
                          },
                        )
                      }
                    >
                      {s.isDefault ? "Current default" : "Make default"}
                    </Button>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <Dialog
        open={enrollOpen}
        onOpenChange={(o) => {
          setEnrollOpen(o);
          if (!o) setIssued(null);
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Enroll legacy hub scanner</DialogTitle>
            <DialogDescription>Generates a one-time enrollment token for a hub agent against a site.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-3">
            <div className="grid gap-1.5">
              <Label>Scanner name</Label>
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="scanner-branch-01" />
            </div>
            <div className="grid gap-1.5">
              <Label>Site</Label>
              <Select value={siteId} onValueChange={setSiteId}>
                <SelectTrigger className="w-full">
                  <SelectValue placeholder="Choose a site" />
                </SelectTrigger>
                <SelectContent>
                  {(sitesQ.data?.items ?? []).map((s) => (
                    <SelectItem key={s.id} value={s.id}>
                      {s.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            {issued && (
              <div className="rounded-lg border bg-[oklch(0.11_0.01_262)] p-3 font-mono text-[11.5px] break-all">
                aegis-hub enroll --server &lt;hub-host&gt;:9090 --token {issued.token}
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="ghost" onClick={() => setEnrollOpen(false)}>
              Close
            </Button>
            {!issued && (
              <Button
                disabled={!name.trim() || !siteId}
                onClick={() =>
                  enroll.mutate(
                    { name, site_id: siteId },
                    {
                      onSuccess: (res) => {
                        setIssued(res);
                        toast({ title: "Scanner enrolled", description: "Copy the one-time token — it is shown only once.", variant: "success" });
                      },
                      onError: (e) => toast({ title: "Enroll failed", description: (e as Error).message, variant: "error" }),
                    },
                  )
                }
              >
                Enroll
              </Button>
            )}
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function FeedsSection() {
  const feedsQ = useFeeds();
  const syncM = useTriggerFeedSync();
  const [syncing, setSyncing] = React.useState<string | null>(null);
  const feeds = feedsQ.data ?? [];
  const sync = (id: string) => {
    setSyncing(id);
    syncM.mutate(id, {
      onSuccess: () => toast({ title: `${id} sync queued`, description: "Matching will use the new snapshot after ingestion.", variant: "success" }),
      onError: (e) => toast({ title: "Sync failed", description: (e as Error).message, variant: "error" }),
      onSettled: () => setSyncing(null),
    });
  };
  const stale = feeds.filter((f) => f.status === "stale" || f.status === "error");
  return (
    <div className="flex flex-col gap-4">
      {stale.length > 0 && (
        <Alert variant="warning">
          <Rss />
          <AlertTitle>
            {stale.length} feed{stale.length > 1 ? "s" : ""} need attention
          </AlertTitle>
          <AlertDescription>Vulnerability matching uses the last successful snapshot. Stale feeds may hide newly published CVEs or KEV entries.</AlertDescription>
        </Alert>
      )}
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Feed</TableHead>
              <TableHead>Kind</TableHead>
              <TableHead className="text-right">Records in index</TableHead>
              <TableHead>Status</TableHead>
              <TableHead>Last sync</TableHead>
              <TableHead>License</TableHead>
              <TableHead className="text-right pr-4" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {feeds.map((f) => (
              <TableRow key={f.id}>
                <TableCell className="pl-4">
                  <div className="font-medium">{f.name}</div>
                  <div className="text-[11px] text-muted-foreground">{f.provider}</div>
                  {f.lastError && <div className="mt-0.5 text-[11px] text-critical">{f.lastError}</div>}
                </TableCell>
                <TableCell>
                  <Badge variant="outline" className="uppercase">
                    {f.kind}
                  </Badge>
                </TableCell>
                <TableCell className="text-right">
                  <div className="tabular">{f.entries !== undefined ? formatNumber(f.entries) : "—"}</div>
                  {f.lastProcessed !== undefined && f.status !== "disabled" && (
                    <div className="text-[11px] tabular text-muted-foreground">
                      last sync: {f.recordsNew ?? 0} new · {f.recordsUpdated ?? 0} updated ({formatNumber(f.lastProcessed)} processed)
                    </div>
                  )}
                </TableCell>
                <TableCell>
                  <StateBadge
                    label={f.status === "running" ? "syncing" : f.status}
                    tone={f.status === "ok" ? "success" : f.status === "running" ? "primary" : f.status === "stale" ? "warning" : f.status === "disabled" ? "muted" : "danger"}
                    pulse={f.status === "running"}
                  />
                </TableCell>
                <TableCell className={cn("tabular text-xs", f.status === "ok" ? "text-muted-foreground" : "text-medium")}>{f.lastSync ? timeAgo(f.lastSync) : "never"}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{f.license ?? "—"}</TableCell>
                <TableCell className="text-right pr-4">
                  <Button size="xs" variant="outline" onClick={() => sync(f.id)} disabled={syncing === f.id}>
                    <RefreshCw className={cn(syncing === f.id && "animate-spin")} /> Sync now
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
const METRICS_RETENTION_PRESETS = [7, 14, 30, 60, 90, 180, 365];

function MetricsSection() {
  const settingsQ = useSettings();
  const updateSettings = useUpdateSettings();
  const cleanup = useRunMetricsCleanup();
  const metrics = settingsQ.data?.metrics;
  const stats = metrics?.stats;
  // Local edit buffer: null until the operator touches the select — the
  // server value stays authoritative while the query loads or refetches.
  const [days, setDays] = React.useState<number | null>(null);
  const [customDays, setCustomDays] = React.useState(45);
  const value = days ?? metrics?.retention_days ?? 30;
  const isPreset = value === 0 || METRICS_RETENTION_PRESETS.includes(value);
  const dirty = days !== null && days !== metrics?.retention_days;
  const appliedPending = !!metrics && metrics.applied_days !== metrics.retention_days;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Metrics retention</CardTitle>
          <CardDescription>
            How long device performance samples are kept in the analytics store. Older data is purged automatically;
            lowering the value immediately clears everything beyond the new window.
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <Select
              value={isPreset ? String(value) : "custom"}
              onValueChange={(v) => setDays(v === "custom" ? customDays : Number(v))}
            >
              <SelectTrigger className="w-52" aria-label="Metrics retention">
                <SelectValue>{value === 0 ? "Keep forever" : `${value} days`}</SelectValue>
              </SelectTrigger>
              <SelectContent>
                {METRICS_RETENTION_PRESETS.map((d) => (
                  <SelectItem key={d} value={String(d)}>
                    {d} days
                  </SelectItem>
                ))}
                <SelectItem value="0">Keep forever</SelectItem>
                <SelectSeparator />
                <SelectItem value="custom">Custom…</SelectItem>
              </SelectContent>
            </Select>
            {!isPreset && (
              <Input
                type="number"
                min={1}
                max={3650}
                value={customDays}
                onChange={(e) => {
                  const n = Math.min(3650, Math.max(1, Math.floor(Number(e.target.value) || 1)));
                  setCustomDays(n);
                  setDays(n);
                }}
                className="w-28"
                aria-label="Custom retention days"
              />
            )}
          </div>
          <div className="flex items-center gap-3">
            <Button size="sm" disabled={!dirty || updateSettings.isPending} onClick={() => updateSettings.mutate({ metrics: { retention_days: value } })}>
              {updateSettings.isPending ? "Saving…" : "Save"}
            </Button>
            {appliedPending && <span className="text-xs text-muted-foreground">Applying the new retention to storage…</span>}
          </div>
          <p className="text-xs text-muted-foreground">
            The setting is deployment-wide: the analytics store is shared by every site. Changes are audited and take
            effect immediately.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Storage</CardTitle>
          <CardDescription>Current usage of the device metrics table</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-col gap-3">
          {stats ? (
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-lg border p-3">
                <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Samples</div>
                <div className="tabular text-lg font-semibold">{formatNumber(stats.rows)}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Oldest sample</div>
                <div className="text-sm font-semibold">{stats.oldest ? timeAgo(stats.oldest) : "—"}</div>
              </div>
              <div className="rounded-lg border p-3">
                <div className="text-[11px] uppercase tracking-wider text-muted-foreground">Newest sample</div>
                <div className="text-sm font-semibold">{stats.newest ? timeAgo(stats.newest) : "—"}</div>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              {settingsQ.isLoading ? "Loading storage stats…" : "The analytics tier is not configured on this deployment."}
            </p>
          )}
          <div className="flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!stats || value === 0 || cleanup.isPending}
              onClick={() => cleanup.mutate()}
            >
              <RefreshCw className={cn("size-3.5", cleanup.isPending && "animate-spin")} /> Clean up now
            </Button>
            <span className="text-xs text-muted-foreground">Removes everything older than the retention window immediately.</span>
          </div>
          {value === 0 && (
            <p className="text-xs text-muted-foreground">Retention is disabled (keep forever) — set a window to enable cleanup.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

/* ------------------------------------------------------------------ */
function AuditSection() {
  const auditQ = useAuditLog({ limit: 200 });
  const [q, setQ] = React.useState("");
  const [outcome, setOutcome] = React.useState("all");
  const list = (auditQ.data ?? []).filter((a) => {
    if (outcome !== "all" && a.outcome !== outcome) return false;
    const n = q.toLowerCase();
    return !n || [a.actor, a.action, a.target, a.ip].some((s) => s.toLowerCase().includes(n));
  });
  const pagedAudit = usePagination(list, "audit");
  const exportCsv = () => {
    const rows = [
      ["timestamp", "actor", "action", "target", "ip", "outcome"],
      ...(auditQ.data ?? []).map((a) => [a.timestamp, a.actor, a.action, a.target, a.ip, a.outcome]),
    ];
    const csv = rows.map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const el = document.createElement("a");
    el.href = url;
    el.download = "aegis-audit.csv";
    el.click();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  };
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 size-4 -translate-y-1/2 text-muted-foreground" />
          <Input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Actor, action, target, IP…" className="h-8 pl-8 text-[13px]" />
        </div>
        <Select value={outcome} onValueChange={setOutcome}>
          <SelectTrigger size="sm" className="w-[150px]">
            <span className="text-muted-foreground">Outcome:</span> <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Any</SelectItem>
            <SelectItem value="success">Success</SelectItem>
            <SelectItem value="denied">Denied</SelectItem>
            <SelectItem value="failure">Failure</SelectItem>
          </SelectContent>
        </Select>
        <div className="ml-auto">
          <Button size="sm" variant="outline" onClick={exportCsv}>
            <Download /> Export
          </Button>
        </div>
      </div>
      <div className="overflow-hidden rounded-xl border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="pl-4">Time</TableHead>
              <TableHead>Actor</TableHead>
              <TableHead>Action</TableHead>
              <TableHead>Target</TableHead>
              <TableHead>Source IP</TableHead>
              <TableHead>Outcome</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.length === 0 ? (
              <TableRow className="hover:bg-transparent">
                <TableCell colSpan={6}>
                  <EmptyState compact icon={ScrollText} title="No audit entries match" />
                </TableCell>
              </TableRow>
            ) : (
              pagedAudit.slice.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className="pl-4 tabular text-xs text-muted-foreground">{formatDateTime(a.timestamp)}</TableCell>
                  <TableCell className="text-xs">
                    <Mono className="text-[11px]">{a.actor.slice(0, 8)}</Mono>
                  </TableCell>
                  <TableCell>
                    <Mono className="text-xs">{a.action}</Mono>
                  </TableCell>
                  <TableCell className="max-w-xs truncate text-xs text-muted-foreground">{a.target}</TableCell>
                  <TableCell>
                    <Mono className="text-xs text-muted-foreground">{a.ip}</Mono>
                  </TableCell>
                  <TableCell>
                    <StateBadge label={a.outcome} tone={a.outcome === "success" ? "success" : a.outcome === "denied" ? "warning" : "danger"} />
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
        {pagedAudit.slice.length > 0 && <TableFooterBar total={pagedAudit.total} page={pagedAudit.page} pageSize={pagedAudit.pageSize} onPage={pagedAudit.setPage} onPageSize={pagedAudit.setPageSize} label="audit entries" />}
      </div>
      <Separator />
      <p className="text-xs text-muted-foreground">Audit entries are append-only. Retention follows the database policy; export captures the most recent entries shown.</p>
    </div>
  );
}
