// Data layer: typed react-query hooks for the whole /api/v1 surface.
// Every hook returns UI-model objects (data/types.ts); the raw snake_case
// API shapes (api-types.ts) are mapped here so pages stay transport-free.
// Mutation hooks invalidate the query keys they affect.
import { keepPreviousData, useMutation, useQuery, useQueryClient, type UseQueryOptions } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { ws, useWSStatus } from "@/lib/ws";
import { toast } from "@/components/ui/toaster";
import { useEffect } from "react";
import * as A from "@/lib/api-types";
import type {
  Asset, AssetDetailBundle, AssetType, AuditEntry, Connection, ConnectionKind,
  Detection, DetectionStatus, EndpointDevice, Exposure, Feed, Finding, FindingStatus, Port, Preset, Report,
  PlatformEvent, Scan, Schedule, Scanner, Severity, SeverityCounts, Site, Software, Trace, User, Vulnerability,
} from "@/data/types";
import type { AssetMetricsResponse } from "@/data/types";
import { isCrit } from "@/lib/labels";

// ---------------------------------------------------------------------------
// helpers

export const qk = {
  me: ["me"] as const,
  sites: ["sites"] as const,
  siteNetworks: (id: string) => ["sites", id, "networks"] as const,
  assets: (params: Record<string, unknown>) => ["assets", params] as const,
  asset: (id: string) => ["asset", id] as const,
  assetFindings: (id: string) => ["asset", id, "findings"] as const,
  assetTraces: (id: string) => ["asset", id, "traces"] as const,
  groups: ["asset-groups"] as const,
  scans: (params?: Record<string, unknown>) => ["scans", params ?? {}] as const,
  scan: (id: string) => ["scan", id] as const,
  profiles: ["scan-profiles"] as const,
  scanners: ["scanners"] as const,
  schedules: ["schedules"] as const,
  vulns: (params: Record<string, unknown>) => ["vulnerabilities", params] as const,
  vuln: (id: string) => ["vulnerability", id] as const,
  findings: (params: Record<string, unknown>) => ["findings", params] as const,
  finding: (id: string) => ["finding", id] as const,
  matches: (params?: Record<string, unknown>) => ["detection-matches", params ?? {}] as const,
  rules: ["detection-rules"] as const,
  events: (params: Record<string, unknown>) => ["events", params] as const,
  connections: ["connectors"] as const,
  connection: (id: string) => ["connector", id] as const,
  reports: ["reports"] as const,
  reportJobs: ["report-jobs"] as const,
  feeds: ["feeds"] as const,
  audit: (params: Record<string, unknown>) => ["audit-log", params] as const,
  users: ["users"] as const,
  webhooks: ["webhooks"] as const,
  search: (q: string) => ["search", q] as const,
  metrics: (site: string) => ["metrics", site] as const,
  metricsTimeseries: (metric: string, days: number, site: string) => ["metrics-ts", metric, days, site] as const,
  settings: ["settings"] as const,
};

const num = (v: unknown, d = 0): number => (typeof v === "number" && Number.isFinite(v) ? v : d);
const str = (v: unknown, d = ""): string => (typeof v === "string" ? v : d);
/** Confidence values arrive 0..1; the UI renders 0..100. */
const pct = (v: unknown, d = 0): number => (typeof v === "number" && Number.isFinite(v) ? (v <= 1 ? Math.round(v * 100) : Math.round(v)) : d);

/** Derive the coarse severity bucket from a CVSS base score. */
export function severityFromScore(score: number): Severity {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

const DEVICE_TYPES: Record<string, AssetType> = {
  workstation: "workstation", server: "server", laptop: "workstation", mobile: "mobile",
  router: "router", switch: "switch", firewall: "firewall", access_point: "access_point",
  printer: "printer", camera: "camera", iot: "iot", nas: "nas", hypervisor: "hypervisor",
  virtual_machine: "virtual_machine", container_host: "container_host", unknown: "unknown",
};
export const assetTypeOf = (raw?: string): AssetType => DEVICE_TYPES[raw ?? "unknown"] ?? "unknown";

const EXPOSURES: Record<string, Exposure> = {
  internet: "internet", dmz: "dmz", internal: "internal", unknown: "unknown",
};
export const exposureOf = (raw?: string): Exposure => EXPOSURES[raw ?? "unknown"] ?? "unknown";

function mapAsset(a: A.Asset): Asset {
  const f = a.findings ?? {};
  const counts: SeverityCounts = {
    critical: num(f.critical), high: num(f.high), medium: num(f.medium), low: num(f.low),
  };
  return {
    id: a.id, ip: a.primary_ip || a.hostname || a.fqdn || a.id,
    hostname: a.hostname || undefined, fqdn: a.fqdn || undefined,
    vendor: a.vendor || undefined, model: a.model || undefined,
    type: assetTypeOf(a.device_type),
    os: [a.os_name, a.os_version].filter(Boolean).join(" ") || undefined,
    osConfidence: pct(a.os_confidence),
    osSources: a.os_sources ?? [],
    criticality: (isCrit(a.criticality) ? a.criticality : "none") as Asset["criticality"],
    exposure: exposureOf(a.exposure),
    risk: num(a.risk_score),
    riskExplanation: a.risk_explanation || undefined,
    hasAgent: !!a.has_agent,
    agentId: a.agent_id ?? undefined,
    site: a.site_id,
    tags: a.tags ?? [],
    owner: a.owner || undefined,
    notes: a.notes || undefined,
    nameOverride: a.name_override ?? null,
    typeOverride: a.device_type_override ?? null,
    parentOverride: a.parent_override ?? null,
    firstSeen: a.first_seen, lastSeen: a.last_seen,
    findings: counts,
    endpoint: a.endpoint ? mapDevice(a.endpoint) : undefined,
  };
}

// mapInterfaces shapes the asset-bundle interfaces for the Network tab.
// The backend flattens each interface (interfaceView: ip = the primary
// observed address, vlan = vlan_id) and also ships the full addresses
// list — every IPv4 and IPv6 the endpoint/scan recorded, primary flagged
// by the hub's reachability selection (management address, then global
// IPv4, then global IPv6). `ip` keeps a fallback chain for old payloads;
// `addresses` is sorted primary-first for rendering.
export function mapInterfaces(rows: A.Interface[] | undefined) {
  return (rows ?? []).map((i) => {
    const addresses = [...(i.addresses ?? [])]
      .map((a) => ({ ip: a.ip, is_primary: !!a.is_primary }))
      .sort((a, b) => Number(b.is_primary) - Number(a.is_primary));
    return {
      name: i.name,
      ip: i.ip || addresses.find((a) => a.is_primary)?.ip || addresses[0]?.ip || "",
      addresses,
      mac: i.mac || undefined,
      vendor: i.vendor || undefined,
      vlan: i.vlan ?? i.vlan_id ?? undefined,
    };
  });
}

function mapService(s: A.Service): Port {
  return {
    port: s.port,
    proto: (s.protocol === "udp" ? "udp" : "tcp"),
    service: s.service_name || "unknown",
    product: [s.vendor, s.product].filter(Boolean).join(" ") || undefined,
    version: s.detected_version || undefined,
    versionMeta: s.version_meta
      ? { raw: s.version_meta.raw, normalized: s.version_meta.normalized, wellFormed: s.version_meta.well_formed, grammar: s.version_meta.grammar, epoch: s.version_meta.epoch, upstream: s.version_meta.upstream, revision: s.version_meta.revision }
      : undefined,
    state: s.state || "open",
    banner: s.banner || undefined,
    exposure: s.exposure || undefined,
    confidence: pct(s.confidence),
  };
}

function mapSoftware(s: A.SoftwareRow): Software {
  return {
    id: s.id, name: s.name, version: s.version || "",
    versionNorm: s.version_norm || undefined,
    versionMeta: s.version_meta
      ? { raw: s.version_meta.raw, normalized: s.version_meta.normalized, wellFormed: s.version_meta.well_formed, grammar: s.version_meta.grammar, epoch: s.version_meta.epoch, upstream: s.version_meta.upstream, revision: s.version_meta.revision }
      : undefined,
    ecosystem: s.ecosystem || undefined, purl: s.purl || undefined, source: s.source || undefined,
  };
}

export function mapVulnRow(r: A.VulnListRow): Vulnerability {
  return {
    id: r.cve_id, title: r.cve_id,
    source: r.source || "nvd", state: r.state,
    severity: severityFromScore(r.cvss_score),
    cvss: r.cvss_score, cvssVector: r.cvss_vector || undefined,
    epss: r.epss, kev: r.known_exploited,
    publishedAt: r.published_at || undefined,
    affectedAssetCount: num(r.affected_assets), openFindings: num(r.open_findings),
    summary: r.description,
  };
}

export function mapFinding(f: A.Finding): Finding {
  return {
    id: f.id, title: f.title,
    severity: (f.severity || "info") as Severity,
    status: (f.status || "open") as FindingStatus,
    assetId: f.asset_id, cve: f.cve_id || undefined, osv: f.osv_id || undefined,
    category: f.match_type || "vulnerability",
    confidence: pct(f.confidence), riskScore: num(f.risk_score),
    remediation: f.remediation || undefined, notes: f.notes || undefined,
    firstSeen: f.first_seen, lastSeen: f.last_seen, assignee: f.owner || undefined,
  };
}

// ---------------------------------------------------------------------------
// auth / me

export function useMe() {
  return useQuery({
    queryKey: qk.me,
    queryFn: () => api.get<A.Me>("/auth/me"),
  });
}

// ---------------------------------------------------------------------------
// sites + networks

export function mapSite(s: A.Site, networks: A.Network[] = []): Site {
  return {
    id: s.id, name: s.name, description: s.description || undefined,
    kind: s.site_type, assets: num(s.asset_count),
    networks: networks.map((n) => ({ id: n.id, cidr: n.cidr, name: n.name || undefined, vlan: n.vlan_id ?? null, gateway: n.gateway || undefined, exposure: n.exposure })),
    createdAt: s.created_at,
  };
}

// fetchSites is the useSites query body, factored out so the response
// contract is unit-testable without a react-query harness. A contract
// violation MUST surface as a thrown error — never as a silent empty
// list, which the UI would render as the (lying) "No sites yet" state.
export async function fetchSites(): Promise<{ items: Site[]; total: number }> {
  const res = await api.get<A.Page<A.Site>>("/sites");
  const raw = res?.items;
  if (!Array.isArray(raw)) {
    const got = raw === undefined ? "no items field" : typeof raw;
    throw new Error(`Sites API returned an unexpected response (expected an items array, got ${got})`);
  }
  // The list endpoint carries no networks, so fan out per site — orgs
  // hold a handful of sites, and without this the table's Networks
  // column and header badge would stay at zero forever. A failed or
  // malformed fan-out degrades to an empty list per site; it must never
  // take the sites table down with it.
  const nets = await Promise.all(
    raw.map(async (s) => {
      try {
        const n = await api.get<{ items: A.Network[] }>(`/sites/${s.id}/networks`);
        return Array.isArray(n?.items) ? n.items : [];
      } catch {
        return [] as A.Network[];
      }
    }),
  );
  return { items: raw.map((s, i) => mapSite(s, nets[i])), total: res.total };
}

export function useSites() {
  return useQuery({ queryKey: qk.sites, queryFn: fetchSites });
}

export function useSiteNetworks(siteId: string | undefined) {
  return useQuery({
    queryKey: qk.siteNetworks(siteId ?? ""),
    enabled: !!siteId,
    queryFn: () => api.get<{ items: A.Network[] }>(`/sites/${siteId}/networks`),
  });
}

// ---------------------------------------------------------------------------
// assets

export interface AssetListParams {
  site?: string
  search?: string
  type?: string
  criticality?: string
  exposure?: string
  minRisk?: number
  hasAgent?: boolean
  page?: number
  limit?: number
}

function assetQuery(p: AssetListParams): string {
  const q = new URLSearchParams();
  if (p.site && p.site !== "all") q.set("site_id", p.site);
  if (p.search) q.set("search", p.search);
  if (p.type && p.type !== "all") q.set("device_type", p.type);
  if (p.criticality && p.criticality !== "all") q.set("criticality", p.criticality);
  if (p.minRisk) q.set("min_risk", String(p.minRisk));
  if (p.hasAgent !== undefined) q.set("has_agent", p.hasAgent ? "true" : "false");
  q.set("limit", String(p.limit ?? 50));
  q.set("page", String(p.page ?? 1));
  return q.toString();
}

export function useAssets(p: AssetListParams = {}) {
  return useQuery({
    queryKey: qk.assets(p as Record<string, unknown>),
    queryFn: async () => {
      const res = await api.get<A.Page<A.Asset>>(`/assets?${assetQuery(p)}`);
      return {
        items: (res.items ?? []).map(mapAsset),
        total: res.total,
      };
    },
  });
}

export function useAsset(id: string | undefined) {
  return useQuery({
    queryKey: qk.asset(id ?? ""),
    enabled: !!id,
    queryFn: async (): Promise<AssetDetailBundle> => {
      const b = await api.get<A.AssetBundle>(`/assets/${id}`);
      const asset = mapAsset(b.asset);
      return {
        asset,
        ports: (b.services ?? []).map(mapService),
        software: (b.software ?? []).map(mapSoftware),
        interfaces: mapInterfaces(b.interfaces),
        findingsCounts: {
          open: num(b.findings_count?.open), critical: num(b.findings_count?.critical),
          high: num(b.findings_count?.high), medium: num(b.findings_count?.medium), low: num(b.findings_count?.low),
        },
        groupIds: b.group_ids ?? [],
        endpoint: b.endpoint ? mapDevice(b.endpoint) : undefined,
      };
    },
  });
}

export function useAssetFindings(id: string | undefined) {
  return useQuery({
    queryKey: qk.assetFindings(id ?? ""),
    enabled: !!id,
    queryFn: async () => {
      const res = await api.get<{ items: A.Finding[] }>(`/assets/${id}/findings`);
      return (res.items ?? []).map(mapFinding);
    },
  });
}

export function useAssetTraces(id: string | undefined) {
  return useQuery({
    queryKey: qk.assetTraces(id ?? ""),
    enabled: !!id,
    queryFn: async () => {
      const res = await api.get<{ items: A.AssetTrace[]; ips: string[] }>(`/assets/${id}/traces`);
      const traces: Trace[] = (res.items ?? []).map((t) => ({
        id: t.id, targetIp: t.target_ip,
        status: t.complete ? "complete" : t.hops_count > 0 ? "partial" : "failed",
        hops: (t.path ?? []).map((h) => ({ ttl: h.ttl, address: h.ip, hostname: h.hostname || undefined, rtt: h.rtt_ms })),
        confidence: pct(t.confidence, 85), lastSeen: t.last_seen, raw: t.raw || "",
      }));
      return { traces, ips: res.ips ?? [] };
    },
  });
}

/** Viewer-controlled query shape of the asset metrics endpoint. */
export interface AssetMetricsParams {
  /** "latest" polls a tail window; "range" fetches a static from/to span. */
  mode: "latest" | "range";
  /** Tail window label ("30s", "5m", "24h", "7d", bare seconds) — latest mode. */
  window: string;
  /** RFC3339 bounds — range mode. */
  from?: string;
  to?: string;
  /** Refresh cadence in ms (0 = off). Applied in latest mode only: a
   * historical range never changes, so polling it would fetch identical data. */
  refreshMs: number;
}

export function useAssetMetrics(id: string | undefined, params: AssetMetricsParams) {
  const rangeMode = params.mode === "range";
  const rangeReady = !rangeMode || (!!params.from && !!params.to);
  return useQuery({
    queryKey: ["asset", id ?? "", "metrics", params.mode, params.window, params.from ?? "", params.to ?? ""] as const,
    enabled: !!id && rangeReady,
    queryFn: async (): Promise<AssetMetricsResponse> => {
      const qs = rangeMode
        ? `from=${encodeURIComponent(params.from ?? "")}&to=${encodeURIComponent(params.to ?? "")}`
        : `window=${encodeURIComponent(params.window)}`;
      const res = await api.get<AssetMetricsResponse>(`/assets/${id}/metrics?${qs}`);
      return {
        points: res.points ?? [], latest: res.latest ?? null, ifaces: res.ifaces ?? [],
        window: res.window ?? "", from: res.from ?? "", to: res.to ?? "",
        bucket: res.bucket ?? 0, tail: res.tail ?? true,
      };
    },
    refetchInterval: !rangeMode && params.refreshMs > 0 ? params.refreshMs : false,
    // Keep the previous window's points rendered while a new key (range
    // commit, window preset, refresh change) loads — without this the data
    // drops to undefined, every chart unmounts into an empty state and
    // remounts with a fresh ECharts instance replaying its entry animation:
    // the whole performance section visibly "reloads" on every timeline drag.
    placeholderData: keepPreviousData,
  });
}

export function useTopology(siteId: string) {
  return useQuery({
    queryKey: [...qk.assets({}), "topology", siteId],
    queryFn: async () => {
      const res = await api.get<{ nodes: A.TopologyNode[]; edges: A.TopologyEdge[] }>(`/topology${siteId && siteId !== "all" ? `?site_id=${siteId}` : ""}`);
      return {
        nodes: (res.nodes ?? []).map((n) => ({
          id: n.id, label: n.label, kind: n.kind, assetId: n.asset_id || undefined,
          refId: n.ref_id || undefined, risk: n.risk, deviceType: n.device_type || undefined,
        })),
        edges: (res.edges ?? []).map((e) => ({
          id: e.id, srcNodeId: e.src_node_id, dstNodeId: e.dst_node_id,
          kind: e.kind, confidence: e.confidence, lastSeen: e.last_seen || undefined,
        })),
      };
    },
  });
}

// ---------------------------------------------------------------------------
// asset groups

export function useAssetGroups(options?: Partial<UseQueryOptions<{ id: string; name: string; description?: string; color: string; icon: string; kind: string; assetIds: string[] }[]>>) {
  return useQuery({
    queryKey: qk.groups,
    queryFn: async () => {
      const res = await api.get<{ items: A.AssetGroup[] }>("/asset-groups");
      return (res.items ?? []).map((g) => ({
        id: g.id, name: g.name, description: g.description || undefined,
        color: g.color || "slate", icon: g.icon || "boxes",
        kind: (g.kind || "custom") as "location" | "function" | "owner" | "custom",
        assetIds: g.asset_ids ?? [],
      }));
    },
    ...options,
  });
}

export function useCreateGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (g: { name: string; description?: string; color: string; icon: string; kind: string; asset_ids?: string[] }) =>
      api.post<{ group: A.AssetGroup }>("/asset-groups", g),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.groups }),
    onError: () =>
      toast({
        title: "Group creation failed",
        description: "The server rejected the request — check that the name is unique and try again.",
        variant: "error",
      }),
  });
}

export function useUpdateGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...patch }: { id: string; name?: string; description?: string; color?: string; icon?: string; kind?: string; asset_ids?: string[] }) =>
      api.patch<{ group: A.AssetGroup }>(`/asset-groups/${id}`, patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.groups }),
    onError: () =>
      toast({
        title: "Group update failed",
        description: "The changes were not saved — please try again.",
        variant: "error",
      }),
  });
}

export function useDeleteGroup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<{ deleted: boolean }>(`/asset-groups/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.groups }),
    onError: () =>
      toast({
        title: "Group deletion failed",
        description: "The group still exists — please try again.",
        variant: "error",
      }),
  });
}

export function useGroupMembership() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, add, remove }: { id: string; add?: string[]; remove?: string[] }) =>
      api.put<{ group: A.AssetGroup }>(`/asset-groups/${id}/assets`, { add, remove }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.groups });
      qc.invalidateQueries({ queryKey: ["asset"] });
    },
    onError: () =>
      toast({
        title: "Group membership change failed",
        description: "The assets were not added or removed — please try again.",
        variant: "error",
      }),
  });
}

// ---------------------------------------------------------------------------
// scans

export function mapScan(s: A.Scan): Scan {
  return {
    id: s.id, name: s.name, profile: s.profile, engine: s.engine,
    state: (s.state || "queued") as Scan["state"],
    progress: Math.round(num(s.progress)),
    phase: s.phase || undefined,
    targets: String(s.config?.ssh_hosts?.length ?? s.stats?.targets ?? 0),
    site: s.site_id,
    reachable: { up: num(s.stats?.reachable), total: num(s.stats?.targets) },
    ports: num(s.stats?.ports_discovered),
    services: num(s.stats?.services_fingerprinted),
    packages: num(s.stats?.packages_collected),
    findings: num(s.stats?.findings_created),
    criticalFindings: num(s.stats?.critical_findings),
    createdAt: s.created_at, startedAt: s.started_at || undefined, finishedAt: s.completed_at || undefined,
    error: s.error || undefined,
    tasks: { total: num(s.stats?.tasks_total), done: num(s.stats?.tasks_done), failed: num(s.stats?.tasks_failed) },
    sshHosts: s.stats?.ssh_hosts?.map((h) => ({
      host: h.host, port: h.port || undefined, user: h.user || undefined,
      os: [h.os_name, h.os_version].filter(Boolean).join(" ") || undefined,
      osOk: h.os_ok, packageCount: num(h.package_count), durationMs: num(h.duration_ms),
      error: h.error || undefined,
      commands: h.commands?.map((c) => ({ cmd: c.cmd, ok: c.ok, lines: c.lines, err: c.err || undefined })),
    })),
  };
}

export function useScans(p: { site?: string; state?: string; limit?: number } = {}) {
  const q = new URLSearchParams();
  const qc = useQueryClient();
  const live = useWSStatus();
  if (p.site && p.site !== "all") q.set("site_id", p.site);
  if (p.state && p.state !== "all") q.set("state", p.state);
  q.set("limit", String(p.limit ?? 50));
  const query = useQuery({
    queryKey: qk.scans({ ...p }),
    queryFn: async () => {
      const res = await api.get<A.Page<A.Scan>>(`/scans?${q.toString()}`);
      return { items: (res.items ?? []).map(mapScan), total: res.total };
    },
    // WS streams progress for every active scan (effect below); polling
    // stays only as the degraded path when the stream is down.
    refetchInterval: (query) =>
      live
        ? false
        : (query.state.data?.items ?? []).some((s) => s.state === "running" || s.state === "queued")
          ? 4000
          : false,
  });

  // Live list: subscribe to the channel of every active scan in this
  // page's result set and patch rows in place; terminal transitions
  // invalidate dependent caches (metrics, assets).
  const items = query.data?.items ?? [];
  const activeKey = items
    .filter((s) => s.state === "running" || s.state === "queued")
    .map((s) => s.id)
    .join(",");
  useEffect(() => {
    if (!live || !activeKey) return;
    const unsubs = activeKey.split(",").map((sid) =>
      ws.sub(`scan:${sid}`, (ev) => {
        if (ev.kind !== "state") return;
        const st = ev.data as {
          state?: Scan["state"]; phase?: string; progress?: number;
          stats?: Partial<Record<"targets" | "reachable" | "ports_discovered" | "services_fingerprinted" | "packages_collected" | "findings_created" | "critical_findings", number>>;
        };
        qc.setQueryData<{ items: Scan[]; total: number }>(qk.scans({ ...p }), (old) =>
          old
            ? {
                ...old,
                items: old.items.map((s) =>
                  s.id === sid
                    ? {
                        ...s,
                        state: (st.state as Scan["state"]) ?? s.state,
                        phase: st.phase ?? s.phase,
                        // progress >= 0: legacy -1 means "keep current".
                        progress: typeof st.progress === "number" && st.progress >= 0 ? Math.round(st.progress) : s.progress,
                        // Counters merge (absent keeps the previous value) so
                        // stats-less state events don't reset the row tiles.
                        reachable: {
                          up: st.stats?.reachable ?? s.reachable.up,
                          total: st.stats?.targets ?? s.reachable.total,
                        },
                        ports: st.stats?.ports_discovered ?? s.ports,
                        services: st.stats?.services_fingerprinted ?? s.services,
                        packages: st.stats?.packages_collected ?? s.packages,
                        findings: st.stats?.findings_created ?? s.findings,
                        criticalFindings: st.stats?.critical_findings ?? s.criticalFindings,
                      }
                    : s,
                ),
              }
            : old,
        );
        if (st.state && st.state !== "running" && st.state !== "queued") {
          qc.invalidateQueries({ queryKey: ["metrics"] });
          qc.invalidateQueries({ queryKey: ["assets"] });
        }
      }),
    );
    return () => unsubs.forEach((u) => u());
    // p is a params object; its identity churn is acceptable here since a
    // key change means a different page anyway.
  }, [live, activeKey, qc]); // eslint-disable-line react-hooks/exhaustive-deps

  return query;
}

export function useScan(id: string | undefined) {
  const live = useWSStatus();
  return useQuery({
    queryKey: qk.scan(id ?? ""),
    enabled: !!id,
    queryFn: async () => {
      const b = await api.get<{ scan: A.Scan; tasks: A.ScanTask[] }>(`/scans/${id}`);
      const [changes, tasks] = await Promise.all([
        api.get<{ items: A.Change[] }>(`/scans/${id}/changes`).catch(() => ({ items: [] as A.Change[] })),
        Promise.resolve(b.tasks ?? []),
      ]);
      return {
        scan: mapScan(b.scan),
        tasks: tasks.map((t) => ({ id: t.id, type: t.type, state: t.state, target: t.target || undefined, attempt: t.attempt, error: t.error || undefined })),
        changes: (changes.items ?? []).map((c) => ({ id: c.id, type: c.type, assetId: c.asset_id || undefined, entity: c.entity || undefined, before: c.before || undefined, after: c.after || undefined, createdAt: c.created_at })),
      };
    },
    refetchInterval: (query) => {
      if (live) return false; // state events arrive over the scan channel
      const s = query.state.data?.scan;
      return s && (s.state === "running" || s.state === "queued") ? 3000 : false;
    },
  });
}

export interface CreateScanInput {
  site_id: string
  scanner_id?: string
  name: string
  profile: string
  targets: string[]
  denylist?: string[]
  ssh_hosts?: A.SSHScanHost[]
  ssh_insecure_host_key?: boolean
  engine?: string
  confirm_elevated?: boolean
}

export function useCreateScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (input: CreateScanInput) => api.post<{ scan: A.Scan; warnings: string[] }>("/scans", input),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["scans"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
}

export function useCancelScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post(`/scans/${id}/cancel`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["scans"] }),
  });
}

// ---------------------------------------------------------------------------
// scan profiles (presets), scanners, schedules

export function useProfiles() {
  return useQuery({
    queryKey: qk.profiles,
    queryFn: async () => {
      const res = await api.get<{ builtin: A.ProfileDef[]; custom: A.ProfileDef[] }>("/scan-profiles");
      const map = (p: A.ProfileDef): Preset => ({
        name: p.name, description: p.description, engine: "nmap",
        ports: p.full_port_scan ? "-" : `top ${p.top_tcp_ports}`,
        timing: `rate ≤ ${p.max_packet_rate}/s`,
        scripts: p.service_detect ? ["service detection", ...(p.os_detect ? ["OS detection"] : []), ...(p.traceroute ? ["traceroute"] : [])] : [],
        builtin: !!p.builtin, maxTargets: p.max_targets, maxPacketRate: p.max_packet_rate,
      });
      return { builtin: (res.builtin ?? []).map(map), custom: (res.custom ?? []).map(map), raw: res };
    },
  });
}

export function useCreateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (p: Partial<A.ProfileDef> & { name: string }) => api.post("/scan-profiles", p),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.profiles }),
  });
}

export function useUpdateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, ...patch }: { name: string } & Partial<A.ProfileDef>) => api.patch(`/scan-profiles/${name}`, patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.profiles }),
  });
}

export function useDeleteProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.del(`/scan-profiles/${name}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.profiles }),
  });
}

export function useScanners() {
  return useQuery({
    queryKey: qk.scanners,
    queryFn: async (): Promise<Scanner[]> => {
      const res = await api.get<A.Page<A.Scanner>>("/scanners");
      return (res.items ?? []).map((s) => ({
        id: s.id, name: s.name, version: s.version, transport: s.transport || "nats",
        health: s.health, lastSeen: s.last_seen, capabilities: s.capabilities ?? [],
        siteId: s.site_id, isDefault: !!s.is_default, connectorId: s.connector_id || undefined,
      }));
    },
    refetchInterval: 15_000,
  });
}

export function useEnrollScanner() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ name, site_id }: { name: string; site_id: string }) =>
      api.post<{ scanner_id: string; token: string }>("/scanners/enroll", { name, site_id }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.scanners }),
  });
}

export function useSetDefaultScanner() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, is_default }: { id: string; is_default: boolean }) =>
      api.post(`/scanners/${id}/default`, { is_default }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.scanners }),
  });
}

export function useSchedules() {
  return useQuery({
    queryKey: qk.schedules,
    queryFn: async (): Promise<Schedule[]> => {
      const res = await api.get<{ items: A.ScanSchedule[] }>("/schedules");
      return (res.items ?? []).map((s) => ({
        id: s.id, name: s.name, siteId: s.site_id, profile: s.profile, cron: s.cron,
        scope: s.scope ?? [], engine: s.engine || "nmap", enabled: s.enabled,
        lastRunAt: s.last_run_at || undefined, nextRunAt: s.next_run_at || undefined,
      }));
    },
  });
}

export function useCreateSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (s: { site_id: string; name?: string; profile: string; cron: string; scope: string[]; engine?: string }) =>
      api.post<A.ScanSchedule>("/schedules", s),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.schedules }),
  });
}

export function useDeleteSchedule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del<void>(`/schedules/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.schedules }),
  });
}

// ---------------------------------------------------------------------------
// vulnerabilities

export interface VulnListParams {
  search?: string
  severity?: string
  /** feed filter: nvd | cvelistv5 ("all" = no filter) */
  source?: string
  kev?: boolean
  /** published window (YYYY-MM-DD), maps to published_after/before */
  publishedFrom?: string
  publishedTo?: string
  minScore?: number
  sort?: string
  order?: string
  page?: number
  limit?: number
}

export function useVulnerabilities(p: VulnListParams = {}) {
  const q = new URLSearchParams();
  if (p.search) q.set("search", p.search);
  const floor = p.severity && p.severity !== "all" ? ({ critical: 9, high: 7, medium: 4, low: 0.1 } as Record<string, number>)[p.severity] : undefined;
  if (floor !== undefined) q.set("min_score", String(floor));
  if (p.source && p.source !== "all") q.set("source", p.source);
  if (p.publishedFrom) q.set("published_after", p.publishedFrom);
  if (p.publishedTo) q.set("published_before", p.publishedTo);
  if (p.kev) q.set("kev", "true");
  if (p.minScore) q.set("min_score", String(p.minScore));
  if (p.sort) q.set("sort", p.sort);
  if (p.order) q.set("order", p.order);
  q.set("limit", String(p.limit ?? 50));
  q.set("page", String(p.page ?? 1));
  return useQuery({
    queryKey: qk.vulns(p as Record<string, unknown>),
    queryFn: async () => {
      const res = await api.get<A.Page<A.VulnListRow>>(`/vulnerabilities?${q.toString()}`);
      return { items: (res.items ?? []).map(mapVulnRow), total: res.total };
    },
  });
}

export function useVulnerability(id: string | undefined) {
  return useQuery({
    queryKey: qk.vuln(id ?? ""),
    enabled: !!id,
    queryFn: async (): Promise<Vulnerability> => {
      const res = await api.get<{ vulnerability: A.VulnerabilityDetail; references: string[]; affected_assets: A.AffectedAssetRow[] }>(`/vulnerabilities/${id}`);
      const v = res.vulnerability;
      const score = v.cvss_v3?.score ?? v.cvss_v2?.score ?? v.cvss_v4?.score ?? 0;
      return {
        id: v.cve_id, title: v.cve_id, source: v.source, state: v.state,
        severity: severityFromScore(score), cvss: score,
        cvssVector: v.cvss_v3?.vector || v.cvss_v2?.vector || v.cvss_v4?.vector || undefined,
        epss: v.epss?.score, kev: !!v.known_exploited, kevDateAdded: v.known_exploited?.date_added || undefined,
        publishedAt: v.published_at || undefined,
        affectedAssetCount: (res.affected_assets ?? []).length,
        openFindings: (res.affected_assets ?? []).filter((a) => a.status === "open").length,
        summary: v.description,
        cwe: v.cwe ?? [],
        references: (res.references ?? []).map((u) => ({ url: u })),
        affectedProducts: (v.affected ?? []).map((ap) => ({
          vendor: ap.vendor, product: ap.product,
          versionStatement: (ap.versions ?? []).map((vr) => {
            const parts: string[] = [];
            if (vr.version) parts.push(vr.version);
            if (vr.lessThan) parts.push(`< ${vr.lessThan}`);
            if (vr.lessThanOrEqual) parts.push(`≤ ${vr.lessThanOrEqual}`);
            return parts.join(" ");
          }).filter(Boolean).join("; ") || ap.defaultStatus || "unknown",
          status: ap.defaultStatus || "affected", platforms: ap.platforms || undefined,
        })),
        cpeMatches: (v.cpe_matches ?? []).map((m) => {
          const ranges: string[] = [];
          if (m.version_start_incl) ranges.push(`≥ ${m.version_start_incl}`);
          if (m.version_start_excl) ranges.push(`> ${m.version_start_excl}`);
          if (m.version_end_excl) ranges.push(`< ${m.version_end_excl}`);
          if (m.version_end_incl) ranges.push(`≤ ${m.version_end_incl}`);
          return { cpe: m.cpe, version: m.version || undefined, ranges };
        }),
        affectedAssets: (res.affected_assets ?? []).map((a) => ({
          assetId: a.asset_id, hostname: a.hostname || undefined, riskScore: a.risk_score,
          findingId: a.finding_id, status: a.status,
        })),
      };
    },
  });
}

export function useRunCorrelation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () => api.post<{ matched: number; detail?: string }>("/vulnerabilities/correlate", {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
}

// ---------------------------------------------------------------------------
// findings

export interface FindingListParams {
  site?: string
  asset?: string
  status?: string
  severity?: string
  search?: string
  kev?: boolean
  minRisk?: number
  page?: number
  limit?: number
}

export function useFindings(p: FindingListParams = {}) {
  const q = new URLSearchParams();
  if (p.site && p.site !== "all") q.set("site_id", p.site);
  if (p.asset) q.set("asset_id", p.asset);
  if (p.status && p.status !== "all") q.set("status", p.status);
  if (p.severity && p.severity !== "all") q.set("severity", p.severity);
  if (p.search) q.set("search", p.search);
  if (p.kev) q.set("kev", "true");
  if (p.minRisk) q.set("min_risk", String(p.minRisk));
  q.set("limit", String(p.limit ?? 50));
  q.set("page", String(p.page ?? 1));
  return useQuery({
    queryKey: qk.findings(p as Record<string, unknown>),
    queryFn: async () => {
      const res = await api.get<A.Page<A.Finding>>(`/findings?${q.toString()}`);
      return { items: (res.items ?? []).map(mapFinding), total: res.total };
    },
  });
}

export function useFinding(id: string | undefined) {
  return useQuery({
    queryKey: qk.finding(id ?? ""),
    enabled: !!id,
    queryFn: async () => {
      const res = await api.get<{ finding: A.Finding; evidence: A.Evidence[]; history: A.StatusHistoryRow[] }>(`/findings/${id}`);
      return {
        finding: mapFinding(res.finding),
        evidence: (res.evidence ?? []).map((e) => ({
          id: e.id, kind: e.kind, statement: e.statement, detail: e.detail ?? {}, source: e.source, createdAt: e.created_at,
        })),
        history: (res.history ?? []).map((h) => ({ from: h.from, to: h.to, changedBy: h.changed_by, reason: h.reason || undefined, createdAt: h.created_at })),
      };
    },
  });
}

export function useUpdateFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status, reason, owner }: { id: string; status?: string; reason?: string; owner?: string }) =>
      api.patch<{ finding: A.Finding }>(`/findings/${id}`, { status, reason, owner }),
    onSuccess: (_d, v) => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["finding", v.id] });
      qc.invalidateQueries({ queryKey: ["asset"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
}

export function useBulkFindings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ ids, status, reason }: { ids: string[]; status: string; reason?: string }) =>
      api.post<{ updated: number }>("/findings/bulk", { ids, status, reason, confirm: true }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
}

export function useSuppressFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, reason }: { id: string; reason: string }) =>
      api.post<{ finding: A.Finding }>(`/findings/${id}/suppress`, { reason }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
    },
  });
}

// ---------------------------------------------------------------------------
// detections

export function useDetectionMatches(p: { level?: string; status?: string; limit?: number } = {}) {
  const q = new URLSearchParams();
  if (p.level && p.level !== "all") q.set("level", p.level);
  if (p.status && p.status !== "all") q.set("status", p.status);
  q.set("limit", String(p.limit ?? 50));
  return useQuery({
    queryKey: qk.matches({ ...p }),
    queryFn: async () => {
      const res = await api.get<A.Page<A.DetectionMatch>>(`/detections/matches?${q.toString()}`);
      const items: Detection[] = (res.items ?? []).map((m) => ({
        id: m.id, title: m.rule_title || m.summary,
        severity: (m.level || "medium") as Severity,
        source: "correlation" as const,
        assetId: m.asset_id || undefined, srcIp: m.src_ip || undefined, entity: m.entity || undefined,
        status: (m.status || "new") as DetectionStatus,
        timestamp: m.timestamp,
        description: m.summary, count: num(m.count, 1),
        indicators: [m.src_ip, m.entity].filter(Boolean).map(String),
      }));
      return { items, total: res.total };
    },
    refetchInterval: 15_000,
  });
}

export function useDetectionRules() {
  return useQuery({
    queryKey: qk.rules,
    queryFn: async () => {
      const res = await api.get<{ items: A.DetectionRule[] }>("/detections/rules");
      return res.items ?? [];
    },
  });
}

export function useUpdateMatchStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.patch<{ id: string; status: string }>(`/detections/matches/${id}`, { status }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["detection-matches"] }),
  });
}

export function useCreateRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (rule: Record<string, unknown>) => api.post("/detections/rules", rule),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.rules }),
  });
}

export function useUpdateRule() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...patch }: { id: string; enabled?: boolean }) => api.patch(`/detections/rules/${id}`, patch),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.rules }),
  });
}

// ---------------------------------------------------------------------------
// events (ClickHouse-backed sensor stream)

export function useEvents(p: { eventType?: string; severity?: string; source?: string; srcIp?: string; limit?: number; cursor?: string; enabled?: boolean } = {}) {
  const q = new URLSearchParams();
  if (p.eventType && p.eventType !== "all") q.set("event_type", p.eventType);
  if (p.severity && p.severity !== "all") q.set("severity", p.severity);
  if (p.source && p.source !== "all") q.set("source", p.source);
  if (p.srcIp) q.set("src_ip", p.srcIp);
  if (p.cursor) q.set("cursor", p.cursor);
  q.set("limit", String(p.limit ?? 50));
  return useQuery({
    queryKey: qk.events(p as Record<string, unknown>),
    enabled: p.enabled ?? true,
    queryFn: async () => {
      const res = await api.get<A.CursorPage<A.SecEvent>>(`/events?${q.toString()}`);
      return {
        items: (res.items ?? []).map((e): PlatformEvent => ({
          id: e.event_id, timestamp: e.timestamp,
          level: e.severity && e.severity !== "info" ? (e.severity as PlatformEvent["level"]) : "info",
          category: e.event_type || "event",
          message: e.rule_name || e.application || `${e.event_type}${e.src_ip ? ` from ${e.src_ip}` : ""}`,
          srcIp: e.src_ip || undefined,
          meta: Object.fromEntries(Object.entries({
            dst: [e.dst_ip, e.dst_port].filter((x) => x !== undefined && x !== null).join(":"),
            protocol: e.protocol, source: e.source, hostname: e.hostname, application: e.application,
          }).filter(([, v]) => v !== undefined && v !== "") as [string, string][]),
        })),
        nextCursor: res.next_cursor || "",
      };
    },
    refetchInterval: 20_000,
  });
}

// ---------------------------------------------------------------------------
// endpoint devices (bound to connections, no separate registry)

export function mapDevice(d: A.DeviceSummary): EndpointDevice {
  return {
    id: d.id, hostname: d.hostname, platform: d.platform, version: d.version || "",
    status: d.status || "offline", lastSeen: d.last_seen, assetId: d.asset_id || undefined,
  };
}

// ---------------------------------------------------------------------------
// connections (connector registry)

export function mapConnection(c: A.Connector): Connection {
  return {
    id: c.id, name: c.name, kind: (c.kind || "agent") as ConnectionKind,
    site: c.site_id || undefined, provider: c.platform || c.hostname || "aegis",
    status: (c.status || "pending") as Connection["status"],
    online: !!c.online, connState: c.conn_state || undefined,
    lastSync: c.last_seen || undefined,
    endpoint: c.hostname || undefined, platform: c.platform || undefined,
    version: c.version || undefined, capabilities: c.capabilities ?? [],
    config: c.config ?? {}, configVersion: c.config_version,
    lastStatus: c.last_status || undefined, enrolledAt: c.enrolled_at || undefined,
    createdAt: c.created_at,
    device: c.device ? mapDevice(c.device) : undefined,
  };
}

export function useConnections(kind?: string) {
  return useQuery({
    queryKey: [...qk.connections, kind ?? "all"],
    queryFn: async (): Promise<Connection[]> => {
      const res = await api.get<{ items: A.Connector[] }>(`/connectors${kind && kind !== "all" ? `?kind=${kind}` : ""}`);
      return (res.items ?? []).map(mapConnection);
    },
    refetchInterval: 15_000,
  });
}

export function useConnection(id: string | undefined) {
  return useQuery({
    queryKey: qk.connection(id ?? ""),
    enabled: !!id,
    queryFn: async () => {
      const res = await api.get<{ connector: A.Connector }>(`/connectors/${id}`);
      return mapConnection(res.connector);
    },
    refetchInterval: 10_000,
  });
}

export function useCreateConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ kind, name, site_id }: { kind: string; name: string; site_id: string }) =>
      api.post<{ connector: A.Connector; token: string; expires_at: string; connect_command: string }>("/connectors", { kind, name, site_id }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.connections }),
  });
}

export function useUpdateConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, name, site_id }: { id: string; name?: string; site_id?: string }) =>
      api.patch<{ connector: A.Connector }>(`/connectors/${id}`, { name, site_id }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.connections });
      qc.invalidateQueries({ queryKey: ["connector"] });
      qc.invalidateQueries({ queryKey: qk.scanners });
    },
  });
}

export function useUpdateConnectionConfig() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, config }: { id: string; config: Record<string, unknown> }) =>
      api.put<{ connector: A.Connector }>(`/connectors/${id}/config`, { config }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.connections });
      qc.invalidateQueries({ queryKey: ["connector"] });
    },
  });
}

export function useRotateConnectionToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) =>
      api.post<{ connector: A.Connector; token: string; expires_at: string; connect_command: string }>(`/connectors/${id}/enroll-token`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.connections }),
  });
}

export function useRevokeConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post(`/connectors/${id}/revoke`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.connections }),
  });
}

export function useDeleteConnection() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del(`/connectors/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.connections }),
  });
}

// ---------------------------------------------------------------------------
// reports

export function useReports() {
  return useQuery({
    queryKey: qk.reports,
    queryFn: async () => {
      const res = await api.get<{ items: A.ReportDefinition[] }>("/reports");
      return res.items ?? [];
    },
  });
}

export function useReportJobs() {
  return useQuery({
    queryKey: qk.reportJobs,
    queryFn: async (): Promise<Report[]> => {
      const [defs, jobs] = await Promise.all([
        api.get<{ items: A.ReportDefinition[] }>("/reports").catch(() => ({ items: [] as A.ReportDefinition[] })),
        api.get<{ items: A.ReportJob[] }>("/reports/jobs"),
      ]);
      const byDef = new Map((defs.items ?? []).map((d) => [d.id, d]));
      const siteNames = await api.get<A.Page<A.Site>>("/sites").catch(() => ({ items: [] as A.Site[] }));
      const siteName = new Map((siteNames.items ?? []).map((s) => [s.id, s.name]));
      return (jobs.items ?? []).map((j): Report => {
        const d = byDef.get(j.definition_id);
        const state = j.state === "done" ? "ready" : j.state === "failed" ? "failed" : j.state === "running" ? "generating" : j.state === "queued" ? "queued" : "ready";
        const scope = d?.asset_id ? `asset ${d.asset_id.slice(0, 8)}` : d?.site_id ? (siteName.get(d.site_id) ?? "site") : "all sites";
        return {
          id: j.id, name: d?.name || d?.type || "report", type: d?.type || "executive",
          scope, format: (d?.format || "html") as Report["format"],
          createdAt: j.created_at, createdBy: d?.created_by || "", status: state as Report["status"],
          progress: Math.round(num(j.progress)), jobId: j.id,
          artifactKey: j.artifact_key || undefined, error: j.error || undefined,
        };
      });
    },
    refetchInterval: (query) => (query.state.data ?? []).some((r) => r.status === "generating" || r.status === "queued") ? 3000 : false,
  });
}

export function useCreateReport() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (req: { type: string; format: string; site_id?: string; asset_id?: string; scan_id?: string }) =>
      api.post<{ job: A.ReportJob }>("/reports", req),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.reportJobs }),
  });
}

// ---------------------------------------------------------------------------
// feeds, users, audit, webhooks

export function useFeeds() {
  return useQuery({
    queryKey: qk.feeds,
    queryFn: async (): Promise<Feed[]> => {
      const res = await api.get<{ items: A.FeedSource[] }>("/feeds");
      return (res.items ?? []).map((f) => ({
        id: f.name, name: f.name, provider: f.name.split(/[-_]/)[0] || f.name,
        kind: f.name.includes("kev") ? "kev" : f.name.includes("epss") ? "epss" : f.name.includes("oval") ? "oval" : "cve",
        lastSync: f.last_sync_at || undefined,
        // The backend enum is healthy|stale|failed|never_synced|running —
        // mapping "healthy" to anything else made every feed look stale
        // forever and the attention banner never cleared.
        status: !f.enabled ? "disabled"
          : f.last_status === "healthy" ? "ok"
          : f.last_status === "running" ? "running"
          : f.last_status === "failed" ? "error"
          : "stale", // stale + never_synced need attention
        entries: f.records_total,
        lastProcessed: f.records_ingested,
        recordsNew: f.records_new,
        recordsUpdated: f.records_updated,
        autoSync: true, license: f.license || undefined,
        lastError: f.last_error || undefined,
      }));
    },
    refetchInterval: 30_000,
  });
}

export function useTriggerFeedSync() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.post<{ queued: boolean }>(`/feeds/${name}/sync`, {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.feeds }),
  });
}

export function useUsers() {
  return useQuery({
    queryKey: qk.users,
    queryFn: async (): Promise<User[]> => {
      const res = await api.get<A.Page<A.UserRow>>("/users");
      return (res.items ?? []).map((u) => ({
        id: u.id, name: u.name, email: u.email, role: u.role,
        status: u.disabled ? "disabled" : "active",
        lastActive: u.last_login_at || undefined, createdAt: u.member_since || u.created_at,
      }));
    },
  });
}

export function useCreateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (u: { email: string; name: string; password: string; role: string }) => api.post("/users", u),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.users }),
  });
}

export function useUpdateUser() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, role, disabled }: { id: string; role?: string; disabled?: boolean }) =>
      api.patch(`/users/${id}`, { role, disabled }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.users }),
  });
}

export function useResetUserPassword() {
  return useMutation({
    mutationFn: ({ id, password }: { id: string; password: string }) =>
      api.post(`/users/${id}/reset-password`, { password }),
  });
}

export function useChangeOwnPassword() {
  return useMutation({
    mutationFn: ({ current, next }: { current: string; next: string }) =>
      api.post("/auth/password", { current_password: current, new_password: next }),
  });
}

export function useRenameOrg() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (name: string) => api.patch("/organizations/current", { name }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.me }),
  });
}

export function useAuditLog(p: { action?: string; limit?: number } = {}) {
  const q = new URLSearchParams();
  if (p.action) q.set("action", p.action);
  q.set("limit", String(p.limit ?? 100));
  return useQuery({
    queryKey: qk.audit(p as Record<string, unknown>),
    queryFn: async (): Promise<AuditEntry[]> => {
      const res = await api.get<A.Page<A.AuditEntry>>(`/audit-log?${q.toString()}`);
      return (res.items ?? []).map((e) => ({
        id: e.id, timestamp: e.created_at, actor: e.actor_id || "system", action: e.action,
        target: e.target || "", ip: e.actor_ip || "", outcome: e.result || "success",
      }));
    },
  });
}

export function useWebhooks() {
  return useQuery({
    queryKey: qk.webhooks,
    queryFn: async () => {
      const res = await api.get<{ items: A.WebhookRow[] }>("/webhooks");
      return res.items ?? [];
    },
  });
}

export function useCreateWebhook() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (w: { name: string; url: string; events: string[]; enabled: boolean }) => api.post("/webhooks", w),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.webhooks }),
  });
}

// ---------------------------------------------------------------------------
// sites CRUD

export function useCreateSite() {
  const qc = useQueryClient();
  return useMutation({
    // The handler answers 201 with the bare site — the caller (SiteDialog)
    // needs its id to flip into edit mode and add networks immediately.
    mutationFn: ({ name, site_type, description }: { name: string; site_type: string; description?: string }) =>
      api.post<A.Site>("/sites", { name, site_type, description }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.sites }),
  });
}

export function useUpdateSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, name, description, site_type }: { id: string; name?: string; description?: string; site_type?: string }) =>
      api.patch(`/sites/${id}`, { name, description, site_type }),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.sites }),
  });
}

export function useDeleteSite() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del(`/sites/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: qk.sites }),
  });
}

export function useCreateNetwork() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ siteId, cidr, name, vlan, gateway, exposure }: { siteId: string; cidr: string; name?: string; vlan?: number; gateway?: string; exposure?: string }) =>
      api.post(`/sites/${siteId}/networks`, { cidr, name, vlan_id: vlan, gateway, exposure }),
    onSuccess: (_d, v) => {
      qc.invalidateQueries({ queryKey: qk.siteNetworks(v.siteId) });
      // useSites embeds networks, so the sites table column + badge must
      // refresh alongside the dialog's live list.
      qc.invalidateQueries({ queryKey: qk.sites });
    },
  });
}

// ---------------------------------------------------------------------------
// asset mutations

export function useUpdateAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...fields }: { id: string; criticality?: string; exposure?: string; tags?: string[]; owner?: string; notes?: string; name_override?: string | null; device_type_override?: string | null; parent_override?: string | null }) =>
      api.patch<Asset>(`/assets/${id}`, fields),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset"] });
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["topology"] });
    },
  });
}

export function useAddNote() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note: string }) => api.post(`/assets/${id}/notes`, { note }),
    onSuccess: (_d, v) => {
      qc.invalidateQueries({ queryKey: ["asset", v.id] });
      qc.invalidateQueries({ queryKey: ["assets"] });
    },
  });
}

export function useRediscoverAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<{ findings_created: number; detail: string }>(`/assets/${id}/rediscover`, {}),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["asset"] });
      qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });
}

// deleteAsset is the DELETE /assets/{id} body, exported so tests can pin the
// endpoint contract without a QueryClient. The server answers 204 once the
// asset and every dependent row are gone.
export function deleteAsset(id: string) {
  return api.del<void>(`/assets/${id}`);
}

export function useDeleteAsset() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => deleteAsset(id),
    onSuccess: () => {
      // The asset is gone from every aggregate it took part in: lists and
      // detail, site asset counts, group memberships, its findings and the
      // vulnerability correlation results derived from them, and the
      // overview dashboards that count assets.
      qc.invalidateQueries({ queryKey: ["assets"] });
      qc.invalidateQueries({ queryKey: ["asset"] });
      qc.invalidateQueries({ queryKey: qk.sites });
      qc.invalidateQueries({ queryKey: qk.groups });
      qc.invalidateQueries({ queryKey: ["findings"] });
      qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
      qc.invalidateQueries({ queryKey: ["metrics"] });
      qc.invalidateQueries({ queryKey: ["metrics-ts"] });
    },
  });
}

// ---------------------------------------------------------------------------
// search + metrics

export function useSearch(q: string) {
  return useQuery({
    queryKey: qk.search(q),
    enabled: q.trim().length >= 2,
    queryFn: async () => {
      const res = await api.get<{ items: A.SearchHit[] }>(`/search?q=${encodeURIComponent(q)}`);
      return res.items ?? [];
    },
  });
}

export function useMetricsSummary(site: string) {
  return useQuery({
    queryKey: qk.metrics(site),
    queryFn: () => api.get<A.MetricsSummary>(`/metrics/summary${site && site !== "all" ? `?site_id=${site}` : ""}`),
    refetchInterval: 30_000,
  });
}

export function useMetricsTimeseries(metric: "risk" | "vulns" | "events", days: number, site: string) {
  return useQuery({
    queryKey: qk.metricsTimeseries(metric, days, site),
    queryFn: () =>
      api.get<{ points: { ts: string; value: number; by_category?: Record<string, number> }[] }>(
        `/metrics/timeseries?metric=${metric}&days=${days}${site && site !== "all" ? `&site_id=${site}` : ""}`,
      ),
  });
}

// ---------------------------------------------------------------------------
// platform settings (metrics retention)

/** Storage snapshot of the analytics tier (absent when ClickHouse is off). */
export interface MetricsStorageStats {
  rows: number;
  oldest?: string;
  newest?: string;
}

export interface SettingsView {
  metrics: {
    retention_days: number;
    applied_days: number;
    stats?: MetricsStorageStats | null;
  };
}

export function useSettings() {
  return useQuery({
    queryKey: qk.settings,
    queryFn: async (): Promise<SettingsView> => {
      const res = await api.get<SettingsView>("/settings");
      return {
        metrics: {
          retention_days: num(res.metrics?.retention_days, 30),
          applied_days: num(res.metrics?.applied_days, 30),
          stats: res.metrics?.stats ?? null,
        },
      };
    },
  });
}

export function useUpdateSettings() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (patch: { metrics: { retention_days: number } }) =>
      api.patch<SettingsView>("/settings", patch),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: qk.settings });
      toast({ title: "Settings saved", description: "The retention change takes effect immediately.", variant: "success" });
    },
    onError: (e) => toast({ title: "Saving settings failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useRunMetricsCleanup() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: () =>
      api.post<{ status: string; retention_days: number; cutoff: string; estimate_rows: number }>(
        "/settings/metrics/cleanup",
        {},
      ),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: qk.settings });
      toast({
        title: "Cleanup finished",
        description: `Everything before ${new Date(res.cutoff).toLocaleString()} is being removed (~${res.estimate_rows.toLocaleString()} samples).`,
        variant: "success",
      });
    },
    onError: (e) => toast({ title: "Cleanup failed", description: (e as Error).message, variant: "error" }),
  });
}
