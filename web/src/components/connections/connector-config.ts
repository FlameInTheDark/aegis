/**
 * Connector configuration model — the pure, React-free half of the
 * connector configuration dialog. MUST mirror connectors.ValidateSettings
 * (internal/connectors/service.go) and the connector-side section reader
 * (internal/connectorapp/hybrid.go). The settings carry two SEPARATE
 * function sections with `enabled` toggles deciding what the connection
 * performs (endpoint collection and/or remote scanning). A flat layout
 * (top-level engine, ssh_* and collection_level keys) is accepted as well.
 */

export interface ConnectorAgentConfig {
  enabled?: boolean;
  collection_level?: string;
  /** Metric probe rate: how often a performance sample is taken (ms). */
  probe_rate_ms?: number;
  /** Metric pull rate: how often buffered samples are flushed to the hub (ms). */
  pull_rate_ms?: number;
}

export interface ConnectorScannerConfig {
  enabled?: boolean;
  engine?: string;
  nmap_path?: string;
  ssh_user?: string;
  ssh_password?: string;
  ssh_key_path?: string;
  ssh_timeout_secs?: number;
  ssh_insecure?: boolean;
  ssh_pinned_key?: string;
}

export interface ConnectorConfig {
  heartbeat_secs?: number;
  agent?: ConnectorAgentConfig;
  scanner?: ConnectorScannerConfig;
}

/** Metrics cadence defaults — MUST mirror internal/endpoint/config.go. */
export const DEFAULT_PROBE_RATE_MS = 5000;
export const DEFAULT_PULL_RATE_MS = 30000;

export const DEFAULT_NMAP_PATH = "/usr/bin/nmap";

export const HEARTBEAT_PRESETS = [
  { value: 15, label: "15 seconds" },
  { value: 30, label: "30 seconds" },
  { value: 60, label: "1 minute" },
  { value: 120, label: "2 minutes" },
  { value: 300, label: "5 minutes" },
];

export const PROBE_RATE_PRESETS = [
  { value: 100, label: "100 ms" },
  { value: 250, label: "250 ms" },
  { value: 500, label: "500 ms" },
  { value: 1000, label: "1 second" },
  { value: 5000, label: "5 seconds" },
  { value: 10000, label: "10 seconds" },
  { value: 30000, label: "30 seconds" },
  { value: 60000, label: "1 minute" },
];

export const PULL_RATE_PRESETS = [
  { value: 1000, label: "1 second" },
  { value: 5000, label: "5 seconds" },
  { value: 10000, label: "10 seconds" },
  { value: 15000, label: "15 seconds" },
  { value: 30000, label: "30 seconds" },
  { value: 60000, label: "1 minute" },
  { value: 300000, label: "5 minutes" },
  { value: 900000, label: "15 minutes" },
];

/**
 * connectionFunctions computes which functions a connection performs:
 * each function defaults to the connection kind's own function, an
 * explicit `enabled` toggle in its section overrides the default. Mirrors
 * connectors.AgentEnabled/ScannerEnabled (internal/connectors/settings.go).
 */
export function connectionFunctions(kind: string, config?: Record<string, unknown>): ("agent" | "scanner")[] {
  const sec = (n: string) =>
    config?.[n] && typeof config[n] === "object" ? (config[n] as Record<string, unknown>) : undefined;
  const agentOn = sec("agent") && typeof sec("agent")!.enabled === "boolean" ? !!sec("agent")!.enabled : kind === "agent";
  const scannerOn = sec("scanner") && typeof sec("scanner")!.enabled === "boolean" ? !!sec("scanner")!.enabled : kind === "scanner";
  const out: ("agent" | "scanner")[] = [];
  if (agentOn) out.push("agent");
  if (scannerOn) out.push("scanner");
  return out;
}

/**
 * defaultConnectorConfig normalizes a connection's stored settings JSON
 * into the fully-populated shape the configuration dialog edits: function
 * toggles default to the connection kind's own function, the legacy flat
 * keys act as fallbacks for the section values, and the metrics cadence
 * falls back to the platform defaults when absent or invalid.
 */
export function defaultConnectorConfig(kind: string, raw?: Record<string, unknown>): ConnectorConfig {
  const src = raw ?? {};
  const sec = (n: string) =>
    src[n] && typeof src[n] === "object" ? (src[n] as Record<string, unknown>) : undefined;
  const flat = (k: string) => (typeof src[k] === "string" ? (src[k] as string) : undefined);
  const flatNum = (k: string) => (typeof src[k] === "number" ? (src[k] as number) : undefined);
  const flatBool = (k: string) => (typeof src[k] === "boolean" ? (src[k] as boolean) : undefined);
  const aRaw = sec("agent");
  const sRaw = sec("scanner");
  const num = (v: unknown, d: number) => (typeof v === "number" ? v : d);
  const rate = (v: unknown, d: number) => (typeof v === "number" && v > 0 ? v : d);
  return {
    heartbeat_secs: num(src["heartbeat_secs"], 60),
    agent: {
      // default: the kind's own function; explicit toggle wins
      enabled: aRaw && typeof aRaw.enabled === "boolean" ? aRaw.enabled : kind === "agent",
      collection_level: (aRaw?.collection_level as string) ?? flat("collection_level") ?? "basic",
      probe_rate_ms: rate(aRaw?.probe_rate_ms ?? flatNum("probe_rate_ms"), DEFAULT_PROBE_RATE_MS),
      pull_rate_ms: rate(aRaw?.pull_rate_ms ?? flatNum("pull_rate_ms"), DEFAULT_PULL_RATE_MS),
    },
    scanner: {
      enabled: sRaw && typeof sRaw.enabled === "boolean" ? sRaw.enabled : kind === "scanner",
      engine: (sRaw?.engine as string) ?? flat("engine") ?? "auto",
      nmap_path: (sRaw?.nmap_path as string) ?? flat("nmap_path") ?? DEFAULT_NMAP_PATH,
      ssh_user: (sRaw?.ssh_user as string) ?? flat("ssh_user"),
      ssh_password: (sRaw?.ssh_password as string) ?? flat("ssh_password"),
      ssh_key_path: (sRaw?.ssh_key_path as string) ?? flat("ssh_key_path"),
      ssh_timeout_secs: num(sRaw?.ssh_timeout_secs ?? flatNum("ssh_timeout_secs"), 30),
      ssh_insecure: (sRaw?.ssh_insecure as boolean) ?? flatBool("ssh_insecure") ?? false,
      ssh_pinned_key: (sRaw?.ssh_pinned_key as string) ?? flat("ssh_pinned_key"),
    },
  };
}

/** formatRate renders a millisecond rate for humans: 100 ms / 2.5 s / 5 min. */
export function formatRate(ms?: number): string {
  const v = typeof ms === "number" && ms > 0 ? ms : 0;
  if (v >= 60000) {
    const mins = v / 60000;
    return `${Number.isInteger(mins) ? mins : mins.toFixed(1)} min`;
  }
  if (v >= 1000) {
    const secs = v / 1000;
    return `${Number.isInteger(secs) ? secs : secs.toFixed(1)} s`;
  }
  return `${v} ms`;
}
