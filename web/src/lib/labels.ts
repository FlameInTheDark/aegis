// Shared label/format helpers.
import type { Asset } from "@/data/types";

export function isCrit(s: string | undefined): boolean {
  return s === "critical" || s === "high" || s === "medium" || s === "low";
}

export function assetLabel(a?: Pick<Asset, "hostname" | "fqdn" | "ip">): string {
  return a ? a.hostname || a.fqdn || a.ip : "—";
}

export function assetOptionLabel(a: Asset): string {
  return a.hostname ? `${a.hostname} (${a.ip})` : a.ip;
}

export const REPORT_TYPE_LABELS: Record<string, string> = {
  executive_summary: "Executive summary",
  technical_vulnerability: "Technical vulnerability",
  asset_inventory: "Asset inventory",
  device_detail: "Device detail",
  compliance: "Compliance",
};

export const reportTypeLabel = (t: string) => REPORT_TYPE_LABELS[t] ?? t;

export const ROLE_LABELS: Record<string, string> = {
  owner: "Owner",
  administrator: "Administrator",
  security_analyst: "Analyst",
  operator: "Operator",
  viewer: "Viewer",
};

export const humanize = (s?: string): string =>
  (s || "").replace(/[_-]+/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
