// Data layer for the alert-trigger engine: occurrences, trigger rules,
// destinations + delivery health, capabilities. Mirrors lib/queries.ts
// conventions: snake_case API shapes (api-types.ts, namespace A) mapped to
// camelCase UI models here, mutations invalidate the keys they affect.
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { toast } from "@/components/ui/toaster";
import * as A from "@/lib/api-types";

// ---------------------------------------------------------------------------
// query keys (alert families live under "alerts-*" so WS invalidation can
// sweep them by prefix)

export const qkAlerts = {
  capabilities: ["alerts-capabilities"] as const,
  occurrences: (params: Record<string, unknown>) => ["alerts-occurrences", params] as const,
  occurrence: (id: string) => ["alerts-occurrence", id] as const,
  triggers: (params: Record<string, unknown>) => ["alerts-triggers", params] as const,
  trigger: (id: string) => ["alerts-trigger", id] as const,
  destinations: ["alerts-destinations"] as const,
  health: ["alerts-health"] as const,
};

// ---------------------------------------------------------------------------
// UI models

export interface AlertOccurrence {
  id: string;
  triggerId: string;
  triggerName: string;
  fingerprint: string;
  state: "firing" | "acknowledged" | "recovered" | "suppressed";
  severity: string;
  title: string;
  summary: string;
  siteId?: string;
  assetId?: string;
  entityType?: string;
  entityId?: string;
  snapshot: Record<string, unknown>;
  evidence: unknown[];
  occurrenceCount: number;
  openedAt: string;
  acknowledgedAt?: string;
  recoveredAt?: string;
  updatedAt: string;
}

export interface AlertTransition {
  id: string;
  fromState: string;
  toState: string;
  actor: string;
  reason: string;
  observedValue?: number;
  createdAt: string;
}

export interface AlertDelivery {
  id: string;
  destinationId: string;
  destinationName: string;
  kind: string;
  status: "pending" | "retry" | "sent" | "dead";
  attempts: number;
  lastStatusCode?: number;
  lastError: string;
  createdAt: string;
  sentAt?: string;
}

export interface AlertTrigger {
  id: string;
  name: string;
  description: string;
  kind: "event" | "device_metric";
  enabled: boolean;
  lifecycle: string;
  severity: string;
  scope: A.AlertTriggerScope;
  conditions: Record<string, unknown>;
  eventTypes: string[];
  recoveryEventTypes: string[];
  metricField: string;
  aggregation: string;
  operator: string;
  threshold: number;
  windowSecs: number;
  groupBy: string;
  activationSecs: number;
  recoverySecs: number;
  recoveryThreshold?: number;
  missingDataPolicy: string;
  cooldownSecs: number;
  repeatSecs: number;
  destinationIds: string[];
  revision: number;
  createdBy: string;
  updatedAt: string;
  lastEvaluatedAt?: string;
  lastError: string;
}

export interface AlertDestination {
  id: string;
  kind: "webhook" | "in_app";
  name: string;
  url: string;
  secretMasked?: string;
  events: string[];
  minSeverity: string;
  enabled: boolean;
  createdAt: string;
  lastSuccessAt?: string;
  lastError: string;
  deliveries: Record<string, number>;
}

// ---------------------------------------------------------------------------
// mappers

export function mapOccurrence(o: A.AlertOccurrence): AlertOccurrence {
  return {
    id: o.id, triggerId: o.trigger_id, triggerName: o.trigger_name || "Trigger",
    fingerprint: o.fingerprint, state: o.state, severity: o.severity,
    title: o.title, summary: o.summary, siteId: o.site_id || undefined,
    assetId: o.asset_id || undefined, entityType: o.entity_type || undefined,
    entityId: o.entity_id || undefined, snapshot: o.snapshot ?? {},
    evidence: o.evidence ?? [], occurrenceCount: o.occurrence_count,
    openedAt: o.opened_at, acknowledgedAt: o.acknowledged_at || undefined,
    recoveredAt: o.recovered_at || undefined, updatedAt: o.updated_at,
  };
}

export function mapTrigger(t: A.AlertTrigger): AlertTrigger {
  return {
    id: t.id, name: t.name, description: t.description, kind: t.kind,
    enabled: t.enabled, lifecycle: t.lifecycle, severity: t.severity,
    scope: t.scope ?? {}, conditions: t.conditions ?? {},
    eventTypes: t.event_types ?? [], recoveryEventTypes: t.recovery_event_types ?? [],
    metricField: t.metric_field, aggregation: t.aggregation, operator: t.operator,
    threshold: t.threshold, windowSecs: t.window_secs, groupBy: t.group_by,
    activationSecs: t.activation_secs, recoverySecs: t.recovery_secs,
    recoveryThreshold: t.recovery_threshold, missingDataPolicy: t.missing_data_policy,
    cooldownSecs: t.cooldown_secs, repeatSecs: t.repeat_secs,
    destinationIds: t.destination_ids ?? [], revision: t.revision,
    createdBy: t.created_by, updatedAt: t.updated_at,
    lastEvaluatedAt: t.last_evaluated_at || undefined, lastError: t.last_error,
  };
}

export function mapDestination(d: A.AlertDestination, deliveries: Record<string, number> = {}): AlertDestination {
  return {
    id: d.id, kind: d.kind, name: d.name, url: d.url, secretMasked: d.secret_masked,
    events: d.events ?? [], minSeverity: d.min_severity, enabled: d.enabled,
    createdAt: d.created_at, lastSuccessAt: d.last_success_at || undefined,
    lastError: d.last_error, deliveries,
  };
}

// ---------------------------------------------------------------------------
// capabilities

export function useAlertCapabilities() {
  return useQuery({
    queryKey: qkAlerts.capabilities,
    queryFn: () => api.get<A.AlertCapabilities>("/alerts/capabilities"),
    staleTime: 5 * 60_000,
  });
}

// ---------------------------------------------------------------------------
// occurrences

export function useAlertOccurrences(params: { state?: string; severity?: string; q?: string; page?: number; limit?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.state) qs.set("state", params.state);
  if (params.severity && params.severity !== "all") qs.set("severity", params.severity);
  if (params.q) qs.set("q", params.q);
  qs.set("page", String(params.page ?? 1));
  qs.set("limit", String(params.limit ?? 50));
  return useQuery({
    queryKey: qkAlerts.occurrences(params),
    queryFn: async () => {
      const res = await api.get<A.Page<A.AlertOccurrence>>(`/alerts?${qs.toString()}`);
      return { items: (res.items ?? []).map(mapOccurrence), total: res.total };
    },
    placeholderData: keepPreviousData,
    refetchInterval: 15_000,
  });
}

export function useAlertOccurrence(id: string | undefined) {
  return useQuery({
    queryKey: qkAlerts.occurrence(id ?? ""),
    enabled: !!id,
    queryFn: async () => {
      const res = await api.get<{ occurrence: A.AlertOccurrence; transitions: A.AlertTransition[]; deliveries: A.AlertDelivery[] }>(
        `/alerts/${id}`,
      );
      return {
        occurrence: mapOccurrence(res.occurrence),
        transitions: (res.transitions ?? []).map((t) => ({
          id: t.id, fromState: t.from_state, toState: t.to_state, actor: t.actor,
          reason: t.reason, observedValue: t.observed_value, createdAt: t.created_at,
        })),
        deliveries: (res.deliveries ?? []).map((d) => ({
          id: d.id, destinationId: d.destination_id, destinationName: d.destination_name || d.destination_id,
          kind: d.kind, status: d.status, attempts: d.attempts,
          lastStatusCode: d.last_status_code, lastError: d.last_error,
          createdAt: d.created_at, sentAt: d.sent_at || undefined,
        })),
      };
    },
    refetchInterval: 15_000,
  });
}

export function useAckAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ackAlert,
    onSuccess: (_d, id) => {
      toast({ title: "Alert acknowledged", variant: "success" });
      qc.invalidateQueries({ queryKey: ["alerts-occurrences"] });
      qc.invalidateQueries({ queryKey: qkAlerts.occurrence(id) });
      qc.invalidateQueries({ queryKey: qkAlerts.health });
    },
    onError: (e) => toast({ title: "Acknowledgement failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useResolveAlert() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: resolveAlert,
    onSuccess: (_d, id) => {
      toast({ title: "Alert resolved", variant: "success" });
      qc.invalidateQueries({ queryKey: ["alerts-occurrences"] });
      qc.invalidateQueries({ queryKey: qkAlerts.occurrence(id) });
      qc.invalidateQueries({ queryKey: qkAlerts.health });
    },
    onError: (e) => toast({ title: "Resolve failed", description: (e as Error).message, variant: "error" }),
  });
}

// ---------------------------------------------------------------------------
// triggers

export function useAlertTriggers(params: { q?: string; kind?: string; enabled?: string; page?: number; limit?: number } = {}) {
  const qs = new URLSearchParams();
  if (params.q) qs.set("q", params.q);
  if (params.kind && params.kind !== "all") qs.set("kind", params.kind);
  if (params.enabled && params.enabled !== "all") qs.set("enabled", params.enabled);
  qs.set("page", String(params.page ?? 1));
  qs.set("limit", String(params.limit ?? 50));
  return useQuery({
    queryKey: qkAlerts.triggers(params),
    queryFn: async () => {
      const res = await api.get<A.Page<{ trigger: A.AlertTrigger; firing: number }>>(`/alerts/triggers?${qs.toString()}`);
      return {
        items: (res.items ?? []).map((r) => ({ trigger: mapTrigger(r.trigger), firing: r.firing ?? 0 })),
        total: res.total,
      };
    },
    placeholderData: keepPreviousData,
  });
}

// Factored fetch bodies: the mutation hooks below stay thin wrappers so
// the endpoint + request contract is testable without a react provider
// (same pattern as fetchSites in queries.ts).
export async function createTrigger(payload: Record<string, unknown>): Promise<A.AlertTrigger> {
  return api.post<A.AlertTrigger>("/alerts/triggers", payload);
}

export async function updateTrigger(id: string, payload: Record<string, unknown>): Promise<A.AlertTrigger> {
  return api.put<A.AlertTrigger>(`/alerts/triggers/${id}`, payload);
}

export async function toggleTrigger(id: string, enabled: boolean): Promise<void> {
  await api.patch(`/alerts/triggers/${id}/enabled`, { enabled });
}

export async function deleteTrigger(id: string): Promise<void> {
  await api.del(`/alerts/triggers/${id}`);
}

export async function testTrigger(id: string): Promise<{ status: string; evaluated?: number; matched?: number; error?: string; samples?: unknown[] }> {
  return api.post<{ status: string; evaluated?: number; matched?: number; error?: string; samples?: unknown[] }>(`/alerts/triggers/${id}/test`, {});
}

export async function ackAlert(id: string): Promise<void> {
  await api.post(`/alerts/${id}/acknowledge`, {});
}

export async function resolveAlert(id: string): Promise<void> {
  await api.post(`/alerts/${id}/resolve`, {});
}

export async function createDestination(payload: Record<string, unknown>): Promise<void> {
  await api.post("/alerts/destinations", payload);
}

export async function updateDestination(id: string, payload: Record<string, unknown>): Promise<void> {
  await api.patch(`/alerts/destinations/${id}`, payload);
}

export async function deleteDestination(id: string): Promise<void> {
  await api.del(`/alerts/destinations/${id}`);
}

export async function testDestination(id: string): Promise<{ delivery_id: string }> {
  return api.post<{ delivery_id: string }>(`/alerts/destinations/${id}/test`, {});
}

export async function replayDeadDeliveries(id: string): Promise<{ replayed: number }> {
  return api.post<{ replayed: number }>(`/alerts/destinations/${id}/replay`, {});
}

export function useCreateTrigger() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createTrigger,
    onSuccess: () => {
      toast({ title: "Trigger created", variant: "success" });
      qc.invalidateQueries({ queryKey: ["alerts-triggers"] });
    },
    onError: (e) => toast({ title: "Trigger create failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useUpdateTrigger() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) => updateTrigger(id, payload),
    onSuccess: () => {
      toast({ title: "Trigger saved", variant: "success" });
      qc.invalidateQueries({ queryKey: ["alerts-triggers"] });
    },
    onError: (e) => toast({ title: "Trigger save failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useToggleTrigger() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) => toggleTrigger(id, enabled),
    onSuccess: (_d, vars) => {
      toast({ title: vars.enabled ? "Trigger enabled" : "Trigger disabled", variant: "success" });
      qc.invalidateQueries({ queryKey: ["alerts-triggers"] });
    },
    onError: (e) => toast({ title: "Toggle failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useDeleteTrigger() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteTrigger,
    onSuccess: () => {
      toast({ title: "Trigger deleted", variant: "success" });
      qc.invalidateQueries({ queryKey: ["alerts-triggers"] });
    },
    onError: (e) => toast({ title: "Delete failed", description: (e as Error).message, variant: "error" }),
  });
}

export function usePreviewTrigger() {
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.post<{ valid: boolean; error?: string; summary?: string; scope?: { sites: number; assets: number; destinations: number }; metric_sample?: Record<string, unknown> }>(
        "/alerts/triggers/preview", payload,
      ),
  });
}

export function useTestTrigger() {
  return useMutation({
    mutationFn: testTrigger,
  });
}

// ---------------------------------------------------------------------------
// destinations

export function useAlertDestinations() {
  return useQuery({
    queryKey: qkAlerts.destinations,
    queryFn: async () => {
      const res = await api.get<{ items: { destination: A.AlertDestination; deliveries: Record<string, number> }[]; total: number }>(
        "/alerts/destinations",
      );
      return (res.items ?? []).map((r) => mapDestination(r.destination, r.deliveries ?? {}));
    },
    refetchInterval: 30_000,
  });
}

export function useCreateDestination() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: createDestination,
    onSuccess: () => {
      toast({ title: "Destination created", description: "Use Test to verify the webhook receives signed deliveries.", variant: "success" });
      qc.invalidateQueries({ queryKey: qkAlerts.destinations });
    },
    onError: (e) => toast({ title: "Destination create failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useUpdateDestination() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) => updateDestination(id, payload),
    onSuccess: () => {
      toast({ title: "Destination saved", variant: "success" });
      qc.invalidateQueries({ queryKey: qkAlerts.destinations });
    },
    onError: (e) => toast({ title: "Destination save failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useDeleteDestination() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: deleteDestination,
    onSuccess: () => {
      toast({ title: "Destination deleted", variant: "success" });
      qc.invalidateQueries({ queryKey: qkAlerts.destinations });
    },
    onError: (e) => toast({ title: "Delete failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useTestDestination() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: testDestination,
    onSuccess: () => {
      toast({ title: "Test delivery enqueued", description: "The delivery worker will POST a signed synthetic alert shortly.", variant: "success" });
      qc.invalidateQueries({ queryKey: qkAlerts.destinations });
    },
    onError: (e) => toast({ title: "Test failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useReplayDeadDeliveries() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: replayDeadDeliveries,
    onSuccess: (res) => {
      toast({ title: `Replayed ${res.replayed} dead deliveries`, variant: "success" });
      qc.invalidateQueries({ queryKey: qkAlerts.destinations });
    },
    onError: (e) => toast({ title: "Replay failed", description: (e as Error).message, variant: "error" }),
  });
}
