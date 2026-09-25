// Data layer for tenant-configurable vulnerability search actions and the
// match workbench. Same conventions as queries.alerts.ts.
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { api } from "@/lib/api";
import { toast } from "@/components/ui/toaster";
import * as A from "@/lib/api-types";

export const qkVulnSearch = {
  capabilities: ["vulnsearch-capabilities"] as const,
  actions: ["vulnsearch-actions"] as const,
  action: (id: string) => ["vulnsearch-action", id] as const,
  diagnostics: (assetId: string) => ["vulnsearch-diagnostics", assetId] as const,
};

export function useVulnSearchCapabilities() {
  return useQuery({
    queryKey: qkVulnSearch.capabilities,
    queryFn: () => api.get<A.VulnSearchCaps>("/vulnerability-search-actions/capabilities"),
    staleTime: 5 * 60_000,
  });
}

export function useVulnSearchActions() {
  return useQuery({
    queryKey: qkVulnSearch.actions,
    queryFn: () => api.get<{ items: A.VulnSearchAction[]; total: number }>("/vulnerability-search-actions"),
  });
}

export function useVulnSearchAction(id: string | undefined) {
  return useQuery({
    queryKey: qkVulnSearch.action(id ?? ""),
    enabled: !!id,
    queryFn: () => api.get<{ action: A.VulnSearchAction; runs: A.VulnSearchRun[] }>(`/vulnerability-search-actions/${id}`),
  });
}

export function useCreateSearchAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) => api.post("/vulnerability-search-actions", payload),
    onSuccess: () => {
      toast({ title: "Search action created", variant: "success" });
      qc.invalidateQueries({ queryKey: qkVulnSearch.actions });
    },
    onError: (e) => toast({ title: "Create failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useUpdateSearchAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: Record<string, unknown> }) =>
      api.put(`/vulnerability-search-actions/${id}`, payload),
    onSuccess: () => {
      toast({ title: "Search action saved", variant: "success" });
      qc.invalidateQueries({ queryKey: qkVulnSearch.actions });
    },
    onError: (e) => toast({ title: "Save failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useDeleteSearchAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.del(`/vulnerability-search-actions/${id}`),
    onSuccess: () => {
      toast({ title: "Search action deleted", variant: "success" });
      qc.invalidateQueries({ queryKey: qkVulnSearch.actions });
    },
    onError: (e) => toast({ title: "Delete failed", description: (e as Error).message, variant: "error" }),
  });
}

export function usePreviewSearchAction() {
  return useMutation({
    mutationFn: (payload: Record<string, unknown>) =>
      api.post<A.VulnSearchPreview>("/vulnerability-search-actions/preview", payload),
  });
}

export function useRunSearchAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => api.post<{ run_id: string }>(`/vulnerability-search-actions/${id}/runs`, {}),
    onSuccess: () => {
      toast({ title: "Run queued", description: "The worker will execute the action; watch the runs list for progress.", variant: "success" });
      qc.invalidateQueries({ queryKey: qkVulnSearch.actions });
    },
    onError: (e) => toast({ title: "Run failed", description: (e as Error).message, variant: "error" }),
  });
}

export function useAssetVulnDiagnostics(assetId: string | undefined) {
  return useQuery({
    queryKey: qkVulnSearch.diagnostics(assetId ?? ""),
    enabled: !!assetId,
    queryFn: () => api.get<A.AssetVulnDiagnostics>(`/assets/${assetId}/vulnerability-diagnostics`),
  });
}
