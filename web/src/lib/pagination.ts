import * as React from "react";

/* ------------------------------------------------------------------ */
/* Page-size preference — shared by every table view                   */
/* ------------------------------------------------------------------ */
/* One storage blob ({"assets":100,"findings":50,...}) keyed per table, */
/* so analysts can keep different densities per view; every table      */
/* defaults to 50 rows and clamps to the known options, which are      */
/* bounded by the API's max limit (200).                               */

export const PAGE_SIZE_OPTIONS = [25, 50, 100, 200] as const;
export type PageSizeOption = (typeof PAGE_SIZE_OPTIONS)[number];
export const DEFAULT_PAGE_SIZE: PageSizeOption = 50;

const STORAGE_KEY = "aegis-page-size";

/** Only stored values that exactly match a known option are honored;
 *  anything else (missing, mistyped, hand-edited) falls back to 50. */
export function normalizePageSize(v: unknown): PageSizeOption {
  const n = Number(v);
  return (PAGE_SIZE_OPTIONS as readonly number[]).includes(n) ? (n as PageSizeOption) : DEFAULT_PAGE_SIZE;
}

export function readStoredPageSize(key: string): PageSizeOption {
  try {
    const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}") as Record<string, unknown>;
    return normalizePageSize(raw[key]);
  } catch {
    return DEFAULT_PAGE_SIZE;
  }
}

export function storePageSize(key: string, size: PageSizeOption): void {
  try {
    const raw = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "{}") as Record<string, unknown>;
    raw[key] = size;
    localStorage.setItem(STORAGE_KEY, JSON.stringify(raw));
  } catch {
    // storage unavailable (private mode, disabled) — the choice stays
    // session-only, which is the correct degradation
  }
}

/** [pageSize, setPageSize] persisted per table under aegis-page-size. */
export function usePageSize(key: string): [PageSizeOption, (n: number) => void] {
  const [size, setState] = React.useState<PageSizeOption>(() => readStoredPageSize(key));
  const set = React.useCallback(
    (n: number) => {
      const next = normalizePageSize(n);
      setState(next);
      storePageSize(key, next);
    },
    [key],
  );
  return [size, set];
}
