import type { usePagination } from "@/components/shared";

/** Shape returned by usePagination — the client-side pager the asset detail
 *  page owns and passes down to its table tabs (services / software). */
export type Paged<T> = ReturnType<typeof usePagination<T>>;
