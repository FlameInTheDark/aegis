// Scan streaming (v1.13.0): job log history + live tail + state folding.
//
// History replays from REST (GET /scans/:id/logs — persisted, cursor-
// paginated); the live tail rides the WebSocket `scan:<id>` channel. State
// events on the same channel are folded into the react-query caches that
// the data layer (lib/queries.ts) owns, which is what removes the 3–4s
// polling loops from the scans pages when the stream is connected.
import { useCallback, useEffect, useRef, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'

import { api } from '@/lib/api'
import { qk } from '@/lib/queries'
import { ws, useWSStatus, type StreamEvent } from '@/lib/ws'
import { toast } from '@/components/ui/toaster'

export interface JobLogLine {
  seq: number
  scan_id: string
  task_id?: string
  scanner_id?: string
  ts: string
  level: 'debug' | 'info' | 'warn' | 'error' | string
  source: string
  msg: string
  fields?: Record<string, unknown>
}

const LIVE_BUFFER_CAP = 5000
const HISTORY_PAGE = 500

interface ScanLogsResponse {
  items: JobLogLine[]
  has_more: boolean
}

interface ScanStateEventData {
  scan_id?: string
  state?: string
  phase?: string
  progress?: number
  error?: string
  stats?: {
    targets?: number
    reachable?: number
    ports_discovered?: number
    services_fingerprinted?: number
    packages_collected?: number
    findings_created?: number
    critical_findings?: number
    tasks_total?: number
    tasks_done?: number
    tasks_failed?: number
  }
}

function num(v: unknown): number {
  const n = typeof v === 'number' ? v : 0
  return Number.isFinite(n) ? n : 0
}

/**
 * Job log tail for one scan. History is loaded once per scan id, live
 * lines are appended (de-duplicated by seq, capped buffer), `loadOlder`
 * pages further back through the persisted history.
 */
export function useScanJobLog(scanId: string | undefined) {
  const [lines, setLines] = useState<JobLogLine[]>([])
  const [hasMore, setHasMore] = useState(false)
  const [loading, setLoading] = useState(!!scanId)
  const live = useWSStatus()
  const seqSeen = useRef(0)

  useEffect(() => {
    if (!scanId) {
      setLines([])
      setHasMore(false)
      setLoading(false)
      return
    }
    let cancelled = false
    setLines([])
    setHasMore(false)
    setLoading(true)
    seqSeen.current = 0

    api
      .get<ScanLogsResponse>(`/scans/${scanId}/logs?limit=${HISTORY_PAGE}`)
      .then((res) => {
        if (cancelled) return
        const items = res.items ?? []
        setLines(items)
        setHasMore(!!res.has_more)
        if (items.length) seqSeen.current = items[items.length - 1].seq
      })
      .catch(() => {
        if (!cancelled) setLines([])
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    const unsubscribe = ws.sub(`scan:${scanId}`, (ev: StreamEvent) => {
      if (ev.kind !== 'log') return
      const line = ev.data as unknown as JobLogLine
      if (!line) return
      // Dedupe replays by seq. The server fans live lines out AFTER they are
      // persisted, so they carry the same seq the REST history shows; older
      // backends (seq absent) still append instead of being dropped.
      if (typeof line.seq === 'number' && line.seq > 0) {
        if (line.seq <= seqSeen.current) return // replay/dedupe
        seqSeen.current = line.seq
      }
      setLines((prev) => {
        const next = prev.length >= LIVE_BUFFER_CAP ? prev.slice(prev.length - LIVE_BUFFER_CAP + 1) : prev.slice()
        next.push(line)
        return next
      })
    })

    return () => {
      cancelled = true
      unsubscribe()
    }
  }, [scanId])

  const loadOlder = useCallback(() => {
    if (!scanId || !lines.length) return
    const oldest = lines[0].seq
    api
      .get<ScanLogsResponse>(`/scans/${scanId}/logs?limit=${HISTORY_PAGE}&before=${oldest}`)
      .then((res) => {
        setHasMore(!!res.has_more)
        const older = (res.items ?? []).filter((l) => l.seq < oldest)
        if (older.length) setLines((prev) => [...older, ...prev])
      })
      .catch(() => {})
  }, [scanId, lines])

  return { lines, hasMore, loading, live, loadOlder }
}

/**
 * Subscribes the caches to scan lifecycle events: patches the open detail
 * cache in place (no refetch per progress tick) and invalidates the list
 * caches on terminal transitions. Returns an unsubscribe function.
 */
export function useScanStateStream(scanId: string | undefined) {
  const qc = useQueryClient()
  useEffect(() => {
    if (!scanId) return
    return ws.sub(`scan:${scanId}`, (ev: StreamEvent) => {
      if (ev.kind !== 'state') return
      const st = ev.data as ScanStateEventData
      // Detail cache: { scan: <mapped model>, tasks, changes }.
      qc.setQueryData<{ scan: Record<string, unknown>; tasks: unknown[]; changes: unknown[] }>(qk.scan(scanId), (old) => {
        if (!old) return old
        // Stats merge, not replace: events frequently carry only a subset
        // (hub state reports ride without stats; stats-only reports arrive
        // between phase changes), so absent fields keep the previous value
        // instead of resetting the tiles to zero.
        const s = st.stats ?? {}
        const prev = old.scan as Record<string, unknown>
        const prevReach = (prev.reachable ?? {}) as { up?: number; total?: number }
        const prevTasks = (prev.tasks ?? {}) as { total?: number; done?: number; failed?: number }
        const keep = (v: unknown, fallback: unknown) => (v === undefined || v === null ? fallback : v)
        const scan = {
          ...old.scan,
          state: (st.state as string) ?? (old.scan.state as string),
          phase: st.phase ?? (old.scan.phase as string | undefined),
          // progress >= 0: legacy backends broadcast -1 as "keep current".
          progress:
            typeof st.progress === 'number' && st.progress >= 0
              ? Math.round(st.progress)
              : (old.scan.progress as number),
          error: st.error ?? (old.scan.error as string | undefined),
          reachable: {
            up: num(keep(s.reachable, prevReach.up)),
            total: num(keep(s.targets, prevReach.total)),
          },
          ports: num(keep(s.ports_discovered, prev.ports)),
          services: num(keep(s.services_fingerprinted, prev.services)),
          packages: num(keep(s.packages_collected, prev.packages)),
          findings: num(keep(s.findings_created, prev.findings)),
          criticalFindings: num(keep(s.critical_findings, prev.criticalFindings)),
          tasks: {
            total: num(keep(s.tasks_total, prevTasks.total)),
            done: num(keep(s.tasks_done, prevTasks.done)),
            failed: num(keep(s.tasks_failed, prevTasks.failed)),
          },
        }
        return { ...old, scan }
      })
      // Lists: in-place progress keeps rows fresh; terminal states also
      // invalidate dependent caches (counters, dashboards, asset pages).
      const terminal = st.state && st.state !== 'running' && st.state !== 'queued'
      if (terminal) {
        qc.invalidateQueries({ queryKey: ['scans'] })
        qc.invalidateQueries({ queryKey: ['metrics'] })
        qc.invalidateQueries({ queryKey: ['assets'] })
      }
    })
  }, [scanId, qc])
}

// Notification severity → toast variant.
function variantFor(severity: string | undefined): "default" | "success" | "warning" | "error" {
  switch (severity) {
    case "critical":
    case "high":
      return "error";
    case "medium":
      return "warning";
    case "info":
    case "low":
    default:
      return "default";
  }
}

/**
 * Org notification stream: toasts + cache invalidation for the bell badge
 * and the counters behind it. Mount ONCE (AppShell).
 */
export function useNotificationStream() {
  const qc = useQueryClient();
  useEffect(
    () =>
      ws.sub("notify", (ev: StreamEvent) => {
        const n = ev.data as {
          type?: string;
          title?: string;
          body?: string;
          severity?: string;
          ref?: Record<string, string>;
        };
        if (!n?.type) return;
        toast({
          title: n.title ?? "Notification",
          description: n.body,
          variant: variantFor(n.severity),
        });
        if (n.type === "findings.created") {
          // The bell's unread count derives from the match queue.
          qc.invalidateQueries({ queryKey: ["detection-matches"] });
          qc.invalidateQueries({ queryKey: ["findings"] });
          qc.invalidateQueries({ queryKey: ["vulnerabilities"] });
          qc.invalidateQueries({ queryKey: ["metrics"] });
        }
        if (n.type === "scan.completed" || n.type === "scan.failed") {
          qc.invalidateQueries({ queryKey: ["scans"] });
          qc.invalidateQueries({ queryKey: ["metrics"] });
          qc.invalidateQueries({ queryKey: ["assets"] });
        }
      }),
    [qc],
  );
}
