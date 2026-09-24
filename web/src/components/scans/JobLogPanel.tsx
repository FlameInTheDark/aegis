// JobLogPanel (v1.13.0): the realtime console for one scan job.
// History replays from REST (useScanJobLog), then the WebSocket tail takes
// over. Fed by the actual pipeline: phase transitions, per-host results,
// raw engine stderr, SSH collection lines, correlation summaries.
import * as React from "react";
import { Download, Loader2 } from "lucide-react";

import { cn, timeAgo } from "@/lib/utils";
import { useScanJobLog, type JobLogLine } from "@/lib/scanstream";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/utils";

const LEVELS = ["all", "info", "warn", "error"] as const;
type LevelFilter = (typeof LEVELS)[number];

function levelTag(level: string): string {
  if (level === "warn") return "WARN";
  if (level === "error") return "ERROR";
  if (level === "debug") return "DEBUG";
  return "INFO";
}

function levelClass(level: string): string {
  switch (level) {
    case "error":
      return "text-critical";
    case "warn":
      return "text-warning";
    case "debug":
      return "text-muted-foreground/70";
    default:
      return "text-foreground/75";
  }
}

function clockOf(ts: string): string {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  return d.toLocaleTimeString("en-GB", { hour12: false });
}

function fieldsSummary(line: JobLogLine): string {
  if (!line.fields || Object.keys(line.fields).length === 0) return "";
  try {
    return JSON.stringify(line.fields, null, 1);
  } catch {
    return "";
  }
}

function downloadLog(scanId: string, lines: JobLogLine[]) {
  const text = lines
    .map((l) => `${l.ts}\t${levelTag(l.level)}\t${l.source}\t${l.msg}${l.fields ? `\t${JSON.stringify(l.fields)}` : ""}`)
    .join("\n");
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `aegis-scan-${scanId.slice(0, 8)}-job.log`;
  a.click();
  URL.revokeObjectURL(url);
}

export function JobLogPanel({ scanId, running }: { scanId: string; running: boolean }) {
  const { lines, hasMore, loading, live, loadOlder } = useScanJobLog(scanId);
  const [filter, setFilter] = React.useState<LevelFilter>("all");
  const [follow, setFollow] = React.useState(true);
  const scrollRef = React.useRef<HTMLDivElement>(null);

  const visible = React.useMemo(() => {
    if (filter === "all") return lines;
    if (filter === "warn") return lines.filter((l) => l.level === "warn" || l.level === "error");
    if (filter === "error") return lines.filter((l) => l.level === "error");
    return lines; // info = everything but debug noise
  }, [lines, filter]);

  // Follow mode: pin to the newest line while the scan streams; scrolling
  // up pauses it, hitting the bottom resumes.
  React.useEffect(() => {
    if (!follow || !scrollRef.current) return;
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
  }, [visible.length, follow]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 24);
  };

  return (
    <div>
      <div className="mb-1.5 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Job log</span>
          {running && (
            <span className="flex items-center gap-1 text-[10.5px] text-muted-foreground">
              <Loader2 className={cn("size-3", live && "animate-spin")} aria-hidden />
              {live ? "streaming" : "waiting for stream"}
            </span>
          )}
          {!running && lines.length > 0 && (
            <span className="text-[10.5px] text-muted-foreground">
              {lines.length} line{lines.length === 1 ? "" : "s"}
              {lines.length > 0 ? ` · last ${timeAgo(lines[lines.length - 1].ts)}` : ""}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1">
          {LEVELS.map((l) => (
            <button
              key={l}
              type="button"
              onClick={() => setFilter(l)}
              className={cn(
                "rounded px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide transition-colors",
                filter === l ? "bg-secondary text-foreground" : "text-muted-foreground hover:text-foreground",
              )}
            >
              {l}
            </button>
          ))}
          <Button
            variant="ghost"
            size="icon-sm"
            className="ml-1 text-muted-foreground"
            onClick={() => downloadLog(scanId, lines)}
            aria-label="Download job log"
            title="Download job log"
          >
            <Download />
          </Button>
        </div>
      </div>

      <div
        ref={scrollRef}
        onScroll={onScroll}
        className="max-h-72 overflow-y-auto rounded-lg border bg-[oklch(0.11_0.01_262)] p-3 font-mono text-[11.5px] leading-relaxed"
        role="log"
        aria-live={running ? "polite" : "off"}
        aria-label="Scan job log"
      >
        {loading && (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="size-3 animate-spin" aria-hidden /> loading history…
          </div>
        )}
        {!loading && hasMore && (
          <div className="pb-2">
            <Button variant="outline" size="sm" className="h-6 px-2 text-[10.5px]" onClick={loadOlder}>
              Load older lines
            </Button>
          </div>
        )}
        {!loading && visible.length === 0 && (
          <div className="text-muted-foreground">
            {lines.length === 0
              ? running
                ? "Waiting for the scanner to report…"
                : "No log lines recorded for this scan."
              : `No ${filter} lines in the retained window.`}
          </div>
        )}
        {visible.map((l) => (
          <div key={l.seq} className="flex gap-3" title={fieldsSummary(l)}>
            <span className="shrink-0 text-muted-foreground/60" title={formatDateTime(l.ts)}>
              {clockOf(l.ts)}
            </span>
            <span className={cn("w-12 shrink-0 font-semibold uppercase", levelClass(l.level))}>{levelTag(l.level)}</span>
            <span className="w-14 shrink-0 truncate text-muted-foreground/70" title={l.source}>
              {l.source}
            </span>
            <span className="break-all text-foreground/85">{l.msg}</span>
          </div>
        ))}
        {!loading && running && (
          <div className="flex items-center gap-2 text-muted-foreground">
            <Loader2 className="size-3 animate-spin" aria-hidden /> streaming…
          </div>
        )}
      </div>
      <p className="mt-1 text-[10.5px] text-muted-foreground">
        {live
          ? "Live tail connected."
          : "Live tail offline — showing history; new lines appear when the connection returns."}
        {!follow && " Scroll to the bottom to resume following."}
      </p>
    </div>
  );
}
