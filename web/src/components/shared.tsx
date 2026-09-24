import * as React from "react";
import {
  ArrowDownRight,
  ArrowUpRight,
  Boxes,
  ChevronLeft,
  ChevronRight,
  CircleHelp,
  Inbox,
  List,
  Minus,
  type LucideIcon,
} from "lucide-react";

import { cn, clamp } from "@/lib/utils";
import { PAGE_SIZE_OPTIONS, usePageSize } from "@/lib/pagination";
import type { Criticality, Exposure, Severity } from "@/data/types";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";

/* ------------------------------------------------------------------ */
/* Severity                                                            */
/* ------------------------------------------------------------------ */
export const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export const severityMeta: Record<Severity, { label: string; text: string; bg: string; dot: string; hex: string }> = {
  critical: { label: "Critical", text: "text-critical", bg: "bg-critical", dot: "bg-critical", hex: "oklch(0.64 0.22 22)" },
  high: { label: "High", text: "text-high", bg: "bg-high", dot: "bg-high", hex: "oklch(0.72 0.18 45)" },
  medium: { label: "Medium", text: "text-medium", bg: "bg-medium", dot: "bg-medium", hex: "oklch(0.8 0.16 85)" },
  low: { label: "Low", text: "text-low", bg: "bg-low", dot: "bg-low", hex: "oklch(0.74 0.12 230)" },
  info: { label: "Info", text: "text-muted-foreground", bg: "bg-muted-foreground", dot: "bg-muted-foreground", hex: "oklch(0.64 0.012 262)" },
};

export function SeverityBadge({ severity, className, compact }: { severity: Severity; className?: string; compact?: boolean }) {
  const m = severityMeta[severity];
  return (
    <Badge variant={severity} className={cn("capitalize", compact && "px-1.5 text-[10px]", className)}>
      <span className={cn("size-1.5 rounded-full", m.dot)} />
      {m.label}
    </Badge>
  );
}

export function CriticalityBadge({ value }: { value: Criticality }) {
  const map: Partial<Record<Criticality, "critical" | "high" | "medium" | "low">> = {
    critical: "critical",
    high: "high",
    medium: "medium",
    low: "low",
  };
  const variant = map[value];
  if (!variant) {
    return <Badge variant="info" className="capitalize">unrated</Badge>;
  }
  return (
    <Badge variant={variant} className="capitalize">
      {value}
    </Badge>
  );
}

export function ExposureBadge({ value }: { value: Exposure }) {
  const meta: Record<Exposure, { label: string; variant: "critical" | "high" | "info" }> = {
    internet: { label: "Internet", variant: "critical" },
    dmz: { label: "DMZ", variant: "high" },
    internal: { label: "Internal", variant: "info" },
    unknown: { label: "Unknown", variant: "info" },
  };
  const m = meta[value] ?? meta.unknown;
  return <Badge variant={m.variant}>{m.label}</Badge>;
}

/* ------------------------------------------------------------------ */
/* Status dot / state                                                  */
/* ------------------------------------------------------------------ */
type Tone = "success" | "primary" | "warning" | "danger" | "muted";

const toneClass: Record<Tone, string> = {
  success: "bg-success text-success",
  primary: "bg-primary text-primary",
  warning: "bg-medium text-medium",
  danger: "bg-critical text-critical",
  muted: "bg-muted-foreground text-muted-foreground",
};

export function StatusDot({ tone, pulse, className }: { tone: Tone; pulse?: boolean; className?: string }) {
  return (
    <span className={cn("relative inline-flex size-2 shrink-0 rounded-full", toneClass[tone], pulse && "pulse-ring", className)} />
  );
}

export function StateBadge({
  label,
  tone,
  pulse,
  className,
}: {
  label: string;
  tone: Tone;
  pulse?: boolean;
  className?: string;
}) {
  const variant: Record<Tone, "success" | "primary" | "medium" | "critical" | "info"> = {
    success: "success",
    primary: "primary",
    warning: "medium",
    danger: "critical",
    muted: "info",
  };
  return (
    <Badge variant={variant[tone]} className={cn("capitalize", className)}>
      <StatusDot tone={tone} pulse={pulse} className="size-1.5" />
      {label.replace(/_/g, " ")}
    </Badge>
  );
}

/* ------------------------------------------------------------------ */
/* Risk / confidence meters                                            */
/* ------------------------------------------------------------------ */
export function riskTone(risk: number): { text: string; bar: string; label: string } {
  if (risk >= 80) return { text: "text-critical", bar: "bg-critical", label: "Critical" };
  if (risk >= 60) return { text: "text-high", bar: "bg-high", label: "High" };
  if (risk >= 35) return { text: "text-medium", bar: "bg-medium", label: "Medium" };
  if (risk > 0) return { text: "text-low", bar: "bg-low", label: "Low" };
  return { text: "text-muted-foreground", bar: "bg-muted-foreground/40", label: "None" };
}

export function RiskMeter({ value, className, showLabel = true }: { value: number; className?: string; showLabel?: boolean }) {
  const t = riskTone(value);
  return (
    <div className={cn("flex items-center gap-2", className)}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-muted">
        <div className={cn("h-full rounded-full", t.bar)} style={{ width: `${clamp(value, 0, 100)}%` }} />
      </div>
      {showLabel && <span className={cn("tabular text-xs font-semibold", t.text)}>{value}</span>}
    </div>
  );
}

export function RiskRing({ value, size = 56, stroke = 5, className }: { value: number; size?: number; stroke?: number; className?: string }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const t = riskTone(value);
  return (
    <div className={cn("relative inline-flex items-center justify-center", className)} style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} className="stroke-muted" strokeWidth={stroke} fill="none" />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          strokeWidth={stroke}
          fill="none"
          strokeLinecap="round"
          className={cn("transition-all", t.text)}
          stroke="currentColor"
          strokeDasharray={c}
          strokeDashoffset={c - (clamp(value, 0, 100) / 100) * c}
        />
      </svg>
      <span className={cn("absolute tabular text-sm font-bold", t.text)}>{value}</span>
    </div>
  );
}

export function ConfidenceMeter({ value, className }: { value: number; className?: string }) {
  const filled = Math.round(clamp(value, 0, 100) / 20);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <div className={cn("flex items-center gap-2", className)}>
          <div className="flex gap-0.5">
            {Array.from({ length: 5 }).map((_, i) => (
              <span key={i} className={cn("h-3 w-1 rounded-sm", i < filled ? "bg-primary" : "bg-muted")} />
            ))}
          </div>
          <span className="tabular text-xs text-muted-foreground">{value}%</span>
        </div>
      </TooltipTrigger>
      <TooltipContent>Fingerprint evidence strength — not certainty</TooltipContent>
    </Tooltip>
  );
}

/** Horizontal stacked bar of severity counts */
export function SeverityStack({
  counts,
  className,
  height = "h-1.5",
}: {
  counts: { critical: number; high: number; medium: number; low: number };
  className?: string;
  height?: string;
}) {
  const total = counts.critical + counts.high + counts.medium + counts.low;
  if (total === 0) {
    return <div className={cn("w-full rounded-full bg-muted", height, className)} />;
  }
  return (
    <div className={cn("flex w-full overflow-hidden rounded-full bg-muted", height, className)}>
      {(["critical", "high", "medium", "low"] as const).map((k) =>
        counts[k] > 0 ? (
          <div key={k} className={severityMeta[k].bg} style={{ width: `${(counts[k] / total) * 100}%` }} />
        ) : null
      )}
    </div>
  );
}

export function SeverityCountsInline({
  counts,
  className,
}: {
  counts: { critical: number; high: number; medium: number; low: number };
  className?: string;
}) {
  const total = counts.critical + counts.high + counts.medium + counts.low;
  if (total === 0) return <span className={cn("text-xs text-muted-foreground", className)}>—</span>;
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      {(["critical", "high", "medium", "low"] as const).map((k) =>
        counts[k] > 0 ? (
          <span key={k} className="flex items-center gap-1 tabular text-xs">
            <span className={cn("size-1.5 rounded-full", severityMeta[k].dot)} />
            <span className={severityMeta[k].text}>{counts[k]}</span>
          </span>
        ) : null
      )}
    </div>
  );
}

/* ------------------------------------------------------------------ */
/* Page scaffolding                                                    */
/* ------------------------------------------------------------------ */
export function PageHeader({
  title,
  description,
  actions,
  className,
  children,
}: {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
  className?: string;
  children?: React.ReactNode;
}) {
  return (
    <div className={cn("flex flex-col gap-4", className)}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex min-w-0 items-center gap-2">
          <h1 className="text-xl font-semibold tracking-tight">{title}</h1>
          {description && (
            <Tooltip>
              <TooltipTrigger asChild>
                <button aria-label="About this page" className="text-muted-foreground/70 transition-colors hover:text-foreground cursor-help">
                  <CircleHelp className="size-4" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="bottom" align="start" className="max-w-sm text-left">
                {description}
              </TooltipContent>
            </Tooltip>
          )}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {children}
    </div>
  );
}

export function SectionTitle({ children, className, action }: { children: React.ReactNode; className?: string; action?: React.ReactNode }) {
  return (
    <div className={cn("flex items-center justify-between", className)}>
      <h3 className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{children}</h3>
      {action}
    </div>
  );
}

export function KpiTile({
  label,
  value,
  hint,
  delta,
  deltaGood,
  tone,
  icon: Icon,
  onClick,
  sparkline,
  className,
}: {
  label: string;
  value: React.ReactNode;
  hint?: string;
  delta?: number;
  /** whether a positive delta is good (default false — for risk metrics up is bad) */
  deltaGood?: boolean;
  tone?: "critical" | "high" | "medium" | "low" | "primary" | "success" | "default";
  icon?: LucideIcon;
  onClick?: () => void;
  sparkline?: number[];
  className?: string;
}) {
  const toneText: Record<NonNullable<typeof tone>, string> = {
    critical: "text-critical",
    high: "text-high",
    medium: "text-medium",
    low: "text-low",
    primary: "text-primary",
    success: "text-success",
    default: "text-foreground",
  };
  const Comp: React.ElementType = onClick ? "button" : "div";
  const DeltaIcon = delta === undefined || delta === 0 ? Minus : delta > 0 ? ArrowUpRight : ArrowDownRight;
  const deltaPositive = delta !== undefined && delta !== 0 && (delta > 0) === !!deltaGood;
  return (
    <Comp
      onClick={onClick}
      className={cn(
        "group relative flex flex-col gap-2 rounded-xl border bg-card p-4 text-left shadow-sm transition-colors",
        onClick && "cursor-pointer hover:border-primary/40 hover:bg-accent/30",
        className
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
        {Icon && <Icon className="size-4 text-muted-foreground/70" />}
      </div>
      <div className="flex items-end justify-between gap-2">
        <span className={cn("tabular text-2xl font-semibold leading-none", toneText[tone ?? "default"])}>{value}</span>
        {sparkline && <Sparkline data={sparkline} className={cn("h-6 w-16", toneText[tone ?? "primary"])} />}
      </div>
      {(hint || delta !== undefined) && (
        <div className="flex items-center gap-2 text-xs text-muted-foreground">
          {delta !== undefined && (
            <span
              className={cn(
                "inline-flex items-center gap-0.5 tabular font-medium",
                delta === 0 ? "text-muted-foreground" : deltaPositive ? "text-success" : "text-critical"
              )}
            >
              <DeltaIcon className="size-3" />
              {Math.abs(delta)}
            </span>
          )}
          {hint && <span className="truncate">{hint}</span>}
        </div>
      )}
    </Comp>
  );
}

export function Sparkline({ data, className }: { data: number[]; className?: string }) {
  if (!data.length) return null;
  const w = 64;
  const h = 24;
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = max - min || 1;
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * w},${h - ((v - min) / range) * (h - 2) - 1}`).join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className={cn("overflow-visible", className)} preserveAspectRatio="none">
      <polyline points={pts} fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

export function EmptyState({
  icon: Icon = Inbox,
  title,
  description,
  action,
  className,
  compact,
}: {
  icon?: LucideIcon;
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
  compact?: boolean;
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center text-center", compact ? "gap-2 py-8" : "gap-3 py-14", className)}>
      <div className="flex size-10 items-center justify-center rounded-lg border bg-muted/40 text-muted-foreground">
        <Icon className="size-5" />
      </div>
      <div>
        <p className="text-sm font-medium">{title}</p>
        {description && <p className="mx-auto mt-1 max-w-sm text-xs text-muted-foreground">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function Kbd({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <kbd
      className={cn(
        "pointer-events-none inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-mono text-[10px] font-medium text-muted-foreground",
        className
      )}
    >
      {children}
    </kbd>
  );
}

export function KeyValue({
  label,
  children,
  mono,
  className,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("flex items-start justify-between gap-4 py-2 text-sm", className)}>
      <span className="shrink-0 text-muted-foreground">{label}</span>
      <span className={cn("min-w-0 text-right", mono && "font-mono text-xs")}>{children ?? "—"}</span>
    </div>
  );
}

export function Mono({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("font-mono text-[13px]", className)}>{children}</span>;
}

/* ------------------------------------------------------------------ */
/* Pagination                                                          */
/* ------------------------------------------------------------------ */
export function TableFooterBar({
  total,
  page,
  pageSize,
  onPage,
  onPageSize,
  pageSizeOptions = PAGE_SIZE_OPTIONS,
  label = "results",
  children,
}: {
  total: number;
  page: number;
  pageSize: number;
  onPage: (p: number) => void;
  /** when provided, a rows-per-page selector renders next to the pager */
  onPageSize?: (n: number) => void;
  pageSizeOptions?: readonly number[];
  label?: string;
  children?: React.ReactNode;
}) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(total, page * pageSize);
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 border-t px-3 py-2 text-xs text-muted-foreground">
      <div className="flex items-center gap-3">
        <span className="tabular">
          {from}–{to} of {total} {label}
        </span>
        {children}
      </div>
      <div className="flex items-center gap-1">
        {onPageSize && (
          <label className="mr-2 flex items-center gap-1.5">
            <span className="hidden md:inline">Rows</span>
            <select
              aria-label="Rows per page"
              value={pageSize}
              onChange={(e) => onPageSize(Number(e.target.value))}
              className="h-7 cursor-pointer rounded-md border bg-transparent px-1.5 text-xs text-fg outline-none transition-colors hover:border-foreground/30 focus:border-primary"
            >
              {pageSizeOptions.map((n) => (
                <option key={n} value={n} className="bg-popover text-fg">
                  {n}
                </option>
              ))}
            </select>
          </label>
        )}
        <Button variant="ghost" size="icon-xs" disabled={page <= 1} onClick={() => onPage(page - 1)}>
          <ChevronLeft />
        </Button>
        <span className="tabular px-2">
          Page {page} / {pages}
        </span>
        <Button variant="ghost" size="icon-xs" disabled={page >= pages} onClick={() => onPage(page + 1)}>
          <ChevronRight />
        </Button>
      </div>
    </div>
  );
}

/** Client-side pagination over a fully-fetched list, with the page size
 *  persisted per table (aegis-page-size.<sizeKey>, default 50). Changing
 *  the size always returns to page 1 so the window can never land past
 *  the end of the list. */
export function usePagination<T>(items: T[], sizeKey: string) {
  const [pageSize, setSizeState] = usePageSize(sizeKey);
  const [page, setPage] = React.useState(1);
  const pages = Math.max(1, Math.ceil(items.length / pageSize));
  React.useEffect(() => {
    if (page > pages) setPage(pages);
  }, [page, pages]);
  const slice = React.useMemo(() => items.slice((page - 1) * pageSize, page * pageSize), [items, page, pageSize]);
  const setPageSize = React.useCallback(
    (n: number) => {
      setSizeState(n);
      setPage(1);
    },
    [setSizeState],
  );
  return { page, setPage, slice, pageSize, setPageSize, total: items.length, pages };
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */
export function TypeIconBubble({ icon: Icon, className }: { icon: LucideIcon; className?: string }) {
  return (
    <span className={cn("flex size-8 shrink-0 items-center justify-center rounded-md border bg-muted/40 text-muted-foreground", className)}>
      <Icon className="size-4" />
    </span>
  );
}

/* ------------------------------------------------------------------ */
/* Segmented control                                                   */
/* ------------------------------------------------------------------ */

/** One option of a SegmentedControl. */
export interface SegmentedOption<V extends string> {
  value: V;
  label: string;
  icon?: LucideIcon;
  title?: string;
}

/**
 * Compact segmented control (pill switch) — one visible choice, one click
 * to flip, no dropdown round-trip. Used for view-level switches such as
 * grouping or layout where the choice is binary and worth showing always.
 */
export function SegmentedControl<V extends string>({
  value,
  onChange,
  options,
  className,
  ariaLabel,
}: {
  value: V;
  onChange: (v: V) => void;
  options: SegmentedOption<V>[];
  className?: string;
  ariaLabel?: string;
}) {
  return (
    <div className={cn("flex items-center rounded-lg border bg-muted/30 p-0.5", className)} role="group" aria-label={ariaLabel}>
      {options.map((o) => {
        const active = value === o.value;
        const Icon = o.icon;
        return (
          <button
            key={o.value}
            type="button"
            onClick={() => onChange(o.value)}
            aria-pressed={active}
            title={o.title}
            className={cn(
              "flex items-center justify-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition-colors cursor-pointer",
              active ? "bg-background text-foreground shadow-sm" : "text-muted-foreground hover:text-foreground",
            )}
          >
            {Icon && <Icon className="size-3.5" />}
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

/** Grouping switch shared by the Assets list and the Topology table. */
export function GroupingToggle({
  value,
  onChange,
  className,
}: {
  value: "none" | "group";
  onChange: (v: "none" | "group") => void;
  className?: string;
}) {
  return (
    <SegmentedControl
      className={className}
      ariaLabel="Group assets"
      value={value}
      onChange={onChange}
      options={[
        { value: "none", label: "Flat", icon: List, title: "One row per asset, paginated" },
        { value: "group", label: "Grouped", icon: Boxes, title: "Collapse assets under their asset group" },
      ]}
    />
  );
}
