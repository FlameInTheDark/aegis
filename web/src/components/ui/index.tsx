import { ReactNode, useState, useEffect, useRef } from 'react'
import { clsx } from 'clsx'
import { AlertTriangle, Check, ChevronDown, Loader2 } from 'lucide-react'
import type { Severity } from '@/types'

export function Button({ children, onClick, variant = 'default', disabled, type = 'button', className }: {
  children: ReactNode
  onClick?: () => void
  variant?: 'default' | 'primary' | 'danger' | 'ghost'
  disabled?: boolean
  type?: 'button' | 'submit'
  className?: string
}) {
  const styles = {
    default: 'bg-bg-raise border border-line hover:border-line-strong',
    primary: 'bg-accent hover:bg-accent-hover text-white border border-accent',
    danger: 'bg-crit/10 text-crit border border-crit/30 hover:bg-crit/20',
    ghost: 'border border-transparent hover:bg-white/5 text-fg-dim hover:text-fg',
  }[variant]
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={clsx('inline-flex h-8 items-center gap-1.5 rounded-sm2 px-2.5 text-[12.5px] font-medium transition-colors disabled:opacity-40 disabled:cursor-not-allowed', styles, className)}
    >
      {children}
    </button>
  )
}

export function Badge({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={clsx('inline-flex items-center gap-1 rounded-sm2 border px-1.5 py-0.5 text-[11px] font-medium', className)}>
      {children}
    </span>
  )
}

// ── Pills ──────────────────────────────────────────────────────────────
// Soft tinted chips (translucent background + matching hairline border)
// used for severity, status and categorical values in data tables.
export type PillTone = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'ok' | 'accent' | 'neutral'

export function Pill({ tone = 'neutral', dot, title, children, className }: {
  tone?: PillTone
  dot?: boolean
  title?: string
  children: ReactNode
  className?: string
}) {
  return (
    <span data-tone={tone} title={title} className={clsx('pill', className)}>
      {dot && <span aria-hidden className="pill-dot" />}
      {children}
    </span>
  )
}

// severityTone maps severities AND criticality labels to pill tones.
export function severityTone(s: string): PillTone {
  switch (s) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'medium': return 'medium'
    case 'low': return 'low'
    case 'info': return 'info'
    default: return 'neutral'
  }
}

export function statusTone(state: string): PillTone {
  switch (state) {
    case 'running': case 'online': case 'healthy': case 'ok':
    case 'completed': case 'succeeded': case 'resolved':
      return 'ok'
    case 'queued': case 'pending': case 'cancelling': case 'in_progress':
    case 'degraded':
      return 'medium'
    case 'failed': case 'cancelled': case 'offline': case 'revoked': case 'critical':
      return 'critical'
    case 'open':
      return 'accent'
    case 'acknowledged':
      return 'info'
    default:
      return 'neutral'
  }
}

export function StatusPill({ state, label, title }: { state: string; label?: string; title?: string }) {
  return (
    <Pill tone={statusTone(state)} dot title={title ?? `Status: ${state}`}>
      {label ?? state}
    </Pill>
  )
}

// ── Toolbar control chips ──────────────────────────────────────────────
// "Label: value" inside one rounded control, per the premium dark table
// reference. Purely presentational — state stays in the page.
export function ChipSelect({ label, value, options, onChange, ariaLabel, className }: {
  label: string
  value: string
  options: { value: string; label: string }[]
  onChange: (value: string) => void
  ariaLabel?: string
  className?: string
}) {
  return (
    <label className={clsx('tbl-chip tbl-chip-select', className)}>
      <span className="tbl-chip-label">{label}:</span>
      <select aria-label={ariaLabel ?? label} value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>
      <ChevronDown size={12} aria-hidden className="tbl-chip-caret" />
    </label>
  )
}

export function ChipToggle({ label, active, onClick, tone = 'accent', title }: {
  label: string
  active: boolean
  onClick: () => void
  tone?: 'accent' | 'critical'
  title?: string
}) {
  return (
    <button type="button" className="tbl-chip tbl-chip-toggle" aria-pressed={active} data-tone={tone} title={title} onClick={onClick}>
      {label}
    </button>
  )
}

// ── In-cell data visuals ───────────────────────────────────────────────
// Meter: segmented value bar, colored by value (red / amber / green)
// unless an explicit tone override is passed (e.g. progress bars).
export function Meter({ value, max = 100, segments = 5, label, tone, className }: {
  value: number
  max?: number
  segments?: number
  label?: string
  tone?: PillTone
  className?: string
}) {
  const pct = max > 0 ? Math.min(Math.max(value / max, 0), 1) : 0
  const auto: PillTone = pct >= 0.8 ? 'critical' : pct >= 0.6 ? 'high' : pct >= 0.35 ? 'medium' : 'ok'
  const filled = Math.round(pct * segments)
  return (
    <span
      className={clsx('meter', className)}
      data-tone={tone ?? auto}
      role="meter"
      aria-valuemin={0}
      aria-valuemax={max}
      aria-valuenow={Math.round(value * 100) / 100}
      aria-label={label}
    >
      {Array.from({ length: segments }, (_, i) => (
        <i key={i} aria-hidden className={i < filled ? 'on' : ''} />
      ))}
    </span>
  )
}

// MiniBars: tiny pure-CSS/div sparkline (no chart library). The last bar
// is emphasized; pass label to expose it to assistive technology.
export function MiniBars({ values, height = 18, label, className }: {
  values: number[]
  height?: number
  label?: string
  className?: string
}) {
  const max = Math.max(...values, 1)
  const bars = values.map((v) => Math.max(Math.round((v / max) * 100), 8))
  return (
    <span
      className={clsx('minibars', className)}
      style={{ height }}
      role={label ? 'img' : undefined}
      aria-label={label}
      aria-hidden={label ? undefined : true}
    >
      {bars.map((h, i) => (
        <i key={i} style={{ height: `${h}%` }} />
      ))}
    </span>
  )
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  if (!severity) return <span className="text-fg-faint">—</span>
  return (
    <Pill tone={severityTone(severity)} dot title={`Severity: ${severity}`}>
      {severity}
    </Pill>
  )
}

export function KEVBadge() {
  return (
    <Pill tone="critical" className="font-semibold" title="Present in CISA Known Exploited Vulnerabilities catalog">
      <AlertTriangle size={10} aria-hidden /> KEV
    </Pill>
  )
}

export function StatusDot({ state, label }: { state: string; label?: string }) {
  return <StatusPill state={state} label={label} />
}

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={clsx(
        'h-8 rounded-sm2 border border-line bg-bg-raise px-2.5 text-[13px] placeholder:text-fg-faint focus:border-accent focus:outline-none',
        props.className,
      )}
    />
  )
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={clsx(
        'rounded-sm2 border border-line bg-bg-raise px-2 py-1.5 text-[12.5px] focus:border-accent focus:outline-none',
        props.className,
      )}
    />
  )
}

export function Dialog({ open, onClose, title, children, wide }: {
  open: boolean
  onClose: () => void
  title: string
  children: ReactNode
  wide?: boolean
}) {
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    if (open) window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, onClose])
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[12vh]" role="dialog" aria-modal="true" aria-label={title} onClick={onClose}>
      <div
        className={clsx('rounded-md2 border border-line bg-bg-panel shadow-2xl', wide ? 'w-[640px]' : 'w-[440px]')}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="border-b border-line px-4 py-3 text-[13px] font-medium">{title}</div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}

export function Tabs({ tabs, active, onChange }: { tabs: string[]; active: string; onChange: (t: string) => void }) {
  return (
    <div className="flex gap-4 border-b border-line" role="tablist">
      {tabs.map((t) => (
        <button
          key={t}
          role="tab"
          aria-selected={t === active}
          onClick={() => onChange(t)}
          className={clsx(
            '-mb-px border-b-2 px-1 pb-2 pt-1 text-[13px] capitalize',
            t === active ? 'border-accent text-fg' : 'border-transparent text-fg-dim hover:text-fg',
          )}
        >
          {t}
        </button>
      ))}
    </div>
  )
}

export function Panel({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx('rounded-md2 border border-line bg-bg-panel shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]', className)}>{children}</div>
}

export function PanelHeader({ title, action }: { title: string; action?: ReactNode }) {
  return (
    <div className="flex items-center justify-between border-b border-line px-3.5 py-2.5">
      <h3 className="text-[12px] font-medium uppercase tracking-wide text-fg-dim">{title}</h3>
      {action}
    </div>
  )
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-fg-dim" role="status">
      <Loader2 size={16} className="animate-spin" aria-hidden />
      <span className="text-[13px]">{label ?? 'Loading…'}</span>
    </div>
  )
}

export function EmptyState({ title, hint, action }: { title: string; hint?: string; action?: ReactNode }) {
  return (
    <div className="tbl-empty flex flex-col items-center justify-center gap-1.5 py-16 text-center">
      <p className="text-[14px] font-medium text-fg">{title}</p>
      {hint && <p className="text-[12.5px] text-fg-dim">{hint}</p>}
      {action && <div className="mt-2">{action}</div>}
    </div>
  )
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-14">
      <p className="flex items-center gap-2 text-[13px] text-crit"><AlertTriangle size={14} aria-hidden /> {message}</p>
      {onRetry && <Button onClick={onRetry}>Retry</Button>}
    </div>
  )
}

export function Pagination({ page, limit, total, onPage }: {
  page: number; limit: number; total: number; onPage: (p: number) => void
}) {
  const pages = Math.max(1, Math.ceil(total / limit))
  return (
    <div className="flex items-center justify-between border-t border-line px-3 py-2 text-[12px] text-fg-dim">
      <span>{total.toLocaleString()} results</span>
      <div className="flex items-center gap-2">
        <Button variant="ghost" disabled={page <= 1} onClick={() => onPage(page - 1)}>Prev</Button>
        <span>Page {page} / {pages}</span>
        <Button variant="ghost" disabled={page >= pages} onClick={() => onPage(page + 1)}>Next</Button>
      </div>
    </div>
  )
}

export function KPICard({ label, value, tone, onClick }: {
  label: string
  value: number | string
  tone?: 'crit' | 'high' | 'default'
  onClick?: () => void
}) {
  return (
    <button
      onClick={onClick}
      className="rounded-md2 border border-line bg-bg-panel px-4 py-3 text-left transition-colors hover:border-line-strong"
    >
      <div className={clsx('text-[22px] font-semibold tabular-nums',
        tone === 'crit' ? 'text-crit' : tone === 'high' ? 'text-high' : 'text-fg')}>
        {value}
      </div>
      <div className="text-[11.5px] uppercase tracking-wide text-fg-dim">{label}</div>
    </button>
  )
}

export function ConfirmDialog({ open, title, body, confirmLabel, onConfirm, onCancel }: {
  open: boolean
  title: string
  body: string
  confirmLabel: string
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <Dialog open={open} onClose={onCancel} title={title}>
      <p className="text-[13px] text-fg-dim">{body}</p>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="ghost" onClick={onCancel}>Cancel</Button>
        <Button variant="danger" onClick={onConfirm}>{confirmLabel}</Button>
      </div>
    </Dialog>
  )
}

export function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      className="text-fg-faint hover:text-fg"
      title="Copy to clipboard"
      aria-label="Copy to clipboard"
      onClick={() => {
        navigator.clipboard.writeText(text)
        setCopied(true)
        setTimeout(() => setCopied(false), 1200)
      }}
    >
      {copied ? <Check size={12} /> : null}
      {!copied && <span className="text-[10px] uppercase">copy</span>}
    </button>
  )
}

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value)
  const t = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  useEffect(() => {
    clearTimeout(t.current)
    t.current = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t.current)
  }, [value, ms])
  return v
}
