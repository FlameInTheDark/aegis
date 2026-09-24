// Formatting + severity utilities (spec §133/§131: label+color pairs,
// relative time with exact timestamp on hover).
import type { Severity } from '@/types'

export function severityColor(s: Severity): string {
  switch (s) {
    case 'critical': return 'text-crit'
    case 'high': return 'text-high'
    case 'medium': return 'text-med'
    case 'low': return 'text-low'
    default: return 'text-info'
  }
}

export function severityBg(s: Severity): string {
  switch (s) {
    case 'critical': return 'bg-crit/10 border-crit/30'
    case 'high': return 'bg-high/10 border-high/30'
    case 'medium': return 'bg-med/10 border-med/30'
    case 'low': return 'bg-low/10 border-low/30'
    default: return 'bg-info/10 border-info/30'
  }
}

export function riskLabel(score: number): string {
  if (score >= 80) return 'Critical'
  if (score >= 60) return 'High'
  if (score >= 35) return 'Moderate'
  if (score >= 15) return 'Low'
  return 'Minimal'
}

export function relTime(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  const diff = Date.now() - d.getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 30) return `${days}d ago`
  return d.toLocaleDateString()
}

// untilTime formats a FUTURE timestamp as a countdown ("in 5m", "in 23h",
// "in 6d"); once the moment passes it degrades to the relTime "ago" form.
// relTime is past-only — fed an expiry it always answers "just now", which
// is exactly how the connect-command dialog ended up claiming every fresh
// token "expires just now" for its whole 24h lifetime.
export function untilTime(iso?: string): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return '—'
  const secs = Math.floor((d.getTime() - Date.now()) / 1000)
  if (secs < -60) return relTime(iso)
  if (secs <= 0) return 'any second'
  if (secs < 60) return `in ${secs}s`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return `in ${mins}m`
  const hours = Math.floor(mins / 60)
  if (hours < 48) return `in ${hours}h`
  const days = Math.floor(hours / 24)
  return `in ${days}d`
}

export function exactTime(iso?: string): string {
  if (!iso) return ''
  return new Date(iso).toISOString().replace('T', ' ').slice(0, 19) + ' UTC'
}

export function fmtNum(n?: number | null): string {
  if (n === null || n === undefined) return '—'
  return n.toLocaleString()
}

// fmtBytes renders a byte count with binary units (KiB/MiB/GiB/TiB).
export function fmtBytes(n?: number | null): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—'
  if (n < 1024) return `${Math.round(n)} B`
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB']
  let v = n
  let i = -1
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < units.length - 1)
  return `${v >= 100 ? v.toFixed(0) : v.toFixed(1)} ${units[i]}`
}

// fmtBps renders a bytes-per-second throughput.
export function fmtBps(n?: number | null): string {
  if (n === null || n === undefined || Number.isNaN(n)) return '—'
  return `${fmtBytes(n)}/s`
}

export function statusColor(state: string): string {
  switch (state) {
    case 'running': case 'open': case 'online': case 'healthy': case 'completed':
      return 'text-ok'
    case 'queued': case 'pending': case 'acknowledged': case 'degraded': case 'in_progress':
      return 'text-med'
    case 'failed': case 'cancelled': case 'offline': case 'revoked': case 'critical':
      return 'text-crit'
    default:
      return 'text-fg-dim'
  }
}

export function humanize(s?: string): string {
  if (!s) return '—'
  return s.replaceAll('_', ' ')
}
