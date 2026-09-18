import { useEffect, useMemo, useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  LayoutDashboard, Boxes, Network, Radar, Bug, ShieldAlert, BellRing,
  Radio, Cpu, FileText, Settings, Search, LogOut, Terminal,
} from 'lucide-react'
import { clsx } from 'clsx'
import { api } from '@/lib/api'
import { useAuth } from '@/lib/auth'
import type { Me } from '@/types'

const nav = [
  { to: '/', label: 'Overview', icon: LayoutDashboard },
  { to: '/assets', label: 'Assets', icon: Boxes },
  { to: '/topology', label: 'Topology', icon: Network },
  { to: '/scans', label: 'Scans', icon: Radar },
  { to: '/vulnerabilities', label: 'Vulnerabilities', icon: Bug },
  { to: '/findings', label: 'Findings', icon: ShieldAlert },
  { to: '/detections', label: 'Detections', icon: BellRing },
  { to: '/events', label: 'Events', icon: Radio },
  { to: '/agents', label: 'Agents', icon: Cpu },
  { to: '/reports', label: 'Reports', icon: FileText },
  { to: '/settings', label: 'Settings', icon: Settings },
]

// g+s/g+a… chord navigation (spec §130).
function useGoChords(navigate: (p: string) => void) {
  useEffect(() => {
    let armed = false
    let timer: ReturnType<typeof setTimeout>
    const handler = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (e.defaultPrevented || target.closest('input, textarea, [contenteditable="true"], [role="combobox"], [role="listbox"], [role="option"]')) {
        armed = false
        return
      }
      if (e.key === 'g') {
        armed = true
        clearTimeout(timer)
        timer = setTimeout(() => (armed = false), 800)
        return
      }
      if (armed) {
        const map: Record<string, string> = { a: '/assets', s: '/scans', v: '/vulnerabilities', e: '/events', d: '/', t: '/topology' }
        if (map[e.key]) {
          navigate(map[e.key])
          armed = false
        }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [navigate])
}

function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [q, setQ] = useState('')
  const navigate = useNavigate()
  const actions = useMemo(
    () => [
      ...nav.map((n) => ({ label: `Go to ${n.label.toLowerCase()}`, run: () => navigate(n.to) })),
      { label: 'Run a scan', run: () => navigate('/scans?new=1') },
      { label: 'Show critical findings', run: () => navigate('/findings?severity=critical') },
      { label: 'Filter KEV vulnerabilities', run: () => navigate('/vulnerabilities?kev=true') },
      { label: 'Generate report', run: () => navigate('/reports?new=1') },
      { label: 'Open settings', run: () => navigate('/settings') },
    ],
    [navigate],
  )
  const filtered = actions.filter((a) => a.label.toLowerCase().includes(q.toLowerCase()))
  if (!open) return null
  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/60 pt-[14vh]" role="dialog" aria-modal="true" onClick={onClose}>
      <div className="w-[560px] overflow-hidden rounded-md2 border border-line bg-bg-panel shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 border-b border-line px-3 py-2.5">
          <Terminal size={14} className="text-fg-dim" aria-hidden />
          <input
            autoFocus
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Type a command or search…"
            className="w-full bg-transparent text-[13px] outline-none placeholder:text-fg-faint"
            aria-label="Command palette"
          />
        </div>
        <div className="max-h-[320px] overflow-y-auto py-1">
          {filtered.length === 0 && <p className="px-4 py-6 text-center text-[12.5px] text-fg-dim">No matching commands</p>}
          {filtered.map((a) => (
            <button
              key={a.label}
              className="block w-full px-4 py-2 text-left text-[13px] text-fg-dim hover:bg-white/5 hover:text-fg"
              onClick={() => { a.run(); onClose() }}
            >
              {a.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

export function AppShell() {
  const [paletteOpen, setPaletteOpen] = useState(false)
  const navigate = useNavigate()
  const { logout } = useAuth()
  useGoChords(navigate)

  const { data: me } = useQuery({
    queryKey: ['me'],
    queryFn: () => api.get<Me>('/auth/me'),
  })

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setPaletteOpen((v) => !v)
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  return (
    <div className="flex h-full">
      <aside className="flex w-[212px] shrink-0 flex-col border-r border-line bg-bg-panel">
        <div className="flex items-center gap-2 px-4 py-4">
          <div className="flex h-6 w-6 items-center justify-center rounded-sm2 bg-accent text-[12px] font-bold text-white">Æ</div>
          <span className="text-[13.5px] font-semibold tracking-tight">Aegis</span>
        </div>
        <nav className="flex-1 space-y-0.5 px-2" aria-label="Primary">
          {nav.map((n) => (
            <NavLink
              key={n.to}
              to={n.to}
              end={n.to === '/'}
              className={({ isActive }) =>
                clsx(
                  'flex items-center gap-2.5 rounded-sm2 px-2.5 py-[7px] text-[13px]',
                  isActive ? 'bg-white/[0.06] text-fg' : 'text-fg-dim hover:bg-white/[0.03] hover:text-fg',
                )
              }
            >
              <n.icon size={15} aria-hidden />
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-line p-3">
          <div className="flex items-center justify-between">
            <div className="min-w-0">
              <p className="truncate text-[12.5px]">{me?.user?.name ?? '…'}</p>
              <p className="truncate text-[11px] text-fg-faint">{me?.organizations?.[0]?.name ?? ''}</p>
            </div>
            <button
              aria-label="Log out"
              className="text-fg-faint hover:text-crit"
              onClick={async () => {
                // auth.logout() revokes the session server-side, clears the
                // refresh cookie, wipes the in-memory token, purges cached
                // data and tells other tabs — navigation happens after the
                // state is actually cleared.
                await logout()
                navigate('/login')
              }}
            >
              <LogOut size={15} aria-hidden />
            </button>
          </div>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 items-center justify-between border-b border-line px-4">
          <button
            onClick={() => setPaletteOpen(true)}
            className="flex w-[320px] items-center gap-2 rounded-sm2 border border-line bg-bg-raise px-2.5 py-1.5 text-[12.5px] text-fg-faint hover:border-line-strong"
          >
            <Search size={13} aria-hidden />
            Search or jump to…
            <kbd className="ml-auto rounded border border-line px-1 text-[10px]">⌘K</kbd>
          </button>
          <span className="text-[11.5px] text-fg-faint">Authorized networks only · All actions audited</span>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto p-5">
          <Outlet />
        </main>
      </div>
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
    </div>
  )
}
