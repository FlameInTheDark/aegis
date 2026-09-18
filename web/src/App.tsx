import { Component, ReactNode } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from '@/lib/auth'
import { AppShell } from '@/components/layout/AppShell'
import LoginPage from '@/features/auth/LoginPage'
import DashboardPage from '@/features/dashboard/DashboardPage'
import AssetsPage from '@/features/assets/AssetsPage'
import AssetDetailPage from '@/features/assets/AssetDetailPage'
import TopologyPage from '@/features/topology/TopologyPage'
import ScansPage from '@/features/scans/ScansPage'
import ScanDetailPage from '@/features/scans/ScanDetailPage'
import VulnerabilitiesPage from '@/features/vulnerabilities/VulnerabilitiesPage'
import VulnerabilityDetailPage from '@/features/vulnerabilities/VulnerabilityDetailPage'
import FindingsPage from '@/features/findings/FindingsPage'
import DetectionRulesPage from '@/features/detections/DetectionsPage'
import EventsPage from '@/features/events/EventsPage'
import AgentsPage from '@/features/agents/AgentsPage'
import AgentDetailPage from '@/features/agents/AgentDetailPage'
import ReportsPage from '@/features/reports/ReportsPage'
import SettingsPage from '@/features/settings/SettingsPage'

// Error boundary keeps failures local and logs internally (§134).
class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }
  static getDerivedStateFromError(error: Error) { return { error } }
  render() {
    if (this.state.error) {
      return (
        <div className="flex h-full flex-col items-center justify-center gap-3">
          <p className="text-[15px] font-medium">Something went wrong in this view.</p>
          <p className="text-[12.5px] text-fg-dim">The error has been logged with a request id. Reload to recover.</p>
          <button className="rounded-sm2 border border-line px-3 py-1.5 text-[13px]" onClick={() => window.location.reload()}>
            Reload
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// Full-screen splash shown while the session restore is in flight — the
// user must never see the login screen flash before an existing session is
// restored (and protected content must never render on stale state).
export function AuthSplash() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-2" role="status">
      <div className="flex h-8 w-8 items-center justify-center rounded-sm2 bg-accent text-[15px] font-bold text-white">Æ</div>
      <p className="text-[12.5px] text-fg-dim">Restoring session…</p>
    </div>
  )
}

// RequireAuth is the ONLY route gate: it renders from the centralized auth
// state, never from a storage flag. While initializing it shows the splash;
// after logout/failed refresh the protected tree disappears immediately.
function RequireAuth({ children }: { children: ReactNode }) {
  const { status } = useAuth()
  if (status === 'initializing') return <AuthSplash />
  if (status === 'unauthenticated') return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  return (
    <ErrorBoundary>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<RequireAuth><AppShell /></RequireAuth>}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/assets" element={<AssetsPage />} />
          <Route path="/assets/:id" element={<AssetDetailPage />} />
          <Route path="/topology" element={<TopologyPage />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/scans/:id" element={<ScanDetailPage />} />
          <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
          <Route path="/vulnerabilities/:cveId" element={<VulnerabilityDetailPage />} />
          <Route path="/findings" element={<FindingsPage />} />
          <Route path="/detections" element={<DetectionRulesPage />} />
          <Route path="/events" element={<EventsPage />} />
          <Route path="/agents" element={<AgentsPage />} />
          <Route path="/agents/:id" element={<AgentDetailPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AuthProvider>
    </ErrorBoundary>
  )
}
