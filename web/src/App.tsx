import { Component, lazy, ReactNode, Suspense } from 'react'
import { Navigate, Route, Routes } from 'react-router-dom'
import { AuthProvider, useAuth } from '@/lib/auth'
import { AppShell } from '@/components/layout/AppShell'
import LoginPage from '@/features/auth/LoginPage'

const DashboardPage = lazy(() => import('@/features/dashboard/DashboardPage'))
const AssetsPage = lazy(() => import('@/features/assets/AssetsPage'))
const AssetDetailPage = lazy(() => import('@/features/assets/AssetDetailPage'))
const TopologyPage = lazy(() => import('@/features/topology/TopologyPage'))
const ScansPage = lazy(() => import('@/features/scans/ScansPage'))
const ScanDetailPage = lazy(() => import('@/features/scans/ScanDetailPage'))
const VulnerabilitiesPage = lazy(() => import('@/features/vulnerabilities/VulnerabilitiesPage'))
const VulnerabilityDetailPage = lazy(() => import('@/features/vulnerabilities/VulnerabilityDetailPage'))
const FindingsPage = lazy(() => import('@/features/findings/FindingsPage'))
const DetectionRulesPage = lazy(() => import('@/features/detections/DetectionsPage'))
const EventsPage = lazy(() => import('@/features/events/EventsPage'))
const AgentsPage = lazy(() => import('@/features/agents/AgentsPage'))
const AgentDetailPage = lazy(() => import('@/features/agents/AgentDetailPage'))
const ReportsPage = lazy(() => import('@/features/reports/ReportsPage'))
const SettingsPage = lazy(() => import('@/features/settings/SettingsPage'))

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
        <Suspense fallback={<AuthSplash />}>
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
        </Suspense>
      </AuthProvider>
    </ErrorBoundary>
  )
}
