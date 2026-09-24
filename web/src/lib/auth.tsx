// Centralized authentication state for the SPA (docs/AUTH.md).
//
// One provider owns the session lifecycle; pages and route guards consume
// it through useAuth() — no component manages tokens independently and no
// flag in browser storage ever decides whether the user is signed in.
//
//   status = 'initializing'      → a session restore is in flight; route
//                                  guards render the splash, NOT the login
//                                  screen (no flash of unauthenticated UI)
//   status = 'authenticated'     → user is known, access JWT is in memory
//   status = 'unauthenticated'   → no session (or it was definitively lost)
//
// Session restore on a full reload: the browser sends the HttpOnly refresh
// cookie to POST /auth/refresh; a 200 puts a fresh access JWT in memory and
// the flow continues as authenticated. A definitive rejection transitions
// to unauthenticated. A transient backend/network failure is retried a few
// times and never treated as a logout of a session we haven't even
// evaluated yet — after the retries the login screen is the honest answer.
//
// Cross-tab behavior: logout in one tab broadcasts on a BroadcastChannel
// and every other tab drops to unauthenticated immediately (no credentials
// are written to any storage to achieve this). A login broadcast makes
// other tabs restore their own session through the shared cookie.
import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { api, clearAccessToken, onSessionLost, refreshSession, setAccessToken } from '@/lib/api'
import { ws } from '@/lib/ws'

export type AuthStatus = 'initializing' | 'authenticated' | 'unauthenticated'

export interface AuthUser {
  id: string
  email: string
  name: string
}

interface AuthContextValue {
  status: AuthStatus
  user: AuthUser | null
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

interface MeResponse {
  user: AuthUser
}

// Network-failure retries during startup restore: short enough not to hang
// the splash forever, long enough to ride out a container restart.
const RESTORE_ATTEMPTS = 3
const RESTORE_BACKOFF_MS = 1500

export function AuthProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<AuthStatus>('initializing')
  const [user, setUser] = useState<AuthUser | null>(null)
  const queryClient = useQueryClient()
  const restoreRef = useRef<(() => Promise<void>) | undefined>(undefined)

  // restore runs on first mount (page load / hard reload): attempt to
  // revive the session purely through the refresh cookie.
  const restore = useCallback(async () => {
    let result: 'ok' | 'invalid' | 'transient' = 'transient'
    for (let attempt = 0; attempt < RESTORE_ATTEMPTS; attempt++) {
      result = await refreshSession()
      if (result !== 'transient') break
      await new Promise((res) => setTimeout(res, RESTORE_BACKOFF_MS * (attempt + 1)))
    }
    if (result === 'ok') {
      try {
        const me = await api.get<MeResponse>('/auth/me')
        setUser(me.user)
        setStatus('authenticated')
        return
      } catch {
        // The fresh token was rejected moments after issuance (e.g. the
        // account was disabled between refresh and /me). Treat as lost.
      }
    }
    clearAccessToken()
    setUser(null)
    // 'invalid' → session truly gone; 'transient' after retries → the
    // backend is unreachable and there is no session in memory to protect:
    // the login screen is the correct, non-destructive answer.
    setStatus('unauthenticated')
  }, [])

  restoreRef.current = restore

  // Defer until after effect setup so StrictMode's setup/cleanup replay
  // cancels the first invocation instead of starting two restore requests.
  useEffect(() => {
    let cancelled = false
    void Promise.resolve().then(() => {
      if (!cancelled) void restore()
    })
    return () => { cancelled = true }
  }, [restore])

  // The API client calls this exactly once when the server definitively
  // rejects the session mid-usage (revoked / expired / unknown refresh).
  useEffect(() => {
    onSessionLost(() => {
      setUser(null)
      setStatus('unauthenticated')
      // Authenticated data cached by react-query must not outlive the
      // session it was fetched under.
      queryClient.clear()
    })
    return () => onSessionLost(() => {})
  }, [queryClient])

  // Cross-tab session propagation — BroadcastChannel carries ONLY the
  // event type; no tokens ever transit it or any storage.
  useEffect(() => {
    if (typeof BroadcastChannel === 'undefined') return
    const channel = new BroadcastChannel('aegis-auth')
    channel.onmessage = (ev: MessageEvent) => {
      const type = ev.data?.type
      if (type === 'logout') {
        clearAccessToken()
        setUser(null)
        setStatus('unauthenticated')
        queryClient.clear()
      } else if (type === 'login') {
        // Another tab just signed in: restore this tab through the shared
        // cookie so both tabs agree on the authenticated state.
        void restoreRef.current?.()
      }
    }
    return () => channel.close()
  }, [queryClient])

  const login = useCallback(
    async (email: string, password: string) => {
      // Clear any stale state before establishing the new session.
      queryClient.clear()
      const res = await api.login(email, password)
      setAccessToken(res.access_token)
      setUser(res.user)
      setStatus('authenticated')
      broadcast({ type: 'login' })
    },
    [queryClient],
  )

  const logout = useCallback(async () => {
    // Server first: revoke the refresh family + clear the cookie. Then
    // local state. Then broadcast so other tabs follow immediately.
    await api.logout()
    ws.disconnect() // drop the streaming socket with the session
    setUser(null)
    setStatus('unauthenticated')
    queryClient.clear()
    broadcast({ type: 'logout' })
  }, [queryClient])

  return <AuthContext.Provider value={{ status, user, login, logout }}>{children}</AuthContext.Provider>
}

function broadcast(message: { type: 'login' | 'logout' }) {
  if (typeof BroadcastChannel === 'undefined') return
  try {
    const channel = new BroadcastChannel('aegis-auth')
    channel.postMessage(message)
    channel.close()
  } catch {
    /* cross-tab sync is best-effort */
  }
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
