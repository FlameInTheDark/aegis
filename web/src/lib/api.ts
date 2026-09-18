// API client: typed fetch wrapper for the Aegis /api/v1 surface.
//
// Token architecture (docs/AUTH.md) — the SPA is NOT the auth authority:
//  - The access JWT lives in MODULE MEMORY only. It is never written to
//    localStorage/sessionStorage/IndexedDB, never placed in URLs, never
//    logged. A full page reload deliberately discards it; the session is
//    restored through the HttpOnly refresh cookie (see auth.tsx).
//  - The refresh token is an HttpOnly + SameSite=Lax (+ Secure in
//    production) cookie the browser attaches automatically. JavaScript
//    cannot read it, so this client never touches it.
//  - Every request carries X-Requested-With: XMLHttpRequest. The
//    cookie-authenticated endpoints (refresh/logout) REQUIRE it — a
//    cross-site attacker cannot add a custom header without a passing
//    CORS preflight, which the server's origin allowlist rejects.
//  - 401 handling: single-flight refresh (ONE network refresh no matter
//    how many requests 401 simultaneously), then each request retries
//    ONCE with the renewed token. Refresh results are tri-state so a
//    transient backend outage never logs the user out, while a definitive
//    session loss routes to the login screen exactly once.
const BASE = '/api/v1'

// Upgrade hygiene: pre-cookie builds persisted JWTs in localStorage. Those
// keys are dead weight (and a lingering XSS target) — drop them once.
if (typeof localStorage !== 'undefined') {
  localStorage.removeItem('aegis_access')
  localStorage.removeItem('aegis_refresh')
}

let accessToken = ''
let refreshTimer: ReturnType<typeof setTimeout> | undefined

// onSessionLost is invoked exactly once when the server definitively
// rejects the session (revoked/expired/unknown). The auth provider
// registers it and transitions the UI to unauthenticated.
let sessionLostCallback: (() => void) | undefined
let sessionLostNotified = false

export function onSessionLost(cb: () => void) {
  sessionLostCallback = cb
  sessionLostNotified = false
}

export class ApiError extends Error {
  code: string
  status: number
  constructor(status: number, code: string, message: string) {
    super(message)
    this.code = code
    this.status = status
  }
}

// expSeconds decodes the JWT `exp` claim without verifying the signature —
// signature verification is the server's job; the client uses this only to
// (a) schedule a proactive renewal and (b) know that retrying a failed
// request with the CURRENT token cannot possibly succeed. Authorization is
// always the server's call.
function expSeconds(jwt: string): number | undefined {
  try {
    const payload = JSON.parse(atob(jwt.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')))
    return typeof payload.exp === 'number' ? payload.exp : undefined
  } catch {
    return undefined
  }
}

function isExpired(jwt: string): boolean {
  const exp = expSeconds(jwt)
  return !exp || exp * 1000 - Date.now() < 0
}

export function setAccessToken(token: string) {
  accessToken = token
  sessionLostNotified = false
  scheduleProactiveRefresh()
}

export function getAccessToken(): string {
  return accessToken
}

export function clearAccessToken() {
  accessToken = ''
  if (refreshTimer) clearTimeout(refreshTimer)
  refreshTimer = undefined
}

function notifySessionLost() {
  clearAccessToken()
  if (!sessionLostNotified) {
    sessionLostNotified = true
    sessionLostCallback?.()
  }
}

// ---------------------------------------------------------------------------
// Refresh: single-flight, tri-state.

// Result is a TRI-STATE:
//   'ok'        — renewed; callers may retry the original request
//   'invalid'   — the session is gone (revoked/expired/unknown) → the UI
//                 must become unauthenticated exactly once
//   'transient' — backend unreachable/rate-limited/5xx/network error → keep
//                 everything, back off, let the re-armed timer recover
type RefreshResult = 'ok' | 'invalid' | 'transient'

let refreshInFlight: Promise<RefreshResult> | undefined
let refreshBackoffMs = 0

function bumpBackoff() {
  refreshBackoffMs = Math.min(refreshBackoffMs ? refreshBackoffMs * 2 : 15_000, 60_000)
}

function refreshOnce(): Promise<RefreshResult> {
  if (refreshInFlight) return refreshInFlight
  refreshInFlight = (async (): Promise<RefreshResult> => {
    try {
      // No body, no client-held token: the HttpOnly cookie authenticates
      // this call. X-Requested-With is the server-side CSRF gate.
      const res = await fetch(BASE + '/auth/refresh', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
      })
      // 401/403 = the session itself is gone (revoked/expired/unknown or a
      // CSRF rejection of a cookie-less call). 429/5xx must NOT clear state.
      if (res.status === 401 || res.status === 403) {
        refreshBackoffMs = 0
        return 'invalid'
      }
      if (!res.ok) {
        bumpBackoff() // transient: keep the session, back off
        return 'transient'
      }
      const data = await res.json()
      if (!data?.access_token) {
        return 'invalid'
      }
      refreshBackoffMs = 0
      setAccessToken(data.access_token)
      return 'ok'
    } catch {
      bumpBackoff() // network failure: keep everything, retry later
      return 'transient'
    } finally {
      refreshInFlight = undefined
      // Re-arm the proactive timer after EVERY attempt so a single failure
      // never strands the session without a renewal path.
      scheduleProactiveRefresh()
    }
  })()
  return refreshInFlight
}

// refreshSession is the public single-flight entry point (also used by the
// auth provider to restore a session on page load — the browser sends the
// refresh cookie automatically).
export function refreshSession(): Promise<RefreshResult> {
  return refreshOnce()
}

function scheduleProactiveRefresh() {
  if (refreshTimer) clearTimeout(refreshTimer)
  if (!accessToken) return
  const exp = expSeconds(accessToken)
  if (!exp) return
  // Renew at ~90s before expiry as a convenience path; the REACTIVE path
  // (401 → refresh → retry) remains the authoritative mechanism, and the
  // server remains the only judge of validity.
  const inMs = exp * 1000 - Date.now() - 90_000
  // Never spin: a failed attempt backs off instead of re-arming instantly,
  // and the floor keeps a dead session from hammering the server.
  const delay = Math.max(inMs, refreshBackoffMs, 15_000)
  refreshTimer = setTimeout(proactiveRefresh, delay)
}

function proactiveRefresh() {
  if (!accessToken) return
  if (refreshInFlight) return
  void refreshOnce().then((r) => {
    if (r === 'invalid') notifySessionLost()
  })
}

// Renew also when the tab regains focus or becomes visible after sleep:
// timers stall in background tabs, so the token may already be expired when
// the user comes back. A 60s interval is the last-resort safety net that
// catches cases no event reaches (clock drift, missed focus). All three
// paths share the single-flight refresh, so at most one request is in air.
if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const expiringSoon = (windowMs: number) => {
    const exp = expSeconds(accessToken)
    return !!accessToken && !!exp && exp * 1000 - Date.now() < windowMs
  }
  window.setInterval(() => {
    if (expiringSoon(180_000)) proactiveRefresh()
  }, 60_000)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible' && expiringSoon(180_000)) proactiveRefresh()
  })
  window.addEventListener('focus', () => {
    if (expiringSoon(120_000)) proactiveRefresh()
  })
}

async function raw(path: string, init: RequestInit): Promise<Response> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest',
  }
  if (accessToken) headers['Authorization'] = `Bearer ${accessToken}`
  // credentials:'include' sends the refresh cookie on same-origin calls and
  // keeps the flow working if the API is deployed on a sibling origin.
  return fetch(BASE + path, { ...init, credentials: 'include', headers })
}

async function request<T>(path: string, init: RequestInit = {}, retry = true): Promise<T> {
  const res = await raw(path, init)
  // 401: the access token is expired/invalid — the one signal that should
  // trigger a (single-flight) refresh and exactly ONE retry of the original
  // request. 403 only triggers a refresh when the access token on hand is
  // already expired: that combination means a middlebox mangled the
  // auth failure mode (field-reported "403 with expired token"), and
  // refreshing is the only sensible recovery. Fresh-token 403s are REAL
  // permission failures and must surface as errors, never logout.
  const authRetryable =
    res.status === 401 || (res.status === 403 && isExpired(accessToken))
  if (authRetryable && retry) {
    const r = await refreshOnce()
    if (r === 'ok' && accessToken) return request<T>(path, init, false)
    if (r === 'invalid') {
      notifySessionLost()
      throw new ApiError(401, 'unauthorized', 'session expired')
    }
    // Transient refresh failure: the token on hand did not change, so
    // retrying now would just fail again. The proactive timer (re-armed in
    // refreshOnce's finally) keeps retrying in the background and the
    // interval/focus/visibility safety nets cover timer-starved tabs; this
    // request surfaces a recoverable error to its page.
    throw new ApiError(401, 'session_expired', 'Session is being renewed — the panel will refresh automatically.')
  }
  if (!res.ok) {
    let code = 'error'
    let message = `Request failed (HTTP ${res.status})`
    try {
      const body = await res.json()
      if (body?.error) {
        code = body.error.code ?? code
        message = body.error.message ?? message
      }
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, code, message)
  }
  if (res.status === 204) return undefined as T
  return res.json()
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(body) }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
  // login is deliberately NOT the generic request(): a 401 from bad
  // credentials must surface as "invalid credentials", never trigger the
  // refresh/retry machinery. The server sets the refresh cookie on success;
  // the access token (and nothing else secret) comes back in the body.
  login: async (email: string, password: string): Promise<{ access_token: string; expires_in: number; user: { id: string; email: string; name: string } }> => {
    const res = await raw('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    })
    if (!res.ok) {
      let code = 'error'
      let message = `Login failed (HTTP ${res.status})`
      try {
        const body = await res.json()
        if (body?.error) {
          code = body.error.code ?? code
          message = body.error.message ?? message
        }
      } catch {
        /* non-JSON error body */
      }
      throw new ApiError(res.status, code, message)
    }
    return res.json()
  },
  // logout asks the server to revoke the session family and clear the
  // refresh cookie, then wipes the in-memory access token. Best-effort on
  // network errors: local state is cleared regardless, so the user is never
  // trapped by a failing backend.
  logout: async (): Promise<void> => {
    try {
      await raw('/auth/logout', { method: 'POST' })
    } catch {
      /* server unreachable — still drop local state */
    }
    clearAccessToken()
  },
  // download fetches a binary artifact WITH the Authorization header and
  // saves it via a same-origin blob URL. A plain <a href> to an API route
  // can never authenticate (browsers strip custom headers on navigation),
  // which is exactly why the reports Download link produced a useless tab.
  download: async (path: string, fallbackName: string): Promise<void> => {
    let res = await raw(path, {})
    if (res.status === 401) {
      const r = await refreshOnce()
      if (r === 'ok') res = await raw(path, {})
      else if (r === 'invalid') {
        notifySessionLost()
        throw new ApiError(401, 'unauthorized', 'session expired')
      }
    }
    if (!res.ok) {
      let message = `Download failed (HTTP ${res.status})`
      try {
        const body = await res.json()
        if (body?.error?.message) message = body.error.message
      } catch {
        /* non-JSON error body */
      }
      throw new ApiError(res.status, 'download_failed', message)
    }
    const blob = await res.blob()
    const cd = res.headers.get('Content-Disposition') ?? ''
    const m = /filename\*?=(?:"([^"]+)"|([^;\s]+))/i.exec(cd)
    const name = (m && (m[1] || m[2])) || fallbackName
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = name
    document.body.appendChild(a)
    a.click()
    a.remove()
    setTimeout(() => URL.revokeObjectURL(url), 30_000)
  },
}
