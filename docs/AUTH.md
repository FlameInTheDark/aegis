# Authentication Architecture

Production-grade JWT authentication for the React SPA + API backend.
This document specifies the token model, endpoints and session flow.

## 1. Token model

| Token | Form | Lifetime | Transport | Storage |
|---|---|---|---|---|
| Access token | JWT (HS256, `org`/`role`/`perms`/`sid` claims) | short (default 1h, `AEGIS_ACCESS_TOKEN_TTL`) | `Authorization: Bearer` header | **React module memory only** |
| Refresh token | opaque 256-bit URL-safe string (`aeg_rt_…`) | long (default 30d, `AEGIS_REFRESH_TOKEN_TTL`) | `HttpOnly` + `SameSite=Lax` (+`Secure`, `__Host-`-prefixed in HTTPS deployments) cookie `aegis_rt` / `__Host-aegis_rt` | server-side **SHA-256 hash** in `sessions.refresh_hash` + retired-hash ledger |

Hard rules enforced by the code and verified by tests:

- The refresh token **never** appears in a JSON response, in JavaScript,
 in logs, in URLs, or in any browser storage.
- The access JWT is **never** written to localStorage/sessionStorage/
 IndexedDB. (The api client deletes stale `aegis_access` /
 `aegis_refresh` localStorage keys on boot.)
- The server re-derives role and organization from the **database** on
 every refresh — a role downgrade or a disabled account takes effect at
 the next refresh, not after the access TTL. Client-side claims are
 presentation only; every API call is re-validated server-side.

## 2. Endpoints

| Endpoint | Auth | Notes |
|---|---|---|
| `POST /auth/login` | credentials | Verifies argon2id hash, creates the session row, sets the refresh cookie, returns `{access_token, expires_in, user}`. Rate-limited 20/min. |
| `POST /auth/refresh` | **cookie** + `X-Requested-With` | Rotates the refresh token, returns a fresh access JWT. Rate-limited 120/min. Also serves as the session-restore endpoint on page load. |
| `POST /auth/logout` | **cookie** + `X-Requested-With` | Revokes the session family, clears the cookie. Idempotent. |
| `GET /auth/me` | Bearer | Profile + org memberships. |
| all other `/api/v1` | Bearer | Access-token middleware; 401 on invalid/expired. |

## 3. Rotation, grace window, reuse detection

Every successful refresh rotates the refresh token:

- `sessions.refresh_hash` — hash of the currently valid token.
- `sessions.retired` (JSONB) — ledger of retired hashes → retirement time
 (kept for 1h, capped at 200 entries).

Rules when a refresh arrives:

1. Token hash matches `refresh_hash` → **rotate**: retire the presented
 hash, install a fresh token, set the new cookie, issue a new access JWT.
2. Token hash matches a **retired** entry **within the grace window**
 (`AEGIS_REFRESH_ROTATION_GRACE`, default 30s) → concurrent-refresh race
 (multi-tab, 401 retry waves): rotate forward as well. The rotation
 UPDATE retires the row's *current* hash atomically at write time (row
 locks serialize rotations), so whatever token landed last in the
 browser's shared cookie jar is always acceptable — no interleave
 strands a tab.
3. Token hash matches a retired entry **beyond the grace window** →
 **reuse of a possibly-stolen token**: the whole session family is
 revoked (reuse detection), the event is audited, and the caller gets 401.
4. No match → 401 `session expired or revoked`.

## 4. CSRF

The refresh token is a cookie, so `POST /auth/refresh` and
`POST /auth/logout` are cookie-authenticated state-changing endpoints.
Two independent defenses:

1. **SameSite=Lax** — browsers do not attach the cookie to cross-site
 POST requests.
2. **Custom-header requirement** (`X-Requested-With: XMLHttpRequest`) — a
 cross-site attacker cannot add custom headers without a CORS preflight,
 and the server's CORS allowlist only accepts the deployed origin
 (`AEGIS_PUBLIC_URL`). Missing header → 403.

Everything else (`/api/v1/*`) is Bearer-header authenticated and therefore
CSRF-irrelevant. The deployment model is same-origin (the frontend nginx
proxies `/api/` to the server); cross-origin API deployments must set
`AEGIS_PUBLIC_URL` to the exact SPA origin (cookies then need
`SameSite=None` — not required for any current deployment shape and not
implemented; keep the API same-origin).

## 5. XSS posture

Assume any XSS can read everything JavaScript can:

- Access token: memory only — gone on reload, invisible to storage dumps.
- Refresh token: HttpOnly — unreadable to JavaScript by construction.
- No tokens in URLs, logs, telemetry, error reports, or persistent state.
- The SPA renders through React's default escaping; no
 `dangerouslySetInnerHTML` is used anywhere in the codebase.
- Short access TTL bounds the value of a stolen in-memory token;
 refresh-token theft is contained by rotation + reuse detection.

## 6. SPA session lifecycle (`web/src/lib/auth.tsx`, `web/src/lib/api.ts`)

One centralized state machine (`AuthProvider` / `useAuth`):

```
initializing ──restore ok──▶ authenticated ──logout / session lost──▶ unauthenticated
     └──restore failed────────▶ unauthenticated
```

- **Startup restore**: on mount the provider calls `POST /auth/refresh`
 (the browser attaches the cookie). `ok` → fetch `/auth/me`, store the
 access JWT in memory, become `authenticated`. Definitive rejection →
 `unauthenticated`. Transient failure (network/5xx) is retried
 (3 attempts, backoff) and never treated as a logout; only after the
 retries the login screen is shown. Route guards render a splash while
 `initializing` — no flash of the login screen before an existing
 session is restored.
- **API client**: all calls go through one client; the access token is
 attached centrally; 401 triggers a **single-flight** refresh (any
 number of simultaneous 401s share one network refresh) and each request
 retries **exactly once**. A 403 on an *expired* access token also
 attempts one refresh+retry (covers middleboxes that mangle the failure
 mode); a 403 on a fresh
 token is a real permission error and never logs out.
- **Refresh tri-state**: `ok` / `invalid` / `transient`. Only a
 definitive rejection moves the UI to unauthenticated (exactly once);
 transient failures keep the session, back off exponentially (15→60s),
 and recover through the re-armed proactive timer (renewal ~90s before
 expiry) plus focus/visibility/interval safety nets. The reactive 401
 path remains the authority; the server remains the only validator.
- **Logout**: `POST /auth/logout` (server revokes the family + clears the
 cookie) → memory token cleared → query cache purged → BroadcastChannel
 tells other tabs → navigation happens after state is actually cleared.
- **Cross-tab**: a BroadcastChannel (`aegis-auth`, event names only — no
 credentials) propagates logout (other tabs drop to unauthenticated
 immediately) and login (other tabs restore through the shared cookie).
 Multi-tab refresh races are safe by design (rotation grace).

## 7. Verification

- `scripts/repro-auth.sh` (34 checks): cookie flags, no-secret-in-body,
 expiry→401, CSRF guards, rotation, grace race, reuse beyond grace →
 family revoked, garbage cookie, logout revocation + cookie clear,
 30-way concurrent refresh storm (zero 5xx/logouts), server-side sorting,
 streamed report download.
- `internal/repository/postgres/integration_session_rotation_test.go`:
 repo-level rotation lifecycle against real PostgreSQL.
- `internal/auth`: opaque token properties, access-JWT session binding,
 expired-token rejection.
- `scripts/e2e-features.sh`: concurrent refresh race with two cookie
 jars, both renewed tokens authenticate, no refresh_token in any body.
