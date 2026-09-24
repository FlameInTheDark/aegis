# Security model

## Authentication

- Argon2id password hashing (never plaintext, minimum 12 chars).
- JWT access tokens (short TTL) + refresh tokens with server-side session revocation (`sessions` table, hashed refresh material).
- Endpoint agents use device certificates issued at enrollment (mTLS-ready); certificates are individually identifiable and revocable.

## Authorization — RBAC

| Role | Highlights |
|---|---|
| `owner` | everything incl. org management |
| `administrator` | sites, scanners, users, settings |
| `security_analyst` | findings triage, detections, elevated scans (with `scan:elevated`) |
| `operator` | scans, assets write, agents |
| `viewer` | read-only |

Permissions are resource-aware strings (`scan:create`, `scan:elevated`, `finding:write`, …) checked in middleware and services — never only in the UI.

## Tenant isolation

Every org-owned row carries tenant identity; repositories filter by `organization_id` at the query layer; API handlers resolve the tenant from the token. Cross-tenant access is impossible without a valid membership.

## Input & injection defense

- SQL: parameterized queries only (pgx + squirrel); no ORM, no string-built SQL.
- Commands: typed argument arrays, validated targets, no shell.
- SSRF: hostname validation, metadata/localhost/link-local screening in scope validation.
- Output: banners/titles treated as attacker-controlled; HTML escaping in reports; CSV formula-injection neutralization; browser rendering never uses raw HTML.

## Redaction, limits, audit

- Secret-shaped banner values redacted before storage.
- Request body caps (10 MiB), event payload caps (256 KiB stream / 8 MiB API), oversized records dropped and logged.
- Rate limits on auth, ingest, expensive endpoints; never on read-only table navigation.
- Audit log: logins, token revocations, scans (incl. elevated with reason), scope changes, agent enrollment/tasks, finding status changes, report generation — who, what, when, from where, result.

## Deployment hardening

Non-root containers (uid 10001), capability `NET_RAW` only on scanner, secure headers + HSTS in production, TLS termination documented for every ingress path, secure-random JWT secret requirement, audit + metrics enabled by default.
