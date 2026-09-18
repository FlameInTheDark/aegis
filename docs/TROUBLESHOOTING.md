# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Login fails on fresh install | bootstrap env unset | set `AEGIS_BOOTSTRAP_ADMIN_EMAIL/PASSWORD`, restart server |
| Login returns 500 `session persistence failed` | version < 1.0.6: session id was derived from refresh-token bytes (invalid for the UUID `sessions.id` column, SQLSTATE 22P02) | upgrade; ≥ 1.0.6 stores the JWT `sid` (a real UUID) — sessions rotate correctly on refresh |
| `auth.login` audit rows missing / `audit write failed ... invalid input syntax for type uuid` in logs | version < 1.0.6 wrote `""` into nullable UUID audit columns on pre-auth events | upgrade to ≥ 1.0.6 (audit insert normalizes empty UUIDs to NULL/nil-UUID) |
| Scanner exits with `invalid input syntax for type uuid: "scanner-..."` | version < 1.0.6 used the scanner *name* as the UUID primary key | upgrade; ≥ 1.0.6 generates a UUID id and keeps the name separate |
| Scanner exits with `AEGIS_SCANNER_SITE_ID is required` | no site exists yet (bootstrap never ran) | start the server once (it bootstraps org+site), then start the scanner; or pin `AEGIS_SCANNER_SITE_ID` |
| `readyz` shows postgres not_ready | DB unreachable/migrating | check `AEGIS_DATABASE_URL`, server logs show migration state |
| Scans stay `queued` | no scanner registered for the site | deploy scanner with `AEGIS_SCANNER_SITE_ID` matching the site |
| Scanner finds nothing | container network isolation | use `network_mode: host` (Linux) or run scanner on-site |
| nmap engine skipped | binary missing in image | use `deploy/docker/Dockerfile.scanner` (installs nmap) |
| No vulnerabilities shown | feeds not synced yet | check Settings → Feeds status; feed-worker logs; wait for first sync |
| Events page empty | ClickHouse down or no sensors | verify `AEGIS_CLICKHOUSE_URL`, attach sensor/agent telemetry |
| Feed `failed` status | upstream outage | per-feed isolation; it retries with backoff automatically |
| Agent shows `offline` | missed heartbeats > 3 min | check agent→server gRPC reachability (default :9090) |
| "No passive visibility for VLAN X" (expected) | sensor placement | deploy gateway/SPAN sensor for that VLAN (§90) |
| Report stuck `queued` | worker not running | ensure `worker` service is up; jobs execute on its 30s loop |
| 429 responses | rate limits engaged (§120) | expected for auth/ingest bursts; back off |
| ClickHouse `code: 516 Authentication failed` | image locks its `default` user to container-internal 127.0.0.1 when no `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD` is set | set `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD` on the clickhouse service and credentials in `AEGIS_CLICKHOUSE_URL` (compose does this); the generic 516 is also returned for network-restricted users |
| ClickHouse schema `Syntax error` on boot | script split inside a trailing `--` comment containing `;`, or numeric→UUID default (`toUUID(0)` unsupported ≥ 24.x) | use a comment/quote-aware splitter (internal/repository/clickhouse) and `DEFAULT toUUID('00000000-0000-0000-0000-000000000000')` |
| `agent CA unavailable — gRPC enroll disabled` | `AEGIS_AGENT_CA_CERT/KEY` unset | dev auto-generates `certs/agent-ca.{crt,key}` (defaults); production mounts the real pair and sets both vars |

## Diagnostics

```bash
curl -s localhost:8080/healthz | jq
curl -s localhost:8080/readyz | jq
docker compose -f deploy/compose/docker-compose.yml logs server | jq 'select(.level=="ERROR")'
```

Logs are structured JSON; every HTTP response carries `X-Request-Id` for correlation.
