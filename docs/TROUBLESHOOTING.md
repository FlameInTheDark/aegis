# Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Login fails on fresh install | bootstrap env unset | set `AEGIS_BOOTSTRAP_ADMIN_EMAIL/PASSWORD`, restart server |
| Scanner exits with `AEGIS_SCANNER_SITE_ID is required` | no site exists yet (bootstrap never ran) | start the server once (it bootstraps org+site), then start the scanner; or pin `AEGIS_SCANNER_SITE_ID` |
| `readyz` shows postgres not_ready | DB unreachable/migrating | check `AEGIS_DATABASE_URL`, server logs show migration state |
| Scans stay `queued` | no scanner registered for the site | deploy scanner with `AEGIS_SCANNER_SITE_ID` matching the site |
| Scanner finds nothing | container network isolation | use `network_mode: host` (Linux) or run scanner on-site |
| nmap engine skipped | binary missing in image | use `deploy/docker/Dockerfile.scanner` (installs nmap) |
| No vulnerabilities shown | feeds not synced yet | check Settings → Feeds status; feed-worker logs; wait for first sync |
| Events page empty | ClickHouse down or no sensors | verify `AEGIS_CLICKHOUSE_URL`, attach sensor/agent telemetry |
| Feed `failed` status | upstream outage | per-feed isolation; it retries with backoff automatically |
| Agent shows `offline` | missed heartbeats > 3 min | check agent→server gRPC reachability (default :9090) |
| Endpoint collects nothing / `inventory rejected: agent ... not found` in the connector log | bound device not linked to an asset, or the agent function toggle changed while the loop runs | verify `agent.enabled` in the connection settings, check the server log for `device metrics`/`inventory` errors, restart the connector process to re-bind |
| Asset has no Performance tab / metrics empty | the asset has no bound endpoint yet, or the ClickHouse tier is off | connect a connector with the agent function, wait for the first sample (~1 min); verify `AEGIS_CLICKHOUSE_URL` — without it samples are dropped and noted once in the connector log |
| "No passive visibility for VLAN X" (expected) | sensor placement | deploy gateway/SPAN sensor for that VLAN |
| Report stuck `queued` | worker not running | ensure `worker` service is up; jobs execute on its 30s loop |
| 429 responses | rate limits engaged | expected for auth/ingest bursts; back off |
| ClickHouse `code: 516 Authentication failed` | image locks its `default` user to container-internal 127.0.0.1 when no `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD` is set | set `CLICKHOUSE_USER`/`CLICKHOUSE_PASSWORD` on the clickhouse service and credentials in `AEGIS_CLICKHOUSE_URL` (compose does this); the generic 516 is also returned for network-restricted users |
| ClickHouse schema `Syntax error` on boot | script split inside a trailing `--` comment containing `;`, or numeric→UUID default (`toUUID(0)` unsupported ≥ 24.x) | use a comment/quote-aware splitter (internal/repository/clickhouse) and `DEFAULT toUUID('00000000-0000-0000-0000-000000000000')` |
| `agent CA unavailable — gRPC enroll disabled` | `AEGIS_AGENT_CA_CERT/KEY` unset | dev auto-generates `certs/agent-ca.{crt,key}` (defaults); production mounts the real pair and sets both vars |
| Connections page blank / app crashes on a page | a render error in that page | the page shows an error card with a "Try again" button; check browser console for `Page crashed:` and report the message |

## Diagnostics

```bash
curl -s localhost:8080/healthz | jq
curl -s localhost:8080/readyz | jq
docker compose -f deploy/compose/docker-compose.yml logs server | jq 'select(.level=="ERROR")'
```

Logs are structured JSON; every HTTP response carries `X-Request-Id` for correlation.
