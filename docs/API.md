# HTTP API (spec §6)

Base: `/api/v1` · Bearer JWT · JSON · structured errors `{error:{code,message,request_id}}` · offset pagination `{items,total,page,limit}`; cursor pagination for events.

## Endpoint map

| Group | Endpoints |
|---|---|
| auth | `POST /auth/login` `POST /auth/refresh` `POST /auth/logout` `GET /auth/me` |
| tenancy | `GET|POST /organizations` `GET|POST /sites` `GET|PATCH|DELETE /sites/{id}` `GET|POST /sites/{id}/networks` |
| assets | `GET /assets` `GET|PATCH /assets/{id}` `GET /assets/{id}/{services,software,findings,interfaces}` `GET /services` |
| topology | `GET /topology` `GET /topology/evidence/{edge}` |
| scans | `GET|POST /scans` `GET /scans/{id}` `POST /scans/{id}/cancel` `GET /scans/{id}/{changes,tasks}` `GET /scanners` `GET|POST /schedules` |
| vulnerabilities | `GET /vulnerabilities` `GET /vulnerabilities/{cve_id}` `GET|POST /findings` `GET|PATCH /findings/{id}` `POST /findings/bulk` `POST /findings/{id}/suppress` `GET /feeds` |
| detections | `GET|POST /detections/rules` `PATCH /detections/rules/{id}` `GET /detections/matches` |
| events | `GET /events` (cursor) `POST /events/ingest` `POST /sensors/{id}/events` |
| agents | `GET /agents` `GET /agents/{id}` `POST /agents/{id}/tasks` `GET|POST /agents/enrollment-tokens` |
| reports | `GET|POST /reports` `GET /reports/jobs/{id}` `GET /reports/jobs/{id}/download` |
| platform | `GET /search` `GET /metrics/{summary,timeseries}` `GET /audit-log` `GET|POST /webhooks` |
| health (unauthenticated) | `GET /healthz` `GET /readyz` |

## Examples

```bash
# login
curl -s localhost:8080/api/v1/auth/login -d '{"email":"admin@aegis.local","password":"aegis-demo-admin-2026"}'

# create a conservative discovery scan
curl -s localhost:8080/api/v1/scans -H "Authorization: Bearer $TOKEN" \
  -d '{"site_id":"<site>","name":"nightly","profile":"inventory","targets":["192.168.1.0/24"],"denylist":["192.168.1.1"]}'

# poll progress (§116: scope → discovery → ports → services → correlation → completed)
curl -s localhost:8080/api/v1/scans/<id> -H "Authorization: Bearer $TOKEN"

# ingest a Suricata EVE record
curl -s localhost:8080/api/v1/events/ingest -H "Authorization: Bearer $TOKEN" \
  -d '{"source":"suricata","raw":{"timestamp":"2026-09-15T10:00:00Z","event_type":"alert","alert":{"signature_id":2027865,"severity":2},"src_ip":"10.0.0.9","dest_ip":"10.0.0.5","dest_port":445}}'
```

Rate limits (§120): auth 20/min/IP, events+ingest 120/min; scan/report creation permission-gated. Swagger/OpenAPI annotations live on every handler; generated docs served at `/swagger/index.html` when built (`make swagger`).
