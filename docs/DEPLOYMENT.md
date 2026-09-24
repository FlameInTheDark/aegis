# Deployment

## Profiles

| Profile | Shape | Use |
|---|---|---|
| LOCAL | single machine, full compose stack | home lab, evaluation |
| SMALL | compose + remote scanners/sensors per site | small office, branch |
| ENTERPRISE | Kubernetes, replicated workers, HA data layer | multi-site, distributed |

## Docker Compose

```bash
docker compose -f deploy/compose/docker-compose.yml up -d
```

- health-checked dependencies with `depends_on: service_healthy`,
- persistent volumes for postgres/clickhouse/nats/rustfs,
- migrations + bootstrap run by `server` on boot,
- optional `--profile monitoring` (Prometheus at :9092) and `--profile sensors`.

The scanner container runs with `cap_add: NET_RAW` only; use `network_mode: host` (Linux) when scanning the host LAN.

## Kubernetes

Manifests under `deploy/kubernetes/`: namespace, config/secret templates, deployments with non-root securityContext, readiness/liveness on `/healthz` `/readyz`, HPA for workers, ingress with TLS annotations, and documented guidance for the scanner's `NET_RAW`/`hostNetwork` isolation (: minimum capabilities, never privileged by default).

## Helm

`deploy/helm/aegis/` wraps the same workloads with values for replicas, resources and ingress (`helm install aegis deploy/helm/aegis`).

## Configuration

Environment-first (`AEGIS_*`), documented in `.env.example` and `configs/*.yaml`. Never hardcode secrets; compose defaults are demo-only and must be overridden in production.

## TLS

Terminate TLS at the ingress/LB for HTTP and gRPC (agent transport); the agent client enables TLS automatically for `https://` server URLs. Production requires valid certificates; plaintext is a development-only, warned path.
