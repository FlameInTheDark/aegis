# Kubernetes deployment (spec §88)

Plain manifests live beside this README (`kubectl apply -f deploy/kubernetes/`).
They cover the application workloads; the data layer (PostgreSQL, Redis, NATS,
ClickHouse, RustFS) is expected from your environment — cloud-managed services
or operators (e.g. CloudNativePG, Strimzi-style operators, RustFS).

| File | Contents |
|---|---|
| `10-namespace.yaml` | `aegis` namespace |
| `11-configmap.yaml` | non-secret configuration |
| `12-secret.yaml` | template — replace with sealed-secrets/external-secrets |
| `30-server.yaml` | control plane + service (readiness/liveness, non-root) |
| `31-worker.yaml` | workers + HPA |
| `32-feed-worker.yaml` | feed synchronization |
| `33-scanner.yaml` | scanner with `NET_RAW` only; `hostNetwork` documented |
| `34-frontend.yaml` | SPA + ingress |

## Scanner capabilities policy

Scanners require raw packets for SYN/OS scans. Policy: `allowPrivilegeEscalation: false`, `capabilities: { drop: [ALL], add: [NET_RAW] }`, no `privileged`, `hostNetwork` only with node isolation for site-adjacent scanning.
