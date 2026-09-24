# Detection engine

## Rule types

| Type | Semantics | Example |
|---|---|---|
| `single_event` | condition matches one event | critical/high IDS alert |
| `threshold` | N events (or N distinct X) in window | 40 distinct dst ports in 60s = port scan |
| `temporal` | ordered condition sequence in window | alert then new outbound TLS |
| `entity_agg` | entity contacted N distinct values | 30 distinct peers on SMB in 5m = lateral movement |

Conditions are typed field/operator/value matchers (`eq neq in gt gte lt lte contains regex exists`) over the normalized event envelope — including `payload_metadata` paths.

## Deduplication

One match per `(rule, entity, window)` via Redis `SETNX` windows: 100 identical alerts in 30 seconds become **one incident with count=100**, not 100 notifications.

## Sigma compatibility

Rules carry Sigma-style metadata (`title`, `id`, `status`, `author`, `references`, `tags`, `logsource`, `level`, `false_positives`) and the correlation concepts `value_count` / `temporal`. The internal AST is the source of truth; full Sigma import is a documented future step.

## Baselines & anomalies

Simple per-entity statistical baselines (mean/σ, sample-bounded) flag *rare behavior* — new peer, new port, volume spikes. An anomaly is always labeled an anomaly; the UI never presents it as confirmed malicious activity (terminology).

## Built-in catalog

`port-scan threshold`, `smb lateral movement`, `abnormal DNS volume`, `critical IDS alert`, `beacon-like cadence (experimental, disabled by default)` — all typed, explainable and disable-able.
