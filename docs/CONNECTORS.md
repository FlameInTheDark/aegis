# External Connections

Every externally connected component of Aegis — **endpoint agents**,
**remote scanners**, **external collectors**, and future kinds — uses one
connection protocol and one management surface. All kinds share identical
enrollment, credential, configuration and liveness mechanics; only the
role logic running on top of the distributed configuration differs.

```
┌──────────┐   1. create in UI          ┌──────────────┐
│ Operator │ ─────────────────────────► │    Aegis     │
└──────────┘ ◄── 2. connect command ─── │    server    │
                                         │  (gRPC :9090)│
┌──────────┐   3. --connect host:port/TOKEN
│ Component│ ─────────────────────────► │              │
│ (agent / │   4. token valid: mark connected, BURN token,
│ scanner/ │      issue long-lived secret                │
│collector)│ ◄── 5. allow message: secret + endpoint info + config
│          │      (invalid/expired/replayed token → error, terminate)
│  6. save │
│  config  │   7. --request_configuration →  current_agent_configuration
│  file    │ ◄──────────────────────────
│          │   8. work: heartbeat + WatchConfig (hot reload)
└──────────┘
```

## 1. The protocol (gRPC service `aegis.connector.v1`)

Implemented by the server on the standard gRPC listener (`AEGIS_GRPC_ADDR`,
default `:9090`); proto source `api/proto/aegis/connector/v1/connector.proto`,
generated code under `api/gen/aegis/connector/v1/`.

| RPC | Auth | Purpose |
|-----|------|---------|
| `Enroll` | one-time token | First contact. Burns the token atomically, flips the record `pending → active`, issues the long-lived secret, returns endpoint info + initial config. |
| `GetConfig` | connector secret | Full configuration reload; the component calls it on **every** (re)connection. |
| `WatchConfig` | connector secret | Server-stream: one snapshot, then a push per configuration change (hot reload, no restart). |
| `Heartbeat` | connector secret | Liveness + role status upload. Response carries the server's current `config_version` so the component recovers if it ever missed a watch update. |
| `GetSelf` | connector secret | The component's own record — powers `aegis-connector status`. |

Continued-run authentication rides as per-call metadata:

```
x-aegis-connector-id:     <connector_id>
x-aegis-connector-secret: <secret from the allow message>
```

- Enrollment tokens and connector secrets are stored **hashed** (SHA-256
 hex); raw material is never persisted server-side and the token/secret
 are shown once (token) / stored client-side only (secret).
- Tokens are **single-use**: the burn is a claim-first atomic
 `UPDATE ... WHERE used_at IS NULL`, so concurrent replays of the same
 token cannot enroll twice.
- Revoked records reject all continued connections immediately.
- TLS: terminate at your LB/ingress for production (`tls://` prefix on the
 connect target makes the CLI use TLS); plaintext is for development.

## 2. The CLI (`aegis-connector`, binary source `cmd/connector`)

Built with `urfave/cli/v3`. One binary for all kinds; which FUNCTIONS run
(endpoint collection and/or remote scanning) follows the connection
settings toggles, with local CLI overrides on top.

```
aegis-connector --connect host:port/TOKEN [--kind agent] [--install]
                [--config PATH] [--no-start] [--agent|--scanner]
                                                 # root: the UI connect string
aegis-connector connect --server host:port --token TOKEN   # same, explicit
aegis-connector start   [--config PATH] [--agent|--scanner]
                                                 # continuous run (systemd ExecStart)
aegis-connector reconnect --connect host:port/NEWTOKEN [--agent|--scanner]
aegis-connector status  [--config PATH]          # backend-visible state (JSON)
aegis-connector install [--config PATH]          # systemd unit (enable + start)
aegis-connector uninstall
aegis-connector reset   [--config PATH]          # remove the credential file
aegis-connector --version
```

Behavior:

- `--connect` accepts `host:port/token` or `tls://host:port/token`; a bare
 host gets the default port (`:9090`, `:443` for TLS).
- By default the functions the process performs follow the connection
 settings on the hub (`agent.enabled` / `scanner.enabled`, defaulting to
 the connection's kind). `--agent` or `--scanner` run exactly ONE
 function regardless of the toggles — useful for one-off runs and service
 units; the two flags are mutually exclusive.
- On successful enrollment the credential file is saved atomically with
 mode `0600` (dir `0700`): path resolution is `--config` flag >
 `AEGIS_CONNECTOR_CONFIG` env > `/etc/aegis-connector/config.json` (root)
 > `~/.aegis-connector/config.json`.
- `connect`/root action then **starts work** (config reload → watch →
 heartbeat → role loop). `--no-start` saves and exits; `--install` also
 installs and starts the systemd service.
- `start` reconnects with exponential backoff (1s→30s). Terminal
 `Unauthenticated/PermissionDenied/NotFound` failures (revocation,
 rotated secret) abort with instructions to use `reconnect` — the loop
 never spins against dead credentials.
- `reconnect` re-enrolls with a **new** one-time token (from the UI
 Reconnect action) against possibly-new endpoint, replaces the saved
 credentials, preserves connector identity/config, and continues work.

## 3. The UI (Connections page, `/connections`)

- **Create** — pick kind (agent/scanner/collector), name, site. For
 `scanner` connections the site is required: the enrolled scanner becomes
 the site's scan executor. The dialog renders the one-time connect
 command with a copy button; the token is displayed exactly once.
- **Status** — pending / online / shutting down / offline / revoked.
 Liveness is heartbeat-derived (`conn_state`): a fresh heartbeat means
 online, a graceful stop (`state=shutting_down`, sent by the component on
 SIGTERM) shows "shutting down" until the freshness window passes, and a
 stale heartbeat shows offline. The window is two heartbeat intervals
 (30s floor) derived from the connector's configured `heartbeat_secs`, so
 a dead component reads offline within seconds. Scanner connections also
 cascade this liveness onto their linked scanners row, and hub Jobs
 streams mark legacy hub agents offline the moment the stream drops.
- **Configure** — what this connector can do, then how. Agent- and
 scanner-kind connections get two function toggles: **Endpoint
 collection** (`agent.enabled`) and **Remote scanning**
 (`scanner.enabled`) — enabling scanning on an agent connection (or vice
 versa) turns it into a hybrid that runs both functions side by side in
 one process; toggling a function off stops its loop live, without a
 restart (toggling it back on restarts the loop on the next config
 push). Every connection gets the heartbeat interval; each enabled
 function gets its own settings SECTION: agent — collection level
 (`basic`/`standard`/`full`); scanner — the scan engine
 (auto/nmap/simulated), the nmap executable path and the SSH inventory
 collector defaults (user, password or key path, timeout, host-key
 policy) — these act as the fallback when a scan does not carry its own
 host list. Host keys are verified by default: pin a key with
 `scanner.ssh_pinned_key` (authorized_keys format, applied to every host
 without a per-scan `pinned_key`), or opt into insecure mode per
 connection (`scanner.ssh_insecure`) / per scan (`ssh_insecure_host_key`
 — lab use only). SSH credentials are tried in order — private key first
 (if set), then the password (plain and keyboard-interactive); the key
 path must point at an unencrypted private key file, and an unusable key
 falls back to password auth with a warning in the scan log. Saving
 bumps `config_version` and pushes to every live watch stream (hot
 reload). Scanner-row plumbing follows the toggle automatically:
 enabling scanning materializes the linked scanners row (scan dispatch
 eligibility), disabling marks it offline until re-enabled.
- **Edit** — rename and re-site; for scanner connections the site decides
 where the connected scanner is offered in the scan dialog, so older
 site-less connections can be fixed here.
- **Reconnect** — rotates the enrollment token and renders the new
 connect command (address change, lost secret, re-onboarding). On a
 revoked record it also re-arms the record and drops the old secret.
- **Revoke / Delete** — immediate credential invalidation / record removal.

API (all under `/api/v1`, `agent:manage` permission):

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/connectors?kind=` | list (with derived `online`, plus the bound `device` per connection) |
| POST | `/connectors` | create + first connect command |
| GET | `/connectors/:id` | detail (includes the bound `device`) |
| PATCH | `/connectors/:id` | rename / re-site |
| PUT | `/connectors/:id/config` | config push (hot reload) |
| POST | `/connectors/:id/enroll-token` | reconnect: new token + command |
| POST | `/connectors/:id/revoke` | invalidate credentials |
| DELETE | `/connectors/:id` | delete record (revokes the bound device) |

## 4. Role logic (the "different logic" per kind)

Roles live in `internal/connectorapp` behind one interface:

```go
type Role interface {
    Kind() string
    Capabilities() []string
    ApplyConfig(ctx, settings) error   // hot reload path
    Run(ctx, log) error                // per-kind work loop
    Status() map[string]any            // heartbeat status payload
}
```

Agent- and scanner-kind connections run a **hybrid
container** (`HybridRole`): it keeps one loop per ENABLED function alive,
routes each function its own settings section, and starts/stops loops as
the toggles flip (no process restart). With one function enabled the
heartbeat status is that function's own payload (unchanged shape); with
both, children nest under `agent` / `scanner` and `role=hybrid`.

- `agent` function — the endpoint device job on top of the shared
 protocol: device binding (`ConnectorService.BindDevice`, CSR → device
 certificate), inventory collection, performance metrics and typed task
 execution through `internal/endpoint`, authenticated with the connector
 credentials. A scanner-kind connection with the agent function enabled
 binds a device the same way. The bound device is an **asset**: its
 identity lives in the connection view (`device` object) and its data in
 the linked asset record — there is no separate device registry.
 Deleting the connection revokes its bound device.
- `scanner` function — a first-class scan executor. Scanner-enabled
 connections materialize a `scanners` row linked to the connector
 (`scanners.connector_id`) with the connection's site;
 while the function runs, it opens the scanner-hub `Jobs` stream with the
 connector credentials (the hub accepts `x-aegis-connector-id/secret` as
 an alternative to legacy `x-scanner-token`) and executes dispatched
 scans through the shared `internal/scanexec` pipeline — identical to the
 embedded scanner and token-enrolled hub agents. The scanner section
 drives the engine (`auto`/`nmap`/`simulated`) and the SSH inventory
 collector defaults; both hot-reload. Scans carrying a per-scan SSH host
 list (chosen in the scan dialog, with per-host credentials) run exactly
 that target set; scans without one fall back to these collector
 defaults. The row appears in Settings -> Scanners ("Connection" badge)
 and in the scan dialog's scanner selector; revoking the connection (or
 toggling the scanner function off) takes the scanner offline.
- `scanner` version reporting — the scanner registers as
 `<binary version>/<engine>` (e.g. `1.5.2/nmap`, `1.5.2/simulated`;
 embedded scanners carry the full nmap version string). The engine
 suffix is the ground truth of what the host actually executes:
 `simulated` means no nmap binary was found (and `auto` mode fell
 back, loudly — see the configuration contract below) or simulation
 was requested explicitly. The heartbeat status payload adds
 `engine_detail`, a human-readable explanation of the current choice.
- `collector` kind — generic external data-forwarder harness (identity,
 config, liveness; the data plane is the collector's own channel). No
 function toggles: it has no agent/scanner function on the hub.

Adding a new externally connected component type = add a kind to
`domain.ValidConnectorKinds` + a `Role` implementation + (optional) UI
label. The protocol needs no changes.

## 5. Configuration contract

The role configuration is free-form JSON (≤ 64 KiB) stored per connector.
It carries two SEPARATE function sections, each with an
`enabled` toggle deciding what the connection performs:

```json
{
  "heartbeat_secs": 30,
  "agent":   { "enabled": true,  "collection_level": "basic",
               "probe_rate_ms": 5000, "pull_rate_ms": 30000 },
  "scanner": { "enabled": false, "engine": "auto", "nmap_path": "/usr/bin/nmap",
               "ssh_user": "", "ssh_key_path": "", "ssh_timeout_secs": 30,
               "ssh_insecure": false, "ssh_pinned_key": "", "ssh_hosts": [] }
}
```

- **Defaults follow the kind**: an `agent` connection collects (scanner
 off), a `scanner` connection scans (agent off). An explicit toggle
 overrides the default in either direction; a collector has no toggles.
- **Flat layout stays valid**: top-level `engine`, `nmap_path`,
 `ssh_*` and `collection_level` keys are applied to the function matching
 the connection's kind (a section, when present, wins wholesale — no
 silent mixing).
- `agent.collection_level` — `basic` (default; hardware + OS overview),
 `standard` (+ installed software and network state) or `full`
 (+ security posture). Hot-reloaded by the endpoint runtime.
- `agent.probe_rate_ms` (100–3600000, default 5000) — how often the
 endpoint takes a performance sample. Hot-reloaded within one loop
 iteration.
- `agent.pull_rate_ms` (100–3600000, default 30000) — how often buffered
 samples are flushed to the hub in one batched call; must not be faster
 than the probe (validated server-side, clamped on the agent).
 Hot-reloaded alongside `agent.probe_rate_ms`.
- `heartbeat_secs` (10–3600, default 15) — heartbeat interval; also drives
 the server-side online window (2×interval, 30s floor) and the agent loop.
- `scanner.nmap_path` — nmap executable path on the scanner host; empty
 means auto-detect (PATH first, then the usual install locations on
 Linux/macOS/Windows). Hot-reloaded alongside `scanner.engine`.
- `scanner.engine` — `auto` (default; use nmap when found, simulate
 otherwise), `nmap` (require the real binary; missing binary degrades to
 simulation with a loud warning) or `simulated` (synthetic demo results —
 deterministic, no probes sent). Every fallback to simulation is logged
 loudly on the component and surfaced via the heartbeat's `engine_detail`,
 so synthetic results can never pass unnoticed.

Server-side validation rejects non-objects and insane values (including
inside the sections — `connectors.ValidateSettings`); role-specific keys
are the role's business and applied via `ApplyConfig` on every watch
update — connected components reload without restarting. Function
toggles additionally drive server-side routing: the endpoint data plane
(`AgentServer`) serves connections with the agent function enabled, and
scan dispatch eligibility follows the scanner function (scanners row
materialized/offline accordingly).

Environment (server):

- `AEGIS_CONNECTOR_PUBLIC_ADDR` — endpoint embedded into connect commands
 and the enroll allow message (default: host of `AEGIS_PUBLIC_URL` +
 gRPC port). Set this to the externally reachable address in deployments.
 The compose stack ships `AEGIS_CONNECTOR_PUBLIC_ADDR=localhost:9090`
 (overridable from `.env`) and publishes the server's `9090` on the host,
 so `aegis-connector --connect localhost:9090/<token>` works out of the
 box for components on the compose host; set the host's DNS name / LAN IP
 for components joining from other machines.
- `AEGIS_CONNECTOR_TOKEN_TTL` — one-time token validity (default `24h`).

## 6. Verification

- Unit: `internal/connectors/service_test.go`, `settings_test.go`,
 `internal/connectorapp/config_test.go`, `roles_test.go`, `hybrid_test.go`.
- End-to-end: `scripts/e2e-connectors.sh` (make e2e) — boots the real
 stack, enrolls a real `aegis-connector` binary over gRPC, proves token
 burn/replay rejection, hot reload on a live process, reconnect rotation,
 revoke semantics and kind-mismatch rejection.
