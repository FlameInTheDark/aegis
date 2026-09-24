## [1.28.1] - 2026-09-24

### Fixed
- **Dragging the range timeline no longer flickers or reloads the
  performance page.** Committing a drag changed the metrics query key, the
  previous window's data dropped to undefined mid-load, and every chart
  unmounted into a "Loading…" empty state and remounted with a fresh
  ECharts instance replaying its entry animation — the whole section
  visibly reloaded on each drag step. The metrics query now keeps the
  previous data rendered while a new range loads (charts morph in place),
  with a small pulsing dot next to the chart descriptions marking the
  background refresh.
- **The timeline no longer redraws and re-centers after a drag.** The
  overview strip's context window used to be recomputed around every
  committed selection (selection ±1 span), so each commit re-keyed the
  overview query, rescaled the strip and landed the selection in the
  middle third — it looked like the whole timeline reloaded and centered
  itself. The overview extent is now held stable across commits and only
  ever grows when a selection comes within a quarter-span of an edge
  (unioned with the previous window, so it never shrinks mid-session);
  dragging within the extent performs exactly one chart refetch and zero
  overview refetches.
- Timeline axis labels now include minutes — the hour-only formatter made
  every intra-hour tick render the identical label (e.g. a strip of ten
  "09-24 04:00" ticks).
- **Scans interrupted by a restart no longer stick in "running" forever.**
  A scan that was running (or cancelling) when the system restarted used
  to stay in that state permanently: the executor claim loop only picks up
  queued scans, and nothing ever transitioned the orphan again. The server
  now sweeps interrupted scans at startup — before the hub and HTTP
  surface open — marking them failed with an "interrupted by restart"
  reason (shown on the scan row) and closing their non-terminal tasks;
  queued scans are left alone (re-claimed as before) and terminal states
  are untouched. An executor that survives a server-only restart keeps
  reporting: its next progress report re-enters running — which also
  clears the stored reason — and the final report lands normally.

## [1.28.0] - 2026-09-24

### Added
- **The asset performance page gets a data-range control bar**: a Latest /
  Range mode toggle; Latest tails a live window selectable from presets
  (30s, 1m, 5m, 15m, 1h, 6h, 24h, 7d) or a custom value with unit
  (seconds to days), plus a refresh-rate selector (Off / 5s / 10s / 30s /
  1m / 5m) deciding how often the charts re-pull points; Range shows two
  datetime inputs and a **visual timeline** — a coarse CPU overview of the
  selected span plus surrounding context with a draggable window (ECharts
  dataZoom slider) that sets the dates with the mouse and stays in sync
  with the inputs. Range mode never polls (a historical span cannot
  change, so refreshing would fetch identical data); the overview stays
  light via server-side density capping (~360 buckets). All viewer
  preferences persist in the browser (localStorage).
- **The metrics API understands both query styles**:
  `GET /assets/{id}/metrics?window=…` accepts the legacy presets, any
  duration (`30s`, `90`, `5m`, `2h`, `3d`) or bare seconds for live tails,
  while `?from=&to=` (RFC3339) returns a static range — with the bucket
  size chosen automatically from a density ladder (1s … 1d, ~240 points
  per tail / ~360 per range, legacy presets keep their exact buckets) and
  the effective `from` / `to` / `bucket` / `tail` echoed in the response.
  Degenerate or inverted ranges are rejected with a 400.
- **Interface sparklines**: the asset's Network interfaces table gains an
  Activity column showing each NIC's receive/transmit speed history as a
  tiny dual-line chart (fixed-size cell, no axes, hover for the rates) —
  backed by a new per-interface series query that flattens the JSON
  interfaces column through `ARRAY JOIN` + `JSONExtract`, so sparkline
  history needs no schema change. NICs without recorded history show a
  muted "no history" placeholder instead of an empty chart.
- **Configurable metrics retention in Settings**: a new Metrics section
  (Settings → Metrics) exposes the retention of the ClickHouse
  `device_metrics` tier — presets from 7 to 365 days, a custom value or
  "Keep forever" — alongside a storage snapshot (stored samples, oldest
  and newest sample age) and a "Clean up now" action that purges
  everything older than the retention window immediately and reports the
  removed-row estimate. The setting is platform-wide (the analytics store
  is shared by every site), saved via the new `GET|PATCH /settings` API
  (`settings:manage` to change, every change audited) and backed by a new
  `settings` key/value table (migration 0034).
- **Retention enforcement loop**: the server keeps the device_metrics TTL
  aligned with the configured retention (MODIFY/REMOVE TTL on change, with
  an applied-value shadow key so restarts never rewrite DDL needlessly)
  and issues bounded delete mutations on a 6-hour cadence, immediately
  after a retention reduction, and on the manual cleanup trigger — so
  storage is actually freed instead of waiting on merge-driven TTL expiry.

### Changed
- The performance charts' legends moved to the top-right corner and x-axis
  labels now hide overlapping ticks, fixing tick/legend collisions on the
  wider date labels; multi-day ranges label ticks with month-day plus time
  so a series spanning several days stays unambiguous.

## [1.27.0] - 2026-09-24

### Added
- **Agents collect performance metrics on a configurable cadence**: the
  new `agent.probe_rate_ms` setting (default 5000, floor 100ms, ceiling
  1h) decides how often a sample is taken from the system, and the new
  `agent.pull_rate_ms` setting (default 30000) decides how often the
  buffered samples are flushed to the hub — in ONE batched
  `SubmitMetricsBatch` gRPC call, so a fast probe never spams the network
  with per-sample requests. Throughput rates keep being computed against
  the previous sample, so a finer probe yields finer-resolution charts
  without distorting the rates; the buffer is bounded (1200 samples,
  oldest dropped) against pathological rate combinations; a failed flush
  keeps its samples for the next pull; a graceful stop flushes what is
  still buffered. An older hub without the batch RPC transparently
  degrades the agent to per-sample submissions, and a hub without the
  analytics tier still acknowledges-and-drops with the familiar one-time
  note. Both settings live in the connection settings' `agent` section,
  hot-reload within one loop iteration (no restart), and are validated
  server-side (`ValidateSettings`: integer milliseconds, 100–3600000,
  pull not faster than probe).
- **The connector configuration dialog is split into tabs**: General
  (function toggles + heartbeat), Agent (collection level, probe rate,
  pull rate) and Scanner (engine, nmap path, SSH inventory credentials).
  The one long form became three focused views; a disabled function's tab
  shows a note that its settings are remembered and take effect on
  enable, the effective-configuration summary now includes the metrics
  cadence, and non-preset stored values remain selectable alongside the
  presets.

### Fixed
- The endpoint runtime no longer ties its performance-sample cadence to
  the heartbeat interval: sampling and flushing are independent tickers
  seeded from the metrics cadence, with a final best-effort flush (5s) on
  shutdown so the samples collected since the last pull are not dropped.

## [1.26.6] - 2026-09-24

### Added
- **Assets can be deleted from the inventory, so discovery recreates
  them**: false discoveries, temporary guests and devices that left the
  network no longer linger forever. `DELETE /api/v1/assets/{id}`
  (asset:write, audited, 204) removes the asset with every dependent
  record — identifiers, interfaces and their addresses, MACs, services,
  software, findings, group memberships — in one cascading delete. An
  endpoint device collecting for the asset survives but is unlinked and
  re-provisions the asset on its next inventory report (adopting a
  matching scan-side record when the evidence is unambiguous), and the
  next scan that sees the address re-creates a scan-side asset.
  Scan-change history and traceroute evidence survive as the audit trail
  of what was observed. The UI exposes the action as a destructive row
  menu entry on the assets list and in the asset detail header, both
  behind a confirmation dialog that names what is removed and how
  rediscovery brings the record back; every asset-dependent cache
  (lists, detail, site counts, groups, findings, vulnerability
  correlations, dashboards) is refreshed after the removal.

## [1.26.5] - 2026-09-24

### Fixed
- **A machine the network scanner had discovered kept a second,
  agent-created asset**: the re-link path required the original asset to
  share the device's MAC, but a remote-subnet nmap scan cannot resolve
  MACs — ARP answers only on the scanner's own link — and often resolves
  no hostname either, so the scanned original held nothing but the address
  and could never be adopted. Adoption is now evidence-ranked: an asset
  sharing a reported MAC with the device and holding one of its current
  addresses wins first, then an asset whose hostname/FQDN identifier
  matches and holds a current address, and finally the address alone —
  adopted only when exactly ONE asset in the site holds one of the
  device's currently reported addresses. Assets another device already
  claims are never adopted, and an address the machine has moved away
  from never yanks a converged link.
- **The adopted original left the abandoned duplicate behind as a phantom
  device**: the duplicate kept `has_agent`, the device link and the
  endpoint's hostname, so the inventory kept showing two machines for
  one. The duplicate is now merged into the adopted asset in a single
  transaction — identity identifiers, interface addresses (donated to the
  interface carrying the same MAC), MAC observations, services, software,
  findings (re-pointed to the target's equivalent service and package
  rows before the move), group memberships — devices bound to it follow,
  and the duplicate row is deleted. Scan history is untouched, and a
  failed merge never fails the inventory application: the device stays on
  the adopted asset and the duplicate at least loses its endpoint flags.

## [1.26.4] - 2026-09-24

### Fixed
- **The network tab showed a single (often IPv6, sometimes link-local)
  address per interface and no IPv4**: the hub flagged whichever address
  happened to enumerate first as the interface's primary — Windows reports
  IPv6 before IPv4 on most NICs — and the read path surfaced only that one
  address. The interface table now records and shows every address the
  endpoint observed (IPv4 and IPv6, global and link-local), each interface
  carries exactly one primary chosen by reachability — the device's
  management address when the interface carries it, else the first global
  IPv4, else the first global IPv6 — and interface addresses read back as
  bare literals (the `inet` column no longer leaks its `/32`, `/64`
  prefix into the UI).
- **Servers without the analytics tier crashed on the first performance
  sample**: the boot wiring assigned the typed-nil `*clickhouse.DB` into
  the metrics-sink interface, so the "not configured" guard never fired
  and `SubmitMetrics` panicked the whole server on the nil driver
  connection. The sink stays an untyped nil when ClickHouse is absent and
  the handler treats any nil concrete value as "tier absent" — the sample
  is acknowledged and dropped, everything else keeps working.
- **Devices bound to connections created without a site assignment failed
  every inventory submission** with an opaque empty-uuid SQL error: the
  device inherited the connection's missing site and the asset insert
  died on `site_id = ''`. A siteless connection now binds its device to
  the organization's first site, and a siteless legacy device fails with
  a readable message instead of SQL noise.
- **A report definition without a creator could not be stored**: the
  empty `created_by` string hit the uuid column directly; it is stored as
  SQL NULL now, consistent with the definition's other optional columns.

### Changed
- The integration test suites repaired and pinned to real Postgres: a
  semicolon inside a migration comment broke the dirty-recovery
  statement splitter (every recovery run failed since migration 0028),
  asset fixtures satisfy the current check constraints, session-rotation
  and null-scan regressions no longer collide across runs, the CVE LIST
  sync test derives "same day" from the real clock instead of a stale
  hardcoded 2026 date and truncates with CASCADE, and the interface
  persistence gained a primary-address convergence regression test.
- New live verification `scripts/e2e-interfaces.sh` (with
  `scripts/verify-ifaces`): boots the real stack, enrolls a real
  connector, injects a Windows-shaped inventory (IPv6 first, CIDR and
  zone forms) through the authenticated data plane and asserts the
  asset bundle contract.

## [1.26.3] - 2026-09-24

### Fixed
- **Endpoint assets showed the hostname as the address and could not be
  matched by IP**: interface addresses were reported in the system's CIDR
  form (`192.168.1.80/24`), which every strict parser downstream rejects —
  so no usable address was ever recorded on the asset, the displayed
  address fell back to the hostname, and address-based correlation never
  fired. Addresses are now normalized to plain literals at the source
  (prefix length and IPv6 zone stripped), and the hub applies the same
  normalization to reports from connectors shipped before this fix.
- **The operating system was reported as a placeholder ("windows windows
  go1.27.1" — the Go compiler version) instead of the real product**:
  Windows now reads the edition, release and build from the registry
  (`Windows 11 Pro 24H2 (build 26100.2894)`, correcting Windows 11 builds
  whose `ProductName` still says "Windows 10"), Linux reports the
  distribution `PRETTY_NAME` and version, macOS reports the product
  version.
- **A device bound before identity persistence stayed attached to its
  duplicate asset forever**: an already-linked device never re-evaluated
  its link. Once the inventory carries hardware identity, the device now
  adopts the organization asset that shares a reported MAC and holds one
  of its reported addresses — the machine's original, scan-created record
  (oldest first). A link whose asset already claims a reported address is
  converged and left alone; a shared MAC alone never moves a link.
- **Performance charts replayed their entry animation on every refresh**
  (lines redrawing left to right): the chart instance was re-created for
  each data update. The instance is now reused and series morph in place;
  the time axes drop the half-slot side padding so the series spans the
  full plot width with the newest sample at the right edge.

## [1.26.2] - 2026-09-24

### Fixed
- **A bound endpoint duplicated a machine the scanner had already
  discovered as a second asset**: applying endpoint inventory always
  created a new asset and never looked for an existing one. Inventory
  application now resolves the device's asset the same way the scan
  pipeline does — machine id and serial, then interface MAC, then
  hostname/FQDN (ambiguous values match nothing), then the reported
  addresses within the site — adopts the match, and re-resolves when a
  linked asset was deleted.
- **Endpoint-created assets showed no address and could never be
  correlated later**: the endpoint path wrote no identity identifiers.
  The machine id, serial, every interface MAC, hostname/FQDN and every
  usable address (loopback, link-local and zone-suffixed ones excluded)
  are now recorded on the asset like scanner observations are.
- **An endpoint asset's displayed address could be a loopback, virtual
  adapter or container bridge**: the inventory now carries the device's
  management address — the source address of its connection toward the
  hub, probed through the routing table with a deterministic interface
  fallback — and the asset read path prefers it over the device's other
  addresses.

### Changed
- The asset read path picks the displayed address by identifier weight
  first and recency second; scan-only assets keep their latest address.

## [1.26.1] - 2026-09-24

### Fixed
- **Asset performance charts returned no data** (`device metrics query
  failed ... converting Float32 to *float64 is unsupported` in the hub
  log): the metrics queries scanned `max()` aggregates and raw columns
  straight into `float64` fields, but the table stores Float32/UInt64
  and the ClickHouse driver does not widen those on scan. Every numeric
  column in the chart and latest-sample queries is now widened to
  Float64 in SQL.
- **The security-events list errored whenever events existed**: rows
  were scanned with the severity column pointed at a named string type,
  which the ClickHouse driver rejects; it is scanned as a plain string
  now.
- **A wrong ClickHouse address or password surfaced only as per-query
  failures**: the hub verifies the analytics-tier connection while
  starting and reports a clean startup error instead.
- **The current-load tiles and per-interface table on the asset page
  stayed empty even with data**: the metrics API serialized the latest
  sample with Go field names while the page reads snake_case keys. The
  JSON contract of both metrics responses is now pinned by tests.

### Changed
- Dev and e2e builds stamp their version from git tags; the release
  archive carries no version file.

## [1.26.0] - 2026-09-24

### Fixed
- **Endpoint inventory submission was rejected for every bound device**
  (`inventory rejected: agent <id> not found` in the connector log):
  inventory application resolved the device with an organization-scoped
  lookup called with an EMPTY org, so any device whose connector carries a
  real organization id never matched and the endpoint collected nothing.
  The data plane already authenticates the connector and resolves its
  bound device, so the lookup is now by device id alone; the asset created
  on first inventory also carries the `agent_id` link (previously set only
  on later updates).

### Changed
- **Bound endpoint devices are assets, not a separate registry**: the
  Agents page and the `/agents` HTTP API are gone. A device surfaces on
  its connection — Connections page rows and `GET /connectors` responses
  carry a `device` object (hostname, platform, version, status, last
  seen, asset link) — and its data lives in the linked asset: asset list
  and detail responses carry an `endpoint` object naming the collector
  and its connector. Deleting a connection revokes its bound device.
- Windows/macOS endpoint collection is real data now (network interfaces
  with MAC/IPs/MTU/status, disk capacity per mount, CPU model/cores,
  memory, kernel, uptime) instead of empty fallbacks.

### Added
- **Endpoint performance metrics**: the connector's agent function
  collects CPU utilization, memory used/available, load averages, uptime
  and per-NIC byte/packet counters with computed rates (gopsutil, all
  platforms) — one sample per heartbeat interval submitted over the new
  `AgentService.SubmitMetrics` RPC. The hub stores samples in the
  ClickHouse `device_metrics` table (monthly partitions, 30-day TTL) and
  serves them at `GET /assets/{id}/metrics?window=1h|6h|24h|7d` (bucketed
  aggregates + latest sample with per-interface rates). The asset detail
  page gains a Performance tab: current load, CPU average/peak, memory,
  network throughput and a per-interface table. Without the ClickHouse
  tier samples are dropped with a one-time note in the connector log;
  every other data-plane function keeps working.

## [1.25.2] - 2026-09-24

### Fixed
- **Device binding followed the agent KIND instead of the agent FUNCTION**:
  enabling endpoint collection on a scanner-kind connection (hybrid mode)
  enrolled fine and hot-started the agent loop, but the loop then stuck in a
  retry storm — `device bind rejected: ... PermissionDenied ... device
  binding is only for agent-kind connections, not "scanner"`. The bind gate
  was the one server-side check still keying on the kind instead of the
  function toggles. `BindDevice` now applies the same gate as the endpoint
  data plane: any connection with the agent function enabled (agent-kind by
  default, any kind with `agent.enabled`) binds a device and receives its
  certificate; connections with the function explicitly disabled are
  rejected with a message naming the kind.

## [1.25.1] - 2026-09-24

### Fixed
- **The Connections page crashed the entire app on mount** (`Uncaught
  Error: useLocation() may be used only in the context of a <Router>
  component`): the page imported `useSearchParams` from react-router-dom,
  but the SPA runs its own hash router and never mounts a react-router
  tree — opening Connections (or following the "Connect endpoint" deep
  link from the Agents page) unmounted the whole application behind a
  blank screen, which also hid the connector function toggles from the
  UI. The deep link now reads the query from the app router and clears it
  with a replace navigation; react-router-dom is removed from the
  dependencies so the wrong import cannot come back.
- One broken page no longer takes down the shell: a per-page error
  boundary renders an error card with a "Try again" action, the rest of
  the app stays usable, and the failure is logged to the browser console
  as `Page crashed:`.

### Changed
- Documentation states functionality and usage only: version markers,
  migration references and historical rationale ("since vX", root-cause
  field reports, audit-record sections, upgrade-conditioned
  troubleshooting rows) are removed from CONNECTORS, AGENT, AUTH, API,
  TROUBLESHOOTING, VULNERABILITY-FEEDS and SSH_VULNERABILITY_SCANNING.
  The API endpoint map dropped the nonexistent
  `GET|POST /agents/enrollment-tokens` entries, and the troubleshooting
  table gained a row describing the per-page error state.

## [1.25.0] - 2026-09-24

### Added
- **Hybrid connectors: one connection performs both endpoint collection and
  remote scanning.** Connection settings now carry two SEPARATE function
  sections — `agent` (endpoint collection on the host the connector runs
  on) and `scanner` (remote scanning) — each with an `enabled` toggle that
  decides what the connection performs. Defaults follow the connection's
  kind (agent connections collect, scanner connections scan), so existing
  deployments behave exactly as before with no settings rewrite; flipping a
  toggle turns the connection into a hybrid that runs both functions side
  by side in one process. Toggle flips arrive through the normal config
  hot-reload path and start/stop the affected function loop WITHOUT a
  process restart.
- **Separate run commands** (`aegis-connector start --agent` /
  `start --scanner`, also on `--connect`/`connect`/`reconnect`): run
  exactly one function regardless of the connection toggles — useful for
  one-off runs and service units. The two flags are mutually exclusive;
  without them the process follows the hub-side toggles.
- **The Configure dialog manages what a connector can do**: "What this
  connector can do" toggles (Endpoint collection / Remote scanning) with a
  dedicated settings section per enabled function — collection level
  (`basic`/`standard`/`full`) for the agent function, the existing
  engine/nmap/SSH settings for the scanner function — plus function badges
  on the connections list (a hybrid row shows both).
- Server-side routing follows the toggles: the endpoint data plane
  (`AgentService`) serves every connection with the agent function enabled
  (kind agent by default, any kind with `agent.enabled`), and scan-dispatch
  eligibility follows the scanner function — enabling scanning on an
  agent-kind connection materializes its linked scanners row (it appears in
  the scan dialog like any scanner), disabling marks it offline until
  re-enabled. Heartbeat liveness cascades onto the scanners row for every
  scanner-ENABLED connection, not only kind=scanner.

### Changed
- Settings validation accepts both layouts (`connectors.ValidateSettings`):
  the new section layout and the legacy flat layout (top-level
  `engine`/`nmap_path`/`ssh_*`/`collection_level` keys, applied to the
  function matching the connection's kind; a section, when present, wins
  wholesale). Nested section keys are validated with the same constraints —
  `agent.collection_level` must be `basic|standard|full`, scanner keys
  mirror their flat counterparts. The UI reads both layouts and re-saves in
  the section layout on the next Configure.
- The connector runtime composes roles through a hybrid container
  (`HybridRole`): with one function enabled the heartbeat status payload is
  that function's own map (unchanged shape, downstream-compatible); with
  both enabled children nest under `agent`/`scanner` with `role=hybrid`, and
  with both toggles off the connector reports `role=idle` while staying
  enrolled and heartbeating.
- Malformed settings sections fall back to the kind default on the
  component — a bad settings push can never silently stop an endpoint's
  collection.

## [1.24.0] - 2026-09-24

### Removed (breaking)
- **The standalone endpoint agent is gone — endpoints are agent-kind
  connectors now.** The `aegis-agent` binary (`cmd/agent`), its Dockerfile
  target, the `aeg_enroll_*` enrollment-token system (issue/list HTTP API,
  `enrollment_tokens` table, `AgentService.Enroll` RPC) and the Agents-page
  token dialog all cease to exist. Deployment, enrollment, liveness and
  configuration for endpoints now ride exclusively on the unified connector
  protocol that scanners and collectors already used: one binary
  (`aegis-connector`), one connect command
  (`aegis-connector --connect <host>:<port>/<token>`), one credential file,
  one heartbeat. Rationale: the two parallel enrollment/liveness/UI surfaces
  were the seam where both enrollment outages (1.23.3, 1.23.4) lived.

### Changed
- **Device identity is bound to the connector, not issued standalone**
  (`ConnectorService.BindDevice`, new RPC): the endpoint generates its CSR
  locally (the private key never leaves) and the hub creates or refreshes
  the device record bound 1:1 to the connector (`agents.connector_id`,
  migration 0033), signing the certificate with the platform agent CA as
  before. Re-binding keeps the same device id and its asset/history links.
- **The endpoint data plane is finally authenticated** (fixes a latent
  security hole): every `AgentService` RPC — inventory/software/network/
  posture submission, task polling/completion, event streaming — now
  requires the connector credential metadata and resolves the caller's
  BOUND device. A client-asserted `agent_id` is ignored, so one endpoint
  can no longer write inventory into another's asset. Non-agent connector
  kinds are rejected with a message naming the kind; unbound connectors are
  told to run BindDevice.
- **The agent kind inside `aegis-connector` is the real endpoint role**:
  it binds the device (CSR → certificate), then runs the full endpoint
  runtime — inventory collection, typed task execution, offline buffering —
  with retries and backoff, while the shared connector session keeps
  liveness and config hot-reload alive. The `collection_level` connection
  setting (basic|standard|full) applies to collection via hot reload.
  Device state (certificate, key, device id) lives next to the connector
  config file (`<dir>/endpoint/`); the connector secret is never copied
  into it.
- **UI consolidation**: the Agents page remains the device/inventory view
  but its "Enroll agent" token flow is replaced by a "Connect endpoint"
  action that deep-links to Connections (`?create=agent` opens the create
  dialog with the agent kind preset) — one creation and enrollment surface
  for every externally connected component.
- The hub now always registers the endpoint data plane (it needs only
  connector auth); a missing agent CA degrades device binding only, with a
  clear error instead of silently dropping the whole service.

### Migration notes
- Apply migration 0033 (adds `agents.connector_id`, drops the dead
  `enrollment_tokens` table). Existing device rows keep their ids, tasks,
  events and asset links; they re-attach to identity the first time an
  updated endpoint connects with its connector credentials and re-binds.
- Replace every `aegis-agent` deployment/service unit with
  `aegis-connector --kind agent` enrollment from the Connections page.
- Build targets: `bin/aegis-agent` is removed from the Makefile;
  cross-compilation of `cmd/connector` for windows/darwin is gated instead.

### Tests
- Transport guards pin the new security model: missing/bad connector
  metadata → Unauthenticated, scanner-kind → PermissionDenied (kind named),
  unbound connector → NotFound pointing at BindDevice, and — the
  anti-spoofing core — inventory submitted with a forged `agent_id` is
  applied to the BOUND device (mutation-verified).
- Real-transport round-trip tests exercise BindDevice against an in-process
  hub stub that REQUIRES the connector metadata (a client that stops
  attaching it fails loudly), plus bind-success state persistence checks
  including the connector-secret non-leak into device state.
- Endpoint-role unit tests pin the connector-config → endpoint-config
  mapping (server/TLS URL, credential flow, collection level, device state
  directory) and the capability/status surface. `GOOS=windows`/`darwin`
  compile gates now cover `cmd/connector`.

## [1.23.4] - 2026-09-23

### Fixed
- **`aegis-agent` had no `enroll` subcommand — the exact command the hub UI
  hands the operator could never run** (field report: `aegis-agent enroll
  --hub localhost:9090 --token aeg_enroll_… --site …` died with
  `fatal: no agent_id and no enroll token; enroll this endpoint via the UI
  first`). `cmd/agent/main.go` never looked at `os.Args[1]`: the `enroll`
  subcommand was silently swallowed together with every flag after it, the
  binary fell into the run loop, `--token` was never bound and the loop
  aborted on the missing local identity. The agent CLI now has real
  subcommand routing — **`enroll`**, **`run`** (default, back-compat with
  flag-only `--config` invocations) and **`version`** — with proper flag
  parsing (`--hub`, `--token`, `--site`, `--state-dir`, `--config`), a
  `help` screen, and **`--hub` accepting the bare `host:9090` form the UI
  emits** (normalized onto the control-plane URL space; full http(s) URLs
  still work). Unknown subcommands and unparsed leftover arguments are
  hard errors — silent arg swallowing is precisely how v1.23.3 shipped
  this. `enroll` performs the handshake, prints the assigned
  `agent_id`/state directory and exits; a state file with an existing
  identity makes `enroll` a friendly no-op, while an explicit `--token`
  re-enrolls a new identity deliberately.
- **Enrollment state was write-only** — `Load()` never read back the
  `agent.json` that a successful enroll writes, so even an env-var
  enrollment did not survive a fresh shell and `run` could not work after
  `enroll` without hand-crafting a config. `Load` now resolves
  defaults < `AEGIS_*` env < state file < explicit config file < flags,
  making `aegis-agent run` a zero-flag command after enrollment.
- **Agent defaults were Unix-only** (`/var/lib/aegis-agent`,
  `/etc/aegis/agent.{crt,key}`) while the reported failure came from
  **Windows** (`platform=windows`), where those paths are meaningless.
  The state directory defaults to `%ProgramData%\aegis-agent` on Windows
  (`/var/lib/aegis-agent` stays for Linux/macOS, matching the `sudo`
  instruction in the UI), and cert/key material defaults **inside the
  state directory** instead of `/etc/aegis`; `AEGIS_CERT_PATH`/
  `AEGIS_KEY_PATH` still override. `Validate` now rejects an empty
  `key_path` outright instead of failing later on a bare
  `open : no such file or directory`.
- **The agent never sent `machine_id`** — the server has mapped the field
  since 1.23.3, but the client left it empty. It is now discovered
  best-effort per platform (`AEGIS_MACHINE_ID` override → `/etc/machine-id`
  and friends on Linux → registry `MachineGuid` on Windows →
  `IOPlatformUUID` on macOS → deterministic hostname hash fallback) and
  pinned non-empty by a wire-level test.
- **Single-use enroll tokens were persisted to local state** after a
  successful enrollment; the token is now cleared before `agent.json` is
  written, matching the server-side single-use semantics. The enroll
  response's `heartbeat_interval_secs` is honored instead of hardcoded 30.
- **The enroll error message dead-ended operators**: "enroll this endpoint
  via the UI first" was the advice whose CLI half did not exist. It now
  names the working command (`aegis-agent enroll --hub <host>:9090 --token
  <token>`).
- **The "Enroll agent" dialog now says what actually creates the agent**:
  after a token is issued it states explicitly that the agent row appears
  only when the command finishes on the endpoint (clicking Done issues a
  token, it does not enroll anything by itself), and that a retry needs a
  fresh token — closing the "click done, agent not being created" report.
  The generated commands also embed the **hub host from the browser
  location** (falling back to the `<hub-host>` placeholder) instead of
  always demanding manual substitution, and the token is **double-quoted**
  in the copyable one-liners so base64 `+`/`/`/`=` survive paste into
  bash, zsh, cmd and PowerShell alike.

### Tests
- Transport round-trip regression guards run the **real gRPC client**
  against an in-process hub stub: token/CSR/`machine_id`/hostname reach
  the wire, the response's agent id and heartbeat interval apply, state is
  persisted token-free, no-token and server-rejection paths fail with
  guidance. CLI parsing is pinned for the literal UI-emit command shape
  (mutation-verified), plus config-resolution priority and per-OS state
  directory tests; `GOOS=windows` and `GOOS=darwin` builds of the agent
  are compile-gated.

## [1.23.3] - 2026-09-23

### Fixed
- **Agent enrollment was structurally impossible — the gRPC transport dropped
  the CSR** (`internal/transport/grpc/agent_server.go`). `AgentServer.Enroll`
  validated `csr_pem` on the wire request and then built the service request
  **without the `CSR` field**, so `agents.Service.Enroll` rejected every
  enrollment with "token and csr are required" no matter how valid the token
  was. `aegis-agent enroll --hub … --token …` could never succeed; an agent
  record could never be created. The mapping (now extracted as the pure
  `enrollRequestFromProto`, unit-tested against exactly this regression)
  passes the CSR again — and also carries `platform_version`, `arch` and
  `machine_id`, so the agents table keeps the endpoint's platform version
  and architecture instead of empty strings. The transport-level guard
  rejects a missing `csr_pem` with a message that names it before the
  service layer is reached.
- **The "Enroll agent" dialog rendered a bare empty site dropdown with a
  silently dead "Issue enrollment token" button** when the sites query was
  in flight, failed, or genuinely returned zero sites — the same
  lying-empty-state class fixed for the sites panel in 1.23.2. The dialog
  now distinguishes all three states: a **"Loading sites…"** row, a
  **"Failed to load sites"** alert with the actual error and a **Retry**
  button, and a **"No sites yet — create a site in Settings → Sites"**
  notice linking straight there. The connector create dialog on the
  Connections page gets the identical treatment: agents and scanners are
  created there too, and its "Generate one-liner" button is disabled for
  the same visible reason instead of a silent dead end.

## [1.23.2] - 2026-09-23

### Fixed
- **The sites panel rendered every failure as "No sites yet"** — field report:
  the backend answered `GET /sites` with the site list, but the UI showed an
  empty list. The table only knew one state beyond "rows": the empty state,
  so a query that ended in an error (an auth blip answered 401, a proxy
  replying 50x/HTML, a malformed body) or was still in flight was rendered
  exactly like an org with zero sites. The panel now distinguishes all
  three: a **loading** row while the request is in flight, a destructive
  **"Failed to load sites"** alert carrying the actual error message with a
  **Retry** button when the query fails, and "No sites yet" only when the
  API genuinely answered with zero sites. The site dialog's networks list
  gets the same treatment instead of implying "No networks yet" on a
  failed request.
- **A malformed `/sites` response killed the query with a cryptic TypeError**
  and landed in the same silent empty state. `useSites` (factored out as
  `fetchSites`, unit-tested) now validates the response shape and rejects
  with a readable message — "Sites API returned an unexpected response
  (expected an items array, got …)" — which the panel displays verbatim.
  A failed or malformed per-site networks fan-out degrades to an empty
  networks list per site instead of taking the sites table down with it.

## [1.23.1] - 2026-09-23

### Fixed
- **Sites editing opened two modals at once**: the "Edit site" dialog and the
  "Networks — …" manager mounted stacked on top of each other, because the
  row action set the edit-dialog state and the networks dialog keyed on the
  same flag. They are now a single **site dialog**: name / type / description
  on top and a Networks section below — the live list with exposure labels
  plus the add row — present as soon as the site exists. Creating a site
  flips the dialog in place into edit mode (the created site comes back from
  the API), so ranges can be added immediately without closing anything.
- **The dialog's network list never refreshed**: it read a prop snapshot
  taken at open time, so a freshly added range showed up only after closing
  and reopening. The dialog now reads the live per-site networks query,
  invalidated on every add; the sites query is invalidated alongside it.
- **The sites table's Networks column and header badge always showed zero**:
  `useSites()` mapped sites without networks and the list endpoint does not
  embed them. It now fans out per site over `GET /sites/:id/networks`
  (orgs hold a handful of sites, failures degrade to an empty list), so the
  column, the badges and the dialog agree with the stored truth.
- **The exposure dropdown was a placebo**: `POST /sites/:id/networks`
  ignored the `exposure` field and hardcoded `internal_only`, and the values
  the dialog offered (`internal`/`dmz`/`internet`) would have failed the
  database CHECK constraint had they ever been forwarded. The handler now
  reads `exposure` and the service validates it against the canonical set
  (`internal_only`, `vpn_only`, `publicly_reachable`, `unknown`;
  `normalizeExposure`, unit-tested — empty defaults to `internal_only`),
  stores it, and the dialog offers the canonical values with readable
  labels.
- **A description typed on "Add site" was silently dropped**: the create
  call never sent the field; it does now, and the API round-trip returns the
  created site so the dialog can switch to edit mode with real data.

## [1.23.0] - 2026-09-23

### Added
- **Analyst parent-node override for the topology map**: transparent L2
  switches are invisible to a network scan — they forward frames without a
  routable hop, so traceroute wires every host behind them straight to the
  router, and no nmap run can recover the real wiring. The switch itself
  still surfaces in the inventory (management web interface, MAC vendor), so
  the analyst can now state what the scan cannot see: a new `parent_override`
  on the asset (migration 0032) pins the node beneath any other asset of the
  organization on the topology map. Like the identity overrides it is never
  written by scan ingestion — clearing it returns the node to the
  evidence-derived position, and the observed topology stays untouched.
  - `PATCH /assets/:id` accepts `parent_override` (asset id or null to
    clear); the handler requires an existing same-organization asset,
    rejects self-references (mirroring the DB CHECK) and walks the candidate
    parent's existing override chain to reject cycles before they can reach
    the graph (`domain.ParentOverrideCycle`, unit-tested).
  - The graph engine (`deriveForest`) takes the pinned links as
    `forceParent`: they beat any evidence confidence, apply cycle-safe (a
    corrupt chain bends the layout, never breaks it), rebuild depth/children/
    roots over the final tree, and always render as edges even when no scan
    ever observed that pair. Two components joined by a pin become one tree.
  - The topology page re-derives live: pinned links draw as solid **amber**
    cables with a legend entry ("pinned parent (analyst)"), the node popover
    wears a "pinned parent" badge, the table Upstream column marks pinned
    rows, and the status bar counts pins. A pinned parent filtered out of
    the current view is still drawn as an anchor node — hiding a switch that
    visible children hang from would strand them.
  - Edit identity (asset page) gains the **Topology parent** select listing
    the site's assets; the current parent stays selectable even beyond the
    200-asset window. Verified end-to-end in the browser against a
    transparent-switch fixture: pinning re-derives the tree immediately
    (gw → switch → servers), clearing snaps the node back under the gateway.

## [1.22.1] - 2026-09-23

### Fixed
- **Topology cables stopped short of the pins**: hierarchy cables trimmed
  their endpoints at hardcoded 26/24 px above the node centre — clearances
  tuned for the pre-redesign pin size. Today's pins are 8–13 px (hubs 18),
  so every cable visually floated up to 17 px away from the child disc and
  ~5 px from its hub. Cable endpoints are now radius-aware: the graph trims
  each end to that pin's actual radius + disc stroke + ~2 px of breathing
  (plus a nudge when the selected pin scales up), so cables land ON the rim
  in every arrangement, and the straight vertical case shares the same
  geometry instead of a duplicated constant. Verified in-browser: all 124
  measured cable endpoints on the 62-link fixture graph touch a pin rim.
- **Topology jank**: every pan/zoom/drag/animation frame re-diffed the whole
  SVG — about a thousand elements per frame since the icon-first pins, with
  no coalescing of pointer/wheel event storms, a redundant 380 ms tween
  after every drag end, and a drop-shadow filter on group/site box headers
  re-rasterizing through layout animations. The render pipeline now
  memoizes: each pin and cable is a `React.memo` subtree keyed by position-
  independent props, device glyphs are shared cached elements (React skips
  identical element references), pan/zoom re-renders coalesce to one frame
  per rAF, a settled layout snaps instead of tweening, dragging writes
  positions without doubling renders, and the box-header filter became a
  paint-order stroke halo (the canvas now contains no SVG filters at all).
  Measured in-browser: a 60-event pan burst produces zero childList DOM
  mutations and zero long tasks; dragging a node likewise re-renders only
  attributes (the dragged pin and the cables that reach it).

## [1.22.0] - 2026-09-22

### Added
- **Rows-per-page selector in every table view**: assets, scans, findings,
  CVEs, connectors, agents, reports, users and the audit log — plus the
  asset-detail software and services tables — gained a rows-per-page
  select in the pagination footer (25 / 50 / 100 / 200; 200 is the API's
  hard limit). The choice is persisted per table under `aegis-page-size`
  in localStorage and defaults to 50 rows. Changing the size always
  returns to page 1, and the "x–y of z" window plus the page counter
  recompute from the new size. Server-paginated views (findings, CVEs,
  assets, audit log) pass the size as the `limit` query parameter, so
  totals and windows stay exact; views that filter client-side over a
  fetched batch (scans, connectors, agents, reports, users, asset-detail
  inventories) paginate that batch with the same control, and the
  pagination math clamps instead of ever landing on an empty page.

### Changed
- **Topology pins are icon-first**: the group identity ring that wrapped
  every pin — the "donut" that survived both earlier redesigns — is gone.
  A pin is now a single risk-coloured disc with the device-type icon
  centred inside it (server, router, camera, … — the same lucide glyphs
  the rest of the UI uses), drawn as a white glyph over a dark
  under-stroke so it reads on every risk fill without any filter. Group
  identity moved from the ring to a small colour dot on the pin's
  bottom-left diagonal (ungrouped assets carry no dot at all); findings
  and agent dots keep their top-right / bottom-right corners, and the
  findings dot gained a light stroke so it stays visible on critical-red
  discs. Selection, search-match and hub states remain the v1.21.1 halo +
  scale language; the legend documents the new vocabulary.

## [1.21.1] - 2026-09-22

### Fixed
- **Pins still stacked rings in the selected state**: 1.21.0 kept a shared
  "state ring" for selection / search match / hover, so a selected hub wore
  a white disc stroke plus two violet-ish rings plus a glow blob — the mush
  the pin redesign was meant to remove. States no longer add circles at
  all: selection / search match / hub render as one soft radial-gradient
  halo (a single `<radialGradient>`, no per-node filters) and the pin
  scales up as one unit (selected 1.12, matched 1.06, 180 ms ease) —
  labels stay put. A pin's silhouette is now at most the identity ring
  around its disc, in every state; the dashed trace ring remains for
  shift-click pinned traces.

## [1.21.0] - 2026-09-22

### Changed
- **Topology pins redesigned**: a pin could previously stack up to five
  concentric circles (glow, selection ring, agent dashed ring, group ring,
  hover halo) — the selection and agent rings sat almost on the same
  radius and read as a mess. A pin is now one visual unit: a single group
  identity ring (r+3) around the risk disc, one shared state ring
  (selection > search match > hover), the agent indicator turned from a
  second dashed ring into a green dot badge sitting on the ring's
  bottom-right diagonal, and the findings dot moved onto the top-right
  diagonal of the same ring. The collapse badge moved to the free
  top-left diagonal. Hub glow is the only remaining blur.
- **Pin labels are name-first and haloed**: the hostname is now the
  primary label (semibold) with the IP below it in mono — matching the
  hover tooltip — and both carry a `paint-order` stroke halo so they stay
  readable over cables without any filter. Labels also de-clutter with
  zoom: below 55% the IP drops, below 30% only clean pins remain.
- **Topology legend redesigned**: the horizontal flex-wrap bar (whose
  "hide" button floated after wrapped content, jumping around) is now a
  fixed-width vertical card in the zoom-furniture design language. The
  toggle is the card's header control (top-right, never moves), and the
  body documents the pin language: risk colours, group ring, agent
  badge, findings badge plus the interaction hints.

## [1.20.1] - 2026-09-22

Hotfix release: 1.20.0 shipped source that did not compile.

### Fixed
- **Missing `strings` import broke the backend build** (introduced with the
  identity-override handler in 1.20.0): `internal/transport/http/
  handlers_assets.go` referenced `strings.TrimSpace` without importing
  `strings`, so every backend image build died at
  `go build ./cmd/server` with `undefined: strings`
  (handlers_assets.go:222, :240). The import is restored; `go build ./...`
  and `go vet ./...` are green again.
- **Release packaging now verifies the tree before shipping**: after 1.20.0
  packaged a non-compiling tree unnoticed, `scripts/package-release.sh`
  gained hard gates — it refuses a dirty working tree and runs the same
  builds the Dockerfile runs (`CGO_ENABLED=0 go build ./...`, `go vet ./...`,
  plus the web `tsc -b && vite build`) before any archive is produced. A
  tree that does not build can no longer be released.

> **Note:** the 1.20.0 archives (`aegis-v1.20.0.zip` / `.tar.gz`) contain
> the broken source — use 1.20.1.

## [1.20.0] - 2026-09-22

> ⚠️ The source archives of this release do not compile (missing import,
> fixed in 1.20.1) — the notes below describe the intended content.

A batch of two UX bug fixes and three features, driven by hands-on feedback.

### Fixed
- **Group icons never persisted visibly**: the icon picker stored PascalCase
  keys ("Boxes"), the API's `sanitizeGroupKey` lower-cased them before
  persisting ("boxes"), and the client icon map only had PascalCase keys —
  so every lookup missed and every group rendered the same Boxes fallback.
  The icon map is now keyed by the canonical lowercase ids (matching the
  API round-trip), the picker default is "boxes", lookups are
  case-insensitive, and "router" joined the palette.
- **Topology search counter nudged the search bar**: the "N matches" text
  was a sibling span after the field, so it shifted the bar on every
  keystroke that changed the count. It now renders inside the input
  (absolutely positioned), so the bar never moves.
- **Topology search did nothing in table view**: the search now filters
  table rows too (grouped or flat), with an explicit "No nodes match the
  current search." empty state.

### Added
- **Asset identity overrides** (migration 0031): analysts can override the
  display name and device type of an asset (detection occasionally calls a
  router a workstation). Overrides live in dedicated `name_override` /
  `device_type_override` columns, are never written by scan ingestion, and
  the read path applies them onto the effective hostname/device_type — so
  inventory, topology and search all show the corrected value, while the
  scanned data stays untouched and comes back the moment the override is
  cleared ("Restore scanned data"). UI: Edit identity dialog on the asset
  page plus an "overridden" badge in the header. Global asset search now
  matches and returns overridden names.
- **Custom profile nmap arguments**: the profile editor (Settings →
  Presets) gained an "Extra nmap arguments" field with the server's
  allowlist spelled out, a live nmap command preview, and the profile card
  shows the stored extra args. Profiles remain selectable per scan in the
  New scan dialog.
- **Software upstream versions first**: the asset software list now shows
  the upstream version by default (the clean version the project
  published, without distro epoch/revision suffixes), falling back to the
  normalized form and then the verbatim reported string; the version
  tooltip lists all three.
- **Collapsible topology legend**: the bottom-left legend defaults to a
  small "Legend" pill and expands on click (remembered per browser).

## [1.19.6] - 2026-09-22

The New scan dialog's Profile/Scanner row read as broken: the profile
description paragraph in the left cell made it much taller than the right
cell, and the grid's default `align-content: stretch` then pushed the
Scanner label + select down inside their cell — the Scanner field sat
visibly lower than Profile.

### Fixed
- **Scanner alignment**: the long profile description paragraph under the
  Profile select is gone; both cells of the Profile/Scanner row now pack
  their rows to the top (`content-start` + `items-start`), so the Scanner
  field always sits on the same line as Profile — including when a warning
  paragraph is present for elevated profiles.
- **Profile help moved into a tooltip**: the description now shows in a
  question-mark button (HelpCircle) beside the Profile label — where a
  help affordance belongs — via the app's Radix tooltip (max-width 300px,
  follows the selected profile, hidden until a profile is loaded). The
  safety warning for elevated profiles stays visible under the select,
  wrapped with the alert icon.
- Fixture server (scratch, dev-only) gained `/api/v1/scan-profiles` and
  `/api/v1/scanners` mirroring the backend's builtin profile registry so
  the dialog verifies with live-shaped data.

## [1.19.5] - 2026-09-22

The blend-mode shadow bands of 1.19.4 solved the compounding, but an
`isolation: isolate` group of 3×N blend strokes still forced the browser to
maintain and recomposite an offscreen buffer on every pan/zoom frame — on
real graph sizes the canvas stayed laggy. Shadows on cables are gone.

### Removed
- **Cable shadows entirely**: the `renderLinkShadow` layer (three
  `mix-blend-mode: darken` ink strokes per cable, isolated group, 35% layer
  opacity) is deleted, together with its `SHADOW_BAND_*` /
  `SHADOW_LAYER_OPACITY` constants. The links layer is now the deepest
  paint layer again and carries only the cable halo + coloured strokes —
  nothing left that recomposites per frame; the lit-route animation holds a
  locked 60 fps (median/p95/max frame gap 16.7/16.7/16.8 ms on the fixture
  dataset, DOM verified: 0 blend paths, no isolate group, no cable-shadow
  filter).
- The small static `ink-shadow` filter on tray header text + count pill
  stays (text bboxes are real extents, the filter region is tiny and never
  animated).

## [1.19.4] - 2026-09-22

The capped-filter shadow of 1.19.3 was correct but expensive: the whole-links
layer blur re-rasterized on every pan/zoom frame and every frame of the route
flow animation, and the canvas became laggy.

### Changed
- **Filter-free soft shadows**: the cable shadow is now painted as three
  concentric opaque ink strokes per cable into an isolated layer whose strokes
  blend with `mix-blend-mode: darken`, composited at 35% opacity for the soft
  translucent look. Overlapping shadows take the darker ink instead of
  stacking alpha, so the shadow still can never compound — a merged fan of
  cables casts the same soft shadow as one cable — but there is no blur
  filter left to re-rasterize: the lit-route animation now holds a locked
  60 fps (median/max frame gap 16.7/16.8 ms on the fixture dataset).
- The tiny static ink-shadow filter on tray headers stays (small, non-
  animated, no cost).

### Fixed
- The shadow band paths need `fill="none"` like their cable siblings —
  without it, each open curve closed with a straight chord and painted gray
  wedges across the hierarchy gutter (spotted in verification, fixed before
  release).

## [1.19.3] - 2026-09-22

Second pass at the cable shadow: the shared union shadow of 1.19.2 still
compounded where cables ran near each other, because a blur composes
linearly — two neighbouring cables' shadow tails sum in the corridor
between them (measured 1.6x a lone cable at 3px spacing, worse for wider
bundles).

### Fixed
- **Shadow response is now capped, not linear**: the blurred union alpha is
  remapped through a `feFuncA` table that plateaus at 0.28 — just above a
  single cable's core response (0.22). Any amount of overlap saturates to
  the same ceiling, so a merged fan of eight cables casts exactly the same
  shadow darkness as one cable (worst-case ratio 1.27x, down from ~2x and
  unbounded). Genuinely separate cables keep their soft penumbra, and
  single-cable shadow darkness is unchanged (pixel-verified parity).
- The filter is a manual drop-shadow chain (blur → offset → alpha table →
  flood → composite) since `feDropShadow` cannot remap its alpha.

## [1.19.2] - 2026-09-22

Fix for the cable shadow introduced in 1.19.1: where several cables ran the
same way, their per-link shadows stacked into a near-black band.

### Fixed
- **Overlapping cables no longer stack their shadows**: the per-link shadow
  strokes are gone; the whole links layer now shares a single `feDropShadow`
  computed from the merged cable alpha, so any number of coincident cables
  cast exactly one shadow of constant darkness. The filter region is
  `userSpaceOnUse` over the layout bounds — near-straight cables with a
  zero-height bounding box can no longer clip it. Verified live in all
  arrange modes: pixel scans at the convergence stem of multiple cables show
  a uniform shadow band, and the route flow animation still renders through
  the filtered layer.

## [1.19.1] - 2026-09-22

Tray header cleanup on the topology canvas: the header loses its furniture,
the member count crosses to the right, and header text and cables pick up a
soft shadow for depth.

### Changed
- **Tray count moved to the top right**: the member-count pill now sits on
  the title line, opposite the tray name, replacing the muted description
  text that occupied that corner; the top-left keeps just the title.
- **Header separator removed**: the divider line under the tray title is
  gone, so a tray reads as one continuous card instead of a boxed header.
- The dead `sub` field is dropped end to end (`Box`, `ClusterMeta`, layout,
  page, tests) — no unused data plumbing behind the removed text.

### Added
- **Soft shadows**: tray titles and count pills carry a subtle ink drop
  shadow (`feDropShadow`), and every cable paints over two wide faint
  strokes that fake a blurred drop shadow. Layered strokes instead of an
  SVG filter on purpose — a filter region would clip near-straight cables
  (zero-height bounding boxes), and per-link rasterisation keeps the route
  flow animation cheap.

## [1.19.0] - 2026-09-22

Visual polish pass on the topology page, driven by field feedback on v1.18.0:
cables get their colour back, the canvas layers read foreground-to-background
as nodes → trays → cables, and the table view loses its dead zones.

### Changed
- **Coloured cables**: observed traceroute routes render as solid cyan,
  inferred links as dashed violet, with arrow markers matched to the cable
  colour — the gray-on-gray muting of the reference's saturated palette is
  gone; a selection still wins attention with the indigo accent.
- **Canvas layer order** is now foreground → background: nodes, group/site
  trays, connection lines — a cable can no longer cover a tray's title or a
  node label. Trays are non-interactive so link hover keeps working inside
  them, and they dim while a route is lit so the animation reads through.
- **Hot cables re-drawn last**: the selected / pinned-route / hovered cable
  paints above its siblings, so a later cable's dark halo can no longer
  silence the flow animation.
- **Topology counters moved to the app's status bar**: "14 nodes · 14 links ·
  3 trays" now lives in the footer status panel (new StatusSlot in the app
  shell — a page can pin live counters without spending in-page space); the
  filter row keeps only the match count and the no-evidence hint.

### Fixed
- **Table rows had a dead right edge**: body rows rendered 9 of the table's
  10 columns, so the right side of every row took no hover background and
  ignored clicks; the missing trailing cell is back.
- **Exposure / Findings collision**: the Exposure column was too narrow for
  its badge, which clipped into the Findings "—"; the columns are rebalanced.
- Arrange-mode buttons (Hierarchy / Groups / Sites / Radial) no longer render
  in the table view, where they did nothing.

## [1.18.0] - 2026-09-22

The topology graph now runs the network-topology-view reference engine: the
page wires the platform's live evidence into it, and the canvas wears the
platform's visual language — the logic is a faithful port, the pixels stay
Aegis.

### Added
- **Reference graph engine** (`web/src/lib/topology-graph.ts`, dependency-free
  and deterministic): tidy-tree hierarchy whose fan-out wraps into patch-panel
  grid rows, weighted-sector radial layout, and labelled cluster trays for
  Groups and Sites (members gridded inside, sorted by IP, numeric-aware);
  orthogonal cable routing with rounded corners and a gutter outside the grid
  so hierarchy links never cross a node; soft beziers across radial and trays;
  user drags are offsets on top of the canonical layout, so a re-render never
  moves a node a hand did not move.
- **Evidence-derived parent tree** (`deriveForest`): traceroute/gateway
  evidence resolves into asset-to-asset pairs and grows the tree — connected
  components are detected, a root is elected per component (no incoming
  evidence first, then device metadata router > firewall > switch > access
  point, then degree, then id), the best-confidence upstream wins where
  several gateways claim a host, and the refinement is cycle-safe; non-tree
  edges survive as cross links and render as curves. Without evidence the
  synthetic per-site star feeds the same engine. Trees of a forest pack side
  by side, so disconnected networks stay separate regions.
- **Graph canvas** (`web/src/components/topology/TopologyGraph.tsx`) with the
  reference interaction set: cursor-anchored wheel zoom, pan, node dragging
  via offsets, 380 ms layout interpolation (reduced-motion aware, paused
  while dragging), collapse/expand branches (double-click, the +N badge or
  the detail panel), route lighting — click lights the full path to the
  gateway, shift-click pins a trace and the filter row grows removable trace
  chips — hover neighbourhood isolation when nothing is lit, node and link
  tooltips (observed route vs inferred link with its confidence), a minimap
  with viewport rectangle and click/drag jumping, keyboard walk (arrow keys
  move parent/child/siblings, Enter pins the trace, F fits, Escape clears),
  fitKey-driven refits that never interrupt a drag, a zoom-percentage chip,
  and an empty state with one-click filter reset.
- **Four arrange modes** on the page — Hierarchy / Groups / Sites / Radial —
  replacing the previous mode toggle and layout-algorithm controls; "/" jumps
  to the new search field, which dims non-matching nodes and reports the
  match count; "Reset layout" drops every dragged node back into its
  canonical place.
- **Layout unit tests** (`web/src/lib/topology-graph.test.ts`, 22 tests):
  patch-panel wrapping (4-wide rows, 3+2 fan grids), subtree block nesting,
  weighted radial sectors, tray geometry and IP ordering, forest packing,
  best-confidence parenting, cycle survival, route-set union, offsets,
  repeat-run determinism over a 100-node mixed graph, and cable/curve
  geometry.

### Changed
- **Replaced** the previous sites-view engine (`lib/topology-layout.ts`, its
  BFS/force strategies and its stability pins) with the reference engine:
  positions are canonical per graph + offsets, so stability comes from
  determinism plus animated transitions instead of a layout cache; drag pins
  are offsets and survive refetches and mode switches.
- Node rendering, edge colours, trays, tooltips, legend and furniture keep
  the platform's existing visual language (risk fills, group rings, agent
  rings, popover chips, mono labels); the table view, asset detail panel,
  group management and every data query are unchanged.

## [1.17.0] - 2026-09-22

The sites view of the topology graph now lays nodes out from the actual
network topology instead of a generic star: the real gateway ends up in the
middle, hierarchies layer top-down, meshed networks untangle, and the
picture stays put when the page refetches.

### Added
- **Topology-aware layout engine** (`web/src/lib/topology-layout.ts`,
  dependency-free and fully deterministic — same graph, same picture):
  connected-component detection; root/infrastructure election from device
  metadata (router > firewall > switch > access point) and graph degree —
  never from IP addresses or subnet membership; per-component shape
  classification (star / near-star, tree, mesh, isolated).
- **Shape-matched layouts**: star/near-star components use a centered radial
  layout (root in the middle, children evenly on rings sized from real node
  radii and label widths); tree/hierarchical components layer top-down with
  the infrastructure at the top and crossing-free child order; mesh/cyclic
  components get a deterministic force-directed relaxation that reduces
  overlap and long edges; disconnected components pack as separate compact
  regions (unlinked assets collapse into one grid).
- **Position stability**: an unchanged graph re-renders without any
  re-layout; small updates adjust the affected area (radial rings keep
  previous angles, hierarchy keeps previous left-to-right order, force
  warm-starts from the previous positions); user-dragged nodes pin where
  dropped and are immovable obstacles for the collision pass; "Reset
  layout" returns to the canonical picture.
- **Node dragging** in the graph view (drag a node to move it; pan, zoom,
  selection, tooltips, detail panel all unchanged) and a layout control bar
  for the sites view: Auto / Radial / Hierarchy / Force plus Reset and Fit
  view, styled with the existing segmented-control and overlay components.
- **Layout unit tests** (`topology-layout.test.ts`, run with the new
  `npm test` / vitest): gateway + 5 and gateway + 15 clients (root centered,
  even rings, compact), router → switch → clients layering, disconnected
  networks as separated regions, cyclic mesh overlap-free and
  deterministic, node add/remove preserving survivor positions, pinned
  nodes staying put, and repeat-run stability over a 100-node mixed graph.

### Fixed
- **Sites view placed nodes with a synthetic star while drawing real
  traceroute edges**: the old `layoutBySite` guessed a hub from asset type
  metadata and never looked at the topology evidence, so when the actual
  gateway wasn't typed as `router` it sat on the ring while every observed
  route fanned out of it — long edges, an unbalanced fan and big empty
  areas (the reported "central gateway off-center" bug). The layout is now
  computed from the evidence graph itself; the synthetic star remains only
  as the no-evidence fallback, feeding the same engine.

## [1.16.1] - 2026-09-22

### Fixed
- **Vulnerability sort was dead** — the UI sent sort keys
  `published` / `name` / `cvss` / `kev` while the server-side ORDER BY
  whitelist only knows `published_at` / `updated_at` / `cve_id` /
  `cvss_score` / `known_exploited`. Every user-chosen option (and the
  asc/desc toggle) silently degraded to the fixed default relevance order,
  so clicking sort never changed anything. The whitelist now normalizes
  case and accepts the friendly aliases (unknown keys still fall back to
  the default order — user input never reaches SQL), the UI sends the
  contract keys, and the order-clause test pins the aliases.

## [1.16.0] - 2026-09-22

The MAC address actually lands in the inventory now (it silently never
did), the asset page surfaces it where you look for it, and version
tooltips in tables are readable again.

### Fixed
- **MAC addresses were never stored — every interface write failed
  silently**: `InterfaceRepo.Upsert` and `AddIP` write with
  `ON CONFLICT (asset_id, mac)` / `(interface_id, ip)`, but migration 0003
  created only *plain* indexes on those column pairs. PostgreSQL rejects
  every such write with `42P10` (no unique constraint matching the conflict
  target) and `ensureInterface` swallowed the error, so
  `network_interfaces` and `ip_addresses` stayed empty for the whole
  product: no MAC address, no NIC vendor, no observed addresses anywhere.
  Migration 0030 dedupes defensively and backfills both unique indexes.
- **Interfaces table would have rendered blank Address/VLAN columns even
  with rows**: the asset bundle serialized raw `domain.Interface`
  (`addresses[]`, `vlan_id`) while the browser reads `ip` / `vlan`. The
  bundle and `/assets/{id}/interfaces` now emit a flattened
  `interfaceView` (ip = primary observed address, vlan = vlan_id); the
  frontend mapping keeps address/vlan_id fallbacks.
- **Interface upsert failures are logged** instead of vanishing — the
  42P10 class of failure erased inventory data for the entire product
  lifetime without a single warning.
- **Version tooltips clipped by table edges**: `VersionCell` used an
  absolutely-positioned CSS bubble inside the table's
  `overflow-x-auto` container, so the tooltip was cut off at the table
  boundary and unreadable. It now renders through a Radix portal tooltip
  with collision-aware placement (the shared dark arrow is dropped for
  the popover-toned bubble).

### Added
- **MAC address on the asset Identity card**: the Overview tab now shows
  the primary interface's MAC (and its NIC vendor) next to Address/FQDN —
  previously the address was only visible in the Network tab's Interfaces
  table, if rows existed at all.
- **Agent-reported NICs are persisted**: `LinkInventory` received the
  agent's interfaces (authoritative MAC/name/MTU/status/addresses) and
  dropped them on the floor. They are upserted now (matched by MAC,
  addresses attached), so agent-covered assets get real interface rows
  with machine-reported MACs.

## [1.15.0] - 2026-09-22

Realtime streaming actually streams, asset-group membership works, the
topology graph shows real traceroute evidence, and MAC addresses with their
resolved hardware vendors are now first-class inventory data.

### Fixed
- **Scan panel live tail was dead** (every transport): log events were
  broadcast to the WebSocket fan-out BEFORE persistence, so they carried no
  sequence number and the browser dropped every live line as a replay.
  The joblog streamer now persists first and re-publishes the seq-stamped
  copies (`aegis.internal.ws.fanout.v1`); live lines dedupe correctly
  against the REST history they loaded on open.
- **Scan counters froze at zero in hub/connector mode**: `UpdateScanStats`
  reports were written to the database but never broadcast, state reports
  rode without stats (the UI folded them into zeros), and the internal
  `progress: -1` keep-current sentinel leaked to browsers. Stats-only
  reports now broadcast too, progress is omitted instead of sentinel, and
  the UI MERGES stat fields instead of replacing them (list rows included).
- **Asset-group membership never saved**: `GroupRepo.AddMembers` passed the
  group id to squirrel as a *column string* - the uuid text was rendered
  verbatim into the SELECT list and the `?` placeholder had no argument, so
  every membership insert failed with a bind error. The id binds as $1 now.
  The create dialog's ticked assets were dropped client-side too: the
  context discarded `assetIds`, so nothing ever called the membership PUT.
  POST /asset-groups accepts `asset_ids` (create with members in one call),
  PATCH accepts `asset_ids` with server-side replace-all diff, errors toast
  (success toasts moved into mutation callbacks), the duplicated
  asset-group route block is gone, and a query-shape regression test plus a
  Postgres integration test pin the behavior.
- **Topology lines were decorative**: sites view drew a synthetic
  hub-and-spoke star (hub guessed from device type) and groups view drew
  links only when a cluster contained a router-typed asset - usually
  nothing. The page now renders the REAL `topology_edges` evidence
  (traceroute routes, gateway links) in both views, resolving hop nodes to
  inventoried assets by IP; solid = observed route, dashed = inferred
  gateway link. The synthetic star is only a fallback when no trace
  evidence exists, and the table's Upstream column shows the actual
  observed upstream hop.

### Added
- **Vulnerability source filter**: the backend had `?source=` all along but
  the UI never exposed it - a Source dropdown (NVD / CVE List v5) now
  filters the list, rows show their feed, and the published date range
  (already supported server-side) is actually sent.
- **MAC address + hardware vendor** (migration 0029): nmap resolves the OUI
  vendor of on-link MACs but the pipeline discarded the string (only a
  device-type hint survived) and only the discovery phase captured MACs.
  Discovery and the -O phase now both carry MAC + vendor through
  `host_up` observations; `network_interfaces` gains a `vendor` column,
  the observed IP is finally attached to the interface row (AddIP existed
  but had zero callers), and the real vendor upgrades the built-in OUI
  guess without trampling agent-reported data. Asset detail shows MAC +
  vendor per interface.

## [1.13.0] - 2026-09-21

The interface is replaced wholesale with the redesigned console (React 19 +
Tailwind 4 + Radix/shadcn design system + Recharts): thirteen pages, a new
login screen, a command palette and persistent asset groups. Every page is
wired to the real /api/v1 surface - the redesign's mock data layer is gone.

### Added
- **Redesigned web console** (`web/`): hash-routed pages for Overview, Assets,
  Asset detail, Topology, Scans, Vulnerabilities, Findings, Detections,
  Events, Agents, Connections, Reports and Settings; collapsible sidebar with
  live badge counts, site scope switcher, command palette, severity/risk
  visual language and a dedicated login screen. Authentication keeps the
  rotating-session architecture (access JWT in memory, HttpOnly refresh
  cookie, single-flight renewal, cross-tab propagation).
- **Asset groups** (migration 0025): analyst-defined grouping of assets with
  color/icon/kind metadata and a many-to-many membership table. Full CRUD +
  membership API (`/asset-groups`), org-scoped and audited; the inventory
  renders group chips, group-filtered views, bulk assign and a groups manager.
- **Detection triage** (migration 0026): detection matches now carry a
  workflow status (`new | investigating | contained | closed`) with
  `PATCH /detections/matches/{id}`; the Detections page is a working triage
  queue with status counters instead of a read-only stream.
- **List enrichment**: `GET /sites` rows carry `asset_count`; `GET /assets`
  rows carry per-asset open-finding severity counts (one aggregate, no N+1);
  `GET /metrics/timeseries?metric=events` returns per-category daily volumes
  for the overview's stacked event chart.
- **Command palette** (Ctrl/Cmd-K): navigation, actions (new scan, generate
  report, enroll agent) and asset-group jumps.
- **Version tooltip preserved**: the v1.10/v1.11 normalization transparency
  tooltip (reported vs normalized version, epoch/upstream/revision structure,
  grammar and well-formed verdict) is rebuilt in the new design language and
  shows on service and software tables.
- **Realtime streaming surface** (`internal/joblog`, `security.scan.log.v1` /
  `security.scan.state.v1` / `security.notification.v1`): WebSocket endpoint
  `/api/v1/ws` (token via `access_token` query param, org-checked channels)
  streams structured job logs, scan lifecycle state and notifications; job
  log lines persist in `scan_job_logs` (migration 0027) with cursor-paged
  history at `GET /scans/{id}/logs` and worker retention
  (`AEGIS_JOBLOG_RETENTION_DAYS`, default 7).
- **Job log capture across every scan transport**: the shared pipeline logs
  phase transitions, per-host discovery/port/service/OS/topology results,
  kill-switch and completion lines; nmap tees argv + raw stderr into the log;
  the SSH collector logs per-host connect/auth/collect outcomes; hub and
  connector agents stream lines through hub reports; failures publish
  `scan.result` events so failed scans notify like completed ones.
- **Polling replaced by push**: scan detail/list pages fold WS state events
  into their query caches (3-4s polls remain only as a degraded-path
  fallback when the socket is down); notifications drive toasts and the
  bell's cache invalidation. New `Job log` console on the scan sheet with
  level filters, follow-tail, copy/download and history paging.
- **E2E**: `scripts/e2e-stream.sh` + `scripts/streamclient` verify the whole
  path against real Postgres/NATS - WS authz, live log/state/notification
  delivery during a running scan and REST history replay (11 checks).
- Playwright suite rebuilt for the new DOM (12 specs: auth flows, overview,
  inventory + groups, scan-dialog payload contract, findings triage PATCH,
  CVE detail sheet).

### Changed
- **Scan dialog speaks the real scan contract**: server-backed profiles
  (`/scan-profiles`), site-scoped scanners, denylist, per-host SSH inventory
  credentials (`ssh_hosts` with redacted read-back), elevated-profile
  confirmation (`active_validation`/`full_audit`) and optional recurring
  schedules created through `/schedules`.
- **Scan detail** renders the actual job record: task list with retries,
  per-host SSH collection summaries (OS, package count, duration, errors),
  inventory changes and cancel for live jobs.
- **Findings workflow** matches backend semantics (open/acknowledged/
  in_progress/resolved/accepted_risk/false_positive/suppressed) with evidence
  records, status history, owner assignment, bulk transitions and suppression
  reasons - all through the real endpoints.
- **Connections page** drives the connector registry end to end: create with
  a one-time connect command, rename/re-site, configuration push using the
  real settings keys (`heartbeat_secs`, `engine`, `nmap_path`, `ssh_*`),
  token rotation, revoke and delete.
- **Reports page** lists jobs with live progress, downloads artifacts through
  the authenticated blob path and offers the full report-type catalogue
  (executive/technical/inventory/topology/events/asset-risk/scan-comparison/
  site/device detail).
- **Settings** covers sites + networks, account (profile, organization
  rename, password change), scan-profile CRUD, user management (roles,
  disable, password reset), scanners (default selection, legacy enrollment),
  feeds (status + on-demand sync) and the audit log with CSV export.
- Playwright/`vite` toolchain upgraded (Vite 7, Tailwind 4 via the Vite
  plugin, React 19, Recharts); the old chart/table components and mock data
  layer are removed.

## [1.12.0] - 2026-09-21

Version comparison becomes domain-aware. An installed distro package and
an upstream CVE boundary live in different version domains: the Ubuntu
openssh-server package reports `1:10.0p1-5ubuntu5.4` (Debian grammar:
epoch 1, upstream `10.0p1`, revision `5ubuntu5.4`) while the CVE for the
same product speaks upstream releases (`affected < 10.5`). Judging one
with the other's comparator silently lies — the epoch sorts above every
epoch-less bound, so each upstream-only CVE boundary appeared "older"
than the package and the vulnerability was hidden. Matching now resolves
the comparison domain per bound and never compares across domains.

### Added
- **Structured OpenSSH version domain** (`internal/pkgversion`):
  `ParseOpenSSHVersion` parses the Portable OpenSSH release grammar
  `<release>[p<update>]` into the structured
  `{Major, Minor, Patch, HasPatch, Update, HasUpdate}` form, and
  `CompareOpenSSH` orders hierarchically — major, then minor, then
  patch, and only for equal base releases the pN update level:
  `10.0 < 10.0p1 < 10.0p2 < 10.1`, `10.0p1 < 10.5` (base 10.0 < 10.5),
  `10.5p1 > 10.5`, `10.9 > 10.5`, `11.0 > 10.5`, `9.9p2 < 10.0`. The pN
  suffix is an explicit update component (NVD CPE data confirms: OpenSSH
  9.9 p1 stores version `9.9`, update `p1`) and is never dropped in
  normalization. Distro packaging never parses in this domain — a full
  Debian version must be projected to its upstream part first, and the
  comparator rejects one outright instead of guessing.
- **Domain-tagged version constraints** (`internal/domain`): `VersionDomain`
  (`debian` / `rpm` / `apk` / `openssh` / `upstream` / `semver` /
  `python` / `generic`) and
  `VersionConstraint {Domain, Introduced, Fixed, LessThan, LessThanOrEqual}`
  name the grammar every applicability statement is evaluated under. An
  OpenSSH CVE is `{Domain: openssh, LessThan: "10.5"}`; an Ubuntu OVAL
  advisory is `{Domain: debian, Fixed: "1:10.0p1-5ubuntu5.5"}`.

### Changed
- **CVE matching is domain-aware** (the headline fix): every
  installed-vs-bound comparison now routes through
  `fingerprinting.ComparePackageBound` / `CompareCPEBound`:
  - A **distro-format bound** (Ubuntu OVAL fixed-in `1:10.0p1-5ubuntu5.5`,
    OSV Debian range `3.0.2-0ubuntu1.16`, rpm release `8.0p1-6.el8`, apk
    `-rN`) orders fully under the distro grammar — revision-only security
    uploads stay decisive.
  - An **upstream-only bound** (`10.5`) is compared against the installed
    version's upstream component: the epoch and distro revision are
    packaging artifacts the CVE boundary must never see. When both sides
    parse as structured OpenSSH releases the verdict is made in the
    OpenSSH domain; other upstream bounds (OpenSSL-style letter patch
    levels `1.0.2k`, tilde pre-releases `2.0~rc1`) order under dpkg
    upstream rules. Custom-versionType CPE ranges (what NVD declares for
    OpenSSH) project a distro-packaged observed version
    (`10.0p2-5ubuntu5.4` -> upstream `10.0p2`) before the structured
    verdict.
  - The OSV package path, the CPE/service path and the distro advisory
    plane (OVAL/gost, confidence 1.0) all share the routing. Match
    evidence records `bound_domain`, `projected_version` and the
    domain-tagged `constraint`, so every verdict is auditable.
- **Tests pin the scenario end to end**: the user's exact case
  (`openssh-server` reported `1:10.0p1-5ubuntu5.4` vs OpenSSH < 10.5 ->
  affected, evidence `bound_domain=openssh`,
  `projected_version=10.0p1`), every ordering relation of the OpenSSH
  grammar in both directions (antisymmetry), parser rejection tables
  (a full Debian version never parses upstream), the CPE
  start-exclusive bound, and a real Ubuntu 25.10 inventory of 76
  packages — epochs up to `5:`, tildes (`20260601~25.10.1`,
  `25.3~2g890873f5-0ubuntu2`), `+ds`/`+0.0.0~ubuntu24` suffixes,
  `~questing` docker backports and the upstream-format OpenSSH
  `10.0p2` — parsing cleanly under the Debian grammar.

## [1.11.0] - 2026-09-21

Version normalization becomes visible. v1.10.0 normalized package
versions at ingestion and matched CVEs on the normalized form, but the
surface barely showed it: discovered services kept their raw banner
strings (`10.0p2 Ubuntu 5ubuntu5.4`), and for versions that are already
canonical (`5.0.0~alpha1-0ubuntu8`) the old hover note never appeared —
normalization looked like it did nothing. This release closes that gap
end to end.

### Added
- **Service banner-version normalization (migration 0024)** — nmap `-sV`
  versions where the distro revision rides along after the upstream
  version (`10.0p2 Ubuntu 5ubuntu5.4`, `10.0p2 Ubuntu-5ubuntu5.4`,
  `OpenSSH_10.0p2 Debian 7`) are now composed and validated under the
  Debian grammar at the ingestion choke point and persisted as
  `service.version_norm` (`10.0p2-5ubuntu5.4`); the raw banner string
  stays on `detected_version` verbatim. Values that do not compose into
  a valid deb version fall back to the generic clean form, with the
  resolved grammar recorded. `fingerprinting.NormalizeServiceVersion`
  fills the same structured epoch/upstream/revision breakdown the
  package path provides.
- **Service CVE matching runs on the normalized version.**
  `CorrelateService` now feeds `version_norm` (raw fallback) into CPE
  range matching and keeps the raw banner on the evidence chain
  (`RawVersion`). A range miss by one CPE candidate version no longer
  silently discards a different candidate version: the synthesized CPE
  carrying the version under judgment is evaluated first, and only
  truly versionless candidates are barred from resurrecting a
  range-rejected CVE (potential-only).
- **Full version-detail tooltip (UI)** — a dedicated `VersionCell`
  component replaces the bare `title` note on the asset's services and
  software tables: hovering (or keyboard-focusing) a version opens a
  tooltip with the verbatim reported version, the normalized form CVE
  matching compares, the parsed `epoch / upstream / revision`
  structure, and the grammar + well-formed verdict (malformed values
  are flagged as excluded from matching). When the normalized form
  differs from the reported one, the cell displays the normalized form;
  for already-canonical versions like `5.0.0~alpha1-0ubuntu8` the
  tooltip shows the dpkg structure instead of silence.
- **`version_meta` on the asset payload** — `GET /api/v1/assets/{id}`
  attaches a computed `{raw, normalized, well_formed, grammar, epoch?,
  upstream?, revision?}` object to every service and software row,
  computed on read so rows collected before normalization existed
  render correctly immediately (no rescan required).

### Changed
- docs/API.md documents `service.version_norm`, service-level
  normalization and the `version_meta` read-time payload.

## [1.10.0] - 2026-09-21

Version normalization becomes a first-class pipeline stage: every
application version the platform collects — SSH dpkg/rpm/apk/pacman
sweeps, endpoint agents, connector scanners, nmap -sV fingerprints — is
now normalized once at the ingestion choke point, stored alongside the
verbatim raw string, and CVE checks (OSV ranges, NVD/CVE-v5 CPE ranges,
distro advisories) run against the normalized form. Banner noise no
longer reaches ordering decisions; grammar-canonical forms do.

### Added
- **Package-version normalization layer (`internal/pkgversion`)** — a
  reusable, registry-based version abstraction for the vulnerability
  matcher: a structured `PackageVersion` (raw string preserved verbatim
  plus epoch/upstream/revision), strict Debian-policy parsing with
  sentinel errors, and a dpkg-faithful comparison (verbatim port of
  dpkg's `verrevcmp`) that keeps revision-only Ubuntu security fixes
  ordered correctly (`1:10.0p1-5ubuntu5.4 < 1:10.0p1-5ubuntu5.5`),
  handles tilde pre-releases and epochs, and compares digit runs as
  strings so numeric components of any length are overflow-free. Zero
  allocations on the comparison hot path; no dpkg binary, no third-party
  dependencies. rpm / apk / pacman / semver backends plug into the same
  `VersionParser` / `VersionComparator` registry when they migrate.

- **Ingestion-time version normalization (`fingerprinting.NormalizeObservedVersion`)** — one pass for every collected version: scanner/banner noise is stripped, the value is validated and canonicalized under its package grammar (Debian Policy via `pkgversion`, rpm, apk-tools, SemVer, PEP 440; unknown labels fall back to the generic grammar exactly like `CompareEcosystem`), and the result is persisted as `software.version_norm` (migration 0023). `software.version` keeps the raw collected string verbatim. A value that does not parse under its grammar is flagged (`well_formed=false`) — a data-quality signal, never a guess.
- **CVE matching runs on the normalized form.** The correlator feeds `version_norm` (falling back to raw when empty) into OSV range checks, the OVAL/advisory plane (`installed` vs `fixed_in`) and CPE identity matching; findings evidence keeps both sides (`version` normalized + `version_raw`, `installed` raw + `installed_norm`) so every verdict stays explainable down to the exact dpkg string.
- The asset software inventory (API and UI) exposes `version_norm`; the software table shows the normalized form on hover when it differs from the raw value.

### Fixed
- **Debian/Ubuntu CVE range matching could silently misorder versions.**
  The in-house dpkg comparison ran `strconv.Atoi` over digit runs,
  silently clamping 20+ digit runs into wrong verdicts, accepted garbage
  epochs (`a:1.0`), and guessed orderings for malformed input. The deb
  path now delegates to the strict, overflow-free `pkgversion` backend;
  malformed versions come back incomparable (which the matcher already
  treats as "never match") instead of being ordered by accident.
- **OSV records with distro-qualified ecosystems (`Debian:12`,
  `Ubuntu:22.04 LTS`) fell through to the generic version ordering.**
  `CompareEcosystem` now routes the platform's own inventory labels
  (`os_debian` / `os_rpm` / `os_alpine`) and distro-qualified feed names
  to the correct package-manager grammar via prefix matching.

## [1.9.0] - 2026-09-20

Field-report release: the SSH inventory pipeline now delivers what it
collects, shows its work, and lets operators solve host-key verification
from the UI. "The best we scan, the best we can secure" — packages land
on the asset with exact versions and are matched against the advisory
plane (OVAL first, CVE/OSV fallback), so findings surface immediately
and re-surface automatically when feeds bring new CVE data later.

### Fixed
- **SSH scans showed no results, no reports, no packages — ever.** The
  connector/agent executor synthesized the SSH task id as
  `<scan-uuid>-ssh`; every observation carried that composite string and
  the server's observation apply died on the `scan_observations.task_id
  UUID` column (SQLSTATE 22P02, one WARN per observation, ~30+ per host).
  Scans still "completed" because state/stats updates bypass observation
  insertion. Task ids are now real UUIDs threaded through creation,
  observations, state updates and the cancel paths (the nmap discovery
  task had the same latent disease).
- **Connector-scanner scans ended "complete at 0%".** The final
  completion report carried no `Progress` field and the hub wrote 0.0
  over the 100 the executor had just reported. The hub now treats an
  absent progress as "keep the current value", the repository clamps
  `completed` to 100, and negative progress means "keep" end to end.
- **"Accept any host key" could not actually unblock lab scans.** The
  host-key policy was env-var-only on some scanner planes and the
  "pin the host key" advice was unactionable (nothing could populate a
  pinned key). Policy is now a per-scan decision with connection
  fallback: per-host `pinned_key` > per-scan `ssh_insecure_host_key` >
  connection `ssh_insecure` / `ssh_pinned_key` >
  `AEGIS_SSH_SCAN_HOST_KEY_POLICY` env > refuse, and the refusal error
  names every working option.

### Added
- **"What exactly was scanned over SSH" is now answerable in the
  product.** The collector records a per-host command log (fixed
  read-only command, outcome, output line count) plus OS fingerprint,
  package count, duration and error; the scan view renders it
  ("SSH collection — what was scanned") and a `ssh_collection`
  observation persists the audit trail in `scan_observations`.
- Hermetic sshd stub (`scripts/sshd_stub.go`) + e2e section 21d: a real
  SSH scan against a stub host must complete at 100%, persist
  observations with zero apply failures, land packages (name, version,
  ecosystem) on the asset and expose the command log.
- Connection setting `ssh_pinned_key` (Connections → Configure → SSH
  collector) and scanner env `AEGIS_SSH_SCAN_PINNED_KEY`.
- Plan of record: docs/SSH_VULNERABILITY_SCANNING.md (root causes, use
  cases, user flows, architecture, verification matrix).

# Changelog

All notable changes to the Aegis Security Platform are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [1.8.0] - 2026-09-20

Consolidated release, re-versioned to avoid confusion between the
intermediate tags: identical content to [1.7.0] (per-scan SSH hosts
feature work) plus [1.6.2] (SSH password-auth fix) in a single version.
1.8.0 is the release to run; the intermediate tags remain for history.

### Added

- **Per-scan SSH hosts with per-host credentials.** SSH inventory scans
  carry their own target list: the create-scan dialog (and `POST /scans`
  via `ssh_hosts`) accepts any number of hosts, each with its own port,
  username and password-or-private-key credentials — mixed credential
  styles in one scan. Every executor kind (embedded scanner, hub agent,
  aegis-connector) runs exactly that set; scans without a list fall back
  to the scanner connection's SSH collector defaults. Credentials are
  stored with the scan config and redacted ("***") in all API responses;
  audit entries record only the host count.

### Changed

- **Compact scan-type selection.** The new-scan dialog drops the
  profile-card grid that could push itself off small screens: a single
  grouped dropdown (Network / Agent-less / Custom presets) with a
  scrollable listbox, and the SSH path gets a real multi-host editor
  with add/remove rows, per-host auth and a height-capped list so the
  modal never overflows.
- The scanner config form and the new-scan SSH editor document the
  credential order (private key first, then the password) and the
  unencrypted-private-key requirement; CONNECTORS.md documents the
  fallback behavior.

### Fixed

- **SSH inventory scanning with login + password failed with
  `ssh key: ssh: no key found`.** An unusable configured key path (e.g.
  a `*.pub` public key or PuTTY file, or a path the scanner cannot
  read) hard-failed authentication before the password was ever
  offered, so every host was reported unreachable with a key error even
  though password auth was configured. The key is now pre-validated
  once per scan: a broken or unreadable key is dropped with a loud
  warning and password auth takes over; when the key is the only
  credential the scan fails fast with one actionable error instead of N
  identical per-host failures. Password auth also tries
  keyboard-interactive (PAM-only sshd setups are reachable with the
  same credentials), and key parsing failures name the file and the
  likely cause instead of the raw ssh error. Covered by hermetic
  in-process sshd handshake tests (password-only,
  keyboard-interactive-only, broken-key fallback, wrong password).

## [1.7.0] - 2026-09-20

### Added

- **Per-scan SSH hosts with per-host credentials.** SSH inventory scans
  carry their own target list: the create-scan dialog (and `POST /scans`
  via `ssh_hosts`) accepts any number of hosts, each with its own port,
  username and password-or-private-key credentials — mixed credential
  styles in one scan. Every executor kind (embedded scanner, hub agent,
  aegis-connector) runs exactly that set; scans without a list fall back
  to the scanner connection's SSH collector defaults. Credentials are
  stored with the scan config and redacted ("***") in all API responses;
  audit entries record only the host count.

### Changed

- **Compact scan-type selection.** The new-scan dialog drops the
  profile-card grid that could push itself off small screens: a single
  grouped dropdown (Network / Agent-less / Custom presets) with a
  scrollable listbox, and the SSH path gets a real multi-host editor
  with add/remove rows, per-host auth and a height-capped list so the
  modal never overflows.

## [1.6.2] - 2026-09-20

### Fixed

- **SSH inventory scanning with login + password failed with
  `ssh key: ssh: no key found`.** An unusable configured key path (e.g.
  a `*.pub` public key or PuTTY file, or a path the scanner cannot
  read) hard-failed authentication before the password was ever
  offered, so every host was reported unreachable with a key error even
  though password auth was configured. The key is now pre-validated
  once per scan: a broken or unreadable key is dropped with a loud
  warning and password auth takes over; when the key is the only
  credential the scan fails fast with one actionable error instead of N
  identical per-host failures. The client also skips an unparseable key
  when a password is available.
- **Clearer key errors.** Private-key parsing failures now name the
  file and the likely cause ("no PEM private key found — a *.pub public
  key, PuTTY .ppk or config file won't work; point the key path at the
  PRIVATE key"), replacing the raw `ssh: no key found` message;
  passphrase-protected keys get their own explanation.
- **Password auth now also tries keyboard-interactive.** Hardened sshd
  setups that disable plain `password` but keep PAM
  keyboard-interactive authentication are reachable with the same
  login + password credentials.

### Changed

- The scanner config form and the new-scan SSH tab document the
  credential order (private key first, then the password) and the
  unencrypted-private-key requirement; CONNECTORS.md documents the
  fallback behavior. New hermetic in-process sshd handshake tests cover
  password-only servers, keyboard-interactive-only servers, the
  broken-key fallback and the wrong-password failure.

## [1.6.1] - 2026-09-20

### Fixed

- **`make dev` was broken by invalid compose YAML (v1.6.0 regression).**
  The version build args shipped as
  `args: { AEGIS_VERSION: ${AEGIS_VERSION:-dev} }` — `${...}` braces are
  illegal inside YAML flow mappings, so docker compose aborted with
  `yaml: line 133: did not find expected ',' or '}'` before starting
  anything. The interpolation is now quoted in all four Go service
  builds. `make dev` also exports `AEGIS_VERSION=$(git describe)` like
  `make docker` does, so locally built stacks report the real version
  instead of "dev".

## [1.6.0] - 2026-09-20

### Added

- **Scan-type tabs in the new-scan dialog.** The dialog now opens on two
  tabs: Network (profile cards grouped by intent — discover, inventory,
  elevated — plus org custom presets) and SSH inventory (agent-less
  package collection from the scanner's SSH host configuration). The
  ssh_inventory profile was implemented server-side since v1.3.0 but was
  unreachable from the UI; its scope is the scanner configuration rather
  than the network, so creating such a scan no longer requires targets
  (target-less network scans still fail with 400). Scan detail gained a
  packages-collected counter. e2e-features 69 checks.

### Changed

- **Quieter UI.** Page headers and toolbars lost their product-narration
  paragraphs; titles stand alone and guidance lives in the dialogs.
- **Docs and comments de-spec-ified.** Design-plan documents
  (VULS_ADAPTATION, SPEC-COMPLIANCE) are removed together with the
  ~230 "(spec §NN)" / "(vuls adaptation §N)" annotations that had
  spread across docs, package comments and config files.

### Build

- **Semantic-release with conventional commits.** The VERSION and
  RELEASE_COMMIT files are gone; the git tag is the single source of
  truth. semantic-release tags vX.Y.Z, maintains this changelog and
  attaches packaged archives to the GitHub release; commitlint lints PR
  titles; make/Docker stamp versions from git describe or AEGIS_VERSION.

## [1.5.6] - 2026-09-20

### Added

- **Per-asset traceroute evidence: parsed paths + raw probe output.** New
 `asset_traces` table (one row per site+target, latest scan wins; history
 stays in observations) stores the full hop path (TTL, address, hostname,
 RTT), the method (`traceroute` / `gateway-l2` / `gateway-guess`), the
 probe family that produced it (nmap tcp-syn/udp/icmp/tcp-connect,
 tracert, tracepath, simulated), a `hop_ips` GIN-indexed array covering
 every address on the path, and the RAW engine output (nmap XML / tracert
 text, bounded at 24 KB). `Engine.Traceroute` now returns
 `Trace{Hops, Method, Raw}` so nothing parsed is separated from its
 evidence.
- **Asset detail "Traces" tab.** Lists every trace COVERING the asset's
 address (traces aimed at it and traces passing through it, e.g. a router
 on someone else's path): from -> to hop table with RTTs, method/probe/
 complete badges with plain-language hints, "this asset" highlight on
 hops matching the asset's own addresses, and a collapsible raw-output
 block. Backed by `GET /assets/:id/traces` (org-scoped).

### Fixed

- Topology observations now feed the trace table on both ingestion paths
 (hub-reported connector scans and the embedded scanner); the server-side
 direct-L2 gateway synthesis is reflected in the stored path and its
 confidence (0.65 vs 0.85 for observed routes).

## [1.5.5] - 2026-09-20

### Fixed

- **Topology scans of a subnet range (`192.168.1.0/24`) built no
 connection lines.** A successful traceroute to a same-subnet host is a
 single hop — the target answers at TTL 1 with no router in between —
 and a one-node path cannot form an edge, so every discovered host
 rendered as an isolated dot even though every trace "worked". The
 pre-1.5.4 builds only showed the gateway link when tracing failed
 completely (gateway guess), which is why single-host scans appeared
 connected while range scans did not. Both the scanner executor
 (`gateway-l2`, confidence 0.65) and the server-side observation
 applier now synthesize the default-gateway link for direct-L2 paths,
 so all hosts connect to their router: multi-hop routes stay as
 observed, partial routes keep the deepest-reachable-hop link, and
 the gateway itself is never linked to an invented parent.
 Regression-tested: `EnsureGatewayLink` hop matrix (direct, multi-hop,
 partial, gateway-target, IPv6, empty) and `topologyHops` payload
 normalization (in-memory shape, JSON round-trip shape, TTL timeouts,
 garbage payloads); suites: connectors 66, features 65, repro-bugs 21,
 auth 34.

## [1.5.4] - 2026-09-20

### Fixed

- **Topology graph rendered no connection lines, ever.** The UI read
 `source` / `dest` from each edge, but the backend emits
 `src_node_id` / `dst_node_id` — every ECharts link got undefined
 endpoints, so nodes displayed as isolated dots even when the server
 returned a fully connected graph (and the edges table showed dashes).
 The types and both views (graph links, table rows) now use the real
 field names. Regression-covered by a Playwright spec that feeds the
 exact backend edge shape and asserts the table resolves node labels
 and confidence.

### Changed

- **Topology graph fills the working area.** The canvas was a fixed
 520px strip, wasting half the page on large screens; it now sizes to
 `calc(100vh - 190px)` (min 480px) via the Chart component's new
 string-height support. Playwright asserts the canvas height.

- **Real traceroute on Windows: native tracert.exe fallback.** nmap's
 traceroute needs raw packets (Npcap + elevation) on Windows, so
 unprivileged connector scans degraded to a bare gateway guess even
 though a real route was one `tracert` away. The engine now falls back
 to `tracert -d -4` (ships with Windows, no admin needed) after the
 nmap probe ladder and before the Linux tracepath fallback; the parser
 keys on hop indices and IPv4 literals so localized Windows output
 ("Zeitüberschreitung der Anforderung.") parses identically — unresponsive
 hops become TTL gaps, never route failures. Override with
 AEGIS_SCANNER_TRACERT_PATH. Gateway-guess remains the last resort, so
 every host always links to at least its gateway.

## [1.5.3] - 2026-09-20

### Fixed

- **Scans executed by connector-connected scanners produced no
 assets/services/topology — only numbers on the scan page.** The hub
 applies reported observations through the server-side scanning
 orchestrator, but that instance was built without the asset-inventory
 service (`Inventory`) and without the topology repository, so every
 host/port/service report died with "hub: observation apply failed...
 scan inventory service is not configured" and traceroute reports were
 silently dropped. Scan state/stats still updated (they bypass the
 orchestrator), which made the scan look healthy while nothing was
 ingested. The server now wires the same `assets.Service` and topology
 repo the embedded scanner uses (including `AEGIS_ASSET_IP_STALE_DAYS`
 via the shared `assets.IPStaleFromEnv`), so connector scans provision
 assets, services, software and the topology graph exactly like local
 scans. Regression-checked by e2e-connectors: a dispatched connector
 scan must now produce assets (primary_ip in scope), services and
 topology nodes/edges.

- **Post-scan CVE correlation never ran for hub-reported scans (and any
 scan-completion event without organization_id).** The correlation
 subscriber requires `organization_id`, but scan-completion events only
 ever carried `scan_id` + `state`. The hub now resolves the org from
 the scan row and includes it in the event, the embedded scanner does
 the same, and the subscriber falls back to looking the scan up by id,
 so KEV/EPSS/CVE matching runs for every completed scan regardless of
 which path reported it.

## [1.5.2] - 2026-09-20

### Fixed

- **Binary version stamping was incomplete, so scanners registered as
 "dev/…".** The Makefile stamped only `main.version`; the connector's
 runtime version (`connectorapp.Version` — the one that lands in the
 scanners registry and heartbeats), the scanner's registration version
 and the endpoint agent's version kept their "dev"/hardcoded defaults
 even for release builds. Every version var is now stamped from the
 VERSION file by `make build` and by all Dockerfiles (server, worker,
 feed-worker, scanner, agent), so a released connector scanner reports
 e.g. `1.5.2/nmap` instead of `dev/simulated`.

### Changed

- **A simulated-fallback scanner can no longer pass unnoticed.** A
 connector scanner in `auto` mode used to degrade to the simulated
 engine *silently* when no nmap binary was found on its host. It now
 logs a loud warning on every engine resolution, and the heartbeat
 status carries `engine_detail` — a human-readable explanation of which
 engine is in use and why ("no nmap binary found on this host —
 producing SIMULATED results (install nmap or set nmap_path in the
 connection config)"). The registered scanner version string remains
 `<binary version>/<engine>` so the engine is always visible.
- **Broader nmap detection** (shared `scanner.DetectNmapPath`): PATH
 first, then the usual install locations — `/usr/local/bin`, sbin dirs,
 macOS Homebrew/MacPorts prefixes and Windows Program Files. The
 embedded scanner also re-detects via the same helper when its
 configured path is missing, instead of immediately degrading.
- **The scanners registry and the scan dialog spell the engine out.**
 Settings → Scanners renders the binary version plus an explicit
 "nmap engine" / "simulated engine" badge (tooltip explains the
 fallback; a warning line tells how to switch to real scans), and the
 scan-creation selector appends "— SIMULATED results (no nmap on host)"
 to affected scanners.

## [1.5.1] - 2026-09-19

### Fixed

- **Connector scanners were invisible to the scan UI for pre-1.5.0
 connections.** Migration 0020 only materialized the linked `scanners`
 row at enrollment time, so connections enrolled before the upgrade never
 got one — they appeared neither in Settings → Scanners nor in the scan
 dialog's selector. Migration 0021 backfills the missing rows, and the
 heartbeat path now creates the row on demand as an extra safety net.

### Changed

- **Heartbeat-driven liveness with real-time semantics.** Every connector
 heartbeat now cascades onto the linked scanners row (healthy + fresh
 `last_seen`; offline on shutdown), so scan UIs see connector scanners
 within one heartbeat instead of depending on the hub stream's slower
 registration path. The default heartbeat interval drops to 15s and the
 online window tightens from 4× to 2× the interval (30s floor) — a dead
 component shows offline in ~30s, not two minutes. Legacy hub agents go
 offline the moment their Jobs stream drops (previously they stayed
 healthy forever) and their liveness touch runs every 30s instead of 60s.
- **Graceful shutdown state.** `aegis-connector` sends one final
 `state=shutting_down` heartbeat on SIGTERM/SIGINT; the UI shows
 "Shutting down" (`conn_state: shutting_down`, migration 0021
 `connectors.shutdown_at`) until the freshness window passes, then
 offline — no more guessing between a crashed and a stopped component.
 The REST API returns `conn_state` (online / shutting_down / offline)
 alongside the boolean `online` on every connector view.
- **Strictly per-kind configuration forms.** The connector Configure
 dialog now renders only the options that exist for the kind: heartbeat
 for agent/collector; heartbeat, engine, nmap path and the SSH inventory
 collector for scanners. Server-side `ValidateSettings` types and bounds
 every known key (`engine` enum, `nmap_path`, `ssh_*`), so typos fail at
 save time instead of silently doing nothing on the component.
- **Scanner `nmap_path` option.** Scanner connections can point at a
 specific nmap executable on the scanner host (empty = auto-detect from
 PATH); pushed live and hot-applied between scans like the engine setting.
- **Connections page**: 5s status polling (was 15s) and an Edit dialog for
 rename/re-site — the documented fix for site-less scanner connections
 created before sites were required (Settings → Scanners hints them).
- Settings → Scanners polls every 10s and flags connector scanners that
 have no site assigned.

### Verified

- go build/vet/gofmt clean; unit tests including new ValidateSettings and
 ConnState/OnlineWindow tables; e2e-connectors extended to 61 checks
 (liveness cascade, conn_state, nmap_path hot-reload push, graceful
 shutdown → shutting_down → offline), e2e-features, e2e-repro-bugs and
 repro-auth suites; web tsc/vite clean.

## [1.5.0] - 2026-09-19

### Added

- **Connector scanners execute scans — the unified connection plane and
 the scan pipeline are one system.** A `scanner` connection created under
 Connections is now a first-class scan executor end to end:
 * Enrollment materializes a `scanners` row linked to the connector
 (migration 0020, `scanners.connector_id` + unique partial index) with
 the connection's required site; the row follows connector renames and
 re-sites, goes offline on revoke and is deleted with the connector.
 * The scanner hub (`aegis.scanner.v1.Hub`) accepts connector credentials
 (`x-aegis-connector-id` / `x-aegis-connector-secret`) alongside legacy
 enrollment tokens, mapping them onto the linked scanners row — one
 connection protocol, per-kind logic, as designed.
 * `aegis-connector` scanner role now runs the real scan pipeline: the
 executor was extracted from `cmd/scanner` into `internal/scanexec`
 (shared by the embedded scanner, hub agents and connectors), and the
 role opens the hub `Jobs` stream with its connector secret, executes
 dispatched scans and reports observations/state back. The engine
 (`auto`/`nmap`/`simulated`) and the SSH inventory collector
 (`ssh_hosts`, `ssh_user`, `ssh_password`, `ssh_key_path`,
 `ssh_insecure`, `ssh_timeout_secs`) are connection configuration and
 hot-reload live.
 * Scan dialog: explicit scanner selector (site-scoped, healthy scanners
 only, transport-labelled); the backend validates a chosen
 `scanner_id` against the site and rejects unhealthy/unknown ones
 (409) instead of silently re-targeting.
 * Settings -> Scanners lists connector-driven scanners with a
 "Connection" badge and shows detected tooling.

### Fixed

- **Connections page: configuration is no longer a raw JSON box.** The
 Configure dialog is now a structured per-kind form (heartbeat interval,
 scan engine, SSH collector fields) with an "Advanced: edit raw JSON"
 escape hatch; unknown role-specific keys survive every round-trip.
- **Latent hub-agent bug inherited from the legacy agent mode:** hub
 client RPCs used the default proto codec against the hub's JSON codec,
 failing every call with "failed to marshal... want proto.Message".
 All hub calls now pin the JSON content subtype — token-enrolled hub
 agents (`aegis-scanner -mode=agent`) get this fix too.

## [1.4.1] - 2026-09-19

### Fixed

- **Connections UI showed "token expires just now" for every fresh token.**
 The connect-command dialog rendered the one-time token's `expires_at` with
 `relTime()`, a past-only "ago" formatter — fed a future timestamp it always
 fell into the `mins < 1 -> "just now"` branch, so a token minted with its
 full 24h TTL claimed to expire immediately for its entire lifetime. New
 `untilTime()` formatter renders future timestamps as a countdown
 ("in 30s / in 5m / in 23h / in 6d"), degrades to the ago-form once passed,
 and the dialog now also carries the exact UTC expiry on hover.

### Changed

- **Compose: the connector/agent gRPC endpoint is now exposed.** The server
 service publishes `9090:9090` (it was deliberately kept internal, so
 external components could not enroll against a compose deployment) and
 ships `AEGIS_CONNECTOR_PUBLIC_ADDR=localhost:9090` (overridable from
 `.env`) so the UI connect command is correct out of the box for components
 on the compose host; set the variable to the host's DNS name / LAN IP for
 components joining from other machines. Verified end-to-end against a
 live stack: UI-created command -> `aegis-connector --connect
 localhost:9090/<token>` enrollment -> `start` -> online in the API, both
 with the explicit env var and with the derived default. Documented in
 `deploy/compose/README.md`, `.env.example` and `docs/CONNECTORS.md`.

## [1.4.0] - 2026-09-19

### Added

- **Unified external-connection plane** (`aegis.connector.v1` gRPC service,
 protocol spec in `docs/CONNECTORS.md`): every externally connected
 component — endpoint agents, remote scanners, external collectors — now
 shares one connection protocol and one management surface, differing only
 in per-kind role logic on top:
 * One-time enrollment over gRPC: an operator creates the connection in
 the UI and receives a single-use connect command
 (`aegis-connector --connect host:port/<token>`). The backend burns the
 token atomically on first use (claim-first `UPDATE... WHERE used_at IS
 NULL` makes token replay impossible; rejected enrollments do NOT
 consume the token), flips the record to active and returns the allow
 message: a long-lived connector secret (stored hashed, shown once),
 canonical endpoint info and the current configuration.
 * Continued-run authentication rides as per-call metadata
 (`x-aegis-connector-id` / `x-aegis-connector-secret`), constant-time
 compared; revoked records are rejected immediately.
 * Configuration distribution with hot reload: `GetConfig` is re-fetched
 on every (re)connect, a server-streaming `WatchConfig` pushes each
 change live (no restart), and the `Heartbeat` response carries the
 server's `config_version` as a drift-recovery backstop.
 * New `aegis-connector` CLI (`cmd/connector`, `urfave/cli/v3`):
 `--connect host:port/token` (root, the UI connect string), `connect`,
 `start` (continuous run: reload-on-connect + watch + heartbeat +
 role loop, exponential reconnect backoff, terminal abort on rejected
 credentials), `reconnect` (new token → replace credentials, keep
 identity — for backend address changes / lost secrets),
 `status` (backend-visible JSON state), `install`/`uninstall`
 (systemd unit, manual instructions elsewhere), `reset`.
 * Local credential file saved atomically mode 0600/0700
 (`--config` > `AEGIS_CONNECTOR_CONFIG` > `/etc/aegis-connector/config.json`
 for root > `~/.aegis-connector/config.json`).
 * Per-kind roles behind one interface (`internal/connectorapp/roles.go`):
 `agent` (host presence + status), `scanner` (advertises local scan
 tooling: nmap/zgrab2/masscan/nuclei), `collector` (generic harness);
 adding a component kind = one domain constant + one Role impl.
 * Connections page in the web UI (`/connections`): create (kind/name/
 site), one-time connect command with copy button and shown-once
 warning, live status pills (pending/online/offline/revoked from
 heartbeat freshness), component metadata + last reported status,
 JSON configuration editor (save = push hot reload), Reconnect
 (rotate token + new command; re-arms revoked records), Revoke/Delete.
 * REST API under `/api/v1/connectors` (list/create/detail/patch/
 config/enroll-token/revoke/delete, `agent:manage` permission,
 audit-logged); migration 0019 `connectors` + `connector_enroll_tokens`
 (org-scoped, site-assignable, JSONB config with monotonic
 `config_version`).
 * Server env: `AEGIS_CONNECTOR_PUBLIC_ADDR` (endpoint embedded into
 connect commands; derived from `AEGIS_PUBLIC_URL` host + gRPC port by
 default), `AEGIS_CONNECTOR_TOKEN_TTL` (default 24h).
 * Verification: `scripts/e2e-connectors.sh` (43 checks: enrollment over
 real gRPC, token replay rejection, live hot-reload on a running
 process, reconnect rotation, revoke semantics, re-arm after revoke,
 kind-mismatch rejection, validation errors) plus unit tests for the
 service and CLI config handling; all pre-existing suites unchanged
 and green.
- `api.put` helper in the web API client (config push uses PUT).

### Fixed

- e2e suites (`e2e-features.sh`, `e2e-repro-bugs.sh`, `e2e-connectors.sh`)
 now discover the Go toolchain robustly (same approach as
 `fetch-bin.sh`) instead of assuming `/home/z/go/bin`.

## [1.3.0] - 2026-09-19

### Added

- **Distro advisory detection plane** (vuls-grade OS-package matching):
 * New `os_advisories` table (migration 0018) storing per-distro-release
 advisory statements: package, first fixed version or "not fixed yet",
 CVE, advisory id (DSA/USN/RHSA/ALSA) and URL, distro severity.
 * New `advisories` feed (`feeds.OvalJob`) with a streaming OVAL parser
 covering the dpkg/rpm/apk definition shapes the Debian, Ubuntu, Red Hat
 and Alpine feeds emit. Opt-in: `AEGIS_FEEDS_ENABLED=advisories` plus
 `AEGIS_FEED_OVAL_SOURCES=family:release:URL[:bz2|gz|zip]`.
 * `Correlator.CorrelateOSPackage`: installed OS packages (dpkg/rpm/apk
 rows recorded by endpoint agents or SSH collection) match against the
 distro advisory plane using **distro-correct version grammars**. Findings
 carry `match_type=OS_PACKAGE`, `confidence=1.0` (deterministic,
 advisory-backed — the vuls OvalMatch philosophy), `os_advisory` evidence
 with the advisory id and fixed-in version, and exact remediation text
 ("Upgrade openssl to 3.0.13-1ubuntu2 (USN-7000-1)." / "No fixed package
 is available yet..."). OS packages fall back to the OSV path only when
 no advisory data covers the asset's release.
- **Agent-less SSH inventory scanning** (vuls' signature capability):
 * New `ssh_inventory` scan profile: the scanner connects to configured
 hosts (read-only commands only, no root required — vuls' fast-scan
 posture), detects the distro from `/etc/os-release`, and enumerates
 installed packages with distro-native commands (dpkg-query / rpm -qa /
 apk list). Everything flows through the standard inventory +
 correlation pipeline; findings appear without any agent installed.
 * `AEGIS_SSH_SCAN_*` configuration: hosts (user@host[:port] list), user,
 password or key path, timeout, host-key policy (insecure or pinned key).
 * Orchestrator gained a "software" observation type with inline
 correlation, so agent and agent-less packages produce findings the same
 way (`Orchestrator.Correlator`).
- Alpine apk version comparator (faithful apk-tools grammar port) wired
 into the version-type dispatch.

### Fixed

- **`findings.remediation` was never persisted**: the finding upsert did
 not include the column, so every remediation hint (advisory upgrades
 included) silently dropped. It is now stored and refreshed on
 re-observation without blanking.
- **Alpine versions compared with Debian ordering** in the OSV ecosystem
 path (e.g. `-rN` revisions and pre-release suffixes mis-ordered);
 alpine now uses the apk grammar.
- Asset OS-string mining no longer panics on short vendor names ("pfSense"
 crashed the correlation sweep via a padded-index slicing bug) and never
 matches partial words ("pfSense" must not match "suse").

## [1.2.9] - 2026-09-18

### Fixed

- **PDF detail reports render the full contract** and their test suite
 passes again: the findings table now prints human asset labels
 (hostname → primary IP) instead of machine UUIDs, network rows carry the
 VLAN annotation, interface addresses honor the recorded primary flag, and
 the test decodes PDF literal-string escapes so assertions match what a
 viewer actually renders ("Evidence (1):", "Scans (1)").
- **Refresh-token rotation grace window is configurable again**:
 `AEGIS_REFRESH_ROTATION_GRACE` was parsed by the config but never applied —
 the middleware always used the hardcoded 30s default, so reuse detection
 fired 30s late. Now wired through (with a safe fallback), and the
 repro-auth suite catches the regression (34/34).
- **Packaging/releases work on a fresh clone**: the repository was missing
 the `VERSION` file that `scripts/package-release.sh` and the Makefile
 build flags require; restored at 1.2.9 plus a CHANGELOG.
- **`.gitignore` repaired**: `internal/scanner/` was ignored while tracked —
 new files there silently vanished from commits (the "added rest of files"
 failure mode); root build-artifact ignores (`/server`, `/worker`,
 `/feed-worker`, `/scanner`, `/agent`) are back.

### Added

- **Playwright browser tests are wired up**: `web/playwright.config.ts`
 (auto-started `vite preview` server), `npm run test:e2e` /
 `test:e2e:ui` scripts, and a `make test-frontend` that builds the SPA and
 runs all 8 specs (7 automated + 1 opt-in live check). The
 `dropdowns` suite now runs against the preview server out of the box.
- **`make e2e` points at the real verification suites**
 (`scripts/e2e-features.sh`, `e2e-repro-bugs.sh`, `repro-auth.sh`) instead
 of a nonexistent `./tests/e2e` package, and the suites auto-provision
 their sandbox binaries (`scripts/sandbox-infra/fetch-bin.sh`: builds
 redis-stub from source, downloads nats-server) and honor
 `AEGIS_REPO_ROOT` so they run from any checkout.
- The phantom `make swagger` target (no `swag` tool, no `api/swagger/`
 directory) is removed; `make generate` regenerates protobuf via buf.

## [1.2.8] - 2026-09-17

### Changed

- **Module path renamed** to `github.com/FlameInTheDark/aegis` (go.mod,
 every import, proto go_package, docs).

### Security

- **Authentication rebuilt to a production-grade, cookie-based rotating
 architecture** (full audit + rationale in `docs/AUTH.md`):
 * The **access JWT is kept in React memory only** — never in
 localStorage/sessionStorage/IndexedDB (pre-v1.2.8 stored keys are
 deleted on boot). It rides the Authorization header and dies with the
 page; sessions survive reloads through the refresh cookie.
 * The **refresh token is now opaque** (256-bit, no parseable claims) and
 travels exclusively in an **HttpOnly + SameSite=Lax cookie** (Secure +
 `__Host-` prefix when the deployment is HTTPS;
 `AEGIS_AUTH_COOKIE_SECURE=false` for plain-HTTP demos). It is never
 returned in JSON, never readable by JavaScript, and stored server-side
 only as a SHA-256 hash.
 * **Refresh tokens rotate on every refresh** (migration 0016). A
 just-retired token presented inside a 30s grace window keeps working —
 that is the multi-tab/401-retry race, and the rotation UPDATE retires
 the row's current hash atomically so no interleave strands a tab.
 Presenting a retired token **beyond** the grace window is reuse of a
 possibly-stolen token and **revokes the whole session family**
 (audited).
 * **Authorization is re-resolved from the database on every refresh** —
 role downgrades, membership removal and disabled accounts now take
 effect at the next refresh instead of living on stale token claims for
 up to 30 days.
 * **CSRF protection** for the cookie-authenticated endpoints
 (`/auth/refresh`, `/auth/logout`): `X-Requested-With: XMLHttpRequest`
 is required — a cross-site attacker cannot attach it without a CORS
 preflight, which the origin allowlist rejects — on top of SameSite=Lax.
 * **Logout actually revokes**: the old client sent an empty body and the
 server revoked nothing; logout now revokes the session family by
 cookie, clears the cookie server-side, purges cached data, and
 broadcasts to other tabs over a BroadcastChannel (event names only).
 * The **SPA auth state is centralized** in one provider
 (`initializing` / `authenticated` / `unauthenticated`): startup
 restores the session through the refresh cookie behind a splash (no
 login-screen flash), route guards render from that state, 401s drive a
 single-flight refresh with exactly one retry per request, transient
 failures never log the user out, and an anomalous **403 on an expired
 access token** (the field-reported "403 with expired token" dead-end)
 now also refreshes and retries once instead of stranding the user.

### Fixed

- Logout left the server-side session alive (empty-body logout call).
- Concurrent refresh rotations could (with per-use rotation attempted
 naively) strand a racing tab on an unaccepted token — the retired-hash
 ledger with atomic row rotation makes every landing order converge.

## [1.2.7] - 2026-09-17

This release unifies the two parallel v1.2.6 builds: the CVE applicability
engine below was field-distributed as the `aegis-v1.2.6` archive while the
main source line carried the v1.2.6 sorting/auth/download fixes. v1.2.7 is
the first tree that contains both halves, verified together.

### Added

- **CVE `affected` products are parsed and stored** (integrated from the
 parallel build). The CVE List v5 `containers.cna.affected` statement —
 vendor, product, `defaultStatus`, official CPEs, platforms, and every
 version range with `version`, `lessThan`, `lessThanOrEqual`, `status`,
 `versionType` and `changes` — is saved verbatim (JSONB, migration 0015)
 and rendered on the CVE detail page: each statement shows as `= 1.0.2k` /
 `≥ 2.0, < 2.7.3` / `< 10.4` with status pills (affected / unaffected /
 unknown) and the declared version type, so an operator can see exactly why
 a discovered version matched and why a newer one is safe.
- **Full affected-statement semantics in the match builder.** Exact version
 pins become pinned CPE matches; `defaultStatus: "affected"` with
 unaffected carve-outs computes the complement (everything outside the
 unaffected intervals is affected); `changes` split ranges at the change
 version with per-segment status; products declared entirely unaffected
 generate no candidates at all; incomparable bounds refuse to guess and
 fall back to explicit statements only.
- **"Rediscover" on assets.** New `POST /api/v1/assets/:id/rediscover`
 re-runs vulnerability matching for everything already discovered on an
 asset (services + software inventory) against the current CVE index —
 for when new CVEs synced after the last scan. No network scan runs;
 findings are created/refreshed and the response reports real counts.
 Available as a per-row action on the Assets page and a header button on
 the asset detail page (requires finding:write, so managers and admins).
- **Software-inventory correlation.** Software rows recorded from network
 fingerprints (product + version + CPEs, e.g. the OpenSSH entry) are now
 matched like services — previously only ecosystem packages (agent
 inventory) and services were correlated; `SweepOrg` and the new
 `SweepAsset` both include them.
- **Automatic cvelistV5 corpus re-ingest after parser upgrades.** The job
 records its ingest schema version in the new `feed_meta` table; when the
 stored version is older, the next sync force-rebootstraps the full
 snapshot once so every previously ingested CVE gets its affected
 statement and correct range bounds rebuilt — no manual action needed.
- **Version comparison rewritten for real-world version strings**
 (`fingerprinting.CompareTyped`, dispatching on the CVE's `versionType`):
 `custom`/`generic`/`maven` (natural order with numeric runs, letter runs,
 pre-release words: `2.0rc1 < 2.0 < 10.4p1`; OpenSSH `pN` and OpenSSL
 letters sort after the base), `semver` (2.0.0 rules, build metadata
 ignored), `deb` (dpkg algorithm: epoch, revision, `~`), `rpm`
 (rpmvercmp with `~` and epoch), `python` (PEP 440 subset: dev < a < b <
 rc < final < post). Observed junk is stripped first (`CleanVersion`:
 `10.0p2 Debian 7` → `10.0p2`, `OpenSSH_10.0p2` → `10.0p2`, `v1.2.3` →
 `1.2.3`). OSV package ranges use the ecosystem's ordering (npm→semver,
 PyPI→PEP 440, Debian/Alpine→dpkg, Red Hat→rpmvercmp) instead of one
 generic comparator. This is what makes the field-acceptance case work:
 OpenSSH `lessThan 10.4` (versionType custom) matches a discovered
 `10.0p2 Debian 7` as vulnerable.

### Fixed

- **CVE version-range matching never produced findings — the core
 applicability engine was dead in production.** `VulnRepo.CVE` returned
 records without their `vulnerability_cpe_matches` rows, so the matcher
 iterated an always-empty list and every CPE / range / pinned-version
 evaluation was skipped; only OSV package advisories could create
 findings. `CVE` now loads CPE matches (and the affected statement) with
 the record. Additionally, cvelistV5 ingest collapsed all affected
 version ranges of a product into ONE CPE match keeping only the last
 `lessThan` and NO start bound: `[2.0–2.5) ∪ [3.0–3.2)` matched 7.4 and
 missed 3.1. Ranges now fan out per statement with correct inclusive /
 exclusive start+end bounds.
- **A known version that fails a CVE's range can no longer be resurrected
 as a "potential" finding** by the versionless CPE candidate — if the
 vendor declared version bounds and the observed version does not fit,
 the CVE produces no finding of any kind (previously a second, weaker
 candidate re-added it at 0.35–0.6 confidence).
- Source-tree hygiene: the parallel builds had drifted to space
 indentation in several Go files; the tree is `gofmt`-clean again.
 `package-release.sh` now packages strictly from the git index
 (`git archive` + `.gitattributes` export-ignore for sandbox artifacts),
 so untracked dev files can never leak into a release.

## [1.2.6] - 2026-09-17

### Fixed

- **Vulnerability list sorting did not sort.** The sort controls issued two
 URL updates in a row (`sort`, then `order`); each built its URL from the
 same stale params snapshot, so the second update overwrote the first and
 the sort key never reached the API — the server kept answering in the
 default relevance order no matter which sort was picked ("weird random
 order" by date). Both the header-click and the sort-preset paths now apply
 the whole `{sort, order}` patch in a single URL update (`patchParams`).
 Server-side ordering was verified correct (new e2e: desc/asc date and
 CVSS ordering with seeded data, in `scripts/repro-auth.sh`).
- **Auth token expiry still stranded sessions ("500 errors on every
 request").** Two compounding defects:
 * *Frontend:* the refresh result was a boolean that conflated "renewed"
 with "retry anyway". Any transient refresh failure (429 rate limit,
 5xx, network blip) retried the original request with the SAME expired
 token, guaranteed another 401, and never logged out — the user sat in
 the app with a dead session and an error on every request until they
 manually cleared storage. The refresh now returns a tri-state
 (`ok` / `invalid` / `transient`): only a definitive 401/400 logs out;
 transient failures keep the session, back off exponentially (15→60 s)
 and recover via the re-armed proactive timer; if the access token is
 truly expired and the backend stays unreachable for 8 consecutive
 attempts (~3–4 min), the login screen is surfaced instead of an endless
 error wall.
 * *Backend:* `/auth/refresh` mapped ANY session-lookup error to 401, so a
 one-off database hiccup force-logged users out, and `/auth/login`
 reported a user-store outage as "invalid credentials". Both now answer
 503 (`service_unavailable`) for store outages and reserve 401 for real
 auth failures. `/auth/refresh` also moved to its own 120/min rate-limit
 bucket — renewal bursts (several tabs, 401-retry waves) no longer
 starve behind the 20/min login bucket.
 * Repro/regression suite: `scripts/repro-auth.sh` (16 checks) drives the
 full lifecycle with a 5 s access TTL — login → 401 on expiry → silent
 refresh → renewed access, a 30-way concurrent refresh storm (zero 5xx),
 and garbage-token rejection.
- **Report download links could not download anything.** The Download
 button was a plain `<a href>` to the API route — browsers strip
 Authorization headers on navigation, so every click opened a tab showing
 an authorization error; and even with a token the old handler 307-
 redirected to a presigned `rustfs:9000` URL that is unreachable from user
 browsers (the object store is not published in compose). The endpoint now
 STREAMS the artifact through the authenticated API with a
 `Content-Disposition: attachment` header and a friendly filename
 (`aegis-report-<type>-<date>-<id>.<ext>`), and the frontend downloads it
 via an authenticated fetch + blob save (works everywhere, no new
 deployment surface). Verified end-to-end against an in-sandbox S3 stub
 (`scripts/sandbox-infra/s3-stub.py`): 401 without token, 404 unknown job,
 200 + attachment bytes + correct filename for a completed job.

## [1.2.5] - 2026-09-17

### Fixed

- **Report generation failed with `column reference "id" is ambiguous`
 (SQLSTATE 42702).** `FindingRepo.List` selects an unqualified `id` and
 joins `assets` for site-scoped report definitions, so every site report
 died during data gathering. All finding columns are table-qualified now.
- **Scan scope accepts IP ranges.** `192.168.1.1-192.168.1.27` (and the
 last-octet shorthand `192.168.1.1-27`) typed into the targets field no
 longer dies with `invalid CIDR or IP ...; scope is empty` — ranges are
 parsed, public/private-checked, counted, and expanded into the minimal
 set of CIDR blocks (`rangeToCIDRs`) so nmap, denylist math and scope
 storage stay canonical. Ranges may be freely mixed with CIDRs/hosts.
- **Cancelled scans now stop immediately.** The scanner polls the kill
 switch every 3 seconds *while probes are in flight* and cancels the run
 context, which kills the running nmap process instead of waiting for the
 phase to finish — the result is not needed. Cancelled scans are recorded
 as `cancelled`, not `failed`.
- **Auth token loss ("never renewed").** The proactive refresh timer was
 scheduled once; a single failed renewal (sleep, server restart, network
 hiccup) left the session with NO timer, so the access token expired
 silently and nothing ever renewed it. The timer now re-arms after every
 attempt with a 15 s backoff floor, a 60 s interval + visibility/focus
 hooks catch what timers miss, and a definitive 401 from /auth/refresh
 logs out (transient failures never clear tokens).
- `GET /scanners` (and scan creation) crashed with a column-count mismatch
 after the hub migration; both `ScannerRepo.List` and `ByID` now select
 and scan the same (12) columns.

### Added

- **gRPC scanner hub — remote scanners on physical hosts.** Scanner
 binaries run in agent mode (`AEGIS_SCANNER_MODE=agent`,
 `AEGIS_SCANNER_HUB_ADDR`, `AEGIS_SCANNER_HUB_TOKEN`) and dial the server
 over gRPC (service `aegis.scanner.v1.Hub`, JSON codec): registration via
 one-time enrollment tokens (Settings → Scanners), server-streamed job
 envelopes carrying the full scan context (agents need NO Postgres/NATS
 access), and unary reports streaming observations/state back through the
 real orchestrator. Scans route to an explicitly chosen connected agent,
 else the org's default agent (configurable, marked in Settings), else
 the embedded NATS path — compose deployments behave exactly as before.
 Cancellation propagates to remote probes via a kill-switch readback RPC.
- **Nmap presets (Settings → Scan presets).** Org-scoped custom profiles
 (ports, full-range sweep, service/OS/trace phases, rate and target caps)
 with allowlist-validated extra nmap arguments (timing/rate/port-spec
 knobs only; `--script*`, `-iL`, `--datadir` etc. are rejected). Presets
 appear as profile options in the scan form and persist per organization.
- **User management & roles (Settings → Users).** Administrators create
 users, assign roles (administrator / manager / operator / viewer),
 reset passwords (kills all sessions) and disable accounts — all audited.
 Managers keep full operational access but cannot manage users, feeds or
 system configuration; every user can change their own password
 (Settings → My account; other devices are signed out).
- **Premium dark table design system** matching the provided reference:
 toolbar control chips, colored soft pills, segmented severity/risk
 meters, right-aligned tabular numerals, custom checkboxes, row hover/
 selected accents — applied across scans, assets, findings,
 vulnerabilities, events, agents and reports.

### Technical
- Migrations 0013 (custom presets) and 0014 (scanner hub: token_hash,
 transport, is_default).
- e2e: repro 21/21, features 50/50; new arg-allowlist and range-expansion
 unit tests.

## [1.2.4] - 2026-09-17

### Fixed — `verify-traceroute` aborted with "line 61: bin: not found"

- **Root cause**: the epilogue's `printf` string wrapped `* * *` in literal
 backticks. POSIX shells treat backticks as command substitution, so the
 glob expanded against the container's working directory (`/`) to
 `bin boot dev …` and tried to execute `bin` — swallowing the nmap
 traceroute smoke-test output and printing the confusing error. The
 backticks are gone; the only ones left in shipped shell scripts are inside
 comments.
- **The self-check is now self-diagnosing.** The TCP/443 traceroute ends
 with a verdict — `OK: TCP/443 reached the target …` or a NOTE explaining
 that blocked/unresponsive hops are recorded as partial paths, never as
 "no route" — and the nmap smoke test prints the first lines of nmap's
 output when no traceroute XML comes back instead of failing silently.
- **Field verification of the v1.2.3 image** (Docker Desktop/WSL2) that
 surfaced this: `CapEff 0x2000 = cap_net_raw`, file caps on
 `nmap`/`traceroute`, and the TCP/443 path reached 1.1.1.1 at hop 4
 (144 ms) with `*` middle hops — the least-privilege (NET_RAW, no
 `privileged: true`) traceroute fix is confirmed working; UDP/ICMP/
 tracepath partial paths are the documented VPNKit/WSL2 NAT behavior.

## [1.2.3] - 2026-09-17

### Fixed — fingerprint profile detects nothing / traceroute dies at hop 1

**The `fingerprint` profile had exactly one OS source — `nmap -O` — and every
`-O` failure mode zeroed the whole pass.** `full_audit` also harvests
service-table OS hints (`ostype`, OS CPEs) from `-sV`; the fingerprint profile
turned that phase off, so a single blocked `-O` meant "no OS, no device type":

- **`-O` now gets explicit, bounded port specs.** Left implicit it scanned
 nmap's default top-1000 and skipped hosts whose only open ports sat outside
 that table. It now reuses the profile's port spec (top-100 for
 `fingerprint`) and caps full-range audits at `--top-ports 1000`.
- **`--osscan-limit` removed.** It skips every host lacking an open AND a
 closed TCP port — behind NATs that swallow RSTs (Docker bridge, Docker
 Desktop) closed ports show as *filtered*, so the check failed exactly where
 scans run, silently skipping every host. `-O` failures caused by missing
 raw sockets now log an explicit "needs CAP_NET_RAW" message instead of
 `exit 1`.
- **A batched light service pass backs `-O` up** (new `ServiceLite` profile
 capability): one `nmap -sV --version-light` per host over the open ports —
 a fraction of the per-port intensity-5 cost, but enough to fill product/
 version/`ostype`/CPE. It flows through the same observation path as full
 service detection, so OS hints, software rows **and new device-type hints**
 (JetDirect/LaserJet → printer, RTSP/Hikvision → camera, Synology/QNAP →
 NAS; hardware CPEs honored) apply with conservative 0.55 confidence.
 `RecordDevice` now uses the same equal-or-higher-confidence override rule
 as `RecordOS`, so weak hints can fill an unclassified asset but never
 trample a MAC-vendor or osclass verdict.
- **OS parsing hardened**: the highest-accuracy `osmatch` wins regardless of
 listing order (accuracy ordering drifted between nmap versions), and bare
 `osclass` output from `--osscan-guess` now yields a 0.5-confidence family
 instead of nothing.

**Assets are named by what you know, not what you don't.** An unidentified
asset used to surface as "Unknown Device · 192.168.1.5" (topology/backend) or
"Unknown Device" (asset list). Labels now lead with hostname → FQDN → IP
address; the device class decorates the address only when actually identified
("Router · 192.168.1.1"), and the Type column shows `—` until there is
evidence. Also fixed: topology click-through to assets was silently dead —
the API serialized only `ref_id` while the UI read `asset_id`; asset-kind
nodes now carry `asset_id` (graph rings + `/assets/:id` navigation work).

**Traceroute from the scanner container.** Investigated networking,
capabilities and the probe implementation; the least-privileged, production-
safe fix is capability-shaped — `privileged: true` is still not used:

- **Probe ladder extended**: TCP SYN/ACK → **UDP** (new; elicits ICMP
 port-unreachable, gets through when TCP probes are filtered) → ICMP →
 TCP connect → **`tracepath`** (new last resort; UDP-based, needs no raw
 sockets). First attempt with hops wins; the method is recorded on the
 topology observation.
- **Blocked probes are never "no route"**: unresponsive hops stay TTL gaps;
 partial paths keep the answered hops; when *everything* fails the
 observation becomes `method: gateway-guess` at confidence 0.5 instead of
 vanishing — the subnet structure shows while honestly flagged as inferred.
- **Container runs with exactly one capability**: compose now sets
 `cap_drop: [ALL]` + `cap_add: [NET_RAW]` + `no-new-privileges:true` (k8s
 manifest already did). The image stamps file caps on `nmap` **and**
 `traceroute` (previously `setcap` silently failed — `libcap` was never
 installed and the failure was masked by `|| true`), ships `traceroute`
 (UDP/ICMP/TCP methods), `iputils-tracepath` and `iproute2`, and bakes in a
 verification script:
 `docker compose exec scanner verify-traceroute` checks CapEff, file caps,
 `ip route`, and runs live `traceroute`, `traceroute -I`, `traceroute -T -p
 443` and `tracepath` against 1.1.1.1.
- `AEGIS_SCANNER_TRACEPATH_PATH` overrides the tracepath lookup (missing
 explicit override disables the fallback rather than guessing).

### Added — vulnerabilities filtering & sorting

- **Server-side sorting** with a strict whitelist (`sort` =
 `published_at|updated_at|cve_id|cvss_score|known_exploited`, `order` =
 `asc|desc`; unknown values degrade to the default KEV/CVSS relevance order,
 injection attempts can never reach SQL; NULL dates sort last).
- **Published-date window** (`published_after` / `published_before`, RFC3339
 or bare `YYYY-MM-DD`; a date bound includes its whole calendar day) —
 applied to both the page and the filtered total.
- **UI**: sortable column headers (CVE, CVSS, KEV, Published — click to
 toggle direction, `aria-sort` annotated), a sort preset selector (newest/
 oldest published, name A→Z/Z→A, highest/lowest CVSS, recently updated),
 two date inputs for the published window, and a one-click Reset for all
 filters.

### Tests

- New unit tests: `-O` argv builder (no `--osscan-limit`, bounded specs),
 traceroute ladder contract (ordering + probe kinds), tracepath parser
 (retransmit dedupe, TTL gaps, partial paths, target append), tracepath
 fallback integration (fake-binary exec through the hardened runner),
 device-hint mapping (incl. "CUPS on a workstation must not become a
 printer"), node-label fallbacks, vuln ORDER-BY whitelist + published-bound
 parsing.
- e2e-features extended to 50 checks: CVE id ordering, published ordering,
 unknown-sort degradation, published-window totals, and `asset_id` on
 asset-kind topology nodes. e2e-repro-bugs: 21/21. `go build`, `go vet`,
 `go test`, `tsc -b` and the web build all clean.

## [1.2.2] - 2026-09-17

### Fixed — scans collect no OS/software data (the core mission)

The engine ran every nmap phase under one global 30-second `--host-timeout`
(hardcoded `TimeoutSecs: 30` in the scan config). Manual `nmap -T4 -A` proved
OS detection and version detection work on the same hosts — inside the app
the data never landed:

- **OS fingerprint phase aborted before it produced anything.** `nmap -O`
 first performs its own port scan (to find an open AND a closed port) plus
 dozens of probe rounds; a 30s budget aborted the host before a single
 probe round completed, so nmap emitted no `<os>` block at all — and the
 failure was swallowed silently. Phase budgets are now sized per phase
 (discovery 60s, port scan scaled `ports/rate × 4 + 60s` min 2 min,
 service fingerprint 90s per port, **OS fingerprint 5 min** with
 `--osscan-guess`, traceroute 90s per attempt); explicit config values act
 as a floor and can only extend a budget. A failing or inconclusive `-O`
 run is now logged (`os fingerprint failed` / `inconclusive`) instead of
 vanishing.
- **Software behind open ports is now collected.** The `software` table had
 zero writers — the software tab was empty for every scanned asset by
 construction. `-sV` fingerprints (product/version/vendor/CPE, e.g.
 "OpenSSH 10.0p2", "Werkzeug 3.1.3 (Python 3.13.5)") are now persisted as
 software rows (OS CPEs excluded) so the software tab works without an
 endpoint agent.
- **OS type from service fingerprints.** nmap appends the host OS CPE to
 service fingerprints (`Service Info: OS: Linux; CPE:
 cpe:/o:linux:linux_kernel`). That signal — often the only one available
 when raw `-O` probes are filtered (typical for container-born scans) —
 now feeds `os_family`/`os_name` whenever the service table has no ostype.
 All service CPEs are parsed (previously only the first was kept), and OS
 matches without a device class are no longer dropped by the applier.
- **Scanner honesty.** A missing nmap binary now logs a prominent warning
 when the scanner falls back to the SIMULATED engine (results tagged
 synthetic — previously silent), and `AEGIS_SCANNER_NMAP_PATH` (compose)
 is honored in addition to `AEGIS_NMAP_PATH`, so an override can no longer
 silently degrade the scanner.

### Fixed — cvelistv5 / NVD feeds stuck at "never synced"

Both feeds showed `never_synced — 0 records` two hours after boot while
KEV/EPSS were healthy. Root causes, all fixed:

- **Sequential runner starvation:** feeds ran one after another and the NVD
 full pull (280k+ records, 140+ paced pages, 3–4 single-row statements per
 record) ran for hours — cvelistV5 sat behind it the whole time. Jobs now
 run **concurrently** with per-feed single-flight, and NVD writes are
 **batched** (page-level multi-row upserts for CVEs, CPE matches and
 references).
- **No visibility:** `feed_sync_runs` rows were never started, the status
 stayed `never_synced` until a full run returned. A sync now marks the
 feed `running` immediately (migration `0012`), partial runs report
 `stale` with the error surfaced, `healthy` only after a completed run,
 and crashed-worker `running` rows are reset at boot.
- **NVD incremental sync never activated:** the sync position was never
 persisted, so every run was a full re-pull. Position now comes from
 `feed_sources.last_sync_at` (2h overlap), query dates are properly
 URL-escaped (a raw `+` in `+00:00` made NVD reject the request), and
 NVD's zone-less timestamps (`2023-10-11T19:15:09.947`) no longer null
 every `published_at`. Rate-limit responses (403/429) honor `Retry-After`
 instead of burning the retry budget. Set `AEGIS_NVD_API_KEY` to raise NVD
 from 5 to 50 requests/30s — the first full sync drops from ~half an hour
 to minutes.
- **cvelistV5 download hazards:** the ~350 MB release archive was fetched
 through the feed client's 90-second whole-request timeout and buffered
 fully in RAM. It is now streamed to a temp file (30-minute budget,
 1 GB cap) with ingest progress logging.
- **EPSS ingested 100 of ~250k records** (one unpaginated page, reported
 "healthy"). Pagination now covers the full corpus with batched upserts,
 and a same-day sync is skipped (EPSS refreshes daily).
- **`POST /api/v1/feeds/:name/sync` was a no-op** (returned `202 queued`
 and queued nothing). It now publishes a trigger on
 `security.feed.sync.v1` which the feed-worker consumes and runs
 immediately (unknown/already-running feeds are answered by the in-flight
 sync). `AEGIS_FEEDS_ENABLED` is honored as the feed selection / kill
 switch again, and the worker gained an opt-in `/healthz` endpoint
 (compose: `restart: unless-stopped` + healthcheck).

### Fixed — regression hardening

- The host_up OS guard compared a missing map key against `""`
 (`nil != ""` is true in Go), so every presence observation stamped
 `os_confidence` with the discovery confidence while leaving `os_name`
 empty — blocking every later real fingerprint of lower numeric
 confidence. `RecordOS` now rejects OS-less observations outright, and
 the guard type-asserts before comparing (caught by the e2e suite).
- `GET /assets/:id/{services,software,findings,interfaces}` serialize `[]`
 instead of `null` for empty relations; the scans table guards missing
 `stats`/`progress`; the feeds panel renders `running`/`never synced`
 labels cleanly.

### Verified

- `go build ./...`, `go vet ./...`, full `go test ./...` clean.
- `scripts/e2e-features.sh`: **41 PASS / 0 FAIL** (also fixed a bare `wait`
 that hung the suite on the section-17 background jobs).
- `scripts/e2e-repro-bugs.sh`: **21 PASS / 0 FAIL**.

## [1.2.1] - 2026-09-16

### Fixed — asset detail crash (services/software tabs)

- The asset detail bundle serialized Go nil slices as JSON `null`; the UI
 read `.length` on it and crashed (`TypeError: Cannot read properties of
 null (reading 'length')`) the moment the services or software tab opened.
 The backend now guarantees `[]` for every list field, the handler
 degrades per-section (one failed relation can no longer 404 the whole
 asset view), and the UI guards every list locally as well.
- Detected ports & services are now surfaced directly on the asset
 overview as port/service chips (top 12 + overflow), with a jump link to
 the full services tab.

### Fixed — login/session churn (random logouts)

- `POST /auth/refresh` used to rotate the session on every use. When the
 15-minute access token lapsed, the SPA's parallel requests all 401'd and
 raced each other through refresh; the first rotation revoked the refresh
 token every other request was still presenting, wiping the freshly
 renewed tokens and bouncing the user to the login screen.
- Refresh is now idempotent: no rotation, the presented refresh token
 stays valid for its TTL (30 days), logout still revokes for real, and
 refreshed access tokens carry the same session id.
- The SPA performs single-flight refresh (all concurrent 401 retries share
 one in-flight refresh promise), renews proactively ~90 s before expiry,
 re-checks on window focus after background-tab stalls, and only logs out
 when the server actually rejects the session — transient network/5xx
 errors no longer clear tokens.
- Default access-token TTL raised 15m → 1h (`AEGIS_ACCESS_TOKEN_TTL`).

### Fixed — scan scope rejects single IPs

- `POST /scans` with a plain address (`"192.168.1.1"`) failed with
 `invalid CIDR "192.168.1.1"; scope is empty`. Bare IPv4/IPv6 targets are
 now accepted as single-address scopes (public-range rules unchanged).
- The scan form's denylist input is now a multi-line textarea and the
 targets hint mentions single IPs.

### Fixed — asset search by IP

- The assets list "Search hostname, IP, FQDN…" box (and the ⌘K global
 search) never actually searched addresses. Both now match stored
 identifiers (ip, mac, …) in addition to hostname/fqdn/vendor.
- Filtered asset totals were computed from an unfiltered `count(*)`, so
 the pagination footer showed wrong numbers under any filter; count and
 list now share the same WHERE builder.

### Changed — traceroute resilience

- The traceroute engine now walks a NAT-friendly probe ladder: TCP SYN +
 ACK discovery probes first, ICMP echo second, and a TCP-connect trace
 (`-sT --traceroute`) as last resort — the target answers with TCP RST,
 which survives NATs that drop even target-bound ICMP.
- Documented the hard container limit: intermediate traceroute hops are
 only ever visible via ICMP Time Exceeded, which the Docker Desktop
 (Win/mac) NAT swallows — LAN topology (device ↔ gateway ↔ device) still
 maps fine, full WAN paths need `network_mode: host` on Linux or a
 natively deployed scanner. See `docs/DEVELOPMENT.md → "Traceroute from
 containers"`.

### Changed — UI polish

- Topology graph: asset-backed nodes are ringed and clickable — clicking
 one opens the asset in the assets view (pure router hops stay inert);
 the edge table links to asset pages too.
- Shared table styling rebuilt: uppercase sticky headers with backdrop
 blur, roomier rows, aligned first/last cells, softer borders, clearer
 hover; scan-detail tables gained horizontal overflow wrappers.
- `DataTable` now supports client-side sorting (`sortValue` columns get
 click-to-sort headers with aria-sort) and tolerates `null` pages.

## [1.2.0] - 2026-09-16

### Fixed — critical asset-identity bugs (rescans no longer copy assets)

- **Root cause 1 — identifiers never persisted**: `asset_identifiers` was
 designed to upsert on `(asset_id, type, value)`, but migration 0003 only
 created non-unique indexes. Postgres rejected every ON CONFLICT insert,
 the scanner swallowed the error, and the correlation table stayed empty —
 so no scan could ever recognize a previously seen device. Migration 0011
 adds the missing unique constraint (and a value trigram index).
- **Root cause 2 — org-scoped lookup always missed**: `AssetRepo.ByID` with
 an empty org filtered on `organization_id = ''`, so the identity resolver
 (hostname / MAC / IP lookups) never found anything and provisioned a new
 asset per observation. Empty org now means "no org scoping".
- **Root cause 3 — presence confidence poisoned OS data**: new assets were
 seeded with `os_confidence = 0.85` (the discovery confidence), which
 blocked every later OS fingerprint of lower numeric confidence. OS data
 now starts at 0 and is filled in by fingerprints.
- **Root cause 4 — topology nodes duplicated per scan**: gateway/asset
 nodes kept their upsert key, but repeated scans minted new edge pairs;
 edges now properly reconcile (e2e: 4 edges after 4 scans, not 16).
- **Root cause 5 — nmap OS family never parsed**: the XML struct tag said
 `family` but nmap's attribute is `osfamily`; OS family from `-O` scans
 was silently empty since the beginning.

### Added — address-aware scans, device classification, fast trace

- **Address-aware identity**: within a site an IP resolves to the asset
 that last held it — rescans update the existing asset instead of
 creating a copy. Strong identifiers (agent/MAC/hostname) still win, so a
 genuinely new device at a reused address is recognized, not merged.
 Optional staleness bound: `AEGIS_ASSET_IP_STALE_DAYS` (default 0 =
 unlimited reuse window).
- **Device-type detection**: nmap's `osclass@type` classification
 (general purpose / WAP / media device / phone / …) is mapped to the
 platform taxonomy — Computer, Phone, Router, Printer, Camera, IoT, …
 with "Unknown Device" as the honest default.
- **`fingerprint` scan profile**: a dedicated device-type + OS pass
 (top-100 ports as detection fuel, no service checks, no tracing) that
 refreshes the stored classification — the latest scan overrides the
 asset's device/OS data.
- **`trace` scan profile**: fast topology pass — ping sweep + traceroute
 only, no port scans. Maps how devices connect (gateway → routers →
 hosts) in a fraction of the time of an inventory scan.
- **Friendly asset names**: the asset list and topology graph show human
 names ("Phone · 10.0.0.12", "Router · 192.168.1.1") with a colored
 device-class dot instead of raw UUIDs; assets now expose `primary_ip`.
- **Topology connection lines**: graph edges are directional (arrows mark
 the packet path), solid for routed hops, dashed for evidence links, with
 kind-aware tooltips. The table view no longer crashes on edges with a
 missing endpoint (`TypeError: reading 'slice'`).

### Added — CVE search that actually finds things

- **Substring + content search** (`?search=`): matches partial CVE ids
 ("CVE-2005-24" finds every CVE-2005-24xxx), description text and
 reference URLs — case-insensitive, powered by pg_trgm GIN indexes
 (migration 0010) at CVE-index scale. Previously the search was an exact
 CVE-id match only.
- **Filtering**: `min_score` / `max_score` (CVSS v3 bounds), `state`
 (published/rejected/reserved/disputed), `source` (nvd/cve/osv/manual) —
 plus the existing severity and KEV filters. The total count now honors
 the filters instead of always reporting the whole index.
- **UI**: debounced live search (400 ms), description column, CVSS/state/
 source filter selects, match count footer.

### Verified

- `go build ./...`, `go vet ./...`, full `go test ./...` — clean; web UI
 TypeScript build clean.
- `scripts/e2e-features.sh`: **33/33 PASS** — including new checks for
 device classes (workstation/phone/camera/printer), per-device OS data,
 rescan-without-copies (17 assets before AND after), topology edge
 reconciliation, trace + fingerprint profiles, and substring/description/
 reference/score CVE searches.
- `scripts/e2e-repro-bugs.sh`: 21/21 PASS (all historical demo bugs stay
 fixed).

## [1.1.1] - 2026-09-16

### Fixed — `make dev` deployment failure (MinIO images gone from Docker Hub)

- **Root cause**: `docker.io/minio/minio:latest` no longer exists — MinIO
 removed every image from Docker Hub in 2025 and moved away from open
 source, so `make dev` (`docker compose up`) aborted with
 `failed to resolve reference "docker.io/minio/minio:latest": not found`
 while pulling the rest of the stack.
- **Fix**: the compose object-store service is now **RustFS**
 (`rustfs/rustfs:latest`) — an S3-compatible, Apache-2.0 licensed object
 store written in Rust. No application code changed: the server already
 speaks generic S3 through the minio-go client, which talks to RustFS
 unchanged (static V4 credentials, path-style addressing, bucket
 auto-creation on boot).
- Compose service details: S3 API stays on host `127.0.0.1:9001` (host
 9000 is ClickHouse), web console on `127.0.0.1:9002` (login = S3
 access/secret pair), credentials unchanged (`aegis` /
 `aegis-secret-change-me`), health-checked via the RustFS
 `/health` endpoint, `no-new-privileges` hardening, data in the
 `rustfsdata` named volume.
- Updated all references: `scripts/dev.sh` (hybrid workflow now brings up
 `rustfs` instead of `minio`), `.env.example`, Kubernetes configmap and
 README, Helm values and NOTES, `deploy/compose/README.md` port table,
 README, and the ARCHITECTURE/DEPLOYMENT/DEVELOPMENT docs.
- Release archives no longer ship the dev `certs/` directory (it is
 git- and docker-ignored; the server auto-generates a dev agent CA on
 first boot).

### Verified

- `go build ./...`, `go vet ./...`, full `go test ./...` — clean.
- `scripts/e2e-repro-bugs.sh`: 21/21 PASS (all five historical demo bugs
 stay fixed).
- `scripts/e2e-features.sh`: 15/15 PASS (topology tracing, high-port
 discovery, service fingerprinting, OS detection, CVE auto-correlation,
 full_audit profile).
- Compose file validated: service list, YAML anchors, healthchecks and
 `depends_on` conditions all resolve (`rustfs: { condition: service_healthy }`).

## [1.1.0] - 2026-09-16

### Added — network topology from scans (highly requested)

- **Topology tracing**: every scan profile now traces the network path to
 each discovered host (nmap `--traceroute`; deterministic gateway path for
 the simulated engine) and records the hop chain as a `topology`
 observation. The orchestrator turns hops into topology nodes
 (`router`/`asset`) and edges (`routes_to`, `observed_through`) in
 `topology_nodes` / `topology_edges`, so `GET /api/v1/topology` and the UI
 map are populated as soon as a scan finishes — previously no code path
 ever wrote to those tables and the view stayed empty forever.
- When traceroute is impossible (filtered probes, missing privileges), the
 scanner still emits the subnet gateway link so the topology view shows
 the network structure instead of an empty graph.
- Asset nodes are linked to inventory entries, letting you jump from the
 topology graph to the asset.

### Added — full host scan for security audits (highly requested)

- New **`full_audit` scan profile**: all 65535 TCP ports, service + version
 detection, OS detection and topology tracing, with an explicit intrusiveness
 warning surfaced through the API (`warnings`) and the UI.
- **Port selection semantics fixed**: the scanner used to probe ports
 `1..N` sequentially — missing MySQL 3306, RDP 3389, Postgres 5432,
 Redis 6379, HTTP-alt 8080 and every other high port. It now uses nmap's
 own frequency table (`--top-ports N`) for top-N profiles, `-p-` for full
 range, and compresses explicit lists into ranges (`1-1000`).
- **OS detection without raw sockets**: nmap service fingerprints now carry
 the per-service `ostype` hint (`Linux`, `Windows`,...), recorded at
 reduced confidence when privileged `-O` fingerprinting is unavailable.
- SYN scans (`-sS`) fall back to TCP connect scans (`-sT`) transparently on
 privilege errors, so unprivileged containers still produce results.
- The simulated demo engine now exposes high ports (3389/5432/8080/9200)
 with full product/version fingerprints (Windows RDP, PostgreSQL 15.4,
 Tomcat 9.0.71, Elasticsearch 7.17.9) so demos exercise the full audit
 path without nmap.

### Added — cvelistV5 as a CVE source (requested)

- New `cvelistv5` feed job ingesting the CVE Program's authoritative
 [cvelistV5](https://github.com/CVEProject/cvelistV5) repository (CVE JSON
 5.0). Bootstrap downloads the latest release archive; the job parses
 descriptions, CVSS v2/v3/v4, CWE, references and maps every
 `affected[].vendor/product/cpes/versions` entry into CPE matches with
 NVD-style version bounds. RESERVED records are skipped, REJECTED are
 tracked. Batched upserts (~250 records/statement) keep a 300k-record
 bootstrap in minutes.
- Override URL via `AEGIS_FEED_CVELIST_URL`; drop the feed via
 `AEGIS_FEEDS_ENABLED` (now honored by the feed-worker).

### Added — service ↔ CVE matching wired end-to-end (requested)

- **The correlation engine is now actually invoked.** The `Correlator`
 existed but nothing ever called it: scans produced services with
 product/version/CPE data that were never compared against the CVE index.
 The scanner now publishes `security.scan.result.v1` on completion; the
 server subscribes and sweeps the organization's services through the
 matcher (EXACT_CPE / CPE_RANGE / SERVICE_VERSION / HEURISTIC), creating
 findings with full evidence chains.
- New `POST /api/v1/vulnerabilities/correlate` endpoint to re-run matching
 on demand — e.g. right after a feed sync pulls new CVE data.
- `ScanConfig` now records `top_tcp_ports` / `full_tcp_ports` so a scan's
 port selection is exactly reproducible.

### Fixed

- API collection fields `refs`/`assets` in the CVE detail response are
 always arrays, never `null` (from the community drop).

## [1.0.9] - 2026-09-16

### Fixed — demo-deployment blocker bugs

This release repairs the five defects reported from the demo deployment that
made the control plane effectively unusable. All fixes are verified end-to-end
against a real PostgreSQL 16 with fresh migrations and the demo seed
(`scripts/e2e-repro-bugs.sh`, 21/21 checks passing).

1. **`POST /api/v1/scans` returned 400 (`scans_profile_fkey` violation).**
 The `scan_profiles` table had no row for `discovery_safe` when scans were
 created before any profile sync had run. Built-in scan profiles are now
 upserted idempotently at server boot (`ProfileRepo.Sync`, log line
 `scan profiles synced`), and the API validates `profile` against the
 in-code registry, returning a clear `400 unknown profile` instead of a raw
 foreign-key error. Unknown/custom profile names can no longer wedge a scan
 into an uninsertable state.

2. **`GET /api/v1/topology?site_id=` returned 500 (`topology query failed`).**
 The UI legitimately calls this endpoint with an *empty* `site_id` before a
 site is selected. Empty `site_id` now returns the org-wide topology graph;
 a non-empty but malformed value returns `400 site_id must be a UUID`
 instead of letting Postgres reject the query.

3. **`POST /api/v1/sites/:id/networks` returned 400
 (`invalid input syntax for type inet: ""`).** Omitting `gateway` sent an
 empty string into a nullable `inet` column. Empty gateways are now stored
 as SQL `NULL` (`nullStr` normalization in the network repo), and the
 service layer validates CIDR and gateway explicitly with actionable error
 messages (`network must be a valid CIDR (got "…")`).

4. **`GET /api/v1/audit-log?limit=100` returned 500 (`audit list failed`).**
 Seeded audit rows carry `NULL` `actor_name`/`actor_ip`/`target`/`actor_id`,
 which pgx cannot scan into plain `string` fields. The list query now
 `COALESCE`s every nullable column, and the total count moved to a separate
 query because a window-function `COUNT(*) OVER ()` returns no row on an
 empty table — which 500'd the whole list on fresh deployments.

5. **`GET /api/v1/feeds` returned 500 (`feed list failed`).** Same NULL-scan
 class: `feed_sources.last_error` is nullable and was scanned into a plain
 string. It is now `COALESCE`d.

### Fixed — regression sweep over the same bug classes

The identical NULL-scanning defect pattern was audited and fixed across every
list endpoint that selects nullable columns: `GET /scans` (`scanner_id`,
`created_by`, `error`, `schedule_cron`), `GET /findings`, `GET
/detections/matches`, `GET /sites/:id/networks`, `GET /scanners`, `GET
/schedules`, `GET /reports`, `GET /agents`, `GET /assets`, `GET /services`
and `GET /vulnerabilities`. A unit regression test
(`nullscan_regression_test.go`) locks the behavior in.

### Added

- `VERSION` file and `-X main.version` build stamping; the running control
 plane now reports its version in the boot log line and in
 `GET /healthz` (`version` field), so a deployment can be verified at a
 glance.
- `scripts/e2e-repro-bugs.sh` — end-to-end regression suite covering the five
 reported bugs plus the same defect class on all other list endpoints.
