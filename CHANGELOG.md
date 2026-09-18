# Changelog

All notable changes to the Aegis Security Platform are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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
  the per-service `ostype` hint (`Linux`, `Windows`, ...), recorded at
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
  findings with full evidence chains (§72/§73).
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
