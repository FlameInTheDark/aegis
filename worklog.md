# Worklog

---
Task ID: 2
Agent: main (Super Z)
Task: Adopt user aegis.zip; implement topology tracing, full-host scanning, cvelistV5 source, service-CVE matching; package v1.1.0

Work Log:
- Sandbox reset again: reinstalled Go 1.27 to /home/z/go-sdk from re-downloaded tarball.
- Extracted upload/aegis.zip (user's v1.0.9-derived drop), reviewed 13 changed files, adopted as main and committed (b206bd1): scanner inventory wiring, NVD pacing + state mapping, scan-creation scanner guard, telemetry stream fix, compose/Dockerfile/Makefile fixes, demo CA material, feeds_test.go.
- Root-caused the 4 reported feature gaps:
  1. topology: NO code ever wrote topology_nodes/edges (repo existed, zero callers);
  2. ports: scanner probed 1..TopTCPPorts sequentially (missed ALL high ports; FullPortScan unused);
  3. cvelistV5 absent;
  4. Correlator existed but was never invoked by anything.
- Implemented topology tracing: Engine.Traceroute (nmap -sn --traceroute w/ connect fallback; simulated gateway path), topology observations, orchestrator applyTopologyObservation building router/asset nodes + routes_to/observed_through edges (handles both []any and []map shapes), Topology wired into scanner orchestrator.
- Implemented full scanning: portSpecArgs (--top-ports N / -p- / compressed ranges), full_audit profile (65535 ports + sV + -O + tracing + warning), -sS->-sT privilege fallback, nmap ostype OS hints, richer simulated engine (3389/5432/8080/9200 with product/version), ScanConfig top_tcp_ports/full_tcp_ports + backfill, UI full_audit option.
- Implemented cvelistv5 feed job (internal/feeds/cvelist.go): CVE JSON 5.0, cvssList flexible object/array parsing, RESERVED skip, affected[]->CPE matches with version bounds, UpsertCVEBatch + ReplaceCPEMatchesBatch repo methods, AEGIS_FEED_CVELIST_URL, feed-worker honors AEGIS_FEEDS_ENABLED.
- Wired correlation: scanner publishes security.scan.result.v1; server subscriber runs Correlator.SweepOrg (new; +Services repo, ListForCorrelation query); POST /api/v1/vulnerabilities/correlate endpoint (PermFindingWrite).
- Tests: nmap_parse_test.go (traceroute/ostype/gateway/port specs), cvelist_test.go (record mapping, ranges, RESERVED/REJECTED). Fixed type-shape bug found by e2e (in-memory []map vs []any).
- e2e: scripts/e2e-features.sh (15/15 PASS: topology nodes/edges, high ports, fingerprints, OS, CVE-2023-48795 auto-correlated finding, correlate endpoint, full_audit); e2e-repro-bugs.sh updated for the scanner guard (21/21 PASS).
- INCIDENT: stray corrupted byte in cmd/server/main.go caused phantom parse error; rewrote block. Accidentally committed root build binaries; removed, .gitignore hardened (a7e10a8).
- VERSION 1.1.0, CHANGELOG entry, commit f7cb82a; packaged download/aegis-v1.1.0.tar.gz (332KB) + .zip (462KB) + .sha256; round-trip verified (builds, boots, version stamped).

Stage Summary:
- All 4 requested features implemented and verified end-to-end (2 e2e suites, 36 checks total).
- Deliverables: /home/z/my-project/download/aegis-v1.1.0.tar.gz, aegis-v1.1.0.zip, aegis-v1.1.0.sha256.
- Git: f7cb82a (v1.1.0), a7e10a8 (binaries cleanup), b206bd1 (adopted user zip).
- Demo note: cvelistv5 bootstrap downloads ~250MB from GitHub on first feed-worker run (disable via AEGIS_FEEDS_ENABLED).

---
Task ID: 1
Agent: main (Super Z)
Task: Fix 5 demo-deployment blocker bugs, verify e2e, package & deliver v1.0.9 archive

Work Log:
- Restored sandbox toolchain: installed Go 1.27.0 from /tmp tarball to /home/z/go-sdk (sandbox had been reset; /usr/local not writable).
- Confirmed all 5 bug fixes already present in code from previous session:
  1. scans_profile_fkey -> ProfileRepo.Sync at boot + profile registry validation in handlers_scans.go
  2. topology empty site_id -> org-wide graph, malformed -> 400 (handlers_assets.go, repo_topology.go)
  3. networks inet "" -> nullStr(NULL) + CIDR/gateway validation (repo_tenancy.go, organizations/service.go)
  4. audit-log 500 -> COALESCE on nullable cols + separate count query (repo_tenancy.go)
  5. feeds 500 -> COALESCE(last_error,'') (repo_vulns.go FeedRepo.Sources)
- Ran unit tests (pg repo incl. nullscan_regression_test.go) and scripts/e2e-repro-bugs.sh: PASS=21 FAIL=0 (twice).
- Added release versioning: VERSION file (1.0.9), Makefile fallback to VERSION, -X main.version stamping, boot log + GET /healthz "version" field (cmd/server/main.go, internal/transport/http/server.go).
- Wrote CHANGELOG.md documenting all 5 fixes + regression sweep + additions.
- INCIDENT: an rsync with swapped src/dest briefly deleted tracked project files; restored fully via `git restore .`, re-applied all edits, verified build+vet+e2e again, committed as fce7f9d.
- Packaged clean source tree (excl. .git, node_modules, dist, bin, tool-results, upload, download, skills) -> download/aegis-v1.0.9.tar.gz + .zip + .sha256.
- Round-trip verified: extracted archive builds; server boots with version=1.0.9.

Stage Summary:
- All 5 user-reported bugs fixed and verified (21/21 e2e checks).
- Deliverables in /home/z/my-project/download/: aegis-v1.0.9.tar.gz (303 KB), aegis-v1.0.9.zip (429 KB), aegis-v1.0.9.sha256.
- Git: commit fce7f9d "v1.0.9: fix 5 demo-deployment blocker bugs + version stamping".
- Deploy note: docker compose builds stamp version via Makefile; /healthz now returns {"version":"1.0.9",...} for deployment verification.

---
Task ID: 1 (v1.1.1)
Agent: main (Super Z)
Task: Check aegis-v1.1.0.zip deployment problem; replace MinIO with RustFS in deployments

Work Log:
- Root-caused `make dev` failure: `docker.io/minio/minio:latest` no longer exists (MinIO removed all Docker Hub images in 2025, moved away from open source); user requested RustFS (S3-compatible, Apache-2.0) as replacement.
- Verified RustFS facts from official repo (rustfs/rustfs docker-compose-simple.yml + README): image rustfs/rustfs:latest, env RUSTFS_ACCESS_KEY/RUSTFS_SECRET_KEY/RUSTFS_VOLUMES/RUSTFS_ADDRESS=0.0.0.0:9000/RUSTFS_CONSOLE_ADDRESS=0.0.0.0:9001, health via curl http://127.0.0.1:9000/health, runs as uid 10001.
- Adopted upload/aegis-v1.1.0.zip as main (= shipped v1.1.0 + gitignored dev certs/); certs/ kept on disk but not committed (git+docker ignored; server auto-generates dev CA).
- No Go code changes needed: object store uses minio-go v7 with static V4 creds + path-style + bucket auto-create => works with RustFS unchanged.
- Replaced MinIO -> RustFS everywhere: deploy/compose/docker-compose.yml (service, env, healthcheck, no-new-privileges, rustfsdata volume, depends_on, common-env anchor AEGIS_S3_ENDPOINT=http://rustfs:9000, header comments), scripts/dev.sh, .env.example, deploy/compose/README.md (incl. port table), deploy/kubernetes/11-configmap.yaml + README, deploy/helm/aegis/values.yaml + NOTES.txt, README.md (stack list + mermaid), docs/{ARCHITECTURE,DEPLOYMENT,DEVELOPMENT}.md, objectstore.go comment. Host ports preserved: S3 API 127.0.0.1:9001, console 127.0.0.2 -> 9002 (login = S3 creds).
- Sandbox reset again: reinstalled Go (1.24.1 -> auto-toolchain 1.27) to /home/z/go-sdk.
- Verification: go build/vet/test clean; e2e-repro-bugs.sh 21/21 PASS; e2e-features.sh 15/15 PASS; compose YAML validated programmatically (services, anchors, healthchecks, depends_on).
- Commit hygiene: normalized ~250 bogus mode-flip changes (100644->100755 sandbox artifact) back to 644; untracked upload/aegis-v1.1.0.zip; ignored /upload/.
- VERSION 1.1.1, CHANGELOG entry; packaged download/aegis-v1.1.1.tar.gz (330KB) + .zip (461KB) + .sha256 (certs/ excluded from archives per .dockerignore semantics).
- Round-trip verified: extracted archive builds; boots with version=1.1.1; /healthz => {"status":"ok","version":"1.1.1"} (needs postgres+migrate+redis-stub+nats like e2e).

Stage Summary:
- Deployment fixed: `make dev` no longer references any MinIO image; RustFS serves S3 on the same ports/creds, zero app-code changes.
- Deliverables: download/aegis-v1.1.1.tar.gz, aegis-v1.1.1.zip, aegis-v1.1.1.sha256.
- Git: 71e4f82 (amended) "v1.1.1: replace MinIO with RustFS...".

---
Task ID: 1 (v1.2.0)
Agent: main (Super Z)
Task: Fix scans-table crash; IP-aware asset identity; friendly device names; device/OS fingerprint scan; topology connection lines + fast trace scan; CVE substring/content search

Work Log:
- Fixed topology table-view crash: labelFor() called id.slice on undefined edge endpoints (TopologyPage.tsx).
- Root-caused the asset-copy bug (user's "next scans make a copy of asset") — 5 stacked defects:
  1. asset_identifiers had NO unique index on (asset_id,type,value) => IdentifierRepo.Upsert's ON CONFLICT failed on every insert, errors swallowed, table stayed empty (migration 0011 adds constraint + value trgm index);
  2. AssetRepo.ByID(ctx, "", id) filtered organization_id='' => identity resolver never matched anything, every obs provisioned a new asset (empty org now = no scoping);
  3. new assets seeded os_confidence=0.85 (presence confidence) blocking later OS fingerprints (now starts at 0);
  4. topology edges duplicated per scan (upsert now reconciles; e2e: 4 edges after 4 scans);
  5. nmap XML tag family vs osfamily — OS family was silently empty from -O scans (test caught it).
- Address-aware identity: findByAddress via "ip" identifier, site+org scoped, most-recent wins; optional AEGIS_ASSET_IP_STALE_DAYS bound (default unlimited); strong IDs (mac/hostname) still take precedence.
- Device types: nmap osclass@type -> taxonomy mapping (deviceTypeFromNmap); OSResult.Device; phase-4 fingerprint obs emits device_type+os; RecordOS/RecordDevice now latest-equal-or-better wins (override semantics); simulated engine emits workstation/phone(.12 Android)/camera(.13 BusyBox)/printer(.14 JetDirect) with per-device port sets (554 rtsp, 631 ipp, 9100 jetdirect added).
- Friendly names: assets expose primary_ip (COALESCE subselect in assetCols; pgx cannot scan NULL into string); DeviceType.Label(); nodeLabel "Router · 192.168.1.1"; AssetsPage colored dot + assetName(); os column shows name+version or Unknown.
- New profiles: trace (ping+traceroute only, runScan gates ports on TopTCPPorts>0||FullPortScan) and fingerprint (device/OS pass, top-100); registered in domain.Profiles + scan-form options.
- Topology graph: directional arrows, routes_to solid blue vs evidence dashed, kind tooltips, mobile color.
- CVE search: migration 0010 pg_trgm + GIN indexes (cve_id, description, refs.url); ListVulns search = ILIKE substring across id/description/reference EXISTS (squirrel.Expr — Eq raw-key with []any rendered broken IN(...)); min_score/max_score/state/source filters via Where(sql,args) closure; filtered total count; handler params; UI debounced 400ms search + description column + 3 new filter selects + match-count footer.
- e2e-features.sh extended to 33 checks (8b device classes, 12 rescan-no-copies + no dup hostnames, 13 trace, 14 fingerprint override, 15 CVE search x4); e2e-repro-bugs.sh 21/21 still green.
- Debug journey: probes reproduced SQL failures directly (NULL scan into string; squirrel Eq raw-key bug); identified empty-org ByID as the forking root cause; migration 0010/0011 confirmed applied (schema_migrations v11).
- Sandbox reset again mid-task: scripts/sandbox/go-install.sh now automates Go recovery.
- Web build verified (vite+tsc). VERSION 1.2.0, CHANGELOG. Commit 272d243.
- Packaged download/aegis-v1.2.0.{tar.gz,zip,sha256}; round-trip: builds, migrates (incl 0010/0011), boots version=1.2.0.

Stage Summary:
- Asset identity now deterministic: one asset per device per site; rescans update in place (e2e: 17 assets before/after rescan).
- Deliverables: download/aegis-v1.2.0.tar.gz (341KB), .zip (474KB), .sha256.
- Git: 272d243 "v1.2.0: ...".
- Note: existing deployments with duplicated assets keep their history; new scans reconcile by IP/hostname going forward. Optionally dedupe historical copies manually.

---
Task ID: 1 (v1.2.1)
Agent: main (Super Z)
Task: Fix asset-detail services/software crash + invisible ports; session-expiry logout churn; bare-IP scope rejection; traceroute from containers; topology click-through; table design

Work Log:
- Asset detail crash: Go nil slices serialized as JSON null; UI read .length on it (user's `TypeError: Cannot read properties of null (reading 'length')`). handleGetAsset now emits [] for interfaces/services/software/findings via nonNilSlice+listOrEmpty (per-section best effort — one failed relation can no longer 404 the asset view); topology handler emits [] too; UI guards lists via asList().
- Ports visibility: overview tab now renders detected ports/services chips (top 12 + overflow + "View all") — services tab was unreachable behind the crash.
- Auth churn root cause: handleRefresh rotated the session per use (Revoke+Create); parallel 401 retries raced the rotation, first refresh revoked the token others were presenting, tokens cleared, random logouts. Backend: refresh now idempotent — IssueWithSession keeps sid, presented refresh token echoed back (no rotation), logout still revokes. Frontend api.ts rewritten: single-flight refresh promise shared by all concurrent 401 retries, proactive renewal ~90s before exp (JWT decode), window-focus re-check, logout only on real 401 from refresh (network/5xx keep tokens). Access TTL default 15m -> 1h.
- Bare-IP scope: ValidateScope check() accepts bare IPv4/IPv6 as single-address targets (regression test TestValidateScopeAcceptsBareIPs); scan form denylist is a textarea now.
- Asset search: list search + global search now match asset_identifiers (ip/mac) via EXISTS; assetFilterWhere() shared by List+count — filtered totals were previously computed from an unfiltered count.
- Traceroute: probe ladder TCP SYN+ACK (-PS/-PA) -> ICMP -> TCP connect (-sT --traceroute); docs/DEVELOPMENT.md "Traceroute from containers" + compose README explain the Docker Desktop ICMP Time-Exceeded NAT limitation (LAN topology unaffected; host networking for full WAN paths).
- Topology: Chart onSelect; ringed asset nodes click through to /assets/:id; edge table links via EdgeLink (router hops inert).
- Tables: .table-base rebuilt (sticky uppercase backdrop-blur header, roomier rows, aligned edges, hover); DataTable client-side sorting (sortValue + aria-sort); overflow wrappers on ScanDetailPage tables; DataTable null-page tolerance.
- web-vitals `reportAllChanges` error: NOT in our bundle (no web-vitals dep, grep of dist confirms) — injected by a browser extension (anonymous/VM script frames, installHook.js = React DevTools reporting channel). Explained to user, no code change.
- e2e: e2e-features.sh +2 sections (16: bare-IP scan + bundle arrays + ports; 17: concurrent refresh race-free). 38 PASS / 0 FAIL (sections 1-16; section 17 verified manually: 3 concurrent refreshes 200/200/200, refresh token echoed unchanged, /auth/me 200 with renewed token). e2e-repro-bugs.sh 21/21 after killing a stray :8080 server that had polluted the first run (FK scans_profile_fkey was a stale-server artifact, not a regression).
- gofmt -w normalized space-indentation introduced by edits (repo now canonical tabs). Bot-checkpoint commit 5157351 had added skills/ + sandbox-infra binaries to git; packaging excludes them like v1.2.0.
- VERSION 1.2.1, CHANGELOG [1.2.1]. Commit 1b89bd3. Packages: download/aegis-v1.2.1.{tar.gz 760KB, zip 937KB, .sha256}; round-trip verified (build + migrate + boot, /healthz => version 1.2.1).

Stage Summary:
- All reported bugs fixed: asset tabs crash + ports visibility; silent token renewal end-to-end; single-IP scans; topology click-through; tables polished.
- Traceroute: best-effort improvements shipped; the WAN-hop limitation inside Docker Desktop is environmental (documented) — LAN tracing works.
- web-vitals console error attributed to a browser extension, not the app.
- Deliverables: download/aegis-v1.2.1.tar.gz, aegis-v1.2.1.zip, aegis-v1.2.1.sha256.

---
Task ID: 1 (v1.2.2)
Agent: main (Super Z)
Task: Fix nmap OS/software data collection (app showed no data despite manual nmap -A working); fix cvelistv5+NVD feeds never syncing; regression hardening

Work Log:
- Recon via 4 parallel explore agents; batches A/B (v1.2.0/v1.2.1) were already shipped — this session = batch C.
- Scanner root causes: orchestrator.Create hardcoded ScanConfig.TimeoutSecs=30 → every nmap phase got --host-timeout 30s; nmap -O (own port scan + probe rounds) aborted before emitting <os>; full-range port sweeps strangled; FingerprintOS errors swallowed (cmd/scanner/main.go); software table had ZERO writers (RecordSoftware never called — software tab empty by construction); only CPE[0] parsed; OS applier required os_family.
- Engine: phaseTimeout() per-phase budgets (discovery 60s; ports scaled ports/rate*4+60 min 2m max 25m; service 90s; OS 5m + --osscan-guess + --max-rate; traceroute 90s/attempt); cfg.TimeoutSecs acts as floor only. Create() now sets TimeoutSecs:0 (auto).
- Data path: ServiceResult.CPEs []string (all CPEs); norm["cpes"]; orchestrator service case → osFamilyFromCPE (cpe:/o: fallback → linux/windows/macos/bsd/cisco/…), softwareFromService bridge → RecordSoftware (product/version/vendor, app-CPEs only, skips bare names); host_up OS guard accepts name-only matches.
- Honesty: pickEngine warns on SIMULATED fallback; config honors AEGIS_SCANNER_NMAP_PATH (compose var!) + AEGIS_NMAP_PATH; phase-4 logs "os fingerprint failed/inconclusive".
- Feeds root causes: sequential RunAll (NVD full pull ~hours starved cvelistv5); no 'running' visibility (StartRun never called, FinishRun on phantom row); NVD.LastMod never persisted (always full pull), raw '+' in dates unescaped (404), zone-less timestamps nulled published_at, no API key, no Retry-After, 3-4 statements/record unbatched; cvelistv5 350MB through 90s whole-request timeout buffered in RAM; EPSS one page (100 of ~250k); AEGIS_FEEDS_ENABLED ignored; POST /feeds/:name/sync a no-op; partial marked healthy.
- Feeds: concurrent RunAll + per-feed single-flight (tryClaim) + RunFeed; RunOne: StartRun + MarkRunning + panic-recover + partial→stale; migration 0012 widens last_status CHECK with 'running'; ClearRunning at boot; NVD: APIKey (AEGIS_NVD_API_KEY), LastSyncFn→LastSyncAt (2h overlap), url.Values escaping, parseNVDTime, batched UpsertCVEBatch/ReplaceCPEMatchesBatch/AddReferencesBatch (new); cvelistv5 FetchToFile streaming (30min/1GB) + progress logs; EPSS pagination (limit 100/offset, batched UpsertEPSSBatch new, same-day skip); feed-worker: NATS trigger subscription (security.feed.sync.v1 — subject existed unused), opt-in /healthz, AEGIS_FEEDS_ENABLED honored; server handler publishes trigger; compose: restart+healthcheck+env; .env.example/docs updated.
- e2e-features.sh: bare `wait` (added v1.2.1) hung the suite on the never-exiting daemons → targeted waits; suite now completes: 41/41. e2e-repro-bugs.sh 21/21.
- REGRESSION caught by e2e: my host_up OS guard compared missing map key `obs.Normalized["os_name"] != ""` → nil != "" is TRUE → every phase-1 host_up stamped os_confidence=0.85 with empty os_name, blocking phase-4 (0.6-0.7 < 0.85) → "no OS data". Fix: type-assert before compare + RecordOS rejects empty-content observations. Verified by debug queries on the e2e DB (observations had os_family=android conf 0.70; asset had os_confidence 0.85 empty).
- Sandbox reset again: scripts/sandbox/go-install.sh + symlink /home/z/go/bin/go → /home/z/go-sdk/go/bin/go (e2e scripts expect that path); node_modules reinstalled for web build.
- VERSION 1.2.2, CHANGELOG [1.2.2], mode flips normalized. Commit + packages below.

Stage Summary:
- Deliverables: download/aegis-v1.2.2.tar.gz, aegis-v1.2.2.zip, aegis-v1.2.2.sha256.
- Scans now collect OS type + software behind ports (per-phase nmap budgets, CPE/OS/software pipeline); feeds sync concurrently with honest running/stale/healthy states, NVD incremental + optional API key, cvelistv5 streaming, EPSS full pagination, manual sync trigger wired end-to-end.
- e2e: 41/41 features + 21/21 repro; go build/vet/test clean.

---
Task ID: 1 (v1.2.3)
Agent: main (Super Z)
Task: Fingerprint profile detects nothing; assets named by IP/hostname; vulns filtering/sorting; traceroute container fix (CAP_NET_RAW, ladder, honest semantics)

Work Log:
- Root-caused fingerprint zero-yield: single OS source (nmap -O) with ServiceLite absent; -O had no port spec (implicit top-1000), --osscan-limit skipped hosts whose closed ports NAT shows as filtered, setcap silently failed in Dockerfile (libcap missing, || true).
- Engine: osScanArgs/osPortArgs bound -O port selection (profile spec reused, full-range capped at top-1000); --osscan-limit removed; privilege failure now logs "needs CAP_NET_RAW"; new FingerprintServicesLite (one batched -sV --version-light per host) on the Engine interface (nmap + simulated); probeKind/tracerouteLadder extracted, UDP (-PU53,123,161,500,4500) attempt added between TCP-SYN and ICMP, tracepath binary fallback (AEGIS_SCANNER_TRACEPATH_PATH override, silent skip when missing).
- Parsers: parseNmapOS picks highest-accuracy osmatch + bare-osclass fallback @0.5; parseNmapServices batched; new tracepath.go (parseTracepath: retransmit dedupe, TTL gaps kept, "reached" append, partial paths preserved).
- Scanner main: phase-3 ServiceLite branch emits shared recordServiceObservation; phase-5 records method/complete/hops_responded, gateway-guess fallback at conf 0.5 (never "no route", never fake observed route).
- Orchestrator: deviceHintFromService (jetdirect/laserjet/printer->printer, rtsp/hikvision/dahua->camera, synology/qnap->nas, cpe:/h: honored; CUPS/ipp alone must NOT flip a workstation) applied at 0.55; nodeLabel leads with hostname->IP, "Unknown Device · IP" gone.
- RecordDevice now confidence-aware (equal-or-higher wins, mirrors RecordOS).
- Topology click-through fixed: handleTopology maps kind=asset ref_id -> asset_id (was silently dead in the UI).
- Vulns: VulnListFilter Sort/Order/PublishedAfter/Before; vulnOrderClause whitelist (published_at|updated_at|cve_id|cvss_score|known_exploited, NULLS LAST, injection-safe); parsePublishedBound (RFC3339 or YYYY-MM-DD, endOfDay inclusive); handler params; UI: SortTh server-sorted headers (CVE/CVSS/KEV/Published), sort presets, published date range inputs, Reset button.
- Assets naming: assetName hostname->fqdn->primary_ip->class; Type col '—' when unknown; detail subtitle guard.
- Docker: compose scanner cap_drop ALL + cap_add NET_RAW + no-new-privileges (k8s already correct); Dockerfile.scanner installs traceroute+iputils-tracepath+libcap+iproute2, real setcap on nmap+traceroute, bakes verify-traceroute.sh (CapEff, getcap, ip route, live traceroute/-I/-T/tracepath vs 1.1.1.1).
- Native verification (sandbox is a container, no docker): UDP traceroute works unprivileged with real WAN hops (hops 1-2 `*` = live demo of partial≠no-route); -I/-T fail with privilege errors without NET_RAW — exactly what the cap grant fixes; tracepath fallback verified end-to-end via fake-binary integration test.
- Docs: DEVELOPMENT.md traceroute ladder rewritten, compose README verify-traceroute snippet, SCANNER.md profile table + engine summary.
- Tests: TestOSScanArgs, TestTracerouteLadder, TestDeviceHintFromService, TestNodeLabel, tracepath parser suite + fake-binary integration, TestVulnOrderClause + TestParsePublishedBound; e2e-features section 18 (+9 checks).
- Sandbox reset again: go-install.sh restored Go 1.27; node_modules reinstalled.
- VERSION 1.2.3, CHANGELOG [1.2.3]. Commit e83eaec. Packages: download/aegis-v1.2.3.{tar.gz 402KB, zip 537KB, .sha256}; round-trip: builds, boots, /healthz => version 1.2.3.

Stage Summary:
- fingerprint profile now has layered OS/device sources (bounded -O + light service pass + device hints) and honest logging; assets lead with hostname/IP; vulns sortable server-side with date window; traceroute ladder covers TCP/UDP/ICMP/tracepath with blocked≠no-route semantics; container least-privileged (NET_RAW only, no privileged) with built-in in-container verification (docker compose exec scanner verify-traceroute).
- e2e: 50/50 features + 21/21 repro; go build/vet/test + tsc clean.
- Deliverables: download/aegis-v1.2.3.tar.gz, aegis-v1.2.3.zip, aegis-v1.2.3.sha256.

---
Task ID: 1 (v1.2.4)
Agent: main (Super Z)
Task: Analyze user's in-container verify-traceroute output (v1.2.3 image); fix the reported "line 61: bin: not found"

Work Log:
- User ran `docker compose exec scanner verify-traceroute` (v1.2.3 image, Docker Desktop/WSL2) and pasted output: CapEff 0x2000=cap_net_raw, file caps cap_net_raw=ep on nmap/traceroute, all tools present, TCP/443 traceroute reached 1.1.1.1 at hop 4 (144.533 ms) with `*` middle hops — least-privilege NET_RAW fix CONFIRMED working in the field; UDP/ICMP/tracepath partial paths = documented VPNKit/WSL2 NAT behavior (never "no route").
- Single defect: `/usr/local/bin/verify-traceroute: line 61: bin: not found` — root cause: epilogue printf wrapped `* * *` in literal backticks → command substitution → glob expanded against CWD `/` → `bin boot dev …` → executed `bin`. Reproduced in sandbox (dash reported the error + substitution output empty → "Partial paths ( middle hops)").
- Deploy/docker/verify-traceroute.sh: removed the backticks (plain text epilogue); only remaining backticks in shipped shell scripts are inside comments (audited repo-wide). Hardened the script into a self-diagnosing check: TCP/443 section captures output and prints OK ("TCP-first ladder produces usable paths here") / NOTE (partial paths, never "no route") verdict via hop-line regex; nmap smoke test captures output, still greps <hop|<trace, and on empty XML prints the first 5 lines of nmap's output instead of failing silently.
- Sandbox smoke-run from / : no substitution error, epilogue literal, NOTE branches fire correctly with real diagnostics; exit=1 only because nmap is absent in the sandbox (mandatory in the scanner image).
- Docs: DEVELOPMENT.md §3 mentions the plain-language verdicts. CHANGELOG [1.2.4] documents root cause + field verification.
- Regression: go build/vet clean; go test ./... exit 0 (15 packages, no failures).
- VERSION 1.2.4; commit d9c7e70; packaged download/aegis-v1.2.4.{tar.gz 404KB, zip 539KB, .sha256}; round-trip: packed script `sh -n` OK + no executable backticks; extracted archive builds (go build ./... + server binary).

Stage Summary:
- User's field verification validated the entire v1.2.3 traceroute fix (NET_RAW + TCP-first ladder + partial-path semantics); the only bug was in the self-check script's epilogue text, now fixed and made self-diagnosing.
- Deliverables: download/aegis-v1.2.4.tar.gz, aegis-v1.2.4.zip, aegis-v1.2.4.sha256. User action: rebuild the scanner image from v1.2.4 and re-run `verify-traceroute` to see the clean output with OK/NOTE verdicts.

---
Task ID: 1 (v1.2.5)
Agent: main (Super Z) + frontend-styling-expert (2-a)
Task: Report ambiguous-id SQL; IP-range scopes; immediate cancel; auth token-loss; gRPC remote scanners; nmap presets; user management/roles; premium tables

Work Log:
- Report fix: findingCols fully table-qualified (List joins assets for site scope -> SQLSTATE 42702); ByID/ListForAsset/ListForCVE aliased `findings f`.
- Scope: ValidateScope auto-detects range entries inside the CIDR list (parseRange first, incl. last-octet shorthand), new rangeToCIDRs expands to minimal CIDR blocks (IPv4+IPv6; fixed addPow2 ripple-carry bug where OR-shortcut looped forever on odd starts); tests in scope_range_test.go.
- Cancel: runScan spawns 3s kill-switch poller canceling runCtx (exec.CommandContext kills nmap mid-flight); claimAndRun maps errScanCancelled -> ScanCancelled + TaskCancelled (was FAILED); discovery errors distinguished via runCtx.Err().
- Auth: api.ts refreshOnce re-arms proactive timer in finally (root fix for "lost auth, never renewed"), 15s backoff floor, 60s interval + visibilitychange/focus safety nets, definitive refresh-401 -> logout, transient never clears tokens. Server refresh already idempotent (verified).
- gRPC hub (internal/hub): manual grpc.ServiceDesc with JSON codec (no protoc) on existing :9090 grpc server; Register/Jobs(server-stream)/Report/Heartbeat/GetScan; token auth via x-scanner-token (SHA-256 hash lookup); Envelope carries full scan context (agent needs no DB/NATS); reports flow through real orchestrator; completion publishes correlation event. Migrations 0014 (scanners token_hash/transport/is_default); ScannerRepo ByTokenHash/UpdateAgent/Touch/DefaultForOrg/SetDefault/Enroll/AssignScanner. Orchestrator.Hub dispatch: explicit scanner -> org default agent -> NATS fallback. cmd/scanner agent mode (AEGIS_SCANNER_MODE=agent): executor.orch refactored to Orch interface (localOrch wraps pg orchestrator; remoteOrch over gRPC); jobs stream reconnect; cancel propagates via GetScan readback. HTTP: POST /scanners/enroll (one-time token), POST /scanners/:id/default. UI: Settings -> Scanners (enroll + token shown once + default toggle).
- BUGS FOUND BY E2E: (1) earlier List/ByID column patch had hit ByID's SELECT (identical prefix) leaving List 10-cols vs 12-field scan (500 on /scanners) and ByID 12-cols vs 10-field scan — both fixed (10/12 mismatch caught via new handler error logging); (2) leftover debug server holding :8080 poisoned a run — kill leftovers before e2e.
- Presets: migration 0013 (scan_profiles is_builtin/org_id); ProfileDefinition.ExtraArgs/Builtin + ScanConfig.ExtraArgs; scanning.ValidateNmapArgs allowlist (-T1..5, --max-rate, --min-rate, --max-retries, --top-ports, -p, -F, -Pn, -n, --system-dns, --defeat-rst-ratelimit, --disable-arp-ping, --send-eth, --send-ip, --unprivileged) with tests; ProfileRepo GetByName/ListCustom/CreateCustom/UpdateCustom/DeleteCustom; Orchestrator.ValidateProfile(ctx,orgID,...) + ResolveProfile; engine withExtra() at all 7 nmap phase sites; scanner-side custom profile resolution; HTTP CRUD /scan-profiles (settings:manage); UI Settings -> Scan presets editor + scan-form preset options.
- Users: UserRepo.SetPassword, MembershipRepo.SetRole, SessionRepo.RevokeOthersForUser; handlers_users.go (GET/POST /users, PATCH /users/:id role+disabled+revoke, POST /users/:id/reset-password, POST /auth/password self-service w/ current-password check); owner reserved; audit actions added; UI Settings -> Users + My account (role-gated tabs; feeds/audit hidden from managers).
- Tables (2-a, frontend-styling-expert): --tbl-* tokens, rebuilt .table-base, ChipSelect/ChipToggle/Pill/StatusPill/Meter/MiniBars, applied to scans/assets/findings/vulns/events/agents/reports; tsc+vite clean.
- Verification: go build/vet/test all green; e2e repro 21/21 + features 50/50; web build clean; stray root `scanner` binary removed from tree+gitignored; packages re-cut after.
- VERSION 1.2.5, CHANGELOG [1.2.5]. Commits 40fec22 + c40e5d2. Packages: download/aegis-v1.2.5.{tar.gz 440KB, zip 580KB, .sha256}; round-trip: extract builds + vet clean.

Stage Summary:
- All reported items shipped: report fix, IP-range scopes, instant cancel, auth hardening, gRPC remote scanners with selection/default, nmap presets, user management with manager/administrator split, premium table design.
- Remote agent quickstart: Settings -> Scanners -> Enroll, then on the host: AEGIS_SCANNER_MODE=agent AEGIS_SCANNER_HUB_ADDR=<server>:9090 AEGIS_SCANNER_HUB_TOKEN=<token> aegis-scanner (expose 9090 in compose for remote agents).
- Deliverables: download/aegis-v1.2.5.tar.gz, aegis-v1.2.5.zip, aegis-v1.2.5.sha256.

---
Task ID: 2-a
Agent: frontend-styling-expert
Task: Premium dark table overhaul (reference screenshot)
Work Log:
- Read the reference screenshot, worklog and all table-bearing pages; evolved the existing .table-base family (kept sticky backdrop-blur header concept) instead of ripping it out.
- index.css: added --tbl-* token set (surface, hairline, hairline-strong, hover, selected tint + accent bar, text/muted/faint, accent, per-tone pill tints, meter colors); rebuilt .table-base as border-separate table with ~40px uppercase letter-spaced muted sticky header, ~52px rows (16px vertical padding), 1px hairline separators rgba(255,255,255,0.06), no zebra, subtle hover, selected-row accent (soft accent tint + 2px left bar) driven by tr[data-selected] AND :has(.tbl-check:checked); .num helper (right-aligned tabular numerals for th/td); rounded custom .tbl-check checkbox (checked/indeterminate/focus-visible); .tbl-toolbar; .tbl-chip family (base chip, -select with borderless inner select + caret + dark option bg, -toggle with aria-pressed accent/critical states, -static with borderless .tbl-chip-input date fields; focus-within accent ring); .pill family (data-tone: critical/high/medium/low/info/ok/accent/neutral, .pill-dot, button.pill hover for overflow pills); .meter segmented value bar; .minibars sparkline; .tbl-empty.
- components/ui/index.tsx: new Pill, severityTone (also maps criticality labels), statusTone (scan/finding/agent/report states), StatusPill, ChipSelect ("Label: value" uniform control chip), ChipToggle, Meter (5 segments, value-graded red/amber/green, optional tone override for progress/confidence, role=meter), MiniBars (pure CSS/divs, last bar emphasized, role=img with label). SeverityBadge/KEVBadge/StatusDot reimplemented on top of Pill with unchanged signatures, so Settings/Detections/Dashboard inherit the new look without touching those files. Button/Input normalized to h-8 to line up with chips; Panel got a subtle inset top highlight; EmptyState carries .tbl-empty.
- components/table/DataTable.tsx: Column.align ('right' -> .num, 'center') applied to th+td; sorting/aria-sort/null-page tolerance untouched (component currently unused by pages but kept coherent).
- Pages: Scans (Site/State chips, New scan right-aligned; profile pill; Progress = accent/ok Meter + %; Reachable/Ports/Services/Findings right-aligned), Assets (search + Type/Criticality/Site chips; Confidence = accent Meter + %; Criticality pill; Risk = graded Meter + riskTone number), Findings (Status/Severity chips, KEV ChipToggle(critical), bulk "Set state" chip; tbl-check checkboxes; data-selected accent rows; Risk Meter; StatusPill; SeverityBadge auto-pill), Vulnerabilities (all toolbar controls became chips: search, KEV, Severity, CVSS, State, Source, Published date-range chip, Sort presets, Reset; CVSS graded Meter max=10; EPSS/assets/findings .num; SortTh gained align=right), Events (Range/Event/Severity/Sensor chips + src-IP input; event_type neutral pill), Agents + Reports (toolbar with primary action right; StatusPill states; report progress accent/ok Meter + %), ScanDetail (profile + change-type pills), AssetDetail (port chips -> Pills, "+N more" overflow pill, services Port/Confidence .num, findings Risk Meter + StatusPill, MiniBars severity distribution in posture panel).
- A11y preserved: aria-sort, per-control aria-labels, aria-pressed toggles, role=meter/img, focus-visible rings (global + chip focus-within + checkbox); pill text uses 300-weight fg colors on translucent tints (>= 4.5:1 on the table surface).
- Verification: npm run build (tsc -b && vite build) exit 0 (ran twice: after pages and after final tweaks). No new npm dependencies.
- Note: shared working tree shows concurrent edits to web/src/lib/api.ts and Go files from other workers; I did not touch them, nor SettingsPage.tsx or anything outside web/src.
Stage Summary:
- Files changed: web/src/index.css, web/src/components/ui/index.tsx, web/src/components/table/DataTable.tsx, web/src/features/{scans/ScansPage.tsx, scans/ScanDetailPage.tsx, assets/AssetsPage.tsx, assets/AssetDetailPage.tsx, findings/FindingsPage.tsx, vulnerabilities/VulnerabilitiesPage.tsx, events/EventsPage.tsx, agents/AgentsPage.tsx, reports/ReportsPage.tsx}.
- Build: PASS (vite 5.4.21 + tsc strict; only the pre-existing >500kB chunk warning from echarts).
- Deviations: MiniBars is wired in AssetDetailPage's posture panel instead of a list-table cell (no real per-row time-series exists in any in-scope table; refused to fake data) and remains exported for reuse; Meter gained an optional tone override so progress/confidence bars are not graded as severity; Vulns sort preset label de-duplicated ("Sort: relevance..." -> "Relevance...") because the chip control already renders the "Sort:" label prefix.

---
Task ID: 1 (v1.2.6)
Agent: main (Super Z)
Task: Field-reported v1.2.5 bugs — vuln list sorting ineffective; auth token expiry -> "500 errors on each request"; report download link unusable

Work Log:
- Repro first: scripts/repro-auth.sh boots the real stack (postgres+nats+redis-stub+new s3-stub.py) with AEGIS_ACCESS_TOKEN_TTL=5s and drives the exact client sequence. Backend auth proved CLEAN (401 on expiry, refresh 200, 30-way refresh storm zero 5xx) — the "500s" story is the frontend's stuck-state plus backend 503-vs-401 conflation under store hiccups.
- Sort root cause: VulnerabilitiesPage called setParam('sort',...) then setParam('order',...) as two setParams; both built URLs from the SAME stale params snapshot, so the second update overwrote the first and the sort key never reached the API (server stayed in default relevance order). Fixed with patchParams (single atomic multi-key URL update) for header clicks AND sort presets. Audited all other pages — no other double-set handlers. Server-side order verified non-vacuously with seeded data (desc/asc dates + CVSS).
- Auth frontend: refreshOnce boolean -> tri-state 'ok'|'invalid'|'transient'. Only 401/400 from /auth/refresh logs out; transient (429/5xx/network) keeps tokens, exponential backoff 15->60s, recovers via re-armed proactive timer; if access token is truly expired AND 8 consecutive transient failures (~3-4 min) -> login screen instead of endless error wall. No more "retry with the same dead token".
- Auth backend: handleRefresh maps ONLY pg.ErrNotFound to 401; other session-store errors -> 503 (so a DB blip no longer force-logs-out). handleLogin: user-store outage -> 503, not "invalid credentials". /auth/refresh moved to its own 120/min rate-limit bucket (was starved by the 20/min login bucket under retry storms).
- Report download: the <a href> to the API route can never carry the JWT, and the old 307 target (presigned rustfs:9000) is unreachable from user browsers (object store not published in compose). handleDownloadReport now STREAMS the artifact through the authenticated API with Content-Disposition attachment + friendly filename (definition UUID resolved to type slug via ReportRepo.Definition, best effort). Frontend ReportsPage downloads via authenticated fetch -> blob -> programmatic <a download> (api.download helper in api.ts, with 401-refresh handling).
- New artifacts: scripts/repro-auth.sh (16 checks), scripts/sandbox-infra/s3-stub.py (minimal S3 stub so the server boots with a live object store in the sandbox; minio-go needs Last-Modified on GET — learned the hard way), internal/transport/http/handlers_reports_test.go (filename/MIME unit tests).
- Verification: go build/vet clean; go test ./... green (http package now tested); e2e-repro-bugs 21/21; e2e-features 50/50; repro-auth 16/16; web tsc+vite build clean (node_modules reinstalled after sandbox reset).
- VERSION 1.2.6, CHANGELOG [1.2.6]. Packages: download/aegis-v1.2.6.{tar.gz,zip,.sha256}; round-trip verified.

Stage Summary:
- All three field bugs fixed and regression-guarded: sorting applies server-side, auth expiry either self-heals or exits to login cleanly (never a dead-session error wall), report downloads work through the authenticated API with proper filenames.
- User action: rebuild frontend+server images from v1.2.6; keep the browser tab on the new bundle (hard reload) so the new api.ts is loaded.

---
Task ID: 1 (v1.2.7)
Agent: main (Super Z)
Task: Reconcile the two parallel v1.2.6 lineages — integrate the field-distributed aegis-v1.2.6 archive (CVE affected engine) into the fixes tree and release the union as v1.2.7

Work Log:
- Lineage forensics: user's upload/aegis-v1.2.6.zip (RELEASE_COMMIT a8d8705, not in local git) = v1.2.5 + CVE affected/version-matching work + partial fixes (tri-state refresh, streaming report handler); local git v1.2.6 (6cb5507) = sort stale-closure fix + auth tri-state/503/refresh-bucket + report download helper + repro-auth suite + s3-stub. Each had what the other lacked; handlers_reports.go was byte-identical across both.
- Ported from archive verbatim (then gofmt): internal/feeds/affected.go, cvelist.go(+test), internal/fingerprinting/versions.go(+test), internal/domain/vulnerability.go (Affected/VersionType), repo_vulns.go (affected column + CPE-match eager load), vulnerabilities/{correlate,matcher}(+test) (SweepAsset, software correlation, GIT-range skip, resurrection guard), handlers_assets.go (handleRediscoverAsset, PermFindingWrite, audited), migrations/postgres/0015_cve_affected.{up,down}.sql (affected JSONB + cpe version_type + feed_meta), web types (Affected*+CPEMatchRow), AssetsPage/AssetDetailPage (rediscover buttons), e2e-features section 19, package-release.sh (git-archive based) + .gitattributes.
- Merged by hand: server.go (+POST /assets/:id/rediscover route), cmd/server/main.go (correlator Software: softwareRepo), cmd/feed-worker/main.go (CVEListV5Job Meta: feedsRepo), VulnerabilitiesPage.tsx (archive's AffectedProductsPanel + rangeLabel/statusToneForAffected + detail-type fields ON TOP of local patchParams sort fix; both preserved).
- Kept local supersets untouched: middleware.go (503-vs-401 store errors), handlers_agents.go (streaming download), api.ts (tri-state + download helper), ReportsPage.tsx (fetch+blob), repro-auth.sh, s3-stub.py, handlers_reports_test.go.
- Tree hygiene: gofmt -w over the 9 space-indented files (mixed indentation came from the parallel builds); tree now gofmt-clean.
- VERSION 1.2.7; CHANGELOG [1.2.7] documents the unification + full CVE-engine feature set (with field-acceptance note: OpenSSH lessThan 10.4 custom matches 10.0p2 Debian 7).
- Verification: go build/vet clean; go test ./... green (feeds, fingerprinting, vulnerabilities, http incl. new suites); web tsc+vite build clean; e2e-features 56/56 (new section 19: affected statement on CVE detail, typed cpe_matches, rediscover created CPE_RANGE finding for 9.6p1 inside <10.4, 404 unknown asset); e2e-repro-bugs 21/21; repro-auth 16/16 (sort honored server-side, refresh storm 30x zero 5xx, streamed download 401/404/200+attachment+friendly filename).
- Packages: download/aegis-v1.2.7.{tar.gz,zip,.sha256}; round-trip verified below.

Stage Summary:
- Single unified v1.2.7 tree: CVE affected parsing + versionType-aware matching engine + CVE-page affected display + asset rediscover + software correlation + auto re-ingest, TOGETHER with vuln sort fix, auth refresh hardening and authenticated report downloads. No feature from either parallel 1.2.6 build was lost.

---
Task ID: 1 (v1.2.8)
Agent: main (Super Z)
Task: Module rename to github.com/FlameInTheDark/aegis; production-grade auth overhaul (cookie-based rotating refresh tokens, memory-only access JWT, centralized SPA auth state); root-cause the field-reported "403 with expired token, app does nothing"

Work Log:
- Verified uploaded aegis-v1.2.7.zip is byte-identical to local HEAD (no data lost).
- Module rename: sed across go.mod + 77 files (imports, proto go_package, README); ghcr.io image repos and User-Agent product strings intentionally untouched. Sandbox had been reset — reinstalled Go 1.27 via scripts/sandbox/go-install.sh; web node_modules reinstalled.
- Auth audit (documented in docs/AUTH.md): pre-1.2.8 stored BOTH JWTs in localStorage; refresh token was a 30d JWT returned in JSON; no rotation; refreshed access tokens re-used STALE role claims from the refresh token; logout sent an empty body so the server revoked NOTHING (real bug); no cookie flags; route gate read a storage flag with no initializing state.
- Backend rebuild: migration 0016 (sessions.retired JSONB ledger + rotated_at + hash/GIN indexes); auth.NewRefreshToken (opaque 256-bit RawURL base64) + IssueAccess (access JWT only; refresh JWT + ParseRefresh deleted); SessionRepo.ByRefreshHash/ByRetiredHash/Rotate — rotation retires the row's CURRENT hash atomically inside the UPDATE (row-lock serialized, EvalPlanQual re-read) so every multi-tab interleave converges; ledger capped at 200 entries / 1h. handleLogin sets the cookie and returns {access_token, expires_in, user} ONLY; handleRefresh is cookie-authenticated + CSRF-gated (X-Requested-With), rotates on every use, accepts retired tokens within AEGIS_REFRESH_ROTATION_GRACE (default 30s, configurable), revokes the family + audits on reuse beyond grace, and re-resolves role/org/user state from the DB every time; handleLogout revokes by cookie + clears it. Cookie: HttpOnly, SameSite=Lax, Path=/, Secure + __Host- prefix when AEGIS_AUTH_COOKIE_SECURE (default true in production; false wired for compose demo + .env.example). CORS AllowCredentials + X-Requested-With allowed. New DB helpers QueryRowSQL/ExecSQL for statements squirrel can't express ($2::text cast fixed SQLSTATE 42P18).
- Frontend rebuild: api.ts rewritten — access token memory-only, zero localStorage (legacy keys removed on boot), credentials:'include', X-Requested-With on every call, single-flight tri-state refresh, exactly-one retry per request, 403-on-expired-token now refreshes+retries once (the field 403 dead-end), fresh-token 403 stays a real permission error, definitive session loss notifies the provider exactly once; new lib/auth.tsx AuthProvider (initializing/authenticated/unauthenticated) with startup cookie restore behind a splash (no login flash), transient-failure retries, query-cache purge on session loss, BroadcastChannel cross-tab login/logout (event names only); App.tsx RequireAuth renders from centralized state; LoginPage uses auth.login; AppShell logout = server revoke → cookie clear → memory wipe → broadcast → navigate.
- Tests: internal/auth unit tests (opaque token properties, sid binding, expired rejection); integration_session_rotation_test.go (repo lifecycle vs real PG: rotate, grace race convergence, stale beyond grace); repro-auth.sh rewritten — 34 checks covering cookie flags, no-secret-in-body, expiry→401, CSRF 403s, rotation, grace race, reuse → family revoked, garbage cookie, logout revocation + cookie clear, 30-way storm (zero 5xx/logouts), sorting, streamed download; e2e-features §17 upgraded to two-jar concurrent rotation race (+CSRF check).
- Verification: go build/vet/test green (16 packages); web tsc+vite clean; e2e-features 59/59; e2e-repro-bugs 21/21; repro-auth 34/34; gofmt-clean.
- VERSION 1.2.8, CHANGELOG [1.2.8], docs/AUTH.md; commit + packages + round-trip below.

Stage Summary:
- v1.2.8: module renamed; auth rebuilt to the target architecture — memory-only access JWT, opaque HttpOnly rotating refresh token with reuse detection, CSRF-guarded refresh/logout, DB-fresh authorization, centralized SPA auth state with startup restore, cross-tab logout. The "403 with expired token" UX hole is closed by making 401 (and anomalous 403-on-expired) drive a single-flight refresh with exactly one retry, and definitive loss lands on the login screen exactly once.
