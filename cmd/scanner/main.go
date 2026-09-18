// Command scanner is the distributed active scanning worker (spec §5.3,
// §69). It registers itself, claims scans assigned to its site, runs the
// configured engine (nmap/simulated), normalizes observations and reports
// them back. It enforces resource limits and honors the kill switch.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"log/slog"

	"github.com/FlameInTheDark/aegis/internal/assets"
	"github.com/FlameInTheDark/aegis/internal/config"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/logging"
	"github.com/FlameInTheDark/aegis/internal/platform"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/scanner"
	"github.com/FlameInTheDark/aegis/internal/scanning"
)

const scannerVersion = "1.0.0"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load("scanner")
	if err != nil {
		return err
	}
	log := logging.New(cfg.LogLevel, cfg.LogFormat)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := pg.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer db.Close()

	// No site pinned: fall back to the platform's first site (demo /
	// single-site deployments — bootstrap creates it). Without a site the
	// registration upsert would violate scanners.organization_id NOT NULL.
	if cfg.Scanner.SiteID == "" {
		site, err := pg.NewSiteRepo(db).First(ctx)
		if err != nil {
			return fmt.Errorf("scanner: AEGIS_SCANNER_SITE_ID is required (no sites exist — start the server once to bootstrap)")
		}
		cfg.Scanner.SiteID = site.ID
		log.Info("scanner: no site configured, using first site", "site", site.ID, "name", site.Name)
	}

	bus, err := platform.ConnectBus(ctx, cfg.NATSURL)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer bus.Close()

	engine := pickEngine(cfg, log)
	engVersion, _ := engine.Version(ctx)

	scannerID, err := register(ctx, cfg, db, engVersion)
	if err != nil {
		return err
	}
	log.Info("scanner registered", "id", scannerID, "site", cfg.Scanner.SiteID, "engine", engine.Name(), "engine_version", engVersion)

	assetsRepo := pg.NewAssetRepo(db)
	changesRepo := pg.NewChangeRepo(db)
	inventory := &assets.Service{
		Assets: assetsRepo, Ident: pg.NewIdentifierRepo(db), Ifaces: pg.NewInterfaceRepo(db),
		Services: pg.NewServiceRepo(db), Software: pg.NewSoftwareRepo(db), Changes: changesRepo, Log: log,
		// Address-aware identity: by default an IP always resolves to
		// the asset that last held it (rescan = update, not copy).
		// Set AEGIS_ASSET_IP_STALE_DAYS to bound that reuse window.
		IPStale: ipStaleFromEnv(),
	}
	orch := &scanning.Orchestrator{
		Scans: pg.NewScanRepo(db), Tasks: pg.NewTaskRepo(db), Observations: pg.NewObservationRepo(db),
		Scanners: pg.NewScannerRepo(db), Schedules: pg.NewScheduleRepo(db), Profiles: pg.NewProfileRepo(db),
		Changes: changesRepo, Assets: assetsRepo, Inventory: inventory, Topology: pg.NewTopologyRepo(db),
		Bus: bus, Log: log,
		AllowPublicScope: cfg.Scanner.AllowPublicScope,
	}
	exec := &executor{cfg: cfg, engine: engine, orch: localOrch{o: orch}, log: log, limits: scanner.DefaultLimits()}
	exec.limits.MaxTargets = cfg.Scanner.MaxTargets
	exec.limits.MaxPacketRate = cfg.Scanner.MaxPacketRate

	// Agent mode: dial the hub and execute pushed scans over gRPC — for
	// scanners installed on physical hosts (no Postgres/NATS access).
	if cfg.Scanner.Mode == "agent" {
		if cfg.Scanner.HubAddr == "" || cfg.Scanner.HubToken == "" {
			return fmt.Errorf("agent mode requires AEGIS_SCANNER_HUB_ADDR and AEGIS_SCANNER_HUB_TOKEN")
		}
		log.Info("scanner running in agent mode", "hub", cfg.Scanner.HubAddr)
		return runAgent(ctx, exec, cfg.Scanner.HubAddr, cfg.Scanner.HubToken)
	}

	// Heartbeat + claim loop.
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("scanner stopping")
			return nil
		case <-t.C:
			_ = pg.NewScannerRepo(db).Upsert(ctx, &domain.Scanner{
				ID: scannerID, OrganizationID: orgForSite(ctx, db, cfg.Scanner.SiteID),
				SiteID: cfg.Scanner.SiteID, Name: cfg.Scanner.ScannerName, Version: scannerVersion,
				Capabilities: cfg.Scanner.Capabilities, Health: "healthy", LastSeen: time.Now().UTC(),
			})
			if err := exec.claimAndRun(ctx, scannerID); err != nil {
				log.Warn("scan run failed", "err", err)
			}
		}
	}
}

func pickEngine(cfg *config.Config, log *slog.Logger) scanner.Engine {
	if cfg.Scanner.NmapPath != "" {
		if _, err := os.Stat(cfg.Scanner.NmapPath); err == nil {
			return &scanner.NmapEngine{BinPath: cfg.Scanner.NmapPath}
		}
		log.Warn("nmap binary not found; falling back to the SIMULATED engine — results are synthetic demo data, not real scans",
			"path", cfg.Scanner.NmapPath)
	} else {
		log.Warn("no nmap path configured; falling back to the SIMULATED engine — results are synthetic demo data, not real scans")
	}
	// Fall back to the simulated engine so demo/air-gapped deployments work
	// without nmap (spec §139/§105). All results are tagged simulated.
	return &scanner.SimulatedEngine{}
}

// register creates or refreshes this scanner's registration (§69).
func register(ctx context.Context, cfg *config.Config, db *pg.DB, engVersion string) (string, error) {
	repo := pg.NewScannerRepo(db)
	ifaces, _ := localInterfaces()
	name := cfg.Scanner.ScannerName
	if name == "" {
		name = "scanner-" + hostnameOrLocal()
	}
	// Reuse an existing registration with the same name at the site.
	existing, err := repo.List(ctx, cfg.Scanner.SiteID)
	if err == nil {
		for _, s := range existing {
			if s.Name == name && s.SiteID == cfg.Scanner.SiteID {
				return s.ID, nil
			}
		}
	}
	// scanners.id is a UUID primary key — the display name never goes there.
	sc := &domain.Scanner{
		ID: ids.New(), OrganizationID: orgForSite(ctx, db, cfg.Scanner.SiteID), SiteID: cfg.Scanner.SiteID, Name: name,
		Version: scannerVersion + "/" + engVersion, Capabilities: cfg.Scanner.Capabilities,
		Interfaces: ifaces, Health: "healthy", LastSeen: time.Now().UTC(),
	}
	if sc.OrganizationID == "" {
		return "", fmt.Errorf("scanner: site %s not found (cannot resolve organization)", cfg.Scanner.SiteID)
	}
	if err := repo.Upsert(ctx, sc); err != nil {
		return "", err
	}
	return sc.ID, nil
}

func hostnameOrLocal() string {
	h, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return h
}

func localInterfaces() ([]string, error) {
	return nil, nil // platform interface enumeration is scanner-deployment specific; documented
}

func orgForSite(ctx context.Context, db *pg.DB, siteID string) string {
	site, err := pg.NewSiteRepo(db).ByID(ctx, "", siteID)
	if err != nil || site == nil {
		return ""
	}
	return site.OrganizationID
}

// errScanCancelled is returned by runScan when the kill switch fires or
// the scan transitions to cancelling: claimAndRun maps it to the CANCELLED
// scan state instead of FAILED, and the in-flight nmap process is killed
// through the run context (exec.CommandContext) rather than left to run.
var errScanCancelled = errors.New("scan cancelled via kill switch")

// executor claims queued scans and drives them through task phases.
type executor struct {
	cfg    *config.Config
	engine scanner.Engine
	orch   Orch
	log    *slog.Logger
	limits scanner.Limits
	mu     sync.Mutex
	active bool
}

type logT = *slog.Logger

// claimAndRun processes one queued scan for this scanner's site.
func (e *executor) claimAndRun(ctx context.Context, scannerID string) error {
	e.mu.Lock()
	if e.active {
		e.mu.Unlock()
		return nil
	}
	e.active = true
	e.mu.Unlock()
	defer func() { e.mu.Lock(); e.active = false; e.mu.Unlock() }()

	scans, err := e.orch.QueueScans(ctx)
	if err != nil {
		return err
	}
	for i := range scans {
		scan := scans[i]
		if scan.SiteID != e.cfg.Scanner.SiteID {
			continue
		}
		if err := e.runScan(ctx, &scan, scannerID); err != nil {
			if errors.Is(err, errScanCancelled) || ctx.Err() != nil {
				e.log.Info("scan cancelled", "scan", scan.ID)
				_ = e.orch.UpdateScanState(ctx, scan.ID, domain.ScanCancelled, "cancelled", scan.Progress)
				_ = e.orch.UpdateTaskState(ctx, scan.ID+"-discover", domain.TaskCancelled, "cancelled")
				continue
			}
			e.log.Error("scan failed", "scan", scan.ID, "err", err)
			_ = e.orch.SetScanError(ctx, scan.ID, err.Error())
			_ = e.orch.UpdateScanState(ctx, scan.ID, domain.ScanFailed, "failed", scan.Progress)
		}
	}
	return nil
}

// runScan executes the phased pipeline (§68): discover -> ports ->
// fingerprint -> OS -> topology trace.
func (e *executor) runScan(ctx context.Context, scan *domain.Scan, scannerID string) error {
	if scan.Config == nil {
		scan.Config = &domain.ScanConfig{Profile: scan.Profile, MaxRate: 100, TimeoutSecs: 30, Engine: e.engine.Name()}
	}
	// Resolve the profile definition: built-ins come from the static
	// registry, custom nmap presets from the scan_profiles table (org-scoped
	// rows created in Settings). An unknown profile degrades to the zero
	// definition — phases gated on its flags simply stay off, with a loud
	// warning instead of silently pretending everything is fine.
	profile, profileOK := domain.Profiles[scan.Profile]
	if !profileOK {
		if def, derr := e.orch.ResolveProfile(ctx, "", scan.Profile); derr == nil {
			profile, profileOK = *def, true
		}
	}
	if !profileOK {
		e.log.Warn("scan references an unknown profile - running with phase gating off", "profile", string(scan.Profile))
	}
	// Custom presets ship validated extra nmap arguments in their spec; the
	// orchestrator already copied them into the scan config at create time.
	if scan.Config != nil && profileOK && len(profile.ExtraArgs) > 0 && len(scan.Config.ExtraArgs) == 0 {
		scan.Config.ExtraArgs = profile.ExtraArgs
	}

	// Backfill port-selection semantics for scans created before the config
	// carried them (older queued scans, manual DB inserts).
	if scan.Config.TopTCPPorts == 0 && !scan.Config.FullTCPPorts && len(scan.Config.TCPPorts) == 0 {
		if profile.FullPortScan {
			scan.Config.FullTCPPorts = true
		} else if profile.TopTCPPorts > 0 {
			scan.Config.TopTCPPorts = profile.TopTCPPorts
		}
	}
	scope, err := e.orch.Scope(ctx, scan.ID)
	if err != nil {
		return err
	}
	targets := scope.CIDRs
	if scope == nil || len(targets) == 0 {
		targets = []string{}
	}
	_ = e.orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "discovery", 5)
	_ = e.orch.CreateTask(ctx, &domain.ScanTask{ID: fmt.Sprintf("%s-discover", scan.ID), ScanID: scan.ID, Type: domain.TaskDiscoverHosts, State: domain.TaskRunning, ScannerID: scannerID, Attempt: 1})

	// Immediate cancellation: poll the kill switch while probes are
	// IN FLIGHT and cancel runCtx, which exec.CommandContext turns into
	// a kill of the running nmap process - a cancelled scan must not
	// wait minutes for the current phase to finish (its result is not
	// needed). DB writes below keep the outer ctx so final state
	// updates still persist after cancellation.
	runCtx, killRun := context.WithCancel(ctx)
	defer killRun()
	pollStop := make(chan struct{})
	defer close(pollStop)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-pollStop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if checkKill(ctx, e.orch, scan.ID) {
					e.log.Info("kill switch observed - aborting in-flight probes", "scan", scan.ID)
					killRun()
					return
				}
			}
		}
	}()

	// Phase 1: host discovery.
	hosts, err := e.engine.DiscoverHosts(runCtx, targets, scan.Config, e.limits)
	if err != nil {
		if runCtx.Err() != nil {
			return errScanCancelled
		}
		return fmt.Errorf("host discovery: %w", err)
	}
	reachable := len(hosts)
	stats := domain.ScanStats{Targets: len(targets), Reachable: reachable, Unreachable: len(targets) - reachable}
	_ = e.orch.UpdateScanStats(ctx, scan.ID, stats)
	for i, h := range hosts {
		if runCtx.Err() != nil || checkKill(ctx, e.orch, scan.ID) {
			return errScanCancelled
		}
		payload, _ := json.Marshal(map[string]any{"ip": h.IP, "hostname": h.Hostname, "mac": h.MAC, "device_type": h.Device})
		_ = e.orch.RecordObservation(ctx, &domain.Observation{
			ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
			Target: h.IP, ObservationType: "host_up", Timestamp: time.Now().UTC(),
			Source: sourceFor(e.engine), Payload: payload,
			Normalized: map[string]any{"ip": h.IP, "hostname": h.Hostname, "mac": h.MAC, "device_type": h.Device},
			Confidence: domain.Confidence(h.Confidence),
		})
		_ = e.orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "discovery", 5+float64(i)/maxF(1, float64(len(hosts)))*20)

		// Phase 2: ports per host. Profiles with TopTCPPorts 0 and no
		// full range (the fast "trace" profile) skip port scanning
		// entirely: ping sweep + traceroute only, which is what makes
		// the trace fast. Port selection otherwise follows nmap's own
		// top-ports table or the full 65535 range (see portSpecArgs).
		wantPorts := profile.TopTCPPorts > 0 || profile.FullPortScan
		var ports []int
		var portResults []scanner.PortResult
		if wantPorts {
			portResults, err = e.engine.ScanPorts(runCtx, h.IP, ports, scan.Config, e.limits)
			if err != nil {
				e.log.Warn("port scan failed", "host", h.IP, "err", err)
				portResults = nil // one host failing never fails the scan (§68)
			}
			for _, pr := range portResults {
				payload, _ := json.Marshal(map[string]any{"ip": h.IP, "port": pr.Port, "protocol": pr.Protocol, "service": pr.Service})
				_ = e.orch.RecordObservation(ctx, &domain.Observation{
					ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
					Target: h.IP, ObservationType: "port_open", Timestamp: time.Now().UTC(),
					Source: sourceFor(e.engine), Payload: payload,
					Normalized: map[string]any{"ip": h.IP, "port": float64(pr.Port), "protocol": pr.Protocol, "service": pr.Service},
					Confidence: 0.9,
				})
			}
		}
		stats.PortsDiscovered += len(portResults)
		_ = e.orch.UpdateScanStats(ctx, scan.ID, stats)
		_ = e.orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "ports", 35)

		// Phase 3: service fingerprinting when the profile allows.
		// ServiceLite profiles (fingerprint) get ONE batched
		// -sV --version-light pass instead: cheap, but enough to fill
		// the service table's ostype/CPE fields — the OS+device signal
		// that keeps working where -O cannot fingerprint (no raw
		// sockets, NAT filtering the open+closed port pair).
		// Observations flow through the same "service" path, so
		// RecordOS/RecordDevice/software apply identically.
		if profile.ServiceDetect {
			for _, pr := range portResults {
				svc, err := e.engine.FingerprintService(runCtx, h.IP, pr.Port, pr.Protocol, scan.Config, e.limits)
				if err != nil || svc == nil {
					continue
				}
				if err := e.recordServiceObservation(ctx, scan, h.IP, svc); err == nil {
					stats.ServicesFingerprinted++
				}
			}
		} else if profile.ServiceLite && len(portResults) > 0 {
			openPorts := make([]int, 0, len(portResults))
			for _, pr := range portResults {
				if pr.Port > 0 {
					openPorts = append(openPorts, pr.Port)
				}
			}
			svcs, liteErr := e.engine.FingerprintServicesLite(runCtx, h.IP, openPorts, scan.Config, e.limits)
			if liteErr != nil {
				e.log.Warn("light service pass failed", "host", h.IP, "err", liteErr)
			}
			for i := range svcs {
				if err := e.recordServiceObservation(ctx, scan, h.IP, &svcs[i]); err == nil {
					stats.ServicesFingerprinted++
				}
			}
		}
		// Phase 4: OS + device-type fingerprinting when the profile
		// allows. The observation reuses the host_up shape so the
		// orchestrator's existing os/device handlers update the asset —
		// the latest scan overrides the stored classification. A failing
		// -O run is logged, not swallowed: silent OS gaps cost hours to
		// diagnose in the field.
		if profile.OSDetect {
			osRes, osErr := e.engine.FingerprintOS(runCtx, h.IP, scan.Config, e.limits)
			switch {
			case osErr != nil:
				e.log.Warn("os fingerprint failed", "host", h.IP, "err", osErr)
			case osRes == nil || (osRes.Name == "" && osRes.Family == "" && osRes.Device == ""):
				e.log.Info("os fingerprint inconclusive", "host", h.IP)
			default:
				payload, _ := json.Marshal(map[string]any{"ip": h.IP, "os_family": osRes.Family, "os_name": osRes.Name, "os_version": osRes.Version, "device_type": osRes.Device})
				_ = e.orch.RecordObservation(ctx, &domain.Observation{
					ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
					Target: h.IP, ObservationType: "host_up", Timestamp: time.Now().UTC(),
					Source: sourceFor(e.engine), Payload: payload,
					Normalized: map[string]any{"ip": h.IP, "os_family": osRes.Family, "os_name": osRes.Name, "os_version": osRes.Version, "device_type": osRes.Device},
					Confidence: domain.Confidence(osRes.Confidence),
				})
			}
		}
		// Phase 5: topology tracing (§24/§56). A traceroute per host
		// builds the site's network graph: gateway -> routers -> host.
		// When tracing is impossible (filtered probes, no privileges)
		// we still emit the gateway link so the topology view shows the
		// subnet structure instead of an empty graph — but tagged as a
		// gateway GUESS at low confidence: blocked probes must never be
		// reported as an observed route, nor silently as "no route".
		if profile.Traceroute {
			_ = e.orch.UpdateScanState(ctx, scan.ID, domain.ScanRunning, "topology", 80)
			hops, terr := e.engine.Traceroute(runCtx, h.IP, scan.Config, e.limits)
			method, conf := "traceroute", 0.85
			if terr != nil {
				e.log.Warn("traceroute failed; falling back to subnet gateway guess", "host", h.IP, "err", terr)
			}
			if terr != nil || len(hops) == 0 {
				if gw := scanner.GatewayOf(h.IP); gw != "" {
					hops = []scanner.Hop{{TTL: 1, IP: gw}, {TTL: 2, IP: h.IP}}
					method, conf = "gateway-guess", 0.5
				}
			}
			if len(hops) > 0 {
				path := make([]map[string]any, 0, len(hops))
				for _, hop := range hops {
					m := map[string]any{"ip": hop.IP, "ttl": hop.TTL}
					if hop.Hostname != "" {
						m["hostname"] = hop.Hostname
					}
					if hop.RTTms > 0 {
						m["rtt_ms"] = hop.RTTms
					}
					path = append(path, m)
				}
				// complete=true when the path structurally ends on
				// the target; TTL gaps mark non-responsive hops
				// (gap count = highest TTL - hops_responded).
				complete := path[len(path)-1]["ip"] == h.IP
				topoPayload, _ := json.Marshal(map[string]any{"ip": h.IP, "method": method, "hops": len(path)})
				if err := e.orch.RecordObservation(ctx, &domain.Observation{
					ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
					Target: h.IP, ObservationType: "topology", Timestamp: time.Now().UTC(),
					Source: sourceFor(e.engine), Payload: topoPayload,
					Normalized: map[string]any{"ip": h.IP, "method": method, "path": path,
						"complete": complete, "hops_responded": len(path)},
					Confidence: domain.Confidence(conf),
				}); err != nil {
					e.log.Warn("topology observation failed", "host", h.IP, "err", err)
				}
			}
		}
	}
	_ = e.orch.UpdateTaskState(ctx, fmt.Sprintf("%s-discover", scan.ID), domain.TaskSucceeded, "")
	_ = e.orch.UpdateScanStats(ctx, scan.ID, stats)
	_ = e.orch.UpdateScanState(ctx, scan.ID, domain.ScanCompleted, "completed", 100)
	e.log.Info("scan completed", "scan", scan.ID, "hosts", reachable, "ports", stats.PortsDiscovered, "runtime_os", runtime.GOOS)
	// Notify the control plane: the server correlates the new services
	// against the vulnerability index (KEV/EPSS/CVE) and raises findings.
	if err := e.orch.PublishScanResult(ctx, scan.ID, domain.ScanCompleted); err != nil {
		e.log.Warn("scan result publish failed", "err", err)
	}
	return nil
}

// recordServiceObservation emits the normalized "service" observation shared
// by the per-port ServiceDetect pass and the batched ServiceLite pass. The
// orchestrator turns it into service records, OS hints (service table ostype
// + OS CPEs), device-type hints and software rows.
func (e *executor) recordServiceObservation(ctx context.Context, scan *domain.Scan, ip string, svc *scanner.ServiceResult) error {
	payload, _ := json.Marshal(map[string]any{
		"ip": ip, "port": svc.Port, "protocol": svc.Protocol, "service": svc.Name,
		"product": svc.Product, "vendor": svc.Vendor, "version": svc.Version, "cpe": svc.CPE, "cpes": svc.CPEs, "banner": svc.Banner,
	})
	norm := map[string]any{
		"ip": ip, "port": float64(svc.Port), "protocol": svc.Protocol, "service": svc.Name,
		"product": svc.Product, "vendor": svc.Vendor, "version": svc.Version,
	}
	if svc.CPE != "" {
		norm["cpe"] = svc.CPE
	}
	if len(svc.CPEs) > 0 {
		norm["cpes"] = svc.CPEs
	}
	if svc.Banner != "" {
		norm["banner"] = svc.Banner
	}
	if svc.OSType != "" {
		norm["os"] = svc.OSType // weak OS hint from the service table
	}
	return e.orch.RecordObservation(ctx, &domain.Observation{
		ScanID: scan.ID, SiteID: scan.SiteID, OrganizationID: scan.OrganizationID,
		Target: ip, ObservationType: "service", Timestamp: time.Now().UTC(),
		Source: sourceFor(e.engine), Payload: payload, Normalized: norm,
		Confidence: domain.Confidence(svc.Confidence),
	})
}

// checkKill polls the kill switch between probes (§11/§13).
func checkKill(ctx context.Context, orch Orch, scanID string) bool {
	scan, err := orch.ScanByID(ctx, "", scanID)
	if err != nil {
		return false
	}
	return scan.KillSwitch || scan.State == domain.ScanCancelling
}

func sourceFor(e scanner.Engine) domain.Source {
	if e.Name() == "simulated" {
		return domain.SourceSimulated
	}
	return domain.Source(e.Name())
}

func maxF(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

// ipStaleFromEnv reads AEGIS_ASSET_IP_STALE_DAYS (default 0 = an address
// always resolves to the asset that last held it within the site).
func ipStaleFromEnv() time.Duration {
	d := strings.TrimSpace(os.Getenv("AEGIS_ASSET_IP_STALE_DAYS"))
	if d == "" {
		return 0
	}
	n, err := strconv.Atoi(d)
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * 24 * time.Hour
}
