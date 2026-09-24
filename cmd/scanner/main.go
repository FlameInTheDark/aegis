// Command scanner is the distributed active scanning worker. It registers itself, claims scans assigned to its site, runs the
// configured engine (nmap/simulated), normalizes observations and reports
// them back. It enforces resource limits and honors the kill switch.
//
// The scan pipeline itself lives in internal/scanexec and is shared with
// the aegis-connector scanner role; this binary adds identity (site
// registration), the embedded NATS claim loop and the hub-agent mode.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
	"github.com/FlameInTheDark/aegis/internal/scanexec"
	"github.com/FlameInTheDark/aegis/internal/scanner"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"github.com/FlameInTheDark/aegis/internal/vulnerabilities"
)

// scannerVersion is stamped at build time: -ldflags "-X main.scannerVersion=$(cat VERSION)".
// A plain `go build` leaves "dev" — the version shown in the scanners registry.
var scannerVersion = "dev"

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
		IPStale: assets.IPStaleFromEnv(),
	}
	correlator := &vulnerabilities.Correlator{
		Index: pg.NewVulnRepo(db), Findings: pg.NewFindingRepo(db), Evidence: pg.NewEvidenceRepo(db),
		Assets: assetsRepo, Services: pg.NewServiceRepo(db), Software: pg.NewSoftwareRepo(db), Log: log,
		Advisories: pg.NewAdvisoryRepo(db),
	}
	orch := &scanning.Orchestrator{
		Scans: pg.NewScanRepo(db), Tasks: pg.NewTaskRepo(db), Observations: pg.NewObservationRepo(db),
		Scanners: pg.NewScannerRepo(db), Schedules: pg.NewScheduleRepo(db), Profiles: pg.NewProfileRepo(db),
		Changes: changesRepo, Assets: assetsRepo, Inventory: inventory, Topology: pg.NewTopologyRepo(db), Traces: pg.NewTraceRepo(db),
		Bus: bus, Log: log,
		AllowPublicScope: cfg.Scanner.AllowPublicScope,
		Correlator:       correlator,
	}
	lo := localOrch{o: orch}
	exec := &scanexec.Executor{
		Engine: engine, Orch: lo, Sink: lo, Log: log,
		Limits: scanner.DefaultLimits(), SiteID: cfg.Scanner.SiteID,
		SSH: sshSettingsFrom(cfg),
	}
	exec.Limits.MaxTargets = cfg.Scanner.MaxTargets
	exec.Limits.MaxPacketRate = cfg.Scanner.MaxPacketRate

	// Agent mode: dial the hub and execute pushed scans over gRPC — for
	// scanners installed on physical hosts (no Postgres/NATS access).
	if cfg.Scanner.Mode == "agent" {
		if cfg.Scanner.HubAddr == "" || cfg.Scanner.HubToken == "" {
			return fmt.Errorf("agent mode requires AEGIS_SCANNER_HUB_ADDR and AEGIS_SCANNER_HUB_TOKEN")
		}
		log.Info("scanner running in agent mode", "hub", cfg.Scanner.HubAddr)
		return scanexec.RunAgent(ctx, exec, scanexec.AgentOptions{
			HubAddr:      cfg.Scanner.HubAddr,
			Auth:         scanexec.HubAuth{ScannerToken: cfg.Scanner.HubToken},
			Name:         cfg.Scanner.ScannerName,
			Version:      scannerVersion + "/" + engine.Name(),
			Capabilities: cfg.Scanner.Capabilities,
		})
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
			if err := exec.ClaimAndRun(ctx, scannerID); err != nil {
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
		// The configured path is missing — try the usual install locations
		// before degrading, so a non-PATH install still gets used.
		if alt := scanner.DetectNmapPath(); alt != "" {
			log.Warn("configured nmap path not found; using detected nmap instead",
				"configured", cfg.Scanner.NmapPath, "using", alt)
			return &scanner.NmapEngine{BinPath: alt}
		}
		log.Warn("nmap binary not found; falling back to the SIMULATED engine — results are synthetic demo data, not real scans",
			"path", cfg.Scanner.NmapPath)
	} else {
		if alt := scanner.DetectNmapPath(); alt != "" {
			log.Info("no nmap path configured; using detected nmap", "using", alt)
			return &scanner.NmapEngine{BinPath: alt}
		}
		log.Warn("no nmap binary found; falling back to the SIMULATED engine — results are synthetic demo data, not real scans")
	}
	// Fall back to the simulated engine so demo/air-gapped deployments work
	// without nmap. All results are tagged simulated.
	return &scanner.SimulatedEngine{}
}

// sshSettingsFrom maps the server-side scanner config onto the shared
// executor's SSH collector settings (agent-less ssh_inventory profile).
func sshSettingsFrom(cfg *config.Config) scanexec.SSHSettings {
	hosts := make([]scanning.SSHHostConfig, 0, len(cfg.SSHScan.Hosts))
	for _, h := range cfg.SSHScan.Hosts {
		hosts = append(hosts, scanning.SSHHostConfig{Host: h.Host, Port: h.Port, User: h.User})
	}
	return scanexec.SSHSettings{
		Hosts:     hosts,
		User:      cfg.SSHScan.User,
		Password:  cfg.SSHScan.Password,
		KeyPath:   cfg.SSHScan.KeyPath,
		Timeout:   cfg.SSHScan.Timeout,
		Insecure:  cfg.SSHScan.Insecure,
		PinnedKey: cfg.SSHScan.PinnedKey,
	}
}

// register creates or refreshes this scanner's registration.
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
