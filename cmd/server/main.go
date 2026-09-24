// Command server is the Aegis control plane: HTTP API, gRPC agent
// transport and Prometheus metrics (.1).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FlameInTheDark/aegis/internal/agents"
	"github.com/FlameInTheDark/aegis/internal/assets"
	"github.com/FlameInTheDark/aegis/internal/audit"
	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/ca"
	"github.com/FlameInTheDark/aegis/internal/config"
	"github.com/FlameInTheDark/aegis/internal/connectors"
	"github.com/FlameInTheDark/aegis/internal/detections"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/hub"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/joblog"
	"github.com/FlameInTheDark/aegis/internal/logging"
	"github.com/FlameInTheDark/aegis/internal/observability"
	"github.com/FlameInTheDark/aegis/internal/organizations"
	"github.com/FlameInTheDark/aegis/internal/platform"
	"github.com/FlameInTheDark/aegis/internal/reports"
	ch "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	redisrepo "github.com/FlameInTheDark/aegis/internal/repository/redis"
	"github.com/FlameInTheDark/aegis/internal/retention"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"github.com/FlameInTheDark/aegis/internal/telemetry"
	grpcx "github.com/FlameInTheDark/aegis/internal/transport/grpc"
	httpx "github.com/FlameInTheDark/aegis/internal/transport/http"
	"github.com/FlameInTheDark/aegis/internal/vulnerabilities"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	"github.com/FlameInTheDark/aegis/migrations"
	"github.com/nats-io/nats.go/jetstream"
)

// version is overridden at build time via:
//
//	go build -ldflags "-X main.version=$(git describe --tags)" ./cmd/server
//
// so a deployed control plane can report exactly what it is running.
var version = "dev"

// migrationsFS reads an embedded migration file by path.
func migrationsFS(path string) ([]byte, error) {
	f, err := migrations.ClickHouse().Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load("server")
	if err != nil {
		return err
	}
	log := newLogger(cfg)
	log.Info("starting aegis server", "version", version, "env", cfg.Env, "http", cfg.HTTPAddr, "grpc", cfg.GRPCAddr)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- infrastructure
	migrator, err := pg.NewMigrator(cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("migrator: %w", err)
	}
	if err := migrator.Up(); err != nil {
		log.Error("migration up failed", "err", err)
		return fmt.Errorf("migrations: %w", err)
	}
	db, err := pg.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer db.Close()
	rdb, err := redisrepo.Connect(ctx, cfg.RedisURL)
	if err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	defer rdb.Close()
	bus, err := platform.ConnectBus(ctx, cfg.NATSURL)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer bus.Close()
	var chDB *ch.DB
	if cfg.ClickHouseURL != "" {
		chDB, err = ch.Connect(ctx, cfg.ClickHouseURL, func() ([]byte, error) {
			b, err := migrationsFS("001_schema.sql")
			return b, err
		})
		if err != nil {
			log.Error("clickhouse connect failed (events disabled until reachable)", "err", err)
			chDB = nil
		}
	}
	store, err := platform.NewObjectStore(ctx, cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, cfg.S3.UseSSL)
	if err != nil {
		log.Warn("object store disabled", "err", err)
		store = nil
	}
	metrics := observability.New("aegis")
	health := observability.NewHealthRegistry()
	health.Register(db)
	health.Register(rdb)
	health.Register(bus)

	// --- repositories & services
	assetsRepo := pg.NewAssetRepo(db)
	identRepo := pg.NewIdentifierRepo(db)
	ifacesRepo := pg.NewInterfaceRepo(db)
	servicesRepo := pg.NewServiceRepo(db)
	softwareRepo := pg.NewSoftwareRepo(db)
	changesRepo := pg.NewChangeRepo(db)
	auditSvc := &audit.Service{Repo: pg.NewAuditRepo(db), Log: log}
	orgSvc := &organizations.Service{
		Orgs: pg.NewOrgRepo(db), Users: pg.NewUserRepo(db), Memberships: pg.NewMembershipRepo(db),
		Sites: pg.NewSiteRepo(db), Networks: pg.NewNetworkRepo(db), Log: log,
	}
	vulnRepo := pg.NewVulnRepo(db)
	feedRepo := pg.NewFeedRepo(db)
	correlator := &vulnerabilities.Correlator{
		Index: vulnRepo, Findings: pg.NewFindingRepo(db), Evidence: pg.NewEvidenceRepo(db),
		Assets: assetsRepo, Services: servicesRepo, Software: softwareRepo, Log: log,
		Advisories: pg.NewAdvisoryRepo(db),
	}
	scanRepo, taskRepo, scannerRepo := pg.NewScanRepo(db), pg.NewTaskRepo(db), pg.NewScannerRepo(db)
	topoRepo := pg.NewTopologyRepo(db)
	traceRepo := pg.NewTraceRepo(db)
	// The hub applies reported observations through this orchestrator, so it
	// needs the SAME ingestion services the embedded scanner wires locally:
	// without Inventory every host/port/service report failed with "scan
	// inventory service is not configured" (scans showed stats but created
	// no assets/services), and without Topology traceroute graphs stayed empty.
	inventory := &assets.Service{
		Assets: assetsRepo, Ident: identRepo, Ifaces: ifacesRepo,
		Services: servicesRepo, Software: softwareRepo, Changes: changesRepo, Log: log,
		IPStale: assets.IPStaleFromEnv(),
	}
	orch := &scanning.Orchestrator{
		Scans: scanRepo, Tasks: taskRepo, Observations: pg.NewObservationRepo(db),
		Scanners: scannerRepo, Schedules: pg.NewScheduleRepo(db), Profiles: pg.NewProfileRepo(db),
		Changes: changesRepo, Assets: assetsRepo, Inventory: inventory, Topology: topoRepo, Traces: traceRepo,
		Bus: bus, Log: log,
		AllowPublicScope: cfg.Scanner.AllowPublicScope,
		Correlator:       correlator,
	}
	// Scanner hub: remote agents dial in over gRPC and run scans exactly like
	// the compose-embedded scanner (they never touch Postgres/NATS directly).
	scannerHub := hub.New(scanRepo, taskRepo, scannerRepo, orch, bus, log)
	orch.Hub = scannerHub

	// Startup recovery: a scan that was running when the previous process
	// died would stay running forever — the claim loop only picks up queued
	// scans. Close the orphans out (failed, "interrupted by restart")
	// before the hub and HTTP surface open.
	if swept, err := orch.RecoverInterrupted(ctx, "interrupted by restart"); err != nil {
		log.Warn("scan recovery failed", "err", err)
	} else if swept > 0 {
		log.Info("scan recovery closed interrupted scans", "count", swept)
	}
	agentsSvc := &agents.Service{
		Repo: pg.NewAgentRepo(db), Tasks: pg.NewAgentTaskRepo(db),
		Events: pg.NewAgentEventRepo(db), Assets: assetsRepo, Ifaces: pg.NewInterfaceRepo(db),
		Ident: identRepo, Sites: pg.NewSiteRepo(db), Merger: assetsRepo, IPStale: assets.IPStaleFromEnv(), Log: log,
	}
	detectEngine := &detections.Engine{
		Rules: pg.NewRuleRepo(db), Matches: pg.NewMatchRepo(db), Baselines: pg.NewBaselineRepo(db),
		Cache: rdb, Log: log,
	}
	ingestor := &telemetry.Ingestor{Bus: bus, CH: chDB, Engine: detectEngine, Cache: rdb, Log: log, BatchSize: 500}
	reportsSvc := &reports.Service{
		Reports: pg.NewReportRepo(db), Findings: pg.NewFindingRepo(db), Assets: assetsRepo, Details: pg.NewReportDetailRepo(db),
		Sites: pg.NewSiteRepo(db), Orgs: pg.NewOrgRepo(db), Services: pg.NewServiceRepo(db), Scans: pg.NewScanRepo(db), Store: store, Log: log,
	}
	// --- unified external connections (agents / scanners / collectors)
	connectorsSvc := connectors.New(pg.NewConnectorRepo(db), pg.NewConnectorTokenRepo(db), log,
		cfg.Connector.PublicAddr, cfg.Connector.EnrollTokenTTL)
	// kind=scanner connectors materialize a scanners row so the scan UI and
	// the hub dispatch treat them exactly like token-enrolled scanners.
	connectorsSvc.Scanners = scannerRepo

	// --- bootstrap (first run)
	bootstrapIfNeeded(ctx, cfg, orgSvc, log)

	// Seed builtin detection rules for every org once.
	seedRules(ctx, pg.NewOrgRepo(db), pg.NewRuleRepo(db), log)

	// Seed the builtin scan profiles once: scans.profile references
	// scan_profiles(name); without this every POST /scans fails with
	// FK violation scans_profile_fkey on a fresh database.
	profilesRepo := pg.NewProfileRepo(db)
	if err := profilesRepo.Sync(ctx, domain.Profiles); err != nil {
		log.Warn("scan profile seed failed (scan creation will be refused)", "err", err)
	} else {
		log.Info("scan profiles synced", "count", len(domain.Profiles))
	}

	// --- HTTP app
	// Streaming stack: persists job log lines, fans realtime events out
	// to browser WebSocket subscribers, replaces short polling (v1.13.0).
	jobLogStore := joblog.NewStore(db)
	jobLogHub := joblog.NewHub()
	joblog.NewStreamer(bus, jobLogStore, jobLogHub, log).Start(ctx)

	// --- metrics retention loop (settings-driven ClickHouse TTL + purge).
	// Started only when the analytics tier exists; the settings store backs
	// the operator-facing metrics retention knob.
	settingsRepo := pg.NewSettingsRepo(db)
	var retentionSvc *retention.Service
	if chDB != nil {
		retentionSvc = retention.New(settingsRepo, chDB, log)
		go retentionSvc.Run(ctx)
	}

	svc := &httpx.Services{
		Version: version,
		Cfg:     cfg, Log: log, Health: health, Bus: bus, Redis: rdb, CH: chDB,
		Orgs: pg.NewOrgRepo(db), Users: pg.NewUserRepo(db), Memberships: pg.NewMembershipRepo(db),
		Sessions: pg.NewSessionRepo(db), Sites: pg.NewSiteRepo(db), Networks: pg.NewNetworkRepo(db),
		Audit: pg.NewAuditRepo(db), Assets: assetsRepo, Ident: identRepo, Ifaces: ifacesRepo,
		Services: servicesRepo, Software: softwareRepo,
		Scans: pg.NewScanRepo(db), Tasks: pg.NewTaskRepo(db), Observations: pg.NewObservationRepo(db),
		Scanners: pg.NewScannerRepo(db), Schedules: pg.NewScheduleRepo(db), Changes: changesRepo,
		Profiles: pg.NewProfileRepo(db), Vulns: vulnRepo, Feeds: feedRepo,
		Findings: pg.NewFindingRepo(db), Evidence: pg.NewEvidenceRepo(db),
		Suppressions: pg.NewSuppressionRepo(db), Notes: pg.NewNoteRepo(db),
		Rules: pg.NewRuleRepo(db), Matches: pg.NewMatchRepo(db), Baselines: pg.NewBaselineRepo(db),
		Webhooks: pg.NewWebhookRepo(db),
		Topology: topoRepo, Traces: traceRepo, Reports: pg.NewReportRepo(db),
		Groups:  pg.NewGroupRepo(db),
		JobLogs: jobLogStore, WSHub: jobLogHub,
		OrgService: orgSvc, Orchestrator: orch, Detections: detectEngine, Ingestor: ingestor,
		ReportsService: reportsSvc, AgentsService: agentsSvc, Correlator: correlator,
		ConnectorsService: connectorsSvc,
		AuditService:      auditSvc, Retention: retentionSvc, Store: store,
	}
	app := httpx.New(svc)

	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if err := app.Fiber().Listen(cfg.HTTPAddr); err != nil {
			log.Error("http server failed", "err", err)
		}
	}()

	// --- metrics endpoint (:9091)
	go serveMetrics(cfg.MetricsAddr, metrics, log)

	// --- gRPC agent transport
	authority, err := ca.Load(cfg.AgentCA.CertPath, cfg.AgentCA.KeyPath, !cfg.IsProduction())
	if err != nil {
		log.Warn("agent CA unavailable — gRPC enroll disabled", "err", err)
	}
	grpcSrv := grpc.NewServer(grpc.Creds(insecure.NewCredentials())) // TLS terminated at LB in production; mTLS documented
	scannerHub.Connectors = connectorsSvc                            // connector-secret auth for scanner-kind connections
	scannerHub.Register(grpcSrv)
	// Unified connector service: enrollment, config, heartbeat for ALL
	// kinds, plus BindDevice (device identity for agent-kind connections).
	grpcx.RegisterConnectorService(grpcSrv, grpcx.ConnectorDeps{
		Connectors: connectorsSvc, Agents: agentsSvc, Log: log,
		IssueCert: func(csrPEM, agentID string) (string, error) {
			if authority == nil {
				return "", fmt.Errorf("agent CA not configured")
			}
			return authority.Issue(csrPEM, agentID)
		},
	})
	// Endpoint data plane (inventory, tasks, telemetry, metrics). Always
	// registered: submissions need only connector auth; only device
	// binding needs the CA. The metrics tier rides on ClickHouse and is
	// disabled when ClickHouse is not configured (samples dropped, logged).
	// The sink must stay an UNTYPED nil when ClickHouse is absent: assigning
	// a typed nil (*ch.DB) into the interface field makes the interface
	// itself non-nil, the SubmitMetrics guard never fires and the first
	// sample panics the server on the nil driver connection.
	var metricsSink grpcx.DeviceMetricsIngest
	if chDB != nil {
		metricsSink = chDB
	}
	agentv1.RegisterAgentServiceServer(grpcSrv, &grpcx.AgentServer{Deps: grpcx.Deps{
		Auth: connectorsSvc, Devices: agentsSvc.Repo, Plane: grpcx.AgentsDataPlane{S: agentsSvc}, Log: log,
		Metrics: metricsSink,
	}})
	go func() {
		lis, err := net.Listen("tcp", cfg.GRPCAddr)
		if err != nil {
			log.Error("grpc listen failed", "err", err)
			return
		}
		log.Info("grpc listening", "addr", cfg.GRPCAddr)
		if err := grpcSrv.Serve(lis); err != nil {
			log.Error("grpc serve failed", "err", err)
		}
	}()

	// --- telemetry consumer runs in-process for single-binary deployments
	go func() {
		if chDB != nil {
			if err := ingestor.Run(ctx); err != nil {
				log.Warn("telemetry consumer stopped", "err", err)
			}
		}
	}()

	// --- vulnerability correlation on scan completion (spec 72). Scanners
	// publish security.scan.result.v1; correlating here keeps the heavy
	// matching out of the scan hot path and centralizes index access.
	go func() {
		err := bus.Subscribe(ctx, platform.StreamScan, "correlate-scan-result", func(msg jetstream.Msg) error {
			var evt struct {
				ScanID         string `json:"scan_id"`
				OrganizationID string `json:"organization_id"`
				State          string `json:"state"`
			}
			if err := json.Unmarshal(msg.Data(), &evt); err != nil {
				return nil // malformed event: ack and move on
			}
			// Scan-completion events have historically carried only
			// scan_id+state; resolve the org from the scan row so hub
			// (connector/remote) scans correlate too instead of being
			// silently skipped.
			orgID := evt.OrganizationID
			if orgID == "" && evt.ScanID != "" {
				if scan, err := scanRepo.ByID(ctx, "", evt.ScanID); err == nil {
					orgID = scan.OrganizationID
				}
			}
			if orgID == "" {
				return nil
			}
			// Lifecycle notifications ride the broadcast subject so open
			// browsers toast instantly instead of discovering the change
			// on their next poll. The scan name personalizes the toast.
			scanName := ""
			if scan, err := scanRepo.ByID(ctx, "", evt.ScanID); err == nil {
				scanName = scan.Name
			}
			switch evt.State {
			case string(domain.ScanCompleted):
				joblog.PublishNotification(ctx, bus, &domain.NotificationEvent{
					ID: ids.New(), OrgID: orgID, Type: domain.NotifyScanCompleted,
					Title:    "Scan completed: " + scanName,
					Body:     "Results merged into inventory; correlation follows.",
					Severity: "info", Ref: map[string]string{"scan_id": evt.ScanID},
				})
			case string(domain.ScanFailed):
				joblog.PublishNotification(ctx, bus, &domain.NotificationEvent{
					ID: ids.New(), OrgID: orgID, Type: domain.NotifyScanFailed,
					Title:    "Scan failed: " + scanName,
					Severity: "high", Ref: map[string]string{"scan_id": evt.ScanID},
				})
			default:
				return nil
			}
			n, err := correlator.SweepOrg(ctx, orgID)
			if err != nil {
				log.Warn("post-scan correlation failed", "org", evt.OrganizationID, "err", err)
				return err // nack: at-least-once redelivery
			}
			if n > 0 {
				log.Info("post-scan correlation created findings", "org", evt.OrganizationID, "findings", n)
				joblog.PublishNotification(ctx, bus, &domain.NotificationEvent{
					ID: ids.New(), OrgID: orgID, Type: domain.NotifyFindingsCreated,
					Title:    fmt.Sprintf("%d new findings raised", n),
					Body:     "Open Detections to triage the new matches.",
					Severity: "medium", Ref: map[string]string{"count": fmt.Sprintf("%d", n)},
				})
			}
			return nil
		})
		if err != nil {
			log.Warn("correlation subscriber stopped", "err", err)
		}
	}()

	log.Info("aegis server ready")
	<-ctx.Done()
	log.Info("shutting down")
	grpcSrv.GracefulStop()
	_ = app.Fiber().Shutdown()
	return nil
}

func serveMetrics(addr string, m *observability.Metrics, log *slog.Logger) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", m.Handler())
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		log.Warn("metrics server stopped", "err", err)
	}
}

func bootstrapIfNeeded(ctx context.Context, cfg *config.Config, orgSvc *organizations.Service, log *slog.Logger) {
	email := cfg.Auth.BootstrapAdminEmail
	if email == "" {
		return
	}
	hash, err := auth.HashPassword(cfg.Auth.BootstrapAdminPassword)
	if err != nil {
		log.Error("bootstrap password rejected", "err", err)
		return
	}
	if _, err := orgSvc.Bootstrap(ctx, "Aegis", email, "Platform Administrator", hash); err != nil {
		log.Info("bootstrap skipped", "reason", err.Error())
	}
}

func seedRules(ctx context.Context, orgs *pg.OrgRepo, rules *pg.RuleRepo, log *slog.Logger) {
	list, err := orgs.List(ctx)
	if err != nil {
		return
	}
	for _, o := range list {
		if err := detections.SeedBuiltinRules(ctx, o.ID, rules); err != nil {
			log.Warn("rule seed failed", "org", o.ID, "err", err)
		}
	}
}

func newLogger(cfg *config.Config) *slog.Logger {
	return logging.New(cfg.LogLevel, cfg.LogFormat)
}
