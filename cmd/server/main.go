// Command server is the Aegis control-plane entry point: it exposes the
// HTTP API (Fiber) under /api/v1, the agent mTLS gRPC transport, JetStream
// orchestration for scan dispatch, and optional OpenTelemetry/metrics.
// Spec anchors: §5 control plane, §6 HTTP API, §16 device CA, §69 scanner
// hub, §78 NATS subjects, §81 health probes, §136 agent gRPC.
package main

import (
	"context"
	"fmt"
	"io"
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
	"github.com/FlameInTheDark/aegis/internal/detections"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/hub"
	"github.com/FlameInTheDark/aegis/internal/logging"
	"github.com/FlameInTheDark/aegis/internal/observability"
	"github.com/FlameInTheDark/aegis/internal/platform"
	"github.com/FlameInTheDark/aegis/internal/reports"
	ch "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	redisrepo "github.com/FlameInTheDark/aegis/internal/repository/redis"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"github.com/FlameInTheDark/aegis/internal/telemetry"
	"github.com/FlameInTheDark/aegis/internal/vulnerabilities"
	grpcx "github.com/FlameInTheDark/aegis/internal/transport/grpc"
	httpx "github.com/FlameInTheDark/aegis/internal/transport/http"
	"github.com/FlameInTheDark/aegis/migrations"
	agentv1 "github.com/FlameInTheDark/aegis/api/gen/aegis/agent/v1"
	"google.golang.org/grpc"
)

var (
	version = "dev"
	commit  = "unknown"
)

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
	log := logging.New(cfg.LogLevel, cfg.LogFormat)
	log.Info("starting aegis server", "version", version, "commit", commit, "env", cfg.Env)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- storage & infrastructure
	migr, merr := pg.NewMigrator(cfg.DatabaseURL)
	if merr == nil {
		if err := migr.Up(); err != nil {
			log.Warn("postgres migrations", "err", err)
		}
	} else {
		log.Warn("migrator init failed", "err", merr)
	}
	db, err := pg.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer db.Close()

	health := observability.NewHealthRegistry()
	health.Register(db)
	metrics := observability.New("aegis_server")

	rdb, err := redisrepo.Connect(ctx, cfg.RedisURL)
	if err != nil {
		log.Warn("redis unavailable; rate limiting degraded to in-process", "err", err)
	} else {
		defer rdb.Close()
		health.Register(rdb)
	}

	bus, err := platform.ConnectBus(ctx, cfg.NATSURL)
	if err != nil {
		return fmt.Errorf("nats: %w", err)
	}
	defer bus.Close()

	var chDB *ch.DB
	if cfg.ClickHouseURL != "" {
		chDB, err = ch.Connect(ctx, cfg.ClickHouseURL, func() ([]byte, error) {
			f, err := migrations.ClickHouse().Open("001_schema.sql")
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(f)
		})
		if err != nil {
			log.Warn("clickhouse unavailable; events path disabled", "err", err)
			chDB = nil
		} else {
			health.Register(chDB)
		}
	}

	var store *platform.ObjectStore
	if cfg.S3.Endpoint != "" {
		store, err = platform.NewObjectStore(ctx, cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, cfg.S3.UseSSL)
		if err != nil {
			log.Warn("object store init failed; report artifacts disabled", "err", err)
			store = nil
		}
	} else {
		log.Warn("object storage not configured (AEGIS_S3_ENDPOINT empty); reports will pend until it is set")
	}

	// --- CA (device identity)
	caAuth, err := ca.Load(cfg.AgentCA.CertPath, cfg.AgentCA.KeyPath, !cfg.IsProduction())
	if err != nil {
		log.Warn("agent CA not configured; enrollment will fail until AEGIS_AGENT_CA_CERT/KEY are provisioned", "err", err)
		caAuth = nil
	}

	// --- repos (one per table, thin storage wrappers)
	orgs := pg.NewOrgRepo(db)
	users := pg.NewUserRepo(db)
	memberships := pg.NewMembershipRepo(db)
	sessions := pg.NewSessionRepo(db)
	sites := pg.NewSiteRepo(db)
	networks := pg.NewNetworkRepo(db)
	auditRepo := pg.NewAuditRepo(db)
	assetRepo := pg.NewAssetRepo(db)
	identRepo := pg.NewIdentifierRepo(db)
	ifaceRepo := pg.NewInterfaceRepo(db)
	serviceRepo := pg.NewServiceRepo(db)
	softwareRepo := pg.NewSoftwareRepo(db)
	scanRepo := pg.NewScanRepo(db)
	taskRepo := pg.NewTaskRepo(db)
	obsRepo := pg.NewObservationRepo(db)
	scannerRepo := pg.NewScannerRepo(db)
	scheduleRepo := pg.NewScheduleRepo(db)
	changeRepo := pg.NewChangeRepo(db)
	profileRepo := pg.NewProfileRepo(db)
	vulnRepo := pg.NewVulnRepo(db)
	feedRepo := pg.NewFeedRepo(db)
	findingRepo := pg.NewFindingRepo(db)
	evidenceRepo := pg.NewEvidenceRepo(db)
	suppressRepo := pg.NewSuppressionRepo(db)
	noteRepo := pg.NewNoteRepo(db)
	ruleRepo := pg.NewRuleRepo(db)
	matchRepo := pg.NewMatchRepo(db)
	baselineRepo := pg.NewBaselineRepo(db)
	webhookRepo := pg.NewWebhookRepo(db)
	agentRepo := pg.NewAgentRepo(db)
	agentTaskRepo := pg.NewAgentTaskRepo(db)
	enrollRepo := pg.NewEnrollmentRepo(db)
	agentEventRepo := pg.NewAgentEventRepo(db)
	topologyRepo := pg.NewTopologyRepo(db)
	reportRepo := pg.NewReportRepo(db)

	// --- domain services
	orgService := &organizations.Service{
		Orgs: orgs, Users: users, Memberships: memberships, Sites: sites, Networks: networks, Log: log,
	}
	auditSvc := &audit.Service{Repo: auditRepo, Log: log}
	inventory := &assets.Service{
		Assets: assetRepo, Ident: identRepo, Ifaces: ifaceRepo,
		Services: serviceRepo, Software: softwareRepo, Changes: changeRepo, Log: log,
	}
	orch := &scanning.Orchestrator{
		Scans: scanRepo, Tasks: taskRepo, Observations: obsRepo,
		Scanners: scannerRepo, Schedules: scheduleRepo, Profiles: profileRepo,
		Changes: changeRepo, Assets: assetRepo, Inventory: inventory,
		Topology: topologyRepo, Bus: bus, Log: log,
		AllowPublicScope: cfg.Scanner.AllowPublicScope,
	}
	// Ensure builtin scan profiles are present before HTTP handlers resolve them.
	if err := profileRepo.Sync(ctx, domain.Profiles); err != nil {
		log.Warn("scan profile sync failed", "err", err)
	}

	correlator := &vulnerabilities.Correlator{
		Findings: findingRepo, Evidence: evidenceRepo,
		Assets: assetRepo, Services: serviceRepo, Software: softwareRepo, Log: log,
	}
	detectEngine := &detections.Engine{
		Rules: ruleRepo, Matches: matchRepo, Baselines: baselineRepo, Cache: rdb, Log: log,
	}
	ingestor := &telemetry.Ingestor{Bus: bus, CH: chDB, Engine: detectEngine, Cache: rdb, Log: log, BatchSize: 500}
	if chDB != nil {
		go func() {
			if err := ingestor.Run(ctx); err != nil && ctx.Err() == nil {
				log.Warn("telemetry consumer stopped", "err", err)
			}
		}()
	}
	reportsSvc := &reports.Service{
		Reports: reportRepo, Findings: findingRepo, Assets: assetRepo,
		Sites: sites, Orgs: orgs, Services: serviceRepo, Scans: scanRepo,
		Store: store, Log: log, Details: pg.NewReportDetailRepo(db),
	}
	agentsSvc := &agents.Service{
		Repo: agentRepo, Tasks: agentTaskRepo, EnrollTok: enrollRepo,
		Events: agentEventRepo, Assets: assetRepo, Log: log,
	}

	// Scan hub (remote scanners dial gRPC; local scanners consume NATS).
	scanHub := hub.New(scanRepo, taskRepo, scannerRepo, orch, bus, log)
	orch.Hub = scanHub

	// Bootstrap the first owner when env provides credentials and the
	// installation is still empty (spec §160).
	if cfg.Auth.BootstrapAdminEmail != "" && cfg.Auth.BootstrapAdminPassword != "" {
		if hash, err := auth.HashPassword(cfg.Auth.BootstrapAdminPassword); err == nil {
			if _, err := orgService.Bootstrap(ctx, "Aegis", cfg.Auth.BootstrapAdminEmail, "Platform Administrator", hash); err != nil {
				// Idempotent: second boot or existing admin is not fatal.
				log.Info("bootstrap skipped", "reason", err)
			} else {
				log.Info("bootstrap owner created", "email", cfg.Auth.BootstrapAdminEmail)
			}
		} else {
			log.Warn("bootstrap hash failed", "err", err)
		}
	}

	// --- HTTP control plane
	svc := &httpx.Services{
		Version: version, Cfg: cfg, Log: log, Health: health, Bus: bus, Redis: rdb, CH: chDB,
		Orgs: orgs, Users: users, Memberships: memberships, Sessions: sessions,
		Sites: sites, Networks: networks, Audit: auditRepo,
		Assets: assetRepo, Ident: identRepo, Ifaces: ifaceRepo,
		Services: serviceRepo, Software: softwareRepo,
		Scans: scanRepo, Tasks: taskRepo, Observations: obsRepo,
		Scanners: scannerRepo, Schedules: scheduleRepo, Changes: changeRepo,
		Profiles: profileRepo, Vulns: vulnRepo, Feeds: feedRepo,
		Findings: findingRepo, Evidence: evidenceRepo, Suppressions: suppressRepo,
		Notes: noteRepo, Rules: ruleRepo, Matches: matchRepo, Baselines: baselineRepo,
		Webhooks: webhookRepo, Agents: agentRepo, AgentTasks: agentTaskRepo,
		EnrollTokens: enrollRepo, AgentEvents: agentEventRepo, Topology: topologyRepo,
		Reports: reportRepo,
		OrgService: orgService, Orchestrator: orch, Detections: detectEngine,
		Ingestor: ingestor, ReportsService: reportsSvc, AgentsService: agentsSvc,
		Correlator: correlator, AuditService: auditSvc, Store: store,
	}
	app := httpx.New(svc)

	// --- gRPC: agent transport + hub
	grpcLis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", cfg.GRPCAddr, err)
	}
	gsrv := grpc.NewServer()
	// Agent mTLS transport (enroll + inventory + posture + streaming).
	agentSrv := &grpcx.AgentServer{
		Deps: grpcx.Deps{
			Agents: agentsSvc, Log: log,
			IssueCert: func(csrPEM, agentID string) (string, error) {
				if caAuth == nil {
					return "", fmt.Errorf("agent CA not configured")
				}
				return caAuth.Issue(csrPEM, agentID)
			},
		},
	}
	agentv1.RegisterAgentServiceServer(gsrv, agentSrv)
	scanHub.Register(gsrv)

	// --- observability / metrics endpoint
	metricsLis, merr2 := net.Listen("tcp", cfg.MetricsAddr)
	var metricsSrv *http.Server
	if merr2 == nil {
		mux := http.NewServeMux()
		mux.Handle("/metrics", metrics.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
		})
		metricsSrv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
		go func() {
			log.Info("metrics listening", "addr", cfg.MetricsAddr)
			if err := metricsSrv.Serve(metricsLis); err != nil && err != http.ErrServerClosed {
				log.Warn("metrics server stopped", "err", err)
			}
		}()
	} else {
		log.Warn("metrics listen failed", "addr", cfg.MetricsAddr, "err", merr2)
	}

	// --- run HTTP + gRPC concurrently
	errCh := make(chan error, 2)
	go func() {
		log.Info("http listening", "addr", cfg.HTTPAddr)
		if err := app.Fiber().Listen(cfg.HTTPAddr); err != nil {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()
	go func() {
		log.Info("grpc listening", "addr", cfg.GRPCAddr)
		if err := gsrv.Serve(grpcLis); err != nil {
			errCh <- fmt.Errorf("grpc: %w", err)
		}
	}()

	log.Info("aegis server ready")
	select {
	case <-ctx.Done():
		log.Info("shutdown signal received")
	case err := <-errCh:
		log.Error("server error", "err", err)
	}

	// Graceful shutdown with bounded waits.
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = shutCtx
	_ = app.Fiber().Shutdown()
	gsrv.GracefulStop()
	if metricsSrv != nil {
		_ = metricsSrv.Shutdown(shutCtx)
	}
	_ = metrics
	return nil
}
