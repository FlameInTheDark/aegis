// Command worker runs background jobs: telemetry ingestion, report
// generation, scan scheduling, housekeeping (spec §5.2, §121-§122).
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FlameInTheDark/aegis/internal/config"
	"github.com/FlameInTheDark/aegis/internal/detections"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/logging"
	"github.com/FlameInTheDark/aegis/internal/observability"
	"github.com/FlameInTheDark/aegis/internal/platform"
	"github.com/FlameInTheDark/aegis/internal/reports"
	ch "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	redisrepo "github.com/FlameInTheDark/aegis/internal/repository/redis"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"github.com/FlameInTheDark/aegis/internal/telemetry"
	"github.com/FlameInTheDark/aegis/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load("worker")
	if err != nil {
		return err
	}
	log := logging.New(cfg.LogLevel, cfg.LogFormat)
	log.Info("starting aegis worker", "env", cfg.Env)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// --- infrastructure
	migr, merr := pg.NewMigrator(cfg.DatabaseURL)
	if merr == nil {
		if uerr := migr.Up(); uerr != nil {
			log.Warn("migrations", "err", uerr)
		}
	} else {
		log.Warn("migrator init failed", "err", merr)
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
			f, err := migrations.ClickHouse().Open("001_schema.sql")
			if err != nil {
				return nil, err
			}
			defer f.Close()
			return io.ReadAll(f)
		})
		if err != nil {
			log.Error("clickhouse unavailable; event ingestion disabled", "err", err)
			chDB = nil
		}
	}
	metrics := observability.New("aegis_worker")
	_ = metrics

	// Object storage: required for report artifacts and evidence uploads.
	// Without it the worker must run degraded (reports fail honestly),
	// never complete jobs that have no artifact behind them.
	var store *platform.ObjectStore
	if cfg.S3.Endpoint != "" {
		store, err = platform.NewObjectStore(ctx, cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, cfg.S3.UseSSL)
		if err != nil {
			return fmt.Errorf("s3: %w", err)
		}
	} else {
		log.Warn("object storage not configured (AEGIS_S3_ENDPOINT empty); report jobs will fail until it is set")
	}

	// --- services
	detectEngine := &detections.Engine{
		Rules: pg.NewRuleRepo(db), Matches: pg.NewMatchRepo(db), Baselines: pg.NewBaselineRepo(db),
		Cache: rdb, Log: log,
	}
	ingestor := &telemetry.Ingestor{Bus: bus, CH: chDB, Engine: detectEngine, Cache: rdb, Log: log, BatchSize: 500}
	if chDB != nil {
		go func() {
			if err := ingestor.Run(ctx); err != nil {
				log.Warn("telemetry consumer stopped", "err", err)
			}
		}()
	}

	orch := &scanning.Orchestrator{
		Scans: pg.NewScanRepo(db), Tasks: pg.NewTaskRepo(db), Observations: pg.NewObservationRepo(db),
		Scanners: pg.NewScannerRepo(db), Schedules: pg.NewScheduleRepo(db), Profiles: pg.NewProfileRepo(db),
		Changes: pg.NewChangeRepo(db), Assets: pg.NewAssetRepo(db), Bus: bus, Log: log,
		AllowPublicScope: cfg.Scanner.AllowPublicScope,
	}
	vulnRepo := pg.NewVulnRepo(db)
	reportsSvc := &reports.Service{
		Reports: pg.NewReportRepo(db), Findings: pg.NewFindingRepo(db), Assets: pg.NewAssetRepo(db), Details: pg.NewReportDetailRepo(db),
		Sites: pg.NewSiteRepo(db), Orgs: pg.NewOrgRepo(db), Services: pg.NewServiceRepo(db), Scans: pg.NewScanRepo(db),
		Vulns: vulnRepo, Store: store, Log: log,
	}
	agentTasks := pg.NewAgentTaskRepo(db)
	agentsRepo := pg.NewAgentRepo(db)
	scannersRepo := pg.NewScannerRepo(db)

	// Keep the builtin scan profiles present: the worker inserts scans for
	// due schedules and scans.profile references scan_profiles(name).
	if err := orch.Profiles.Sync(ctx, domain.Profiles); err != nil {
		log.Warn("scan profile sync failed", "err", err)
	}

	// --- periodic maintenance loop (§121)
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n := orch.RunDueSchedules(ctx, time.Now().UTC()); n > 0 {
					log.Info("schedules fired", "count", n)
				}
				_ = agentTasks.ExpireStale(ctx)
				_ = agentsRepo.MarkOffline(ctx, time.Now().UTC().Add(-3*time.Minute))
				_ = scannersRepo.MarkOffline(ctx, time.Now().UTC().Add(-3*time.Minute))
				jobs, err := pg.NewReportRepo(db).QueuedJobs(ctx, 5)
				if err == nil {
					for _, job := range jobs {
						reportsSvc.RunJob(ctx, job.OrgID, job.ID)
					}
				}
			}
		}
	}()

	log.Info("aegis worker ready")
	<-ctx.Done()
	log.Info("worker shutting down")

	return nil
}
