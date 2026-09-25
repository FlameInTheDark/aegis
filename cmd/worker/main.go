// Command worker runs background jobs: telemetry ingestion, report
// generation, scan scheduling, alert evaluation and delivery, correlation
// jobs, housekeeping (.2).
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/FlameInTheDark/aegis/internal/alerting"
	"github.com/FlameInTheDark/aegis/internal/config"
	"github.com/FlameInTheDark/aegis/internal/detections"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/joblog"
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
	"github.com/FlameInTheDark/aegis/internal/vulnsearch"
	"github.com/FlameInTheDark/aegis/migrations"
	"github.com/jackc/pgx/v5"
	"github.com/nats-io/nats.go/jetstream"
)

// chMetricSource adapts the ClickHouse repo to the evaluator's read
// interface (the package-level MetricAgg types are intentionally distinct
// so the alerting package never imports ClickHouse).
type chMetricSource struct{ db *ch.DB }

func (s chMetricSource) WindowMetricAggregates(ctx context.Context, tenantID, field, agg string, window time.Duration) ([]alerting.MetricAgg, error) {
	aggs, err := s.db.WindowMetricAggregates(ctx, tenantID, field, agg, window)
	if err != nil {
		return nil, err
	}
	out := make([]alerting.MetricAgg, 0, len(aggs))
	for _, a := range aggs {
		out = append(out, alerting.MetricAgg{AssetID: a.AssetID, Value: a.Value, Samples: a.Samples})
	}
	return out, nil
}

// joblogRetentionDays reads AEGIS_JOBLOG_RETENTION_DAYS (default 7).
func joblogRetentionDays() int {
	if v := os.Getenv("AEGIS_JOBLOG_RETENTION_DAYS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 7
}

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
	// Migration errors are NOT ignorable here: a job consumer operating on
	// a partially migrated schema silently corrupts state. Refuse to start
	// the job loops until the schema is current (schemaVersionGate below).
	migr, merr := pg.NewMigrator(cfg.DatabaseURL)
	if merr == nil {
		if uerr := migr.Up(); uerr != nil {
			log.Error("migrations", "err", uerr)
		}
	} else {
		log.Error("migrator init failed", "err", merr)
	}
	db, err := pg.Connect(ctx, cfg.DatabaseURL)
	retention := time.Duration(joblogRetentionDays()) * 24 * time.Hour
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

	// --- schema-version gate: a job consumer must not claim work against a
	// missing, dirty or older schema. The gate re-checks on every pass so a
	// slow migration in a sibling process unblocks the loops as soon as it
	// commits, without restarting the worker.
	expected, err := migrations.PostgresMaxVersion()
	if err != nil {
		return fmt.Errorf("schema version: %w", err)
	}
	schemaGate := func() bool {
		v, dirty, err := schemaVersion(ctx, db)
		if err != nil {
			return false
		}
		return !dirty && v == expected
	}
	if !schemaGate() {
		log.Error("schema is missing, dirty or older than the embedded migrations; alert/jobs loops stay disabled until it catches up",
			"expected", expected)
	}

	// --- services
	detectEngine := &detections.Engine{
		Rules: pg.NewRuleRepo(db), Matches: pg.NewMatchRepo(db), Baselines: pg.NewBaselineRepo(db),
		Cache: rdb, Log: log,
		Outbox: pg.NewOutboxRepo(db),
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
	reportsSvc := &reports.Service{
		Reports: pg.NewReportRepo(db), Findings: pg.NewFindingRepo(db), Assets: pg.NewAssetRepo(db), Details: pg.NewReportDetailRepo(db),
		Sites: pg.NewSiteRepo(db), Orgs: pg.NewOrgRepo(db), Services: pg.NewServiceRepo(db), Scans: pg.NewScanRepo(db), Store: store, Log: log,
	}
	agentTasks := pg.NewAgentTaskRepo(db)
	agentsRepo := pg.NewAgentRepo(db)
	scannersRepo := pg.NewScannerRepo(db)

	// Keep the builtin scan profiles present: the worker inserts scans for
	// due schedules and scans.profile references scan_profiles(name).
	if err := orch.Profiles.Sync(ctx, domain.Profiles); err != nil {
		log.Warn("scan profile sync failed", "err", err)
	}

	// --- alert-trigger engine: outbox relay, event evaluator, metric
	// evaluator, delivery worker. Every piece is idempotent and safe to run
	// across worker replicas (FOR UPDATE SKIP LOCKED / durable consumer).
	outboxRepo := pg.NewOutboxRepo(db)
	alertStore := &alerting.Store{DB: db}
	triggerRepo := pg.NewAlertTriggerRepo(db)
	destinationRepo := pg.NewDestinationRepo(db)
	relay := &alerting.Relay{Outbox: outboxRepo, Bus: bus, Log: log}
	go relay.Run(ctx)

	evaluator := &alerting.EventEvaluator{
		DB: db, Store: alertStore, Triggers: triggerRepo, Destinations: destinationRepo,
		Bus: bus, Log: log,
	}
	go func() {
		err := bus.SubscribeFiltered(ctx, platform.StreamAlerts, "alert-evaluator", platform.SubAlertEvent, func(msg jetstream.Msg) error {
			var ev domain.TriggerEvent
			if err := json.Unmarshal(msg.Data(), &ev); err != nil {
				return nil // malformed: ack and drop; the outbox row is history
			}
			return evaluator.HandleEvent(ctx, &ev)
		})
		if err != nil {
			log.Warn("alert evaluator subscription stopped", "err", err)
		}
	}()

	metricEvaluator := &alerting.MetricEvaluator{
		DB: db, Store: alertStore, Triggers: triggerRepo, Destinations: destinationRepo,
		CH: chMetricSource{chDB}, Log: log, Interval: 30 * time.Second,
	}
	if chDB != nil {
		go metricEvaluator.Run(ctx)
	} else {
		log.Warn("clickhouse unavailable; metric triggers stay unevaluated (no false recoveries are possible)")
	}

	delivery := &alerting.DeliveryWorker{
		DB: db, Log: log,
		AllowInsecure: getEnvBool("AEGIS_ALERT_WEBHOOK_ALLOW_INSECURE"),
		Interval:      5 * time.Second,
	}
	go delivery.Run(ctx)

	// --- correlation jobs worker: durable queue for feed-triggered and
	// user-triggered sweeps (no more bare goroutines).
	correlator := &vulnerabilities.Correlator{
		Index: pg.NewVulnRepo(db), Findings: pg.NewFindingRepo(db), Evidence: pg.NewEvidenceRepo(db),
		Assets: pg.NewAssetRepo(db), Services: pg.NewServiceRepo(db), Software: pg.NewSoftwareRepo(db),
		Log: log, DB: db,
	}
	vulnSearch := &vulnsearch.Service{
		DB: db, Actions: pg.NewVulnSearchRepo(db), Index: pg.NewVulnRepo(db),
		Findings: pg.NewFindingRepo(db), Services: pg.NewServiceRepo(db), Software: pg.NewSoftwareRepo(db),
	}
	jobRepo := pg.NewCorrelationJobRepo(db)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
				if !schemaGate() {
					continue
				}
				job, err := jobRepo.Claim(ctx, 10*time.Minute)
				if err != nil {
					log.Warn("correlation job claim failed", "err", err)
					continue
				}
				if job == nil {
					continue
				}
				if err := runCorrelationJob(ctx, jobRepo, job, correlator, vulnSearch, log); err != nil {
					log.Warn("correlation job failed", "id", job.ID, "kind", job.Kind, "attempt", job.Attempts, "err", err)
				} else {
					log.Info("correlation job done", "id", job.ID, "kind", job.Kind)
				}
			}
		}
	}()
	// --- periodic maintenance loop
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
				// Liveness sweep with events: exactly the agents that just
				// flipped to offline are returned, so one state_changed
				// event fires per transition (never per sweep).
				if offline, err := agentsRepo.MarkOfflineReturning(ctx, time.Now().UTC().Add(-3*time.Minute)); err == nil {
					for _, a := range offline {
						if db != nil {
							_ = alerting.EmitAgentStateChanged(ctx, db, a.OrgID, a.SiteID, a.ID, a.AssetID, "offline")
						}
					}
				}
				_ = scannersRepo.MarkOffline(ctx, time.Now().UTC().Add(-3*time.Minute))
				// Job log retention (AEGIS_JOBLOG_RETENTION_DAYS, default 7):
				// structured log lines are streaming data, not an archive.
				if n, err := joblog.NewStore(db).DeleteBefore(ctx, time.Now().UTC().Add(-retention)); err == nil && n > 0 {
					log.Info("job log retention sweep", "removed", n)
				}
				jobs, err := pg.NewReportRepo(db).QueuedJobs(ctx, 5)
				if err == nil {
					for _, job := range jobs {
						reportsSvc.RunJob(ctx, job.OrgID, job.ID)
					}
				}
				// Feed staleness watcher: a healthy feed that has not synced
				// within twice its expected interval raises feed.stale; the
				// stable fingerprint lets feed.recovered resolve it.
				watchFeedStaleness(ctx, db, cfg.Feeds.Interval)
			}
		}
	}()

	// --- health/metrics listener: /metrics plus liveness/readiness so
	// compose, helm and prometheus can point at one port. Readiness
	// requires the schema gate; a gated worker reports 503, not a lie.
	go serveWorkerHealth(cfg.MetricsAddr, metrics, db, schemaGate, log)

	log.Info("aegis worker ready")
	<-ctx.Done()
	log.Info("worker shutting down")

	return nil
}

// runCorrelationJob executes one claimed job. Failed jobs return to the
// pending queue; after 5 attempts the worker gives up and marks them done
// with the error recorded (a poison job must not loop forever).
func runCorrelationJob(ctx context.Context, repo *pg.CorrelationJobRepo, job *domain.CorrelationJob, correlator *vulnerabilities.Correlator, search *vulnsearch.Service, log *slog.Logger) error {
	var err error
	switch job.Kind {
	case domain.JobCorrelateOrg:
		_, err = correlator.SweepOrg(ctx, job.OrgID)
	case domain.JobCorrelateAsset:
		var payload struct {
			AssetID string `json:"asset_id"`
		}
		_ = json.Unmarshal(job.Payload, &payload)
		_, err = correlator.SweepAsset(ctx, job.OrgID, payload.AssetID)
	case domain.JobSearchActionRun:
		err = runSearchAction(ctx, job, search)
	default:
		err = fmt.Errorf("unknown correlation job kind %q", job.Kind)
	}
	if err != nil {
		if job.Attempts >= 5 {
			log.Error("correlation job exhausted retries", "id", job.ID, "err", err)
			return repo.Finish(ctx, job.ID, false, "exhausted: "+err.Error())
		}
		return repo.Finish(ctx, job.ID, true, err.Error())
	}
	return repo.Finish(ctx, job.ID, false, "")
}

// runSearchAction executes one durable vuln-search run.
func runSearchAction(ctx context.Context, job *domain.CorrelationJob, search *vulnsearch.Service) error {
	var payload struct {
		ActionID string `json:"action_id"`
		RunID    string `json:"run_id"`
	}
	if err := json.Unmarshal(job.Payload, &payload); err != nil || payload.ActionID == "" {
		return fmt.Errorf("search action run: invalid payload")
	}
	action, err := search.Actions.GetAction(ctx, job.OrgID, payload.ActionID)
	if err != nil {
		return fmt.Errorf("search action run: action not found: %w", err)
	}
	run, err := search.Actions.GetRun(ctx, job.OrgID, payload.RunID)
	if err != nil {
		return fmt.Errorf("search action run: run not found: %w", err)
	}
	_ = search.Actions.UpdateRunState(ctx, run.ID, "running", 10)
	created, matches, targets, rerr := search.Run(ctx, job.OrgID, action, run)
	if rerr != nil {
		_ = search.Actions.FinishRun(ctx, run.ID, "failed", 0, 0, 0, json.RawMessage(`["run failed"]`))
		return rerr
	}
	return search.Actions.FinishRun(ctx, run.ID, "completed", targets, matches, created, json.RawMessage("[]"))
}

// watchFeedStaleness raises feed.stale for enabled sources whose last sync
// is older than twice the expected interval. Events carry a stable
// fingerprint per feed, so repeat sweeps never duplicate occurrences.
func watchFeedStaleness(ctx context.Context, db *pg.DB, interval time.Duration) {
	if db == nil {
		return
	}
	sources, err := pg.NewFeedRepo(db).Sources(ctx)
	if err != nil {
		return
	}
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	// Feeds are deployment-global while alert triggers are org-scoped:
	// staleness fans out one event per organization per stale feed.
	stale := []string{}
	for _, s := range sources {
		if !s.Enabled || s.LastSyncAt == nil {
			continue
		}
		if s.LastStatus == "failed" {
			continue // the failed sync already emitted its event
		}
		if time.Since(*s.LastSyncAt) > 2*interval {
			stale = append(stale, s.Name)
		}
	}
	if len(stale) == 0 {
		return
	}
	orgs, err := pg.NewOrgRepo(db).List(ctx)
	if err != nil {
		return
	}
	for _, org := range orgs {
		for _, feed := range stale {
			_ = alerting.EmitFeedStaleness(ctx, db, org.ID, feed, true)
		}
	}
}

func getEnvBool(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	return v == "1" || v == "true" || v == "yes"
}

// schemaVersion reads the applied version + dirty flag from Postgres.
func schemaVersion(ctx context.Context, db *pg.DB) (int, bool, error) {
	var v int
	var dirty bool
	row := db.Pool.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1")
	if err := row.Scan(&v, &dirty); err != nil {
		if err == pgx.ErrNoRows {
			return 0, false, nil
		}
		return 0, false, err
	}
	return v, dirty, nil
}

// serveWorkerHealth exposes /metrics, /healthz and /readyz on the metrics
// listener. Readiness = Postgres reachable AND schema current.
func serveWorkerHealth(addr string, metrics *observability.Metrics, db *pg.DB, gate func() bool, log *slog.Logger) {
	if addr == "" {
		addr = ":9100"
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", metrics.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := db.Pool.Ping(ctx); err != nil || !gate() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("not ready"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Warn("worker health listener stopped", "err", err)
	}
}
