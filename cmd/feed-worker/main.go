// Command feed-worker synchronizes vulnerability intelligence feeds
// (NVD, CISA KEV, FIRST EPSS, cvelistV5) on a schedule (.5).
// Feeds run concurrently: a slow bootstrap (NVD full pull, cvelistV5
// archive) never starves the other sources. The worker also consumes the
// security.feed.sync.v1 trigger subject so POST /api/v1/feeds/:name/sync
// takes effect immediately.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/FlameInTheDark/aegis/internal/config"
	"github.com/FlameInTheDark/aegis/internal/feeds"
	"github.com/FlameInTheDark/aegis/internal/logging"
	"github.com/FlameInTheDark/aegis/internal/platform"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "fatal:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load("feed-worker")
	if err != nil {
		return err
	}
	log := logging.New(cfg.LogLevel, cfg.LogFormat)
	log.Info("starting aegis feed-worker", "interval", cfg.Feeds.Interval, "enabled", strings.Join(cfg.Feeds.Enabled, ","), "nvd_api_key", cfg.Feeds.NVDAPIKey != "")
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := pg.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer db.Close()
	vulns := pg.NewVulnRepo(db)
	feedsRepo := pg.NewFeedRepo(db)

	// A previous worker crash can leave 'running' rows behind; reset them so
	// the feeds API reflects reality from boot.
	if n, err := feedsRepo.ClearRunning(ctx); err != nil {
		log.Warn("clearing stale running markers failed", "err", err)
	} else if n > 0 {
		log.Warn("reset feeds stuck in 'running' from a previous worker", "feeds", n)
	}

	var store *platform.ObjectStore
	if cfg.S3.Endpoint != "" {
		store, err = platform.NewObjectStore(ctx, cfg.S3.Endpoint, cfg.S3.AccessKey, cfg.S3.SecretKey, cfg.S3.Bucket, cfg.S3.UseSSL)
		if err != nil {
			log.Warn("object store disabled; raw feed snapshots not stored", "err", err)
			store = nil
		}
	}

	client := feeds.NewClient(log)
	// LastSyncFn reads the persisted sync position, so incremental windows
	// (NVD lastModStartDate, EPSS same-day skip) survive restarts.
	lastSyncOf := func(name string) func(context.Context) time.Time {
		return func(ctx context.Context) time.Time {
			t, err := feedsRepo.LastSyncAt(ctx, name)
			if err != nil {
				return time.Time{}
			}
			return t
		}
	}
	allJobs := []feeds.FeedJob{
		&feeds.KEVJob{Client: client, Vulns: vulns, Store: store, Log: log},
		&feeds.EPSSJob{Client: client, Vulns: vulns, Log: log, LastSyncFn: lastSyncOf("epss")},
		&feeds.NVDJob{Client: client, Vulns: vulns, Store: store, Log: log,
			APIKey: cfg.Feeds.NVDAPIKey, LastSyncFn: lastSyncOf("nvd")},
		&feeds.CVEListV5Job{Client: client, Vulns: vulns, Log: log,
			URL: cfg.Feeds.CVEListURL, LastSyncFn: lastSyncOf("cvelistv5"),
			Meta: feedsRepo},
	}
	// Distro advisory plane: enabled via
	// AEGIS_FEEDS_ENABLED=advisories plus AEGIS_FEED_OVAL_SOURCES.
	advisoriesRepo := pg.NewAdvisoryRepo(db)
	if len(cfg.Feeds.OvalSources) > 0 {
		sources := make([]feeds.OvalSource, 0, len(cfg.Feeds.OvalSources))
		for _, src := range cfg.Feeds.OvalSources {
			sources = append(sources, feeds.OvalSource{Family: src.Family, Release: src.Release, URL: src.URL, Compress: src.Compress})
		}
		allJobs = append(allJobs, &feeds.OvalJob{Client: client, Advisories: advisoriesRepo, Log: log,
			Sources: sources, LastSyncFn: lastSyncOf("advisories")})
	}
	// AEGIS_FEEDS_ENABLED is the documented kill switch for the heavy
	// bootstrap downloads (demo / air-gapped deployments). Unknown names are
	// ignored so the list may mention sources that don't exist yet.
	enabled := map[string]bool{}
	for _, n := range cfg.Feeds.Enabled {
		enabled[strings.TrimSpace(n)] = true
	}
	var jobs []feeds.FeedJob
	for _, j := range allJobs {
		if enabled[j.Name()] {
			jobs = append(jobs, j)
		}
	}
	if len(jobs) == 0 {
		log.Warn("AEGIS_FEEDS_ENABLED matches no known feed; running all feeds", "configured", strings.Join(cfg.Feeds.Enabled, ","))
		jobs = allJobs
	}
	runner := &feeds.Runner{
		Repo: feedsRepo, Vulns: vulns, Store: store, Log: log,
		Jobs: jobs,
		DB:   db,
	}

	// Register sources with license attribution.
	for _, job := range runner.Jobs {
		_ = feedsRepo.EnsureSource(ctx, job.Name(), job.License())
	}

	// Optional health endpoint for container orchestration (the Helm probe
	// already expects /healthz on AEGIS_METRICS_ADDR). Opt-in: only listen
	// when the variable is explicitly set.
	if os.Getenv("AEGIS_METRICS_ADDR") != "" {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "service": "feed-worker"})
		})
		go func() {
			srv := &http.Server{Addr: cfg.MetricsAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
			log.Info("feed-worker health endpoint listening", "addr", cfg.MetricsAddr)
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("feed-worker health endpoint stopped", "err", err)
			}
		}()
	}

	// Trigger channel: POST /api/v1/feeds/:name/sync publishes here and the
	// named feed runs immediately (single-flight per feed; a request while a
	// sync is in flight is answered by the running sync).
	bus, err := platform.ConnectBus(ctx, cfg.NATSURL)
	if err != nil {
		// Triggers are an optimization, not a lifeline — a NATS outage must
		// not take the scheduled syncs down with it.
		log.Warn("nats unavailable; POST /feeds/:name/sync triggers are disabled", "err", err)
	} else {
		defer bus.Close()
		if err := bus.Subscribe(ctx, platform.StreamFeeds, "feed-worker-sync", func(msg jetstream.Msg) error {
			var req struct {
				Feed string `json:"feed"`
			}
			if err := json.Unmarshal(msg.Data(), &req); err != nil || req.Feed == "" {
				return nil // malformed trigger: ack and drop
			}
			if err := runner.RunFeed(ctx, req.Feed, false); err != nil {
				log.Warn("feed trigger rejected", "feed", req.Feed, "err", err)
			}
			return nil
		}); err != nil {
			log.Warn("feed trigger subscription failed", "err", err)
		}
	}

	interval := cfg.Feeds.Interval
	if interval < 30*time.Minute {
		interval = 6 * time.Hour
	}
	// First sync shortly after boot so the index fills fast, then scheduled.
	// Feeds run concurrently inside RunAll; the ticker cannot overlap a run
	// of the same feed (per-feed single-flight in the Runner).
	go func() {
		select {
		case <-time.After(5 * time.Second):
			runner.RunAll(ctx, false)
		case <-ctx.Done():
		}
	}()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Info("feed-worker stopping")
			return nil
		case <-t.C:
			runner.RunAll(ctx, false)
		}
	}
}
