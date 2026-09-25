// Package httpx implements the control-plane HTTP API (Fiber) under
// /api/v1 with consistent pagination, structured errors, request IDs,
// rate limiting and auth.
package httpx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/FlameInTheDark/aegis/internal/agents"
	"github.com/FlameInTheDark/aegis/internal/audit"
	"github.com/FlameInTheDark/aegis/internal/config"
	"github.com/FlameInTheDark/aegis/internal/connectors"
	"github.com/FlameInTheDark/aegis/internal/detections"
	"github.com/FlameInTheDark/aegis/internal/joblog"
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
	"github.com/FlameInTheDark/aegis/internal/vulnerabilities"
	"github.com/gofiber/contrib/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/favicon"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

// Services bundles every dependency the handlers need. Handlers stay thin;
// business logic lives in the service packages.
type Services struct {
	Version string
	Cfg     *config.Config
	Log     *slog.Logger
	Health  *observability.HealthRegistry
	Bus     *platform.Bus
	Redis   *redisrepo.Client
	CH      *ch.DB

	// DB enables domain-event emission from HTTP mutations (finding status
	// changes, asset deletion) into the alert outbox.
	DB *pg.DB

	// Alerting surface (triggers/occurrences/destinations/outbox) and the
	// vulnerability search-action plane.
	AlertTriggers     *pg.AlertTriggerRepo
	Alerts            *pg.AlertOccurrenceRepo
	AlertDestinations *pg.DestinationRepo
	Outbox            *pg.OutboxRepo
	CorrelationJobs   *pg.CorrelationJobRepo
	VulnSearch        *pg.VulnSearchRepo

	Orgs         *pg.OrgRepo
	Users        *pg.UserRepo
	Memberships  *pg.MembershipRepo
	Sessions     *pg.SessionRepo
	Sites        *pg.SiteRepo
	Networks     *pg.NetworkRepo
	Audit        *pg.AuditRepo
	Assets       *pg.AssetRepo
	Ident        *pg.IdentifierRepo
	Ifaces       *pg.InterfaceRepo
	Services     *pg.ServiceRepo
	Software     *pg.SoftwareRepo
	Scans        *pg.ScanRepo
	Tasks        *pg.TaskRepo
	Observations *pg.ObservationRepo
	Scanners     *pg.ScannerRepo
	Schedules    *pg.ScheduleRepo
	Changes      *pg.ChangeRepo
	Profiles     *pg.ProfileRepo
	Vulns        *pg.VulnRepo
	Feeds        *pg.FeedRepo
	Findings     *pg.FindingRepo
	Evidence     *pg.EvidenceRepo
	Suppressions *pg.SuppressionRepo
	Notes        *pg.NoteRepo
	Rules        *pg.RuleRepo
	Matches      *pg.MatchRepo
	Baselines    *pg.BaselineRepo
	Topology     *pg.TopologyRepo
	Traces       *pg.TraceRepo
	Reports      *pg.ReportRepo
	Groups       *pg.GroupRepo

	// Streaming surface (v1.13.0): job log history + browser fan-out.
	JobLogs *joblog.Store
	WSHub   *joblog.Hub

	OrgService        *organizations.Service
	Orchestrator      *scanning.Orchestrator
	Detections        *detections.Engine
	Ingestor          *telemetry.Ingestor
	ReportsService    *reports.Service
	AgentsService     *agents.Service
	ConnectorsService *connectors.Service
	Correlator        *vulnerabilities.Correlator
	AuditService      *audit.Service
	Retention         *retention.Service

	Store *platform.ObjectStore
}

// App is the HTTP application.
type App struct {
	fiber *fiber.App
	svc   *Services
	log   *slog.Logger
}

// New builds the Fiber app and registers all routes.
func New(svc *Services) *App {
	a := &App{svc: svc, log: svc.Log}
	cfg := fiber.Config{
		AppName:               "aegis-server",
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          60 * time.Second,
		IdleTimeout:           90 * time.Second,
		BodyLimit:             10 << 20, // request size limits
		ErrorHandler:          a.errorHandler,
		DisableStartupMessage: true,
		ProxyHeader:           "X-Forwarded-For",
		// Only honor the X-Forwarded-For chain when the direct peer is a
		// trusted proxy. Globally trusting the header let any client rotate
		// arbitrary XFF values to bypass rate limits and forge audit IPs.
		EnableTrustedProxyCheck: true,
		TrustedProxies:          svc.Cfg.TrustedProxies,
	}
	a.fiber = fiber.New(cfg)
	a.fiber.Use(recover.New(recover.Config{EnableStackTrace: false})) // never expose stacks
	a.fiber.Use(favicon.New())
	a.fiber.Use(cors.New(cors.Config{
		AllowOrigins: svc.Cfg.PublicURL,
		AllowMethods: "GET,POST,PATCH,PUT,DELETE,OPTIONS",
		AllowHeaders: "Authorization,Content-Type,X-Request-Id,X-Requested-With",
		// Credentials (the refresh cookie) ride along on cross-origin API
		// calls; the explicit origin (never *) keeps this safe.
		AllowCredentials: true,
		MaxAge:           600,
	}))
	a.registerRoutes()
	return a
}

// Fiber exposes the underlying app for the server binary.
func (a *App) Fiber() *fiber.App { return a.fiber }

func (a *App) errorHandler(c *fiber.Ctx, err error) error {
	var he *HTTPError
	if errors.As(err, &he) {
		he.Body.RequestID = RequestIDFromCtx(c)
		return c.Status(he.Status).JSON(he.Body)
	}
	reqID := RequestIDFromCtx(c)
	// fiber.NewError carries an INTENDED http status (426 upgrade-required,
	// 401, 429, ...). Answer it verbatim and keep 4xx out of the error log:
	// a proxy that strips an Upgrade header must not read as a server fault,
	// nor flood the log on every websocket reconnect attempt.
	var fe *fiber.Error
	if errors.As(err, &fe) {
		if fe.Code >= http.StatusInternalServerError {
			a.log.Error("request failed", "err", fe.Message, "request_id", reqID, "path", c.Path())
		} else {
			a.log.Debug("request error", "code", fe.Code, "err", fe.Message, "request_id", reqID, "path", c.Path())
		}
		return c.Status(fe.Code).JSON(Error{Code: "http_error", Message: fe.Message, RequestID: reqID})
	}
	a.log.Error("unhandled error", "err", err, "request_id", reqID, "path", c.Path())
	e := Internal("internal error")
	e.Body.RequestID = reqID
	return c.Status(e.Status).JSON(e.Body)
}

func (a *App) registerRoutes() {
	f := a.fiber

	// Unauthenticated health endpoints.
	f.Get("/healthz", a.handleHealthz)
	f.Get("/readyz", a.handleReadyz)

	api := f.Group("/api/v1")
	api.Use(a.requestID())
	api.Use(a.secureHeaders())

	// Auth — stricter rate limits. /auth/refresh gets its own,
	// much larger bucket: renewal traffic is token-gated (brute-force
	// irrelevant) but bursts legitimately — several open tabs, a wave of
	// 401 retries after a backend hiccup, the proactive safety nets.
	// Sharing the 20/min login bucket starved refreshes with 429s and
	// left clients stuck with expired tokens.
	lim, _ := a.rateLimiter("auth", 20, time.Minute)
	auth := api.Group("/auth", lim)
	limRefresh, _ := a.rateLimiter("auth-refresh", 120, time.Minute)
	auth.Post("/login", a.handleLogin)
	auth.Post("/refresh", limRefresh, a.handleRefresh)
	auth.Post("/logout", a.handleLogout)

	// Streaming socket (v1.13.0): realtime job logs, scan state and
	// notifications. The guard authenticates via the access_token query
	// parameter (browsers hold the JWT in memory; the handshake cannot
	// carry custom headers), then websocket.New performs the upgrade.
	api.Get("/ws", a.wsUpgradeGuard(), websocket.New(a.handleWSConn))

	// Everything below requires authentication.
	g := api.Group("", a.authenticate())
	g.Get("/auth/me", a.handleMe)
	g.Post("/auth/password", a.handleChangeOwnPassword) // self-service, every role

	// Organizations & tenancy.
	g.Get("/organizations", a.handleListOrgs)
	g.Post("/organizations", a.handleCreateOrg)
	g.Patch("/organizations/current", a.handleRenameOrg)
	g.Get("/users/me", a.handleMe)
	g.Get("/sites", a.handleListSites)
	g.Post("/sites", a.handleCreateSite)
	g.Get("/sites/:id", a.handleGetSite)
	g.Patch("/sites/:id", a.handleUpdateSite)
	g.Delete("/sites/:id", a.handleDeleteSite)
	g.Post("/sites/:id/networks", a.handleCreateNetwork)
	g.Get("/sites/:id/networks", a.handleListNetworks)

	// Asset groups (analyst-curated).
	g.Get("/asset-groups", a.handleListAssetGroups)
	g.Post("/asset-groups", a.handleCreateAssetGroup)
	g.Patch("/asset-groups/:id", a.handleUpdateAssetGroup)
	g.Delete("/asset-groups/:id", a.handleDeleteAssetGroup)
	g.Put("/asset-groups/:id/assets", a.handleSetGroupMembers)

	// Assets & inventory.
	g.Get("/assets", a.handleListAssets)
	g.Get("/assets/:id", a.handleGetAsset)
	g.Patch("/assets/:id", a.handleUpdateAsset)
	g.Get("/assets/:id/services", a.handleAssetServices)
	g.Get("/assets/:id/software", a.handleAssetSoftware)
	g.Get("/assets/:id/findings", a.handleAssetFindings)
	g.Get("/assets/:id/interfaces", a.handleAssetInterfaces)
	g.Get("/assets/:id/traces", a.handleAssetTraces)
	g.Get("/assets/:id/metrics", a.handleGetAssetMetrics)
	g.Post("/assets/:id/notes", a.handleAddNote)
	g.Get("/assets/:id/notes", a.handleListNotes)
	g.Post("/assets/:id/rediscover", a.handleRediscoverAsset)
	g.Delete("/assets/:id", a.handleDeleteAsset)
	g.Get("/services", a.handleListServices)

	// Topology.
	g.Get("/topology", a.handleTopology)
	g.Get("/topology/evidence/:edgeID", a.handleTopologyEvidence)

	// Scanning.
	g.Get("/scans", a.handleListScans)
	g.Post("/scans", a.handleCreateScan)
	g.Get("/scans/:id", a.handleGetScan)
	g.Post("/scans/:id/cancel", a.handleCancelScan)
	g.Get("/scans/:id/changes", a.handleScanChanges)
	g.Get("/scans/:id/logs", a.handleScanLogs)
	g.Get("/scans/:id/tasks", a.handleScanTasks)
	g.Get("/scan-profiles", a.handleListScanProfiles)
	g.Post("/scan-profiles", a.handleCreateScanProfile) // settings:manage
	g.Patch("/scan-profiles/:name", a.handleUpdateScanProfile)
	g.Delete("/scan-profiles/:name", a.handleDeleteScanProfile)
	g.Get("/users", a.handleListUsers) // user:manage
	g.Post("/users", a.handleCreateUser)
	g.Patch("/users/:id", a.handleUpdateUser)
	g.Post("/users/:id/reset-password", a.handleResetUserPassword)
	g.Get("/scanners", a.handleListScanners)
	g.Post("/scanners/enroll", a.handleEnrollScanner) // agent:manage
	g.Post("/scanners/:id/default", a.handleSetDefaultScanner)
	g.Get("/schedules", a.handleListSchedules)
	g.Post("/schedules", a.handleCreateSchedule)
	g.Delete("/schedules/:id", a.handleDeleteSchedule)

	// Vulnerabilities & findings.
	g.Get("/vulnerabilities", a.handleListVulns)
	g.Get("/vulnerabilities/:cveID", a.handleGetVuln)
	g.Post("/vulnerabilities/correlate", a.handleRunCorrelation)
	g.Get("/findings", a.handleListFindings)
	// Static-segment routes must precede /findings/:id so Fiber does not
	// bind "suppressions" as an id.
	g.Get("/findings/suppressions", a.handleListSuppressions)
	g.Delete("/findings/suppressions/:id", a.handleRevokeSuppression)
	g.Get("/findings/:id", a.handleGetFinding)
	g.Patch("/findings/:id", a.handleUpdateFinding)
	g.Post("/findings/bulk", a.handleBulkFindings)
	g.Post("/findings/:id/suppress", a.handleSuppressFinding)
	g.Get("/feeds", a.handleListFeeds)
	g.Post("/feeds/:name/sync", a.handleTriggerFeedSync)

	// Detections.
	g.Get("/detections/rules", a.handleListRules)
	g.Post("/detections/rules", a.handleCreateRule)
	g.Patch("/detections/rules/:id", a.handleUpdateRule)
	g.Get("/detections/matches", a.handleListMatches)
	g.Patch("/detections/matches/:id", a.handleUpdateMatchStatus)

	// Events.
	lim2, _ := a.rateLimiter("events", 120, time.Minute)
	g.Get("/events", lim2, a.handleListEvents)
	g.Post("/events/ingest", lim2, a.handleIngestEvent)

	// External connections (unified connector registry).
	g.Get("/connectors", a.handleListConnectors)
	g.Post("/connectors", a.handleCreateConnector)
	g.Get("/connectors/:id", a.handleGetConnector)
	g.Patch("/connectors/:id", a.handleUpdateConnector)
	g.Delete("/connectors/:id", a.handleDeleteConnector)
	g.Put("/connectors/:id/config", a.handleUpdateConnectorConfig)
	g.Post("/connectors/:id/enroll-token", a.handleRotateConnectorToken)
	g.Post("/connectors/:id/revoke", a.handleRevokeConnector)

	// Bound endpoint devices are served as part of the connector views
	// above (there is no separate device registry) and their performance
	// history rides on the asset metrics endpoint below.

	// Reports.
	g.Get("/reports", a.handleListReports)
	g.Post("/reports", a.handleCreateReport)
	g.Get("/reports/jobs", a.handleListReportJobs)
	g.Get("/reports/jobs/:id", a.handleGetReportJob)
	g.Get("/reports/jobs/:id/download", a.handleDownloadReport)

	// Alerts: occurrences, trigger rules, destinations, engine health.
	g.Get("/alerts/capabilities", a.handleAlertCapabilities)
	g.Get("/alerts/health", a.handleAlertsHealth)
	g.Get("/alerts", a.handleListAlerts)
	g.Get("/alerts/:id", a.handleGetAlert)
	g.Post("/alerts/:id/acknowledge", a.handleAckAlert)
	g.Post("/alerts/:id/resolve", a.handleResolveAlert)
	g.Get("/alerts/triggers", a.handleListTriggers)
	g.Post("/alerts/triggers", a.handleCreateTrigger)
	g.Post("/alerts/triggers/preview", a.handlePreviewTrigger)
	g.Get("/alerts/triggers/:id", a.handleGetTrigger)
	g.Put("/alerts/triggers/:id", a.handleUpdateTrigger)
	g.Patch("/alerts/triggers/:id/enabled", a.handleToggleTrigger)
	g.Delete("/alerts/triggers/:id", a.handleDeleteTrigger)
	g.Post("/alerts/triggers/:id/test", a.handleTestTrigger)
	g.Get("/alerts/destinations", a.handleListDestinations)
	g.Post("/alerts/destinations", a.handleCreateDestination)
	g.Patch("/alerts/destinations/:id", a.handleUpdateDestination)
	g.Delete("/alerts/destinations/:id", a.handleDeleteDestination)
	g.Post("/alerts/destinations/:id/test", a.handleTestDestination)
	g.Post("/alerts/destinations/:id/replay", a.handleReplayDeadDeliveries)

	// Vulnerability search actions + match workbench.
	g.Get("/vulnerability-search-actions/capabilities", a.handleVulnSearchCapabilities)
	g.Get("/vulnerability-search-actions", a.handleListSearchActions)
	g.Post("/vulnerability-search-actions", a.handleCreateSearchAction)
	g.Post("/vulnerability-search-actions/preview", a.handlePreviewSearchAction)
	g.Get("/vulnerability-search-actions/:id", a.handleGetSearchAction)
	g.Put("/vulnerability-search-actions/:id", a.handleUpdateSearchAction)
	g.Delete("/vulnerability-search-actions/:id", a.handleDeleteSearchAction)
	g.Post("/vulnerability-search-actions/:id/preview", a.handlePreviewSearchAction)
	g.Post("/vulnerability-search-actions/:id/runs", a.handleRunSearchAction)
	g.Get("/vulnerability-search-runs/:id", a.handleGetSearchRun)
	g.Post("/vulnerabilities/match/search", a.handleVulnerabilityMatchSearch)
	g.Get("/assets/:id/vulnerability-diagnostics", a.handleAssetVulnDiagnostics)

	// Search, metrics, audit.
	g.Get("/search", a.handleSearch)
	g.Get("/metrics/summary", a.handleMetricsSummary)
	g.Get("/metrics/timeseries", a.handleMetricsTimeseries)
	g.Get("/audit-log", a.handleAuditLog)

	// Platform settings (metrics retention; settings:manage to change).
	g.Get("/settings", a.handleGetSettings)
	g.Patch("/settings", a.handleUpdateSettings)
	g.Post("/settings/metrics/cleanup", a.handleMetricsCleanup)

	// Sensor ingest (API key or agent token; kept on the authed group for
	// the initial release — sensors use per-org ingest tokens).
	g.Post("/sensors/:sensorID/events", a.handleSensorIngest)
}

// requestID assigns/propagates X-Request-Id.
func (a *App) requestID() fiber.Handler {
	return func(c *fiber.Ctx) error {
		rid := c.Get("X-Request-Id")
		if rid == "" {
			rid = fmt.Sprintf("req_%d", time.Now().UnixNano())
		}
		c.Locals("request_id", rid)
		c.Set("X-Request-Id", rid)
		return c.Next()
	}
}

// secureHeaders applies defensive HTTP headers.
func (a *App) secureHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Referrer-Policy", "no-referrer")
		c.Set("X-XSS-Protection", "0")
		c.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		if a.svc.Cfg.IsProduction() {
			c.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		return c.Next()
	}
}

// rateLimiter builds a redis-backed sliding-window limiter; falls back to
// an in-process limiter when redis is unavailable.
func (a *App) rateLimiter(bucket string, limit int, window time.Duration) (fiber.Handler, error) {
	var mu sync.Mutex
	local := map[string][]time.Time{}
	lastSeen := map[string]time.Time{}
	return func(c *fiber.Ctx) error {
		key := RateLimitBucket(c, bucket)
		if a.svc.Redis != nil {
			allowed, _, err := a.svc.Redis.RateLimit(c.Context(), "rl:"+key, limit, window)
			if err == nil && !allowed {
				return RateLimited("rate limit exceeded, slow down")
			}
		} else {
			mu.Lock()
			now := time.Now()
			hits := local[key]
			fresh := hits[:0]
			for _, t := range hits {
				if now.Sub(t) < window {
					fresh = append(fresh, t)
				}
			}
			if len(fresh) >= limit {
				local[key] = fresh
				lastSeen[key] = now
				mu.Unlock()
				return RateLimited("rate limit exceeded, slow down")
			}
			local[key] = append(fresh, now)
			lastSeen[key] = now
			// Idle-key eviction: keys used to live here forever, so every
			// distinct (or spoofed) client IP grew the map without bound.
			if len(local) > 8192 {
				cutoff := now.Add(-4 * window)
				for k, t := range lastSeen {
					if t.Before(cutoff) {
						delete(local, k)
						delete(lastSeen, k)
					}
				}
			}
			mu.Unlock()
		}
		return c.Next()
	}, nil
}

// handleHealthz / handleReadyz implement.
func (a *App) handleHealthz(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok", "service": a.svc.Cfg.Service, "version": a.svc.Version, "time": time.Now().UTC().Format(time.RFC3339)})
}

func (a *App) handleReadyz(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.UserContext(), 5*time.Second)
	defer cancel()
	critical := map[string]bool{"postgres": true}
	ready, deps := a.svc.Health.Check(ctx, critical)
	status := "ready"
	code := fiber.StatusOK
	if !ready {
		status = "not_ready"
		// Fail closed: a 200 here kept Kubernetes routing user traffic to
		// pods whose database was gone.
		code = fiber.StatusServiceUnavailable
	}
	return c.Status(code).JSON(fiber.Map{"status": status, "dependencies": deps})
}
