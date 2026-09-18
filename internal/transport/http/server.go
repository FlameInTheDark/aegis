// Package httpx implements the control-plane HTTP API (Fiber) under
// /api/v1 with consistent pagination, structured errors, request IDs,
// rate limiting and auth (spec §6/§82).
package httpx

import (
        "context"
        "errors"
        "fmt"
        "log/slog"
        "sync"
        "time"

        "github.com/FlameInTheDark/aegis/internal/agents"
        "github.com/FlameInTheDark/aegis/internal/audit"
        "github.com/FlameInTheDark/aegis/internal/config"
        "github.com/FlameInTheDark/aegis/internal/detections"
        "github.com/FlameInTheDark/aegis/internal/observability"
        "github.com/FlameInTheDark/aegis/internal/organizations"
        "github.com/FlameInTheDark/aegis/internal/platform"
        "github.com/FlameInTheDark/aegis/internal/reports"
        ch "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
        pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
        redisrepo "github.com/FlameInTheDark/aegis/internal/repository/redis"
        "github.com/FlameInTheDark/aegis/internal/scanning"
        "github.com/FlameInTheDark/aegis/internal/telemetry"
        "github.com/FlameInTheDark/aegis/internal/vulnerabilities"
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
        Webhooks     *pg.WebhookRepo
        Agents       *pg.AgentRepo
        AgentTasks   *pg.AgentTaskRepo
        EnrollTokens *pg.EnrollmentRepo
        AgentEvents  *pg.AgentEventRepo
        Topology     *pg.TopologyRepo
        Reports      *pg.ReportRepo

        OrgService     *organizations.Service
        Orchestrator   *scanning.Orchestrator
        Detections     *detections.Engine
        Ingestor       *telemetry.Ingestor
        ReportsService *reports.Service
        AgentsService  *agents.Service
        Correlator     *vulnerabilities.Correlator
        AuditService   *audit.Service

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
                BodyLimit:             10 << 20, // request size limits (§82)
                ErrorHandler:          a.errorHandler,
                DisableStartupMessage: true,
                ProxyHeader:           "X-Forwarded-For",
        }
        a.fiber = fiber.New(cfg)
        a.fiber.Use(recover.New(recover.Config{EnableStackTrace: false})) // never expose stacks (§134)
        a.fiber.Use(favicon.New())
        a.fiber.Use(cors.New(cors.Config{
                AllowOrigins:     svc.Cfg.PublicURL,
                AllowMethods:     "GET,POST,PATCH,PUT,DELETE,OPTIONS",
                AllowHeaders:     "Authorization,Content-Type,X-Request-Id,X-Requested-With",
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
        a.log.Error("unhandled error", "err", err, "request_id", reqID, "path", c.Path())
        e := Internal("internal error")
        e.Body.RequestID = reqID
        return c.Status(e.Status).JSON(e.Body)
}

func (a *App) registerRoutes() {
        f := a.fiber

        // Unauthenticated health endpoints (§81).
        f.Get("/healthz", a.handleHealthz)
        f.Get("/readyz", a.handleReadyz)

        api := f.Group("/api/v1")
        api.Use(a.requestID())
        api.Use(a.secureHeaders())

        // Auth — stricter rate limits (§120). /auth/refresh gets its own,
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

        // Assets & inventory.
        g.Get("/assets", a.handleListAssets)
        g.Get("/assets/:id", a.handleGetAsset)
        g.Patch("/assets/:id", a.handleUpdateAsset)
        g.Get("/assets/:id/services", a.handleAssetServices)
        g.Get("/assets/:id/software", a.handleAssetSoftware)
        g.Get("/assets/:id/findings", a.handleAssetFindings)
        g.Get("/assets/:id/interfaces", a.handleAssetInterfaces)
        g.Post("/assets/:id/notes", a.handleAddNote)
        g.Post("/assets/:id/rediscover", a.handleRediscoverAsset)
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

        // Events.
        lim2, _ := a.rateLimiter("events", 120, time.Minute)
        g.Get("/events", lim2, a.handleListEvents)
        g.Post("/events/ingest", lim2, a.handleIngestEvent)

        // Agents.
        g.Get("/agents", a.handleListAgents)
        g.Get("/agents/:id", a.handleGetAgent)
        g.Post("/agents/:id/tasks", a.handleIssueAgentTask)
        g.Post("/agents/enrollment-tokens", a.handleCreateEnrollmentToken)
        g.Get("/agents/enrollment-tokens", a.handleListEnrollmentTokens)

        // Reports.
        g.Get("/reports", a.handleListReports)
        g.Post("/reports", a.handleCreateReport)
        g.Get("/reports/jobs", a.handleListReportJobs)
        g.Get("/reports/jobs/:id", a.handleGetReportJob)
        g.Get("/reports/jobs/:id/download", a.handleDownloadReport)

        // Webhooks (alerting §170).
        g.Get("/webhooks", a.handleListWebhooks)
        g.Post("/webhooks", a.handleCreateWebhook)

        // Search, metrics, audit.
        g.Get("/search", a.handleSearch)
        g.Get("/metrics/summary", a.handleMetricsSummary)
        g.Get("/metrics/timeseries", a.handleMetricsTimeseries)
        g.Get("/audit-log", a.handleAuditLog)

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

// secureHeaders applies defensive HTTP headers (§82).
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
                                mu.Unlock()
                                return RateLimited("rate limit exceeded, slow down")
                        }
                        local[key] = append(fresh, now)
                        mu.Unlock()
                }
                return c.Next()
        }, nil
}

// handleHealthz / handleReadyz implement §81.
func (a *App) handleHealthz(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{"status": "ok", "service": a.svc.Cfg.Service, "version": a.svc.Version, "time": time.Now().UTC().Format(time.RFC3339)})
}

func (a *App) handleReadyz(c *fiber.Ctx) error {
        ctx, cancel := context.WithTimeout(c.UserContext(), 5*time.Second)
        defer cancel()
        critical := map[string]bool{"postgres": true}
        ready, deps := a.svc.Health.Check(ctx, critical)
        status := "ready"
        if !ready {
                status = "not_ready"
        }
        return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": status, "dependencies": deps})
}

var _ = pg.Page{}
