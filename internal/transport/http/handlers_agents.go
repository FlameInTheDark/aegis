package httpx

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/agents"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
)

// ---------------------------------------------------------------------------
// Agents (§16/§19/§62)

func (a *App) handleListAgents(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Agents.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("agent list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleGetAgent(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	agent, err := a.svc.Agents.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("agent not found")
	}
	tasks, _ := a.svc.AgentTasks.ListForAgent(Context(c), agent.ID, 20)
	events, _ := a.svc.AgentEvents.ListForAgent(Context(c), agent.ID, 20)
	// Never expose private key material (§62/§127): agent record contains none.
	return c.JSON(fiber.Map{"agent": agent, "tasks": tasks, "events": events})
}

// handleIssueAgentTask assigns a typed task (no remote shell, ever, §19).
func (a *App) handleIssueAgentTask(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	var req struct {
		Type string         `json:"type"`
		Args map[string]any `json:"args"`
	}
	if err := c.BodyParser(&req); err != nil || req.Type == "" {
		return BadRequest("type is required")
	}
	if len(req.Args) > 32 {
		return BadRequest("too many task arguments")
	}
	task, err := a.svc.AgentsService.IssueTask(Context(c), claims.OrganizationID, c.Params("id"), domain.AgentTaskType(req.Type), req.Args, 10*time.Minute)
	if err != nil {
		return BadRequest(err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "agent.task_executed", "agent:"+c.Params("id"), c.IP(), "", "success", map[string]any{"task_type": req.Type, "task_id": task.ID})
	return c.Status(201).JSON(task)
}

// handleCreateEnrollmentToken issues a one-time enrollment token (§16).
func (a *App) handleCreateEnrollmentToken(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	var req struct {
		SiteID string `json:"site_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.SiteID == "" {
		return BadRequest("site_id is required")
	}
	token, prefix, err := agents.GenerateEnrollmentToken()
	if err != nil {
		return Internal("token generation failed")
	}
	t := &domain.EnrollmentToken{
		ID: ids.New(), OrganizationID: claims.OrganizationID, SiteID: req.SiteID,
		TokenHash: agents.TokenHash(token), Prefix: prefix,
		CreatedBy: claims.Subject, CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().UTC().Add(24 * time.Hour),
	}
	if err := a.svc.EnrollTokens.Create(Context(c), t); err != nil {
		return Internal("token persist failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "agent.enrolled", "enrollment_token:"+t.ID, c.IP(), "", "success", map[string]any{"site_id": req.SiteID})
	// The raw token is returned exactly once and never stored (§16).
	return c.Status(201).JSON(fiber.Map{"token": token, "prefix": prefix, "expires_at": t.ExpiresAt})
}

func (a *App) handleListEnrollmentTokens(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	items, err := a.svc.EnrollTokens.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("token list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

// ---------------------------------------------------------------------------
// Reports (§50/§63/§138)

func (a *App) handleListReports(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Reports.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("report list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleCreateReport(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermReportCreate); he != nil {
		return he
	}
	var req struct {
		Type   string `json:"type"`
		Format string `json:"format"`
		SiteID string `json:"site_id"`
		AssetID string `json:"asset_id"`
		ScanID string `json:"scan_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.Type == "" {
		return BadRequest("type is required")
	}
	if req.Format == "" {
		req.Format = "html"
	}
	// A device-detail report requires an explicit target asset; a site-detail
	// report requires a site. Both checks keep report scope unambiguous.
	switch domain.ReportType(req.Type) {
	case domain.ReportDeviceDetail:
		if req.AssetID == "" {
			return BadRequest("asset_id is required for device_detail reports")
		}
	case domain.ReportSiteDetail:
		if req.SiteID == "" {
			return BadRequest("site_id is required for site_detail reports")
		}
	}
	_, job, err := a.svc.ReportsService.CreateDefinition(Context(c), claims.OrganizationID, claims.Subject,
		domain.ReportType(req.Type), domain.ReportFormat(req.Format), req.SiteID, req.AssetID, req.ScanID, "")
	if err != nil {
		return BadRequest("invalid report request: " + err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "report.generated", "report_job:"+job.ID, c.IP(), "", "success", map[string]any{"type": req.Type, "format": req.Format})
	// Reports are generated by background jobs, never in-request (§50).
	return c.Status(202).JSON(fiber.Map{"job": job})
}

func (a *App) handleListReportJobs(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Reports.ListJobs(Context(c), claims.OrganizationID, 50)
	if err != nil {
		return Internal("job list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleGetReportJob(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	job, err := a.svc.Reports.Job(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("report job not found")
	}
	return c.JSON(job)
}

// handleDownloadReport streams the finished artifact through the API with a
// Content-Disposition attachment header.
//
// Why streaming instead of the previous 307-to-presigned-URL redirect: the
// presigned URL points at the object store's INTERNAL endpoint (rustfs:9000
// — not published in compose), which no user's browser can resolve; and the
// API route itself sits behind JWT auth that a plain <a href> navigation
// cannot satisfy. The API is the one hop every client can reach, report
// artifacts are small (KBs–MBs), so proxying them is cheap and works
// everywhere. Clients that want a URL can still read it from the job.
func (a *App) handleDownloadReport(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	job, err := a.svc.Reports.Job(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("report job not found")
	}
	if job.State != "completed" || job.ArtifactKey == "" {
		return Conflict("report is not ready (state: " + job.State + ")")
	}
	if a.svc.Store == nil {
		return Unavailable("object storage not configured")
	}
	data, err := a.svc.Store.Get(Context(c), job.ArtifactKey)
	if err != nil {
		a.svc.Log.Error("report artifact read failed", "job", job.ID, "key", job.ArtifactKey, "err", err)
		// The job row claims completion but the object is gone (storage
		// cleared, retention sweep, or a historical false-completion).
		// 404 is the truthful answer; retrying will never fix it.
		return NotFound("report artifact is missing; regenerate the report")
	}
	c.Set("Content-Type", artifactContentType(job.ArtifactKey))
	c.Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", artifactName(Context(c), a, job)))
	c.Set("Content-Length", itoa(len(data)))
	return c.Send(data)
}

// artifactContentType maps an artifact key's extension to a MIME type.
func artifactContentType(key string) string {
	switch {
	case strings.HasSuffix(key, ".pdf"):
		return "application/pdf"
	case strings.HasSuffix(key, ".csv"):
		return "text/csv; charset=utf-8"
	case strings.HasSuffix(key, ".json"):
		return "application/json"
	default:
		return "text/html; charset=utf-8"
	}
}

// artifactName builds a friendly download filename such as
// aegis-report-executive_security-20260917-9f32c1ab.html. The definition
// UUID is resolved to its human type slug when possible (best effort — a
// lookup failure must never block the download).
func artifactName(ctx context.Context, a *App, job *domain.ReportJob) string {
	label := job.Definition
	if def, err := a.svc.Reports.Definition(ctx, job.OrgID, job.Definition); err == nil && def != nil && def.Type != "" {
		label = string(def.Type)
	}
	return artifactFileName(label, job)
}

// artifactFileName is the pure filename composer (unit-testable).
func artifactFileName(label string, job *domain.ReportJob) string {
	ext := "html"
	if i := strings.LastIndexByte(job.ArtifactKey, '.'); i >= 0 && len(job.ArtifactKey)-i <= 6 {
		ext = job.ArtifactKey[i+1:]
	}
	if label == "" {
		label = "report"
	}
	return fmt.Sprintf("aegis-report-%s-%s-%s.%s",
		label, job.CreatedAt.Format("20060102"), shortID(job.ID), ext)
}

// shortID returns the first segment of a UUID-ish id for filenames.
func shortID(id string) string {
	id = strings.ReplaceAll(id, "-", "")
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// ---------------------------------------------------------------------------
// Webhooks (§170/§171)

func (a *App) handleListWebhooks(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Webhooks.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("webhook list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleCreateWebhook(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	var w domain.WebhookConfig
	if err := c.BodyParser(&w); err != nil || w.URL == "" {
		return BadRequest("url is required")
	}
	w.ID = ids.New()
	w.OrgID = claims.OrganizationID
	w.CreatedAt = time.Now().UTC()
	if err := a.svc.Webhooks.Insert(Context(c), &w); err != nil {
		return Internal("webhook insert failed")
	}
	return c.Status(201).JSON(w)
}

var _ = pg.Page{}
