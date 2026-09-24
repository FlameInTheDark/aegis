package httpx

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/feeds"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
)

// authClaimsDef names the concrete claims type for handler helpers.
type authClaimsDef = auth.Claims

// hasRolePerm checks a permission via the RBAC registry.
func hasRolePerm(role domain.Role, perm domain.Permission) bool {
	return auth.HasPermission(role, perm)
}

// authClaimsAlias is the concrete claims type used by helpers.
type authClaimsAlias = authClaimsDef

func idsNew() string { return ids.New() }

// ---------------------------------------------------------------------------
// Vulnerabilities

// handleListVulns lists the CVE index with enrichment.
func (a *App) handleListVulns(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	page, limit := pageParams(c)
	kev := c.Query("kev") == "true"
	search := c.Query("search")
	severity := c.Query("severity")
	minScore, _ := strconv.ParseFloat(c.Query("min_score"), 64)
	maxScore, _ := strconv.ParseFloat(c.Query("max_score"), 64)

	rows, err := a.svc.Vulns.ListVulns(Context(c), claims.OrganizationID, pg.VulnListFilter{
		Search: search, Severity: severity, KEV: kev,
		State: c.Query("state"), Source: c.Query("source"),
		MinScore: minScore, MaxScore: maxScore,
		// Server-side sorting (published date, name, CVSS, KEV) and a
		// published window; the repo whitelists everything, unknown
		// values degrade to the default relevance order.
		Sort: c.Query("sort"), Order: c.Query("order"),
		PublishedAfter:  c.Query("published_after"),
		PublishedBefore: c.Query("published_before"),
		Limit:           limit, Page: page,
	})
	if err != nil {
		return Internal("vulnerability list failed")
	}
	// Enrich with affected-asset counts from findings.
	items := make([]vulnRow, 0, len(rows.Items))
	var cveIDs []string
	for _, r := range rows.Items {
		cveIDs = append(cveIDs, r.CVEID)
	}
	epssMap, _ := a.svc.Vulns.EPSSForCVEs(Context(c), cveIDs)
	for _, r := range rows.Items {
		row := vulnRow{VulnListRow: r}
		if e, ok := epssMap[r.CVEID]; ok {
			row.EPSS = e
		}
		items = append(items, row)
	}
	return c.JSON(fiber.Map{"items": items, "total": rows.Total, "page": page, "limit": limit})
}

type vulnRow struct {
	pg.VulnListRow
	EPSS float64 `json:"epss"`
}

func (a *App) handleGetVuln(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	cveID := c.Params("cveID")
	vuln, err := a.svc.Vulns.CVE(Context(c), cveID)
	if err != nil || vuln == nil {
		return NotFound("CVE not found in the local index; ensure feeds have synchronized")
	}
	refs, _ := a.svc.Vulns.References(Context(c), cveID)
	if refs == nil {
		refs = []string{}
	}
	findings, _ := a.svc.Findings.ListForCVE(Context(c), claims.OrganizationID, cveID)
	type affected struct {
		AssetID   string  `json:"asset_id"`
		Hostname  string  `json:"hostname,omitempty"`
		RiskScore float64 `json:"risk_score"`
		FindingID string  `json:"finding_id"`
		Status    string  `json:"status"`
	}
	// API collection fields are always arrays, never JSON null. This keeps
	// clients simple and gives empty CVEs the same response shape as enriched
	// ones.
	assets := make([]affected, 0)
	for _, f := range findings {
		host := ""
		if a2, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, f.AssetID); err == nil && a2 != nil {
			host = a2.Hostname
		}
		assets = append(assets, affected{AssetID: f.AssetID, Hostname: host, RiskScore: f.RiskScore, FindingID: f.ID, Status: string(f.Status)})
	}
	return c.JSON(fiber.Map{"vulnerability": vuln, "references": refs, "affected_assets": assets})
}

// ---------------------------------------------------------------------------
// Findings

func (a *App) handleListFindings(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingRead); he != nil {
		return he
	}
	page, limit := pageParams(c)
	f := pg.FindingFilter{
		OrgID:    claims.OrganizationID,
		SiteID:   c.Query("site_id"),
		AssetID:  c.Query("asset_id"),
		Status:   c.Query("status"),
		Severity: c.Query("severity"),
		KEV:      c.Query("kev") == "true",
		Search:   c.Query("search"),
		Limit:    limit,
		Page:     page,
	}
	if mr := c.QueryFloat("min_risk", -1); mr >= 0 {
		f.MinRisk = mr
	}
	items, total, err := a.svc.Findings.List(Context(c), f)
	if err != nil {
		return Internal("finding list failed")
	}
	return c.JSON(fiber.Map{"items": items, "total": total, "page": page, "limit": limit})
}

func (a *App) handleGetFinding(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingRead); he != nil {
		return he
	}
	f, err := a.svc.Findings.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("finding not found")
	}
	evidence, _ := a.svc.Evidence.ListForFinding(Context(c), f.ID)
	history, _ := a.svc.Findings.StatusHistory(Context(c), f.ID)
	return c.JSON(fiber.Map{"finding": f, "evidence": evidence, "history": history})
}

// handleUpdateFinding changes status with audit trail.
func (a *App) handleUpdateFinding(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	var req struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	if err := c.BodyParser(&req); err != nil || req.Status == "" {
		return BadRequest("status is required")
	}
	status := domain.FindingStatus(req.Status)
	valid := map[domain.FindingStatus]bool{
		domain.FindingOpen: true, domain.FindingAcknowledged: true, domain.FindingInProgress: true,
		domain.FindingResolved: true, domain.FindingAcceptedRisk: true, domain.FindingFalsePositive: true,
		domain.FindingSuppressed: true,
	}
	if !valid[status] {
		return BadRequest("invalid status")
	}
	if err := a.svc.Findings.SetStatus(Context(c), claims.OrganizationID, c.Params("id"), status, claims.Subject, req.Reason); err != nil {
		return NotFound("finding not found or status change failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "finding.status_changed", "finding:"+c.Params("id"), c.IP(), "", "success",
		map[string]any{"to": string(status), "reason": req.Reason})
	f, _ := a.svc.Findings.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	return c.JSON(f)
}

// handleBulkFindings applies bulk status changes with confirmation guard.
func (a *App) handleBulkFindings(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	var req struct {
		IDs     []string `json:"ids"`
		Status  string   `json:"status"`
		Reason  string   `json:"reason"`
		Confirm bool     `json:"confirm"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.IDs) == 0 || req.Status == "" {
		return BadRequest("ids and status are required")
	}
	if len(req.IDs) > 500 {
		return BadRequest("bulk limit is 500 findings per request")
	}
	status := domain.FindingStatus(req.Status)
	// Dangerous bulk ops need explicit confirmation.
	if status == domain.FindingFalsePositive || status == domain.FindingAcceptedRisk || status == domain.FindingSuppressed {
		if !req.Confirm {
			return Conflict("confirmation required for dangerous bulk operation")
		}
	}
	if req.Reason == "" {
		return BadRequest("reason is required for bulk status changes")
	}
	n, err := a.svc.Findings.BulkStatus(Context(c), claims.OrganizationID, req.IDs, status, claims.Subject, req.Reason)
	if err != nil {
		return Internal("bulk update failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "finding.bulk_status", "findings:"+itoa(len(req.IDs)), c.IP(), "", "success",
		map[string]any{"to": string(status), "updated": n})
	return c.JSON(fiber.Map{"updated": n})
}

// handleSuppressFinding records a scoped suppression.
func (a *App) handleSuppressFinding(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	var req struct {
		Reason    string `json:"reason"`
		ExpiresAt string `json:"expires_at"`
	}
	if err := c.BodyParser(&req); err != nil || req.Reason == "" {
		return BadRequest("reason is required for suppressions")
	}
	sup := &domain.Suppression{
		ID: ids.New(), OrgID: claims.OrganizationID,
		Scope:  domain.SuppressionScope{Vulnerability: strPtr(c.Query("cve")), AssetID: strPtr(c.Query("asset_id"))},
		Reason: req.Reason, CreatedBy: claims.Subject, CreatedAt: time.Now().UTC(),
	}
	if req.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, req.ExpiresAt); err == nil {
			sup.ExpiresAt = &t
		}
	}
	if err := a.svc.Suppressions.Insert(Context(c), sup); err != nil {
		return Internal("suppression insert failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "finding.suppressed", "finding:"+c.Params("id"), c.IP(), "", "success", map[string]any{"reason": req.Reason})
	return c.Status(201).JSON(sup)
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ---------------------------------------------------------------------------
// Feeds (freshness)

func (a *App) handleListFeeds(c *fiber.Ctx) error {
	items, err := a.svc.Feeds.Sources(Context(c))
	if err != nil {
		return Internal("feed list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleTriggerFeedSync(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFeedManage); he != nil {
		return he
	}
	name := c.Params("name")
	// Feed sync is asynchronous by design — publish a trigger the
	// feed-worker consumes on security.feed.sync.v1 so the request takes
	// effect immediately instead of silently doing nothing until the next
	// scheduled tick.
	if a.svc.Bus == nil {
		return Unavailable("feed worker unavailable")
	}
	payload, _ := json.Marshal(map[string]any{"feed": name, "requested_by": claims.Subject})
	if err := a.svc.Bus.Publish(Context(c), feeds.SyncRequestSubject, payload); err != nil {
		return Internal("feed trigger failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "feed.configured", "feed:"+name, c.IP(), "", "success", map[string]any{"action": "sync_requested"})
	return c.Status(202).JSON(fiber.Map{"queued": true, "feed": name})
}

// handleRunCorrelation re-runs the service↔CVE matching sweep for the whole
// organization on demand — typically right after a feed sync pulled new CVE
// data, or when the user wants fresh findings without re-scanning. Runs in
// the background; results appear as findings (pipeline, evidence).
func (a *App) handleRunCorrelation(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	if a.svc.Correlator == nil {
		return Unavailable("correlator unavailable")
	}
	org := claims.OrganizationID
	a.svc.AuditService.Entry(Context(c), org, claims.Subject, "correlation.requested", "org:"+org, c.IP(), "", "success", nil)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
		defer cancel()
		n, err := a.svc.Correlator.SweepOrg(ctx, org)
		if err != nil {
			a.svc.Log.Warn("on-demand correlation failed", "org", org, "err", err)
			return
		}
		a.svc.Log.Info("on-demand correlation finished", "org", org, "findings_created", n)
	}()
	return c.Status(202).JSON(fiber.Map{"started": true, "detail": "correlation is running in the background; refresh findings shortly"})
}
