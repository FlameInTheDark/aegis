package httpx

import (
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/scanning"
	"github.com/gofiber/fiber/v2"
)

// ---------------------------------------------------------------------------
// Scans (spec §57/§68/§116)

// handleCreateScan validates and starts a scan with full scope safety.
func (a *App) handleCreateScan(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermScanCreate); he != nil {
		return he
	}
	var req struct {
		SiteID          string   `json:"site_id"`
		Name            string   `json:"name"`
		Profile         string   `json:"profile"`
		Targets         []string `json:"targets"`
		Denylist        []string `json:"denylist"`
		Engine          string   `json:"engine"`
		ScannerID       string   `json:"scanner_id"`
		ConfirmElevated bool     `json:"confirm_elevated"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid JSON body")
	}
	if req.SiteID == "" || len(req.Targets) == 0 {
		return BadRequest("site_id and targets are required")
	}
	// Do not create scans that no scanner can ever claim. A scanner is scoped to
	// a site; accepting a scan for another site leaves it queued indefinitely.
	scanners, err := a.svc.Scanners.List(Context(c), claims.OrganizationID)
	if err != nil {
		a.log.Error("scanner list failed", "err", err)
		return Internal("scanner list failed")
	}
	available := false
	for _, scanner := range scanners {
		if scanner.SiteID == req.SiteID && scanner.Health == "healthy" && time.Since(scanner.LastSeen) < 3*time.Minute {
			available = true
			break
		}
	}
	if !available {
		return Conflict("no healthy scanner is registered for this site")
	}
	profile := domain.ScanProfile(req.Profile)
	if profile == "" {
		profile = domain.ProfileDiscoverySafe
	}
	// Elevated profile guard: requires permission AND explicit confirmation.
	// Resolution covers built-ins AND custom nmap presets (org-scoped).
	def, err := a.svc.Orchestrator.ResolveProfile(Context(c), claims.OrganizationID, profile)
	if err != nil {
		return BadRequest("unknown profile")
	}
	if def.ElevatedReqs {
		if !authzHasPerm(claims, domain.PermScanElevated) {
			return Forbidden("scan:elevated permission required for this profile")
		}
		if !req.ConfirmElevated {
			return fiber.NewError(409, string(domain.ProfileActiveValidation)+": requires explicit confirmation")
		}
	}
	if req.Name == "" {
		req.Name = string(profile) + " scan"
	}
	scan, err := a.svc.Orchestrator.Create(Context(c), scanning.CreateScanInput{
		OrgID: claims.OrganizationID, SiteID: req.SiteID, Name: req.Name,
		Profile: profile, Targets: req.Targets, Denylist: req.Denylist,
		Engine: req.Engine, ScannerID: req.ScannerID,
		CreatedBy: claims.Subject, ElevatedOK: req.ConfirmElevated,
	})
	if err != nil {
		return BadRequest(err.Error())
	}
	userID, ip, ua := a.auditContext(c)
	detail := map[string]any{"profile": string(profile), "targets": req.Targets, "engine": req.Engine}
	if def.ElevatedReqs {
		a.svc.AuditService.EntryElevated(Context(c), claims.OrganizationID, userID, "scan.created_elevated", "scan:"+scan.ID, ip, ua, def.Warning, detail)
	} else {
		a.svc.AuditService.Entry(Context(c), claims.OrganizationID, userID, "scan.created", "scan:"+scan.ID, ip, ua, "success", detail)
	}
	// Immediate UX data (§116): scope, scanner, profile, rate, warnings.
	return c.Status(201).JSON(fiber.Map{
		"scan":     scan,
		"warnings": warningsFor(profile),
	})
}

func warningsFor(p domain.ScanProfile) []string {
	var out []string
	def := domain.Profiles[p] // custom presets carry no built-in warning text
	if def.Warning != "" {
		out = append(out, def.Warning)
	}
	out = append(out, "Scans are recorded with their exact configuration and are auditable. Only scan networks you are authorized to assess.")
	return out
}

// authzHasPerm checks a permission directly on claims.
func authzHasPerm(claims *authClaimsDef, perm domain.Permission) bool {
	if claims == nil {
		return false
	}
	for _, p := range claims.Permissions {
		if p == string(perm) {
			return true
		}
	}
	return hasRolePerm(claims.Role, perm)
}

func (a *App) handleListScans(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	page, limit := pageParams(c)
	items, total, err := a.svc.Scans.List(Context(c), pg.ScanListFilter{
		OrgID: claims.OrganizationID, SiteID: c.Query("site_id"),
		State: c.Query("state"), Limit: limit, Page: page,
	})
	if err != nil {
		return Internal("scan list failed")
	}
	return c.JSON(fiber.Map{"items": items, "total": total, "page": page, "limit": limit})
}

func (a *App) handleGetScan(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	scan, err := a.svc.Scans.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("scan not found")
	}
	scope, _ := a.svc.Scans.Scope(Context(c), scan.ID)
	tasks, _ := a.svc.Tasks.ListForScan(Context(c), scan.ID)
	return c.JSON(fiber.Map{"scan": scan, "scope": scope, "tasks": tasks})
}

func (a *App) handleCancelScan(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermScanCancel); he != nil {
		return he
	}
	if err := a.svc.Orchestrator.Cancel(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return Conflict(err.Error())
	}
	userID, ip, ua := a.auditContext(c)
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, userID, "scan.cancelled", "scan:"+c.Params("id"), ip, ua, "success", nil)
	scan, _ := a.svc.Scans.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	return c.JSON(scan)
}

func (a *App) handleScanChanges(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if _, err := a.svc.Scans.ByID(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("scan not found")
	}
	items, err := a.svc.Changes.ListForScan(Context(c), c.Params("id"))
	if err != nil {
		return Internal("changes query failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleScanTasks(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if _, err := a.svc.Scans.ByID(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("scan not found")
	}
	items, err := a.svc.Tasks.ListForScan(Context(c), c.Params("id"))
	if err != nil {
		return Internal("tasks query failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

// handleListScanners lists registered scanners (§69).
func (a *App) handleListScanners(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Scanners.List(Context(c), claims.OrganizationID)
	if err != nil {
		a.log.Error("scanner list failed", "err", err)
		return Internal("scanner list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

// ---------------------------------------------------------------------------
// Schedules (§17 recurring scans)

func (a *App) handleListSchedules(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Schedules.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("schedule list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleCreateSchedule(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermScanCreate); he != nil {
		return he
	}
	var req struct {
		SiteID  string   `json:"site_id"`
		Name    string   `json:"name"`
		Profile string   `json:"profile"`
		CRON    string   `json:"cron"`
		Scope   []string `json:"scope"`
		Engine  string   `json:"engine"`
	}
	if err := c.BodyParser(&req); err != nil || req.SiteID == "" || req.CRON == "" {
		return BadRequest("site_id, cron and scope are required")
	}
	profile := domain.ScanProfile(req.Profile)
	if profile == "" {
		profile = domain.ProfileInventory
	}
	if _, ok := domain.Profiles[profile]; !ok {
		return BadRequest("unknown profile")
	}
	s := &domain.ScanSchedule{
		ID: idsNew(), OrganizationID: claims.OrganizationID, SiteID: req.SiteID,
		Name: req.Name, Profile: profile, CRON: req.CRON, Scope: req.Scope,
		Engine: req.Engine, Enabled: true, CreatedBy: claims.Subject,
	}
	if err := a.svc.Schedules.Create(Context(c), s); err != nil {
		return Internal("schedule create failed")
	}
	return c.Status(201).JSON(s)
}

func (a *App) handleDeleteSchedule(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermScanCreate); he != nil {
		return he
	}
	if err := a.svc.Schedules.Delete(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("schedule not found")
	}
	return c.SendStatus(204)
}
