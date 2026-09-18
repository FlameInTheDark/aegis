package httpx

import (
	"github.com/FlameInTheDark/aegis/internal/audit"
	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/hub"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/gofiber/fiber/v2"
)

// Scanner hub management: enroll remote agents (issue a one-time enrollment
// token) and pick the org default scanner. Requires agent:manage.

type enrollResp struct {
	ScannerID string `json:"scanner_id"`
	Token     string `json:"token"` // shown ONCE; only its SHA-256 is stored
}

func (a *App) handleEnrollScanner(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	var req struct {
		Name   string `json:"name"`
		SiteID string `json:"site_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return BadRequest("name is required")
	}
	claims := a.claimsFrom(c)
	ctx := Context(c)
	if req.SiteID == "" {
		return BadRequest("site_id is required (the scanner scans that site's network)")
	}
	site, err := a.svc.Sites.ByID(ctx, claims.OrganizationID, req.SiteID)
	if err != nil || site == nil {
		return BadRequest("unknown site for this organization")
	}
	token, err := auth.GenerateToken("aegissc")
	if err != nil {
		return Internal("could not generate token")
	}
	hash := hub.HashToken(token)
	sc := &domain.Scanner{
		ID: ids.New(), OrganizationID: claims.OrganizationID, SiteID: req.SiteID,
		Name: req.Name, Version: "pending", Health: "offline",
	}
	if err := a.svc.Scanners.Enroll(ctx, sc, hash); err != nil {
		return Internal("could not enroll scanner")
	}
	a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionAgentEnroll,
		"scanner:"+sc.ID, c.IP(), string(c.Request().Header.UserAgent()), "success",
		map[string]any{"name": req.Name, "site": req.SiteID})
	return c.Status(201).JSON(enrollResp{ScannerID: sc.ID, Token: token})
}

func (a *App) handleSetDefaultScanner(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	var req struct {
		IsDefault bool `json:"is_default"`
	}
	_ = c.BodyParser(&req)
	claims := a.claimsFrom(c)
	if _, err := a.svc.Scanners.ByID(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("scanner not found")
	}
	if err := a.svc.Scanners.SetDefault(Context(c), claims.OrganizationID, c.Params("id"), req.IsDefault); err != nil {
		return Internal("could not update default")
	}
	return c.SendStatus(204)
}
