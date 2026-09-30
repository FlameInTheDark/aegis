package httpx

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/handoff"
	"github.com/gofiber/fiber/v2"
)

// ---------------------------------------------------------------------------
// Outbound integrations + finding handoff (F6)

func (a *App) handleGetIntegrations(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	kind := c.Params("kind")
	if !domain.ValidIntegrationKind(kind) {
		return BadRequest("unknown integration kind")
	}
	integ, err := a.svc.Integrations.Get(Context(c), claims.OrganizationID, kind)
	if err != nil {
		// Unconfigured is a normal state the settings UI renders as an
		// empty form, not an error.
		return c.JSON(fiber.Map{"kind": kind, "configured": false})
	}
	return c.JSON(fiber.Map{"configured": true, "integration": integ})
}

func (a *App) handleUpsertIntegration(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	kind := c.Params("kind")
	if !domain.ValidIntegrationKind(kind) {
		return BadRequest("unknown integration kind")
	}
	var req struct {
		Config json.RawMessage `json:"config"`
		Secret string          `json:"secret"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid body")
	}
	switch kind {
	case domain.IntegrationGitHub:
		var cfg domain.GitHubConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil || strings.Count(strings.TrimPrefix(cfg.Repo, "/"), "/") != 1 {
			return BadRequest("config must set repo to \"owner/name\"")
		}
	case domain.IntegrationJira:
		var cfg domain.JiraConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil || cfg.Site == "" || cfg.Project == "" {
			return BadRequest("config must set site and project")
		}
	case domain.IntegrationAWS:
		var cfg domain.AWSConfig
		if err := json.Unmarshal(req.Config, &cfg); err != nil || cfg.Region == "" || cfg.AccessKey == "" || cfg.SiteID == "" {
			return BadRequest("config must set region, access_key and site_id")
		}
		if _, err := a.svc.Sites.ByID(Context(c), claims.OrganizationID, cfg.SiteID); err != nil {
			return BadRequest("site_id does not exist in this organization")
		}
		if req.Secret == "" {
			if existing, gerr := a.svc.Integrations.Get(Context(c), claims.OrganizationID, kind); gerr != nil || existing.Secret == "" {
				return BadRequest("secret (secret access key) is required")
			}
		}
	}
	integ := &domain.Integration{
		OrgID: claims.OrganizationID, Kind: kind,
		Config: req.Config, Secret: req.Secret, CreatedBy: claims.Subject,
	}
	if err := a.svc.Integrations.Upsert(Context(c), integ); err != nil {
		return Internal("integration save failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "integration.configured", "integration:"+kind, c.IP(), "", "success", nil)
	fresh, _ := a.svc.Integrations.Get(Context(c), claims.OrganizationID, kind)
	return c.JSON(fiber.Map{"configured": fresh != nil, "integration": fresh})
}

// handleAWSSync runs one read-only EC2 DescribeInstances sweep and lands
// the instances as assets in the configured site (F10 first slice).
func (a *App) handleAWSSync(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	integ, err := a.svc.Integrations.Get(Context(c), claims.OrganizationID, domain.IntegrationAWS)
	if err != nil || integ.Secret == "" {
		return Unavailable("aws integration is not configured")
	}
	ctx, cancel := context.WithTimeout(Context(c), 60*time.Second)
	defer cancel()
	created, updated, err := a.svc.Cloud.SyncEC2(ctx, claims.OrganizationID, integ)
	if err != nil {
		a.svc.Log.Warn("aws sync failed", "org", claims.OrganizationID, "err", err)
		return Internal("aws sync failed: " + err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "integration.aws_synced", "integration:aws", c.IP(), "", "success",
		map[string]any{"created": created, "updated": updated})
	return c.JSON(fiber.Map{"created": created, "updated": updated})
}

// handleFindingHandoff pushes one finding to the org's tracker ("create
// issue"), stores the external key on the finding and audits the push.
func (a *App) handleFindingHandoff(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	var req struct {
		Tracker string `json:"tracker"`
	}
	if err := c.BodyParser(&req); err != nil || !domain.ValidIntegrationKind(req.Tracker) {
		return BadRequest("tracker must be github or jira")
	}
	f, err := a.svc.Findings.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("finding not found")
	}
	if f.ExternalKey != "" {
		return BadRequest("finding is already tracked as " + f.ExternalTracker + ":" + f.ExternalKey)
	}
	integ, err := a.svc.Integrations.Get(Context(c), claims.OrganizationID, req.Tracker)
	if err != nil || integ.Secret == "" {
		return Unavailable("tracker " + req.Tracker + " is not configured")
	}
	assetName := ""
	if asset, aerr := a.svc.Assets.ByID(Context(c), claims.OrganizationID, f.AssetID); aerr == nil {
		if asset.NameOverride != nil && *asset.NameOverride != "" {
			assetName = *asset.NameOverride
		} else {
			assetName = asset.Hostname
		}
	}
	issue, err := a.svc.Handoff.Create(Context(c), integ, f, assetName, a.svc.Cfg.PublicURL)
	if err != nil {
		a.svc.Log.Warn("finding handoff failed", "finding", f.ID, "tracker", req.Tracker, "err", err)
		return Internal("tracker create failed: " + err.Error())
	}
	if err := a.svc.Findings.MarkHandoff(Context(c), claims.OrganizationID, f.ID, req.Tracker, issue.Key, issue.URL); err != nil {
		return Internal("handoff mark failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "finding.handoff_created", "finding:"+f.ID, c.IP(), "", "success",
		map[string]any{"tracker": req.Tracker, "key": issue.Key})
	return c.Status(201).JSON(fiber.Map{"tracker": req.Tracker, "key": issue.Key, "url": issue.URL, "state": issue.State})
}

// handleHandoffRefresh pulls the tracker state of a handed-off finding and
// maps done/closed back to the resolved status.
func (a *App) handleHandoffRefresh(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	f, err := a.svc.Findings.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("finding not found")
	}
	if f.ExternalKey == "" || f.ExternalTracker == "" {
		return BadRequest("finding has no tracker handoff to refresh")
	}
	integ, err := a.svc.Integrations.Get(Context(c), claims.OrganizationID, f.ExternalTracker)
	if err != nil || integ.Secret == "" {
		return Unavailable("tracker " + f.ExternalTracker + " is not configured")
	}
	ctx, cancel := context.WithTimeout(Context(c), 20*time.Second)
	defer cancel()
	state, err := a.svc.Handoff.FetchState(ctx, integ, f.ExternalKey)
	if err != nil {
		return Internal("tracker fetch failed: " + err.Error())
	}
	resolved := false
	if handoff.IsClosed(state) && f.Status != domain.FindingResolved && f.Status != domain.FindingSuppressed {
		if serr := a.svc.Findings.SetStatus(Context(c), claims.OrganizationID, f.ID, domain.FindingResolved, claims.Subject, "tracker "+f.ExternalTracker+" issue "+f.ExternalKey+" closed"); serr == nil {
			resolved = true
		}
	}
	_ = a.svc.Findings.MarkHandoffSynced(Context(c), claims.OrganizationID, f.ID)
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "finding.handoff_refreshed", "finding:"+f.ID, c.IP(), "", "success",
		map[string]any{"tracker": f.ExternalTracker, "key": f.ExternalKey, "state": state, "resolved": resolved})
	return c.JSON(fiber.Map{"state": state, "resolved": resolved})
}
