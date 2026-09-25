package httpx

// HTTP API for tenant-configurable vulnerability search actions and the
// target-bound match workbench. Preview is read-only; applying creates a
// durable, idempotent run (202) processed by the worker.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/FlameInTheDark/aegis/internal/vulnsearch"
)

func (a *App) handleVulnSearchCapabilities(c *fiber.Ctx) error {
	ctx := Context(c)
	return c.JSON(fiber.Map{
		"target_kinds": []string{"software", "service"},
		"fields":       []string{"name", "vendor", "product", "ecosystem", "version", "source"},
		"operators":    []string{"eq", "in", "not_in", "contains", "starts_with"},
		"modes":        []string{domain.VulnActionModeShadow, domain.VulnActionModeAugment, domain.VulnActionModeFallbackOnly},
		"sources": []fiber.Map{
			{"source": domain.VulnSourceCPE, "available": true, "description": "CPE applicability rows from the synchronized NVD/CVE List index"},
			{"source": domain.VulnSourceCVEAffected, "available": true, "description": "CVE List affected-product data"},
			{"source": domain.VulnSourceOSV, "available": a.vulnSourceAvailable(ctx, "osv_records"), "description": "OSV ecosystem advisories (local table)"},
			{"source": domain.VulnSourceOVAL, "available": a.vulnSourceAvailable(ctx, "oval_records"), "description": "Distro OVAL advisories (local table)"},
		},
		"limits": fiber.Map{"target_cap": 500, "values_cap": 50, "conditions_cap": 10},
	})
}

// vulnSourceAvailable reports whether a local source currently holds rows.
func (a *App) vulnSourceAvailable(ctx context.Context, table string) bool {
	// Table names come from a fixed allowlist — never user input.
	if table != "osv_records" && table != "oval_records" {
		return false
	}
	var n int64
	if err := a.svc.DB.Pool.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil {
		return false
	}
	return n > 0
}

func (a *App) handleListSearchActions(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	items, err := a.svc.VulnSearch.ListActions(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("search action list failed")
	}
	return c.JSON(fiber.Map{"items": items, "total": len(items)})
}

func (a *App) handleCreateSearchAction(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	var req struct {
		Name          string          `json:"name"`
		Description   string          `json:"description"`
		TargetKind    string          `json:"target_kind"`
		Selector      json.RawMessage `json:"selector"`
		Mode          string          `json:"mode"`
		Priority      int             `json:"priority"`
		Enabled       bool            `json:"enabled"`
		VersionPolicy json.RawMessage `json:"version_policy"`
		ConfidenceCap float64         `json:"confidence_cap"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return BadRequest("name is required")
	}
	if req.Mode == "" {
		req.Mode = domain.VulnActionModeShadow
	}
	if req.TargetKind == "" {
		req.TargetKind = "software"
	}
	if req.ConfidenceCap == 0 {
		req.ConfidenceCap = 0.8
	}
	if req.Priority == 0 {
		req.Priority = 100
	}
	if len(req.VersionPolicy) == 0 {
		req.VersionPolicy = json.RawMessage(`{"input":"normalized","projection":"auto"}`)
	}
	action := &domain.VulnSearchAction{
		OrgID: claims.OrganizationID, Name: req.Name, Description: req.Description,
		TargetKind: req.TargetKind, Selector: req.Selector, Mode: req.Mode,
		Priority: req.Priority, Enabled: req.Enabled, VersionPolicy: req.VersionPolicy,
		ConfidenceCap: req.ConfidenceCap, CreatedBy: claims.Subject,
	}
	if err := vulnsearch.ValidateAction(action); err != nil {
		return ValidationError(err.Error())
	}
	if err := a.svc.VulnSearch.CreateAction(Context(c), action); err != nil {
		if isUniqueViolation(err) {
			return Conflict("an action with this name already exists")
		}
		return Internal("search action create failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "vuln.action_created", "search-action:"+action.ID, c.IP(), "", "success",
		map[string]any{"mode": action.Mode, "target_kind": action.TargetKind})
	return c.Status(201).JSON(action)
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "duplicate key")
}

func (a *App) handleGetSearchAction(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	action, err := a.svc.VulnSearch.GetAction(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("search action not found")
	}
	runs, _ := a.svc.VulnSearch.ListRuns(Context(c), claims.OrganizationID, action.ID, 10)
	return c.JSON(fiber.Map{"action": action, "runs": runs})
}

func (a *App) handleUpdateSearchAction(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	existing, err := a.svc.VulnSearch.GetAction(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("search action not found")
	}
	var req struct {
		Name          *string         `json:"name"`
		Description   *string         `json:"description"`
		TargetKind    *string         `json:"target_kind"`
		Selector      json.RawMessage `json:"selector"`
		Mode          *string         `json:"mode"`
		Priority      *int            `json:"priority"`
		Enabled       *bool           `json:"enabled"`
		VersionPolicy json.RawMessage `json:"version_policy"`
		ConfidenceCap *float64        `json:"confidence_cap"`
		Revision      int             `json:"revision"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid body")
	}
	if req.Revision != 0 && req.Revision != existing.Revision {
		return Conflict("action was modified by someone else; reload and retry")
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Description != nil {
		existing.Description = *req.Description
	}
	if req.TargetKind != nil {
		existing.TargetKind = *req.TargetKind
	}
	if len(req.Selector) > 0 {
		existing.Selector = req.Selector
	}
	if req.Mode != nil {
		existing.Mode = *req.Mode
	}
	if req.Priority != nil {
		existing.Priority = *req.Priority
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if len(req.VersionPolicy) > 0 {
		existing.VersionPolicy = req.VersionPolicy
	}
	if req.ConfidenceCap != nil {
		existing.ConfidenceCap = *req.ConfidenceCap
	}
	if err := vulnsearch.ValidateAction(existing); err != nil {
		return ValidationError(err.Error())
	}
	if err := a.svc.VulnSearch.UpdateAction(Context(c), existing, existing.Revision); err != nil {
		return Internal("search action update failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "vuln.action_updated", "search-action:"+existing.ID, c.IP(), "", "success",
		map[string]any{"revision": existing.Revision})
	return c.JSON(existing)
}

func (a *App) handleDeleteSearchAction(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	if err := a.svc.VulnSearch.DeleteAction(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("search action not found")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "vuln.action_deleted", "search-action:"+c.Params("id"), c.IP(), "", "success", nil)
	return c.SendStatus(204)
}

// handlePreviewSearchAction evaluates an unsaved or saved action read-only.
func (a *App) handlePreviewSearchAction(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	action, err := a.searchActionFromBody(c, claims.OrganizationID, claims.Subject)
	if err != nil {
		return BadRequest(err.Error())
	}
	if err := vulnsearch.ValidateAction(action); err != nil {
		return ValidationError(err.Error())
	}
	svc := a.searchService()
	res, err := svc.Preview(Context(c), claims.OrganizationID, action)
	if err != nil {
		return Internal("preview failed")
	}
	return c.JSON(res)
}

// handleRunSearchAction creates a durable idempotent run (202) executed by
// the worker.
func (a *App) handleRunSearchAction(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	action, err := a.svc.VulnSearch.GetAction(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("search action not found")
	}
	if !action.Enabled {
		return ValidationError("action is disabled; enable it before running")
	}
	run := &domain.VulnSearchRun{
		OrgID: claims.OrganizationID, ActionID: action.ID, Revision: action.Revision,
		Requester: claims.Subject,
	}
	if err := a.svc.VulnSearch.CreateRun(Context(c), run); err != nil {
		return Internal("run create failed")
	}
	payload, _ := json.Marshal(map[string]string{"action_id": action.ID, "run_id": run.ID})
	if _, err := a.svc.CorrelationJobs.Enqueue(Context(c), claims.OrganizationID, domain.JobSearchActionRun, payload, "search-run:"+run.ID); err != nil {
		return Internal("run enqueue failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "vuln.action_run", "search-action:"+action.ID, c.IP(), "", "success",
		map[string]any{"run_id": run.ID})
	return c.Status(202).JSON(fiber.Map{"run_id": run.ID, "state": "pending"})
}

func (a *App) handleGetSearchRun(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	run, err := a.svc.VulnSearch.GetRun(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("run not found")
	}
	return c.JSON(run)
}

// handleVulnerabilityMatchSearch is the ad-hoc, target-bound workbench
// matcher: evaluates one observed identity against the local indexes and
// explains every result.
func (a *App) handleVulnerabilityMatchSearch(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	var req struct {
		Vendor     string   `json:"vendor"`
		Product    string   `json:"product"`
		Name       string   `json:"name"`
		Version    string   `json:"version"`
		RawVersion string   `json:"raw_version"`
		Ecosystem  string   `json:"ecosystem"`
		CPEs       []string `json:"cpes"`
	}
	if err := c.BodyParser(&req); err != nil || (req.Product == "" && req.Name == "") {
		return BadRequest("product or name is required")
	}
	svc := a.searchService()
	in := vulnsearch.MatchInputOf(req.Vendor, req.Product, req.Name, req.Version, req.RawVersion, req.Ecosystem, req.CPEs)
	matches, truncated, err := svc.Match(Context(c), claims.OrganizationID, in)
	if err != nil {
		return Internal("match search failed")
	}
	return c.JSON(fiber.Map{"matches": matches, "truncated": truncated})
}

// handleAssetVulnDiagnostics is the per-asset workbench: for every
// service/software row it shows the observed identity, the normalized
// version, the effective alias (when one exists), the automatic matches
// (existing findings) and the configured-action result.
func (a *App) handleAssetVulnDiagnostics(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermVulnRead); he != nil {
		return he
	}
	assetID := c.Params("id")
	asset, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, assetID)
	if err != nil || asset == nil {
		return NotFound("asset not found")
	}
	orgID := claims.OrganizationID
	svc := a.searchService()

	svcs, _ := a.svc.Services.ListForAsset(Context(c), assetID)
	sws, _ := a.svc.Software.ListForAsset(Context(c), assetID)
	findings, _ := a.svc.Findings.ListForAsset(Context(c), assetID)

	type diag struct {
		Type         string   `json:"type"`
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Vendor       string   `json:"vendor"`
		Version      string   `json:"version"`
		RawVersion   string   `json:"raw_version,omitempty"`
		Ecosystem    string   `json:"ecosystem,omitempty"`
		AliasApplied string   `json:"alias_applied,omitempty"`
		Findings     []string `json:"findings"`
		Configured   int      `json:"configured_matches"`
	}
	out := make([]diag, 0, len(svcs)+len(sws))
	// Existing findings keyed by target.
	findingTitles := map[string][]string{}
	for _, f := range findings {
		key := f.AssetID
		if f.ServiceID != nil {
			key = *f.ServiceID
		} else if f.SoftwareID != nil {
			key = *f.SoftwareID
		}
		findingTitles[key] = append(findingTitles[key], fmt.Sprintf("%s (%s)", f.CVEID, f.Severity))
	}
	for i := range svcs {
		s := svcs[i]
		name := s.Product
		if name == "" {
			name = s.ServiceName
		}
		d := diag{Type: "service", ID: s.ID, Name: name, Vendor: s.Vendor,
			Version: s.VersionNorm, RawVersion: s.DetectedVersion, Ecosystem: "cpe",
			Findings: findingTitles[s.ID]}
		out = append(out, d)
	}
	for i := range sws {
		sw := sws[i]
		out = append(out, diag{Type: "software", ID: sw.ID, Name: sw.Name, Vendor: sw.Vendor,
			Version: sw.VersionNorm, RawVersion: sw.Version, Ecosystem: sw.Ecosystem,
			Findings: findingTitles[sw.ID]})
	}
	// Configured-action contribution: preview every enabled action once and
	// count matches per target id.
	actions, _ := a.svc.VulnSearch.EnabledActions(Context(c), orgID)
	configured := map[string]int{}
	for _, action := range actions {
		res, err := svc.Preview(Context(c), orgID, action)
		if err != nil {
			continue
		}
		for _, row := range res.Rows {
			configured[row.Target.ID]++
		}
	}
	for i := range out {
		out[i].Configured = configured[out[i].ID]
		if alias, err := a.svc.VulnSearch.AliasFor(Context(c), orgID, out[i].Name, out[i].Vendor, out[i].Name); err == nil {
			out[i].AliasApplied = alias.CanonicalVendor + "/" + alias.CanonicalProduct
		}
	}
	return c.JSON(fiber.Map{
		"asset_id": assetID, "diagnostics": out,
		"enabled_actions": len(actions),
		"sources": fiber.Map{
			"cpe": true, "osv": a.vulnSourceAvailable(Context(c), "osv_records"), "oval": a.vulnSourceAvailable(Context(c), "oval_records"),
		},
	})
}

// searchService builds the vulnsearch executor from the HTTP services.
func (a *App) searchService() *vulnsearch.Service {
	return &vulnsearch.Service{
		DB: a.svc.DB, Actions: a.svc.VulnSearch, Index: a.svc.Vulns,
		Findings: a.svc.Findings, Services: a.svc.Services, Software: a.svc.Software,
	}
}

// searchActionFromBody decodes a draft action (preview endpoint).
func (a *App) searchActionFromBody(c *fiber.Ctx, orgID, user string) (*domain.VulnSearchAction, error) {
	var req struct {
		Name          string          `json:"name"`
		Description   string          `json:"description"`
		TargetKind    string          `json:"target_kind"`
		Selector      json.RawMessage `json:"selector"`
		Mode          string          `json:"mode"`
		Priority      int             `json:"priority"`
		Enabled       bool            `json:"enabled"`
		VersionPolicy json.RawMessage `json:"version_policy"`
		ConfidenceCap float64         `json:"confidence_cap"`
	}
	if err := c.BodyParser(&req); err != nil {
		return nil, fmt.Errorf("invalid body")
	}
	return &domain.VulnSearchAction{
		ID: ids.New(), OrgID: orgID, Name: req.Name, Description: req.Description,
		TargetKind: req.TargetKind, Selector: req.Selector, Mode: req.Mode,
		Priority: req.Priority, Enabled: req.Enabled, VersionPolicy: req.VersionPolicy,
		ConfidenceCap: req.ConfidenceCap, CreatedBy: user,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}, nil
}
