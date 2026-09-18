package httpx

import (
	"context"
	"encoding/json"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// Assets (spec §55)

// handleListAssets lists the org's assets with filters.
func (a *App) handleListAssets(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	page, limit := pageParams(c)
	var hasAgent *bool
	if v := c.Query("has_agent"); v == "true" {
		hasAgent = boolPtr(true)
	} else if v == "false" {
		hasAgent = boolPtr(false)
	}
	f := pg.AssetFilter{
		OrgID:       claims.OrganizationID,
		SiteID:      c.Query("site_id"),
		DeviceType:  c.Query("device_type"),
		OS:          c.Query("os"),
		Search:      c.Query("search"),
		Criticality: c.Query("criticality"),
		HasAgent:    hasAgent,
		Limit:       limit,
		Page:        page,
	}
	if mr := c.QueryFloat("min_risk", -1); mr >= 0 {
		f.MinRisk = mr
	}
	items, total, err := a.svc.Assets.List(Context(c), f)
	if err != nil {
		return Internal("asset list failed")
	}
	return c.JSON(fiber.Map{"items": items, "total": total, "page": page, "limit": limit})
}

// nonNilSlice guarantees an empty JSON array ([]) instead of null for list
// fields. Go nil slices serialize as null, which crashes JS callers that
// read .length — the asset detail UI crashed exactly this way (§137).
func nonNilSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// handleGetAsset returns one asset with its relations.
func (a *App) handleGetAsset(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	asset, err := a.svc.Assets.ByID(ctx, claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	// Best-effort relations: a failure in one section must not 404 the whole
	// asset view, and nil slices must serialize as [] (never null — a null
	// list crashed the UI reading .length).
	ifaces := nonNilSlice(listOrEmpty(a.svc.Ifaces.ListForAsset(ctx, asset.ID)))
	services := nonNilSlice(listOrEmpty(a.svc.Services.ListForAsset(ctx, asset.ID)))
	software := nonNilSlice(listOrEmpty(a.svc.Software.ListForAsset(ctx, asset.ID)))
	findings := nonNilSlice(listOrEmpty(a.svc.Findings.ListForAsset(ctx, asset.ID)))
	open, crit, high, med, low := 0, 0, 0, 0, 0
	for _, f := range findings {
		if f.Status == domain.FindingOpen || f.Status == domain.FindingAcknowledged || f.Status == domain.FindingInProgress {
			open++
		}
		switch f.Severity {
		case domain.SeverityCritical:
			crit++
		case domain.SeverityHigh:
			high++
		case domain.SeverityMedium:
			med++
		case domain.SeverityLow:
			low++
		}
	}
	return c.JSON(fiber.Map{
		"asset": asset, "interfaces": ifaces, "services": services, "software": software,
		"findings_count": fiber.Map{"open": open, "critical": crit, "high": high, "medium": med, "low": low},
	})
}

// listOrEmpty converts a (items, err) repo pair into items, swapping errors
// for empty results — relation sections are best-effort (§94).
func listOrEmpty[T any](items []T, err error) []T {
	if err != nil {
		return []T{}
	}
	return items
}

// handleUpdateAsset updates analyst-controlled fields (§94/§95).
func (a *App) handleUpdateAsset(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	var fields map[string]any
	if err := c.BodyParser(&fields); err != nil {
		return BadRequest("invalid JSON body")
	}
	allowed := map[string]bool{"criticality": true, "exposure": true, "tags": true, "owner": true, "notes": true}
	for k := range fields {
		if !allowed[k] {
			delete(fields, k)
		}
	}
	if len(fields) == 0 {
		return BadRequest("no updatable fields provided")
	}
	if err := a.svc.Assets.Update(Context(c), c.Params("id"), fields); err != nil {
		return NotFound("asset not found or update failed")
	}
	asset, _ := a.svc.Assets.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	return c.JSON(asset)
}

func (a *App) handleAssetServices(c *fiber.Ctx) error {
	items, err := a.svc.Services.ListForAsset(Context(c), c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	// nil slices serialize as JSON null; JS callers read .length on it.
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

func (a *App) handleAssetSoftware(c *fiber.Ctx) error {
	items, err := a.svc.Software.ListForAsset(Context(c), c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

func (a *App) handleAssetFindings(c *fiber.Ctx) error {
	items, err := a.svc.Findings.ListForAsset(Context(c), c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

// handleRediscoverAsset re-runs vulnerability matching for everything
// already discovered on this asset (services + software inventory) against
// the current CVE index — the "Rediscover" button. Use case: a feed sync
// pulled in new CVEs after the last scan, so previously discovered software
// was never matched against them. No network scan is involved; only the
// correlation pipeline re-runs, and existing findings are refreshed
// (last_seen bumped) rather than duplicated.
func (a *App) handleRediscoverAsset(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermFindingWrite); he != nil {
		return he
	}
	if a.svc.Correlator == nil {
		return Unavailable("correlator unavailable")
	}
	assetID := c.Params("id")
	if _, err := a.svc.Assets.ByID(Context(c), claims.OrganizationID, assetID); err != nil {
		return NotFound("asset not found")
	}
	// Asset-scoped sweep is bounded (a handful of services/software rows),
	// so it runs synchronously and reports real counts instead of a vague 202.
	ctx, cancel := context.WithTimeout(Context(c), 2*time.Minute)
	defer cancel()
	n, err := a.svc.Correlator.SweepAsset(ctx, claims.OrganizationID, assetID)
	if err != nil {
		a.svc.Log.Warn("asset rediscover failed", "asset", assetID, "err", err)
		return Internal("rediscover failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "asset.rediscover", "asset:"+assetID, c.IP(), "", "success",
		map[string]any{"findings_created": n})
	return c.JSON(fiber.Map{"findings_created": n, "detail": "matching refreshed against the current CVE index"})
}

func (a *App) handleAssetInterfaces(c *fiber.Ctx) error {
	items, err := a.svc.Ifaces.ListForAsset(Context(c), c.Params("id"))
	if err != nil {
		return NotFound("asset not found")
	}
	return c.JSON(fiber.Map{"items": nonNilSlice(items)})
}

// handleListServices lists observed services org-wide (§58).
func (a *App) handleListServices(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	page, limit := pageParams(c)
	f := pg.ServiceFilter{
		OrgID:    claims.OrganizationID,
		Product:  c.Query("product"),
		Port:     c.QueryInt("port"),
		Protocol: c.Query("protocol"),
		Search:   c.Query("search"),
		Limit:    limit,
		Page:     page,
	}
	items, total, err := a.svc.Services.List(Context(c), f)
	if err != nil {
		return Internal("service list failed")
	}
	return c.JSON(fiber.Map{"items": items, "total": total, "page": page, "limit": limit})
}

// ---------------------------------------------------------------------------
// Topology (§24/§56)

func (a *App) handleTopology(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	siteID := c.Query("site_id")
	// Empty = org-wide view (UI default before a site is selected); a
	// non-empty value must be a real UUID or the DB would reject the query.
	if siteID != "" && uuid.Validate(siteID) != nil {
		return BadRequest("site_id must be a UUID")
	}
	nodes, edges, err := a.svc.Topology.Graph(Context(c), claims.OrganizationID, siteID)
	if err != nil {
		return Internal("topology query failed")
	}
	// TopologyNode carries its reference as ref_id; the UI reads asset_id
	// for asset-kind nodes (graph ring styling + click-through to the
	// asset detail page). Emit both so clients keep working: the embedded
	// struct flattens in JSON, the alias carries the asset reference.
	out := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		m, err := structToMap(n)
		if err != nil {
			continue
		}
		if n.Kind == domain.NodeAsset && n.RefID != "" {
			m["asset_id"] = n.RefID
		}
		out = append(out, m)
	}
	return c.JSON(fiber.Map{"nodes": out, "edges": nonNilSlice(edges)})
}

// structToMap marshals a value and unmarshals it back into a generic map —
// used to append computed fields to API rows without re-declaring every
// column. Marshaling cannot fail for domain structs (plain JSON types).
func structToMap(v any) (map[string]any, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	m := make(map[string]any, 16)
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (a *App) handleTopologyEvidence(c *fiber.Ctx) error {
	items, err := a.svc.Topology.EvidenceForEdge(Context(c), c.Params("edgeID"))
	if err != nil {
		return NotFound("edge not found")
	}
	return c.JSON(fiber.Map{"items": items})
}
