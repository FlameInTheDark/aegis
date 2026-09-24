package httpx

import (
	"strings"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
)

// ---------------------------------------------------------------------------
// Asset groups (v1.13.0)
//
// Analyst-curated grouping of assets ("Room 1", "IoT devices", "PCI scope").
// Groups carry presentation metadata (color/icon keys resolved client-side)
// and a kind that hints at intent. The list endpoint returns membership
// inline — the UI needs every asset row's chips, and one call serves the
// whole client-side group store. All mutations are audited.

var groupKinds = map[domain.AssetGroupKind]bool{
	domain.GroupKindLocation: true,
	domain.GroupKindFunction: true,
	domain.GroupKindOwner:    true,
	domain.GroupKindCustom:   true,
}

// handleListAssetGroups GET /asset-groups → {items: [{...group, asset_ids}]}
func (a *App) handleListAssetGroups(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Groups.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("list asset groups failed")
	}
	if items == nil {
		items = []domain.AssetGroupWithMembers{}
	}
	return c.JSON(fiber.Map{"items": items})
}

// handleCreateAssetGroup POST /asset-groups
func (a *App) handleCreateAssetGroup(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	var req struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Color       string   `json:"color"`
		Icon        string   `json:"icon"`
		Kind        string   `json:"kind"`
		AssetIDs    []string `json:"asset_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return BadRequest("name is required")
	}
	if len(req.Name) > 80 {
		return BadRequest("name is too long (max 80)")
	}
	kind := domain.AssetGroupKind(req.Kind)
	if kind == "" || !groupKinds[kind] {
		kind = domain.GroupKindCustom
	}
	g := &domain.AssetGroup{
		OrgID:       claims.OrganizationID,
		Name:        req.Name,
		Description: strings.TrimSpace(req.Description),
		Color:       sanitizeGroupKey(req.Color),
		Icon:        sanitizeGroupKey(req.Icon),
		Kind:        kind,
	}
	if err := a.svc.Groups.Create(Context(c), g); err != nil {
		if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "SQLSTATE 23505") {
			return BadRequest("a group with this name already exists")
		}
		return Internal("create asset group failed")
	}
	// Optional initial membership: the create dialog lets the analyst tick
	// assets before saving, so a group can be born with its members in one
	// call (the PUT membership endpoint stays available for later edits).
	if len(req.AssetIDs) > 0 {
		if err := a.svc.Groups.AddMembers(Context(c), claims.OrganizationID, g.ID, dedupeIDs(req.AssetIDs)); err != nil {
			return Internal("group membership update failed")
		}
	}
	out, err := a.svc.Groups.ByID(Context(c), claims.OrganizationID, g.ID)
	if err != nil {
		return Internal("asset group reload failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"asset_group.created", "asset_group:"+g.ID, c.IP(), "", "success",
		map[string]any{"name": g.Name, "kind": string(g.Kind), "members": len(out.AssetIDs)})
	return c.Status(201).JSON(fiber.Map{"group": out})
}

// handleUpdateAssetGroup PATCH /asset-groups/:id
func (a *App) handleUpdateAssetGroup(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	var req struct {
		Name        *string   `json:"name"`
		Description *string   `json:"description"`
		Color       *string   `json:"color"`
		Icon        *string   `json:"icon"`
		Kind        *string   `json:"kind"`
		AssetIDs    *[]string `json:"asset_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	fields := map[string]any{}
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n == "" {
			return BadRequest("name cannot be empty")
		}
		if len(n) > 80 {
			return BadRequest("name is too long (max 80)")
		}
		fields["name"] = n
	}
	if req.Description != nil {
		fields["description"] = strings.TrimSpace(*req.Description)
	}
	if req.Color != nil {
		fields["color"] = sanitizeGroupKey(*req.Color)
	}
	if req.Icon != nil {
		fields["icon"] = sanitizeGroupKey(*req.Icon)
	}
	if req.Kind != nil {
		kind := domain.AssetGroupKind(*req.Kind)
		if !groupKinds[kind] {
			return BadRequest("unknown group kind")
		}
		fields["kind"] = kind
	}
	if len(fields) == 0 && req.AssetIDs == nil {
		return BadRequest("nothing to update")
	}
	if len(fields) > 0 {
		if err := a.svc.Groups.Update(Context(c), claims.OrganizationID, c.Params("id"), fields); err != nil {
			if err == pg.ErrNotFound {
				return NotFound("asset group not found")
			}
			if strings.Contains(err.Error(), "duplicate key") || strings.Contains(err.Error(), "SQLSTATE 23505") {
				return BadRequest("a group with this name already exists")
			}
			return Internal("update asset group failed")
		}
	}
	// Membership replace-all when the client sent asset_ids: diff against
	// the current members so only the delta is written (the edit dialog
	// always posts the full desired member list).
	if req.AssetIDs != nil {
		id := c.Params("id")
		cur, gerr := a.svc.Groups.ByID(Context(c), claims.OrganizationID, id)
		if gerr != nil {
			if gerr == pg.ErrNotFound {
				return NotFound("asset group not found")
			}
			return Internal("asset group reload failed")
		}
		add, remove := diffMembers(cur.AssetIDs, dedupeIDs(*req.AssetIDs))
		if err := a.svc.Groups.AddMembers(Context(c), claims.OrganizationID, id, add); err != nil {
			return Internal("group membership update failed")
		}
		if err := a.svc.Groups.RemoveMembers(Context(c), id, remove); err != nil {
			return Internal("group membership update failed")
		}
	}
	g, err := a.svc.Groups.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return Internal("asset group reload failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"asset_group.updated", "asset_group:"+g.ID, c.IP(), "", "success", nil)
	return c.JSON(fiber.Map{"group": g})
}

// handleDeleteAssetGroup DELETE /asset-groups/:id — membership cascades.
func (a *App) handleDeleteAssetGroup(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	id := c.Params("id")
	if err := a.svc.Groups.Delete(Context(c), claims.OrganizationID, id); err != nil {
		if err == pg.ErrNotFound {
			return NotFound("asset group not found")
		}
		return Internal("delete asset group failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"asset_group.deleted", "asset_group:"+id, c.IP(), "", "success", nil)
	return c.JSON(fiber.Map{"deleted": true})
}

// handleSetGroupMembers PUT /asset-groups/:id/assets — {add: [...], remove: [...]}
//
// Ids pointing at assets of another organization are silently skipped by
// the membership insert's org guard: existence leaks nothing and the UI
// only ever offers same-org assets.
func (a *App) handleSetGroupMembers(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAssetWrite); he != nil {
		return he
	}
	id := c.Params("id")
	var req struct {
		Add    []string `json:"add"`
		Remove []string `json:"remove"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	if len(req.Add) == 0 && len(req.Remove) == 0 {
		return BadRequest("no membership changes provided")
	}
	if _, err := a.svc.Groups.ByID(Context(c), claims.OrganizationID, id); err != nil {
		return NotFound("asset group not found")
	}
	if err := a.svc.Groups.AddMembers(Context(c), claims.OrganizationID, id, req.Add); err != nil {
		return Internal("group membership update failed")
	}
	if err := a.svc.Groups.RemoveMembers(Context(c), id, req.Remove); err != nil {
		return Internal("group membership update failed")
	}
	g, err := a.svc.Groups.ByID(Context(c), claims.OrganizationID, id)
	if err != nil {
		return Internal("asset group reload failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"asset_group.members_updated", "asset_group:"+id, c.IP(), "", "success",
		map[string]any{"added": len(req.Add), "removed": len(req.Remove)})
	return c.JSON(fiber.Map{"group": g})
}

// dedupeIDs drops empty and duplicate asset ids, preserving order.
func dedupeIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, v := range ids {
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

// diffMembers splits a desired membership list against the current one
// (order-preserving; backs the PATCH replace-all semantics).
func diffMembers(current, want []string) (add, remove []string) {
	wantSet := make(map[string]bool, len(want))
	curSet := make(map[string]bool, len(current))
	for _, v := range want {
		wantSet[v] = true
	}
	for _, v := range current {
		curSet[v] = true
		if !wantSet[v] {
			remove = append(remove, v)
		}
	}
	for _, v := range want {
		if !curSet[v] {
			add = append(add, v)
		}
	}
	return add, remove
}

// sanitizeGroupKey bounds a color/icon palette key: trimmed, lowercase-ish,
// hard length cap. Unknown keys fall back client-side, so no allowlist here.
func sanitizeGroupKey(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return ""
	}
	if len(s) > 32 {
		return s[:32]
	}
	return s
}
