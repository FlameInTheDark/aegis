package httpx

import (
	"encoding/json"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	ch "github.com/FlameInTheDark/aegis/internal/repository/clickhouse"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/telemetry"
	"github.com/gofiber/fiber/v2"
)

// chEventFilter is the ClickHouse event filter type.
type chEventFilter = ch.EventFilter

// ---------------------------------------------------------------------------
// Detections (§40/§41/§61)

func (a *App) handleListRules(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	items, err := a.svc.Rules.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("rule list failed")
	}
	return c.JSON(fiber.Map{"items": items})
}

func (a *App) handleCreateRule(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermDetectionManage); he != nil {
		return he
	}
	var rule domain.DetectionRule
	if err := c.BodyParser(&rule); err != nil {
		return BadRequest("invalid JSON body")
	}
	rule.ID = ids.New()
	rule.OrgID = claims.OrganizationID
	if rule.Identifier == "" {
		rule.Identifier = "custom-" + rule.ID
	}
	if rule.Level == "" {
		rule.Level = domain.SeverityMedium
	}
	if err := a.svc.Rules.Upsert(Context(c), &rule); err != nil {
		return BadRequest("rule validation failed: " + err.Error())
	}
	return c.Status(201).JSON(rule)
}

func (a *App) handleUpdateRule(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermDetectionManage); he != nil {
		return he
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.BodyParser(&req); err != nil || req.Enabled == nil {
		return BadRequest("enabled is required")
	}
	if err := a.svc.Rules.SetEnabled(Context(c), claims.OrganizationID, c.Params("id"), *req.Enabled); err != nil {
		return NotFound("rule not found")
	}
	rule, _ := a.svc.Rules.ByID(Context(c), claims.OrganizationID, c.Params("id"))
	return c.JSON(rule)
}

func (a *App) handleListMatches(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	page, limit := pageParams(c)
	items, total, err := a.svc.Matches.List(Context(c), pg.MatchFilter{
		OrgID: claims.OrganizationID, RuleID: c.Query("rule_id"),
		Level: c.Query("level"), Limit: limit, Page: page,
	})
	if err != nil {
		return Internal("match list failed")
	}
	return c.JSON(fiber.Map{"items": items, "total": total, "page": page, "limit": limit})
}

// ---------------------------------------------------------------------------
// Events (§22/§60)

// handleListEvents is a cursor-paginated event explorer backed by ClickHouse.
func (a *App) handleListEvents(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermEventRead); he != nil {
		return he
	}
	limit := c.QueryInt("limit", 100)
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	f := chFilter(claims.OrganizationID, c)
	if a.svc.CH == nil {
		return Unavailable("events require ClickHouse")
	}
	events, err := a.svc.CH.QueryEvents(Context(c), f)
	if err != nil {
		return Internal("event query failed; is ClickHouse running?")
	}
	nextCursor := ""
	if len(events) == limit {
		last := events[len(events)-1]
		nextCursor = last.Timestamp.UTC().Format(time.RFC3339Nano) + "|" + last.EventID
	}
	return c.JSON(fiber.Map{"items": events, "next_cursor": nextCursor})
}

func chFilter(orgID string, c *fiber.Ctx) (f chEventFilter) {
	f.TenantID = orgID
	f.EventType = c.Query("event_type")
	f.Severity = c.Query("severity")
	f.Source = c.Query("source")
	f.SrcIP = c.Query("src_ip")
	f.DstIP = c.Query("dst_ip")
	f.SiteID = c.Query("site_id")
	f.Port = c.QueryInt("port")
	f.Protocol = c.Query("protocol")
	f.Limit = c.QueryInt("limit", 100)
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if cur := c.Query("cursor"); cur != "" {
		parts := splitCursor(cur)
		if len(parts) == 2 {
			if t, err := time.Parse(time.RFC3339Nano, parts[0]); err == nil {
				f.CursorTS = t
				f.CursorID = parts[1]
			}
		}
	}
	if from := c.Query("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			f.From = t
		}
	} else {
		f.From = time.Now().UTC().Add(-24 * time.Hour)
	}
	if to := c.Query("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			f.To = t
		}
	}
	return f
}

func splitCursor(cur string) []string {
	var out []string
	start := 0
	for i := 0; i < len(cur); i++ {
		if cur[i] == '|' {
			out = append(out, cur[start:i])
			start = i + 1
		}
	}
	out = append(out, cur[start:])
	return out
}

// handleIngestEvent accepts a sensor/agent push with dedup and caps (§104).
func (a *App) handleIngestEvent(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermEventRead); he != nil {
		return he
	}
	var req telemetry.SubjectEvent
	if err := c.BodyParser(&req); err != nil || len(req.Raw) == 0 {
		return BadRequest("source and raw payload are required")
	}
	if req.TenantID == "" || req.TenantID != claims.OrganizationID {
		// Tenant isolation: sensors may only push into their own org (§84).
		req.TenantID = claims.OrganizationID
	}
	accepted, err := a.svc.Ingestor.HTTPIngest(Context(c), req)
	if err != nil {
		return BadRequest(err.Error())
	}
	return c.Status(202).JSON(fiber.Map{"accepted": accepted})
}

// handleSensorIngest is the per-sensor endpoint (same semantics as ingest).
func (a *App) handleSensorIngest(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermEventRead); he != nil {
		return he
	}
	var raw json.RawMessage
	if err := c.BodyParser(&raw); err != nil {
		return BadRequest("JSON payload required")
	}
	req := telemetry.SubjectEvent{
		TenantID: claims.OrganizationID,
		SensorID: c.Params("sensorID"),
		Source:   c.Query("source"),
		Raw:      raw,
	}
	if req.Source == "" {
		req.Source = "suricata"
	}
	accepted, err := a.svc.Ingestor.HTTPIngest(Context(c), req)
	if err != nil {
		return BadRequest(err.Error())
	}
	return c.Status(202).JSON(fiber.Map{"accepted": accepted})
}

var _ = pg.Page{}
