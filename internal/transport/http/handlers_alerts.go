package httpx

// HTTP API for the alert-trigger engine: capabilities, occurrences,
// trigger CRUD + preview/test, destinations with delivery health, and the
// engine health summary. Every route is organization-scoped by the JWT
// claims; foreign ids are clean 404s (plan §7.1).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/gofiber/fiber/v2"

	"github.com/FlameInTheDark/aegis/internal/alerting"
	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// ValidationError builds a 422 with the message in the standard shape.
func ValidationError(msg string) *HTTPError {
	return NewHTTPError(422, "VALIDATION", msg)
}

// --- capabilities -----------------------------------------------------------

func (a *App) handleAlertCapabilities(c *fiber.Ctx) error {
	return c.JSON(alerting.Catalog())
}

// --- occurrences --------------------------------------------------------------

func (a *App) handleListAlerts(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertRead); he != nil {
		return he
	}
	pq := ParsePageQuery(c)
	items, total, err := a.svc.Alerts.List(Context(c), claims.OrganizationID, pg.OccurrenceListFilter{
		State:     c.Query("state", "active"),
		Severity:  c.Query("severity"),
		TriggerID: c.Query("trigger_id"),
		SiteID:    c.Query("site_id"),
		AssetID:   c.Query("asset_id"),
		Search:    c.Query("q"),
		Limit:     pq.Limit, Page: pq.Page,
	})
	if err != nil {
		return Internal("alert list failed")
	}
	return c.JSON(NewPage[any](occurrencesToAny(items), int64(total), pq))
}

func occurrencesToAny(items []*domain.Occurrence) []any {
	out := make([]any, 0, len(items))
	for _, o := range items {
		out = append(out, o)
	}
	return out
}

func (a *App) handleGetAlert(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertRead); he != nil {
		return he
	}
	occ, err := a.svc.Alerts.Get(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("alert not found")
	}
	transitions, _ := a.svc.Alerts.Transitions(Context(c), claims.OrganizationID, occ.ID)
	deliveries, _ := a.svc.Alerts.DeliveriesFor(Context(c), claims.OrganizationID, occ.ID)
	return c.JSON(fiber.Map{"occurrence": occ, "transitions": transitions, "deliveries": deliveries})
}

func (a *App) handleAckAlert(c *fiber.Ctx) error {
	return a.occurrenceTransition(c, domain.OccurrenceAcknowledged)
}

func (a *App) handleResolveAlert(c *fiber.Ctx) error {
	return a.occurrenceTransition(c, domain.OccurrenceRecovered)
}

func (a *App) occurrenceTransition(c *fiber.Ctx, toState string) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = c.BodyParser(&req)
	occ, err := a.svc.Alerts.SetOccurrenceState(Context(c), claims.OrganizationID, c.Params("id"), toState,
		claims.Subject, req.Reason, RequestIDFromCtx(c))
	if err != nil {
		return NotFound("alert not found or transition failed")
	}
	action := "alert.acknowledged"
	if toState == domain.OccurrenceRecovered {
		action = "alert.resolved"
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, action, "alert:"+occ.ID, c.IP(), "", "success",
		map[string]any{"reason": req.Reason})
	return c.JSON(occ)
}

// --- triggers -----------------------------------------------------------------

// validateTrigger enforces the server-side contract the editor must live
// with: bounded enums, valid condition DSL, resolvable destinations.
func (a *App) validateTrigger(ctx context.Context, orgID string, t *domain.Trigger) error {
	if t.Name == "" || len(t.Name) > 120 {
		return fmt.Errorf("name must be 1-120 characters")
	}
	if len(t.Description) > 2000 {
		return fmt.Errorf("description must be at most 2000 characters")
	}
	switch t.Kind {
	case domain.TriggerKindEvent:
		if len(t.EventTypes) == 0 {
			return fmt.Errorf("at least one event type is required")
		}
		catalog := alerting.Catalog()
		known := map[string]bool{}
		for _, e := range catalog.EventTypes {
			known[e.Type] = true
		}
		for _, et := range append(append([]string{}, t.EventTypes...), t.RecoveryEventTypes...) {
			if !known[et] {
				return fmt.Errorf("unknown event type %q", et)
			}
		}
		if len(t.Conditions) > 0 {
			var cond alerting.Condition
			if err := json.Unmarshal(t.Conditions, &cond); err != nil {
				return fmt.Errorf("conditions: invalid JSON")
			}
			if err := cond.Validate(0); err != nil {
				return err
			}
		}
	case domain.TriggerKindMetric:
		knownField := false
		for _, f := range alerting.MetricFields {
			if f == t.MetricField {
				knownField = true
				break
			}
		}
		if !knownField {
			return fmt.Errorf("unknown metric field %q", t.MetricField)
		}
		knownAgg := false
		for _, ag := range alerting.Aggregations {
			if ag == t.Aggregation {
				knownAgg = true
				break
			}
		}
		if !knownAgg {
			return fmt.Errorf("unknown aggregation %q", t.Aggregation)
		}
		if t.Operator != "gt" && t.Operator != "gte" && t.Operator != "lt" && t.Operator != "lte" {
			return fmt.Errorf("metric operator must be gt, gte, lt or lte")
		}
		if t.WindowSecs < 60 || t.WindowSecs > 24*3600 {
			return fmt.Errorf("window must be between 60s and 24h")
		}
		switch t.MissingDataPolicy {
		case domain.MissingDataIgnore, domain.MissingDataTrigger, domain.MissingDataResolve:
		default:
			return fmt.Errorf("unknown missing-data policy %q", t.MissingDataPolicy)
		}
		switch t.GroupBy {
		case "", "asset":
		default:
			return fmt.Errorf("unsupported group_by %q", t.GroupBy)
		}
	default:
		return fmt.Errorf("unknown trigger kind %q", t.Kind)
	}
	switch t.Severity {
	case string(domain.SeverityInfo), string(domain.SeverityLow), string(domain.SeverityMedium),
		string(domain.SeverityHigh), string(domain.SeverityCritical):
	default:
		return fmt.Errorf("unknown severity %q", t.Severity)
	}
	switch t.Lifecycle {
	case "", domain.TriggerLifecycleStable, domain.TriggerLifecycleExperimental, domain.TriggerLifecycleDeprecated:
	default:
		return fmt.Errorf("unknown lifecycle %q", t.Lifecycle)
	}
	if t.CooldownSecs < 0 || t.CooldownSecs > 7*24*3600 {
		return fmt.Errorf("cooldown must be between 0s and 7d")
	}
	if t.RepeatSecs < 0 || t.RepeatSecs > 7*24*3600 {
		return fmt.Errorf("repeat must be between 0s and 7d")
	}
	if t.ActivationSecs < 0 || t.ActivationSecs > 24*3600 {
		return fmt.Errorf("activation must be between 0s and 24h")
	}
	if t.RecoverySecs < 0 || t.RecoverySecs > 24*3600 {
		return fmt.Errorf("recovery must be between 0s and 24h")
	}
	// Destinations must exist in the same organization.
	for _, id := range t.DestinationIDs {
		if _, err := a.svc.AlertDestinations.Get(ctx, orgID, id); err != nil {
			return fmt.Errorf("unknown destination %q", id)
		}
	}
	return nil
}

func (a *App) handleListTriggers(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertRead); he != nil {
		return he
	}
	pq := ParsePageQuery(c)
	f := pg.TriggerListFilter{Kind: c.Query("kind"), Severity: c.Query("severity"),
		Search: c.Query("q"), Limit: pq.Limit, Page: pq.Page}
	if c.Query("enabled") == "true" || c.Query("enabled") == "false" {
		v := c.Query("enabled") == "true"
		f.Enabled = &v
	}
	items, total, err := a.svc.AlertTriggers.List(Context(c), claims.OrganizationID, f)
	if err != nil {
		return Internal("trigger list failed")
	}
	firing, _ := a.svc.AlertTriggers.FiringCounts(Context(c), claims.OrganizationID)
	out := make([]any, 0, len(items))
	for _, t := range items {
		out = append(out, fiber.Map{
			"trigger": t, "firing": firing[t.ID],
		})
	}
	return c.JSON(NewPage[any](out, int64(total), pq))
}

func (a *App) handleCreateTrigger(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	t, err := triggerFromBody(c)
	if err != nil {
		return BadRequest(err.Error())
	}
	t.OrgID = claims.OrganizationID
	t.CreatedBy = claims.Subject
	t.Enabled = reqBool(c, "enabled", false)
	if err := a.validateTrigger(Context(c), claims.OrganizationID, t); err != nil {
		return ValidationError(err.Error())
	}
	if err := a.svc.AlertTriggers.Create(Context(c), t); err != nil {
		return Internal("trigger create failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.trigger_created", "trigger:"+t.ID, c.IP(), "", "success", nil)
	return c.Status(201).JSON(t)
}

func (a *App) handleGetTrigger(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertRead); he != nil {
		return he
	}
	t, err := a.svc.AlertTriggers.Get(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("trigger not found")
	}
	return c.JSON(t)
}

func (a *App) handleUpdateTrigger(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	existing, err := a.svc.AlertTriggers.Get(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("trigger not found")
	}
	body, err := triggerFromBody(c)
	if err != nil {
		return BadRequest(err.Error())
	}
	body.OrgID = claims.OrganizationID
	body.ID = existing.ID
	body.Enabled = reqBool(c, "enabled", existing.Enabled)
	if err := a.validateTrigger(Context(c), claims.OrganizationID, body); err != nil {
		return ValidationError(err.Error())
	}
	if err := a.svc.AlertTriggers.Update(Context(c), body, existing.Revision); err != nil {
		if err == pg.ErrConflict {
			return Conflict("trigger was modified by someone else; reload and retry")
		}
		return Internal("trigger update failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.trigger_updated", "trigger:"+existing.ID, c.IP(), "", "success",
		map[string]any{"revision": body.Revision})
	return c.JSON(body)
}

func (a *App) handleToggleTrigger(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("enabled is required")
	}
	if err := a.svc.AlertTriggers.SetEnabled(Context(c), claims.OrganizationID, c.Params("id"), req.Enabled); err != nil {
		return NotFound("trigger not found")
	}
	action := "alert.trigger_disabled"
	if req.Enabled {
		action = "alert.trigger_enabled"
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, action, "trigger:"+c.Params("id"), c.IP(), "", "success", nil)
	return c.JSON(fiber.Map{"enabled": req.Enabled})
}

func (a *App) handleDeleteTrigger(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	if err := a.svc.AlertTriggers.Delete(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("trigger not found")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.trigger_deleted", "trigger:"+c.Params("id"), c.IP(), "", "success", nil)
	return c.SendStatus(204)
}

// handlePreviewTrigger validates an unsaved draft and returns the compiled
// human-readable summary + scope facts. Read-only, no side effects.
func (a *App) handlePreviewTrigger(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	t, err := triggerFromBody(c)
	if err != nil {
		return BadRequest(err.Error())
	}
	t.OrgID = claims.OrganizationID
	resp := fiber.Map{}
	if verr := a.validateTrigger(Context(c), claims.OrganizationID, t); verr != nil {
		resp["valid"] = false
		resp["error"] = verr.Error()
		return c.JSON(resp)
	}
	resp["valid"] = true
	resp["summary"] = compileTriggerSummary(t)
	// Scope facts: destination count; for metric triggers also the live
	// sample overview (bounded, no state touched).
	destCount := len(t.DestinationIDs)
	resp["scope"] = fiber.Map{
		"sites":        len(t.Scope.SiteIDs),
		"assets":       len(t.Scope.AssetIDs),
		"destinations": destCount,
	}
	if t.Kind == domain.TriggerKindMetric && a.svc.CH != nil {
		aggs, err := a.svc.CH.WindowMetricAggregates(Context(c), claims.OrganizationID, t.MetricField, t.Aggregation,
			time.Duration(t.WindowSecs)*time.Second)
		if err != nil {
			resp["metric_sample"] = fiber.Map{"available": false, "error": "clickhouse unavailable"}
		} else {
			matched := 0
			for _, agg := range aggs {
				if alerting.TestMetricSample(t, agg.Value, agg.Samples) == "fire" ||
					alerting.TestMetricSample(t, agg.Value, agg.Samples) == "arm" {
					matched++
				}
			}
			if len(aggs) > 20 {
				aggs = aggs[:20]
			}
			resp["metric_sample"] = fiber.Map{
				"available": true, "assets_evaluated": len(aggs), "matched": matched, "samples": aggs,
			}
		}
	}
	return c.JSON(resp)
}

// handleTestTrigger evaluates a bounded recent sample without creating
// occurrences or deliveries. Event triggers replay recent outbox events
// through their conditions; metric triggers run one window query.
func (a *App) handleTestTrigger(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	t, err := a.svc.AlertTriggers.Get(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("trigger not found")
	}
	out := fiber.Map{"trigger_id": t.ID}
	switch t.Kind {
	case domain.TriggerKindMetric:
		if a.svc.CH == nil {
			out["status"] = "source_unavailable"
			return c.JSON(out)
		}
		aggs, err := a.svc.CH.WindowMetricAggregates(Context(c), claims.OrganizationID, t.MetricField, t.Aggregation,
			time.Duration(t.WindowSecs)*time.Second)
		if err != nil {
			out["status"] = "source_unavailable"
			out["error"] = err.Error()
			return c.JSON(out)
		}
		matched := 0
		type sample struct {
			AssetID string  `json:"asset_id"`
			Value   float64 `json:"value"`
			Result  string  `json:"result"`
		}
		samples := make([]sample, 0, 20)
		for _, agg := range aggs {
			if len(t.Scope.AssetIDs) > 0 && !triggerScopeHas(t.Scope.AssetIDs, agg.AssetID) {
				continue
			}
			res := alerting.TestMetricSample(t, agg.Value, agg.Samples)
			if res == "fire" || res == "arm" {
				matched++
			}
			if len(samples) < 20 {
				samples = append(samples, sample{AssetID: agg.AssetID, Value: agg.Value, Result: res})
			}
		}
		out["status"] = "ok"
		out["evaluated"] = len(aggs)
		out["matched"] = matched
		out["samples"] = samples
	default:
		evs, err := a.svc.Outbox.ListRecent(Context(c), claims.OrganizationID, t.EventTypes, 100)
		if err != nil {
			out["status"] = "source_unavailable"
			out["error"] = err.Error()
			return c.JSON(out)
		}
		if len(evs) == 0 {
			out["status"] = "no_sample"
			return c.JSON(out)
		}
		var cond alerting.Condition
		hasCond := len(t.Conditions) > 0
		if hasCond {
			if err := json.Unmarshal(t.Conditions, &cond); err != nil {
				out["status"] = "error"
				out["error"] = err.Error()
				return c.JSON(out)
			}
		}
		matched := 0
		type evSample struct {
			Type    string `json:"type"`
			ID      string `json:"id"`
			Matched bool   `json:"matched"`
		}
		samples := make([]evSample, 0, 20)
		for _, ev := range evs {
			data := map[string]any{"type": ev.Type, "source": ev.SubjectType}
			var m map[string]any
			if len(ev.Payload) > 0 {
				_ = json.Unmarshal(ev.Payload, &m)
				for k, v := range m {
					data[k] = v
				}
			}
			ok := true
			if hasCond {
				ok = cond.Evaluate(data)
			}
			if ok {
				matched++
			}
			if len(samples) < 20 {
				samples = append(samples, evSample{Type: ev.Type, ID: ev.ID, Matched: ok})
			}
		}
		out["status"] = "ok"
		out["evaluated"] = len(evs)
		out["matched"] = matched
		out["samples"] = samples
	}
	return c.JSON(out)
}

func triggerScopeHas(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// compileTriggerSummary renders the plan's "fire when ..." sentence.
func compileTriggerSummary(t *domain.Trigger) string {
	switch t.Kind {
	case domain.TriggerKindMetric:
		s := fmt.Sprintf("Fire when a device's %s %s is %s %.0f", t.Aggregation, t.MetricField, humanizeOp(t.Operator), t.Threshold)
		s += fmt.Sprintf(" over a %s window", humanizeDuration(t.WindowSecs))
		if t.ActivationSecs > 0 {
			s += fmt.Sprintf(", sustained for at least %s", humanizeDuration(t.ActivationSecs))
		}
		if t.RecoveryThreshold != nil {
			s += fmt.Sprintf("; recover when the value crosses %v for %s", *t.RecoveryThreshold, humanizeDuration(maxOf(t.RecoverySecs, 60)))
		} else if t.RecoverySecs > 0 {
			s += fmt.Sprintf("; recover after staying below the threshold for %s", humanizeDuration(t.RecoverySecs))
		}
		return s
	default:
		s := "Fire on " + joinAnd(t.EventTypes)
		if len(t.Conditions) > 0 {
			var cond alerting.Condition
			if err := json.Unmarshal(t.Conditions, &cond); err == nil {
				if cs := cond.CompileSummary(); cs != "" && cs != "()" {
					s += " when " + cs
				}
			}
		}
		if len(t.RecoveryEventTypes) > 0 {
			s += "; recover on " + joinAnd(t.RecoveryEventTypes)
		}
		return s
	}
}

func humanizeOp(op string) string {
	switch op {
	case "gt":
		return "above"
	case "gte":
		return "at or above"
	case "lt":
		return "below"
	case "lte":
		return "at or below"
	}
	return op
}

func humanizeDuration(secs int) string {
	switch {
	case secs >= 3600 && secs%3600 == 0:
		return fmt.Sprintf("%dh", secs/3600)
	case secs >= 60 && secs%60 == 0:
		return fmt.Sprintf("%dm", secs/60)
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

func maxOf(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func joinAnd(xs []string) string {
	out := ""
	for i, x := range xs {
		if i > 0 {
			out += ", "
		}
		out += x
	}
	return out
}

// --- destinations ---------------------------------------------------------------

func (a *App) handleListDestinations(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertRead); he != nil {
		return he
	}
	items, err := a.svc.AlertDestinations.List(Context(c), claims.OrganizationID)
	if err != nil {
		return Internal("destination list failed")
	}
	stats, _ := a.svc.Alerts.DeliveryStats(Context(c), claims.OrganizationID)
	out := make([]any, 0, len(items))
	for _, d := range items {
		out = append(out, fiber.Map{"destination": d, "deliveries": stats[d.ID]})
	}
	return c.JSON(fiber.Map{"items": out, "total": len(items)})
}

func (a *App) handleCreateDestination(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	var req struct {
		Name        string   `json:"name"`
		Kind        string   `json:"kind"`
		URL         string   `json:"url"`
		Events      []string `json:"events"`
		MinSeverity string   `json:"min_severity"`
		Enabled     bool     `json:"enabled"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return BadRequest("name is required")
	}
	kind := req.Kind
	if kind == "" {
		kind = domain.DestinationWebhook
	}
	if kind != domain.DestinationWebhook && kind != domain.DestinationInApp {
		return BadRequest("kind must be webhook or in_app")
	}
	if kind == domain.DestinationWebhook {
		if _, err := alerting.SafeWebhookURL(req.URL, false); err != nil {
			return ValidationError("invalid webhook url: " + err.Error())
		}
	}
	for _, e := range req.Events {
		if e != domain.DeliveryFired && e != domain.DeliveryRecovered && e != domain.DeliveryRepeat {
			return BadRequest("events may only contain fired, recovered, repeat")
		}
	}
	minSev := req.MinSeverity
	if minSev == "" {
		minSev = string(domain.SeverityLow)
	}
	d := &domain.Destination{
		OrgID: claims.OrganizationID, Kind: kind, Name: req.Name, URL: req.URL,
		Secret: newDestinationSecret(), Events: req.Events, MinSeverity: minSev,
		Enabled: req.Enabled, CreatedBy: claims.Subject,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	}
	if err := a.svc.AlertDestinations.Create(Context(c), d); err != nil {
		return Internal("destination create failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.destination_created", "destination:"+d.ID, c.IP(), "", "success",
		map[string]any{"kind": d.Kind, "url_host": hostOf(d.URL)})
	d.CreatedAt, d.UpdatedAt = time.Now().UTC(), time.Now().UTC()
	fresh, _ := a.svc.AlertDestinations.Get(Context(c), claims.OrganizationID, d.ID)
	if fresh == nil {
		fresh = d
	}
	return c.Status(201).JSON(fresh)
}

// newDestinationSecret issues the HMAC signing key for webhook deliveries.
func newDestinationSecret() string {
	if s, err := auth.GenerateToken("whsec"); err == nil {
		return s
	}
	return "whsec_" + ids.New()
}

func hostOf(raw string) string {
	if u, err := urlParse(raw); err == nil {
		return u.Host
	}
	return ""
}

func (a *App) handleUpdateDestination(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	existing, err := a.svc.AlertDestinations.Get(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("destination not found")
	}
	var req struct {
		Name        *string   `json:"name"`
		URL         *string   `json:"url"`
		Events      *[]string `json:"events"`
		MinSeverity *string   `json:"min_severity"`
		Enabled     *bool     `json:"enabled"`
		Secret      *string   `json:"secret"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid body")
	}
	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.URL != nil {
		if _, err := alerting.SafeWebhookURL(*req.URL, false); err != nil && existing.Kind == domain.DestinationWebhook {
			return ValidationError("invalid webhook url: " + err.Error())
		}
		existing.URL = *req.URL
	}
	if req.Events != nil {
		for _, e := range *req.Events {
			if e != domain.DeliveryFired && e != domain.DeliveryRecovered && e != domain.DeliveryRepeat {
				return BadRequest("events may only contain fired, recovered, repeat")
			}
		}
		existing.Events = *req.Events
	}
	if req.MinSeverity != nil && *req.MinSeverity != "" {
		existing.MinSeverity = *req.MinSeverity
	}
	if req.Enabled != nil {
		existing.Enabled = *req.Enabled
	}
	if req.Secret != nil && *req.Secret != "" {
		existing.Secret = *req.Secret // explicit rotation
	}
	if err := a.svc.AlertDestinations.Update(Context(c), existing); err != nil {
		return Internal("destination update failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.destination_updated", "destination:"+existing.ID, c.IP(), "", "success", nil)
	fresh, _ := a.svc.AlertDestinations.Get(Context(c), claims.OrganizationID, existing.ID)
	return c.JSON(fresh)
}

func (a *App) handleDeleteDestination(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	if err := a.svc.AlertDestinations.Delete(Context(c), claims.OrganizationID, c.Params("id")); err != nil {
		return NotFound("destination not found")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.destination_deleted", "destination:"+c.Params("id"), c.IP(), "", "success", nil)
	return c.SendStatus(204)
}

// handleTestDestination enqueues a signed synthetic delivery; the delivery
// worker performs the real send and the UI can watch the attempts.
func (a *App) handleTestDestination(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	d, err := a.svc.AlertDestinations.Get(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("destination not found")
	}
	payload, _ := json.Marshal(map[string]any{
		"schema_version": 1,
		"kind":           "test",
		"sent_at":        time.Now().UTC(),
		"trigger":        map[string]any{"id": "", "name": "Aegis test notification", "kind": "test", "severity": string(domain.SeverityInfo)},
		"occurrence": map[string]any{
			"id": "", "state": "test", "severity": string(domain.SeverityInfo),
			"title":            "Aegis test notification",
			"summary":          "This is a synthetic delivery triggered from the Aegis console. If you can read this, the destination works.",
			"occurrence_count": 1, "opened_at": time.Now().UTC(),
			"snapshot": map[string]any{"synthetic": true},
			"evidence": []any{},
		},
	})
	// Synthetic rows use a zero occurrence id by convention (kind=test).
	testOccID := "00000000-0000-0000-0000-000000000000"
	delim := ":"
	_ = delim
	id := ids.New()
	_, derr := a.svc.DB.Pool.Exec(Context(c),
		`INSERT INTO alert_deliveries (id, organization_id, occurrence_id, destination_id, kind, status, idempotency_key, payload, created_at)
		 VALUES ($1,$2,$3,$4,'test','pending',$5,$6,now())`,
		id, claims.OrganizationID, testOccID, d.ID, "test:"+id, payload)
	if derr != nil {
		return Internal("test delivery enqueue failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.destination_tested", "destination:"+d.ID, c.IP(), "", "success", nil)
	return c.Status(202).JSON(fiber.Map{"delivery_id": id, "status": "pending"})
}

// handleReplayDeadDeliveries requeues dead deliveries of one destination.
func (a *App) handleReplayDeadDeliveries(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertManage); he != nil {
		return he
	}
	n, err := alerting.ReplayDead(Context(c), a.svc.DB, claims.OrganizationID, c.Params("id"))
	if err != nil {
		return Internal("replay failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "alert.deliveries_replayed", "destination:"+c.Params("id"), c.IP(), "", "success",
		map[string]any{"count": n})
	return c.JSON(fiber.Map{"replayed": n})
}

// --- health ----------------------------------------------------------------------

func (a *App) handleAlertsHealth(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAlertRead); he != nil {
		return he
	}
	backlog, oldestMin, _ := a.svc.Outbox.CountUnpublished(Context(c))
	dead, _ := a.svc.Alerts.DeadCount(Context(c), claims.OrganizationID)
	active, _, _ := a.svc.Alerts.List(Context(c), claims.OrganizationID, pg.OccurrenceListFilter{State: "active", Limit: 1})
	return c.JSON(fiber.Map{
		"outbox_backlog":     backlog,
		"outbox_oldest_min":  oldestMin,
		"dead_deliveries":    dead,
		"active_occurrences": active,
		"evaluator":          "worker",
	})
}

// --- local helpers ------------------------------------------------------------

// triggerFromBody decodes the editor draft into a domain.Trigger.
func triggerFromBody(c *fiber.Ctx) (*domain.Trigger, error) {
	var req struct {
		Name               string              `json:"name"`
		Description        string              `json:"description"`
		Kind               string              `json:"kind"`
		Enabled            bool                `json:"enabled"`
		Lifecycle          string              `json:"lifecycle"`
		Severity           string              `json:"severity"`
		Scope              domain.TriggerScope `json:"scope"`
		Conditions         json.RawMessage     `json:"conditions"`
		EventTypes         []string            `json:"event_types"`
		RecoveryEventTypes []string            `json:"recovery_event_types"`
		MetricField        string              `json:"metric_field"`
		Aggregation        string              `json:"aggregation"`
		Operator           string              `json:"operator"`
		Threshold          float64             `json:"threshold"`
		WindowSecs         int                 `json:"window_secs"`
		GroupBy            string              `json:"group_by"`
		ActivationSecs     int                 `json:"activation_secs"`
		RecoverySecs       int                 `json:"recovery_secs"`
		RecoveryThreshold  *float64            `json:"recovery_threshold"`
		MissingDataPolicy  string              `json:"missing_data_policy"`
		CooldownSecs       int                 `json:"cooldown_secs"`
		RepeatSecs         int                 `json:"repeat_secs"`
		DestinationIDs     []string            `json:"destination_ids"`
	}
	if err := c.BodyParser(&req); err != nil {
		return nil, fmt.Errorf("invalid body")
	}
	t := &domain.Trigger{
		Name: req.Name, Description: req.Description, Kind: req.Kind, Enabled: req.Enabled,
		Lifecycle: req.Lifecycle, Severity: req.Severity, Scope: req.Scope, Conditions: req.Conditions,
		EventTypes: req.EventTypes, RecoveryEventTypes: req.RecoveryEventTypes,
		MetricField: req.MetricField, Aggregation: req.Aggregation, Operator: req.Operator,
		Threshold: req.Threshold, WindowSecs: req.WindowSecs, GroupBy: req.GroupBy,
		ActivationSecs: req.ActivationSecs, RecoverySecs: req.RecoverySecs,
		RecoveryThreshold: req.RecoveryThreshold, MissingDataPolicy: req.MissingDataPolicy,
		CooldownSecs: req.CooldownSecs, RepeatSecs: req.RepeatSecs, DestinationIDs: req.DestinationIDs,
	}
	if t.Severity == "" {
		t.Severity = string(domain.SeverityMedium)
	}
	if t.Aggregation == "" {
		t.Aggregation = "avg"
	}
	if t.Operator == "" {
		t.Operator = "gt"
	}
	if t.WindowSecs == 0 {
		t.WindowSecs = 300
	}
	if t.MissingDataPolicy == "" {
		t.MissingDataPolicy = domain.MissingDataIgnore
	}
	if t.CooldownSecs == 0 {
		t.CooldownSecs = 300
	}
	return t, nil
}

// reqBool reads a boolean from the raw body when present, else def.
func reqBool(c *fiber.Ctx, key string, def bool) bool {
	var m map[string]json.RawMessage
	if err := c.BodyParser(&m); err != nil {
		return def
	}
	raw, ok := m[key]
	if !ok {
		return def
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return def
	}
	return b
}

// urlParse is a tiny indirection so handlers do not import net/url twice.
func urlParse(raw string) (*url.URL, error) { return url.Parse(raw) }
