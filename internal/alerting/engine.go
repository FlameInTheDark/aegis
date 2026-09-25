package alerting

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/joblog"
	"github.com/FlameInTheDark/aegis/internal/platform"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// EventEvaluator consumes domain events from the dedicated alert stream
// and applies them to enabled event triggers. It is idempotent: rule-state
// last_event_id plus the open-occurrence unique index make duplicate or
// replayed events harmless.
type EventEvaluator struct {
	DB           *pg.DB
	Store        *Store
	Triggers     *pg.AlertTriggerRepo
	Destinations *pg.DestinationRepo
	Bus          *platform.Bus // post-commit UI hint; never authoritative
	Log          *slog.Logger
	Now          func() time.Time
}

// HandleEvent evaluates one decoded event against the trigger set.
func (e *EventEvaluator) HandleEvent(ctx context.Context, ev *domain.TriggerEvent) error {
	if ev == nil || ev.OrganizationID == "" || ev.Type == "" {
		return nil // not an alertable event; drop silently
	}
	triggers, err := e.Triggers.EnabledEventTriggers(ctx, ev.OrganizationID, ev.Type)
	if err != nil {
		return err
	}
	if len(triggers) == 0 {
		return nil
	}
	now := e.now()
	dests, err := e.Destinations.List(ctx, ev.OrganizationID)
	if err != nil {
		e.Log.Warn("alert destinations unavailable", "org", ev.OrganizationID, "err", err)
		dests = nil
	}
	for _, t := range triggers {
		isRecovery := contains(t.RecoveryEventTypes, ev.Type)
		isFiring := contains(t.EventTypes, ev.Type)
		if !isRecovery && !isFiring {
			continue
		}
		if !eventScopeAllows(t.Scope, ev) {
			continue
		}
		// Conditions gate firing events only: a recovery event explicitly
		// resolves the matching occurrence and cannot be condition-locked.
		if isFiring && !isRecovery && len(t.Conditions) > 0 {
			var cond Condition
			if err := json.Unmarshal(t.Conditions, &cond); err != nil {
				_ = e.Triggers.SetLastError(ctx, t.ID, "invalid conditions: "+err.Error())
				continue
			}
			if err := cond.Validate(0); err != nil {
				_ = e.Triggers.SetLastError(ctx, t.ID, "invalid conditions: "+err.Error())
				continue
			}
			data, _ := eventMap(ev)
			if !cond.Evaluate(data) {
				continue
			}
		}
		res, err := e.Store.EvaluateEvent(ctx, t, ev, isRecovery && !isFiring, dests, now)
		if err != nil {
			e.Log.Warn("trigger evaluation failed", "trigger", t.ID, "event", ev.EventID, "err", err)
			_ = e.Triggers.SetLastError(ctx, t.ID, err.Error())
			continue
		}
		_ = e.Triggers.TouchEvaluated(ctx, t.ID)
		e.hint(t, res)
	}
	return nil
}

// hint broadcasts the post-commit UI notification. Delivery failure never
// affects alert state — this is a convenience hint, the REST list is the
// recovery path.
func (e *EventEvaluator) hint(t *domain.Trigger, res *EvalResult) {
	if e.Bus == nil || res == nil || (!res.Fired && !res.Recovered && !res.Repeated) {
		return
	}
	n := &domain.NotificationEvent{
		ID:       res.Occurrence.ID,
		OrgID:    t.OrgID,
		Title:    t.Name,
		Severity: t.Severity,
		Ref: map[string]string{
			"occurrence_id": res.Occurrence.ID,
			"trigger_id":    t.ID,
		},
	}
	switch {
	case res.Fired:
		n.Type = "alert.fired"
		n.Body = res.Occurrence.Summary
	case res.Recovered:
		n.Type = "alert.recovered"
		n.Body = "Condition recovered"
	case res.Repeated:
		n.Type = "alert.repeated"
		n.Body = res.Occurrence.Summary
	}
	joblog.PublishNotification(context.Background(), e.Bus, n)
}

func (e *EventEvaluator) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now().UTC()
}

// eventScopeAllows applies the trigger scope: empty site/asset lists mean
// organization-wide; device_types filters on the event data field.
func eventScopeAllows(scope domain.TriggerScope, ev *domain.TriggerEvent) bool {
	if len(scope.SiteIDs) > 0 && !contains(scope.SiteIDs, ev.SiteID) {
		return false
	}
	if len(scope.AssetIDs) > 0 && !contains(scope.AssetIDs, ev.AssetID) {
		return false
	}
	if len(scope.DeviceTypes) > 0 {
		data, _ := eventMap(ev)
		dt, _ := data["device_type"].(string)
		if !contains(scope.DeviceTypes, dt) {
			return false
		}
	}
	return true
}

// eventMap flattens the envelope + data payload into the condition
// evaluation map.
func eventMap(ev *domain.TriggerEvent) (map[string]any, error) {
	out := map[string]any{
		"type":        ev.Type,
		"source":      ev.Source,
		"entity_type": ev.EntityType,
		"entity_id":   ev.EntityID,
		"severity":    ev.Severity,
	}
	if ev.SiteID != "" {
		out["site_id"] = ev.SiteID
	}
	if ev.AssetID != "" {
		out["asset_id"] = ev.AssetID
	}
	if len(ev.Data) > 0 {
		var m map[string]any
		if err := json.Unmarshal(ev.Data, &m); err == nil {
			for k, v := range m {
				out[k] = v
			}
		}
	}
	return out, nil
}

func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
