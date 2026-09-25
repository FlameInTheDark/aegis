package alerting

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Store owns the transactional alert state machine. Every evaluation
// commits the occurrence, transition, delivery and rule-state rows in ONE
// transaction, so a crash can never leave half an alert behind and a
// duplicate event can never open a second occurrence (the partial unique
// index is the last line of defense).
type Store struct {
	DB *pg.DB
}

// EvalResult reports what one evaluation actually did.
type EvalResult struct {
	Occurrence *domain.Occurrence
	Fired      bool
	Recovered  bool
	Repeated   bool
	Suppressed bool
	Deliveries int
}

// --- Event triggers ---------------------------------------------------------

// EvaluateEvent applies one domain event to one trigger. The caller has
// already checked scope and conditions; recovery=true marks an event that
// resolves matching open occurrences.
func (s *Store) EvaluateEvent(ctx context.Context, t *domain.Trigger, ev *domain.TriggerEvent, recovery bool, dests []*domain.Destination, now time.Time) (*EvalResult, error) {
	if recovery {
		return s.recoverByEvent(ctx, t, ev, dests, now)
	}
	return s.fireByEvent(ctx, t, ev, dests, now)
}

func fingerprintFor(t *domain.Trigger, ev *domain.TriggerEvent) string {
	base := ev.DedupKey
	if base == "" {
		base = ev.EntityType + ":" + ev.EntityID
	}
	if base == ":" || base == "" {
		base = "asset:" + ev.AssetID
	}
	return t.ID + "|" + base
}

func (s *Store) fireByEvent(ctx context.Context, t *domain.Trigger, ev *domain.TriggerEvent, dests []*domain.Destination, now time.Time) (*EvalResult, error) {
	res := &EvalResult{}
	fp := fingerprintFor(t, ev)
	err := s.DB.WithTx(ctx, func(tx pgx.Tx) error {
		// Lock the open occurrence (if any) for this rule/fingerprint.
		occ, err := lockOpenOccurrence(ctx, tx, t.ID, fp)
		if err != nil {
			return err
		}
		if occ != nil {
			// Repeat notification after the repeat interval (respecting the
			// cooldown floor); otherwise the repeated observation only
			// refreshes last-seen. No new occurrence can be created.
			interval := t.RepeatSecs
			if t.CooldownSecs > interval {
				interval = t.CooldownSecs
			}
			if t.RepeatSecs > 0 && now.Sub(occ.UpdatedAt) >= time.Duration(interval)*time.Second {
				n, err := insertDeliveries(ctx, tx, t, occ, "", domain.DeliveryRepeat, dests, now)
				if err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `UPDATE alert_occurrences SET occurrence_count = occurrence_count + 1, updated_at = $2 WHERE id = $1`, occ.ID, now); err != nil {
					return err
				}
				occ.OccurrenceCount++
				occ.UpdatedAt = now
				res.Occurrence, res.Repeated, res.Deliveries = occ, true, n
				return nil
			}
			res.Occurrence = occ
			return nil
		}
		// Cooldown on reopening: the same fingerprint recovered less than
		// cooldown_secs ago stays quiet (flap suppression).
		var recoveredAt *time.Time
		err = tx.QueryRow(ctx, `SELECT recovered_at FROM alert_occurrences
			WHERE trigger_id = $1 AND fingerprint = $2 AND state = 'recovered'
			ORDER BY recovered_at DESC LIMIT 1`, t.ID, fp).Scan(&recoveredAt)
		if err != nil && err != errNoRows {
			return err
		}
		if recoveredAt != nil && now.Sub(*recoveredAt) < time.Duration(t.CooldownSecs)*time.Second {
			res.Suppressed = true
			return nil
		}
		occ, n, err := openOccurrence(ctx, tx, t, fp, ev, dests, now)
		if err != nil {
			return err
		}
		res.Occurrence, res.Fired, res.Deliveries = occ, true, n
		return nil
	})
	return res, err
}

func (s *Store) recoverByEvent(ctx context.Context, t *domain.Trigger, ev *domain.TriggerEvent, dests []*domain.Destination, now time.Time) (*EvalResult, error) {
	res := &EvalResult{}
	fp := fingerprintFor(t, ev)
	err := s.DB.WithTx(ctx, func(tx pgx.Tx) error {
		occ, err := lockOpenOccurrence(ctx, tx, t.ID, fp)
		if err != nil {
			return err
		}
		if occ == nil {
			return nil // nothing to recover
		}
		from := occ.State
		if _, err := tx.Exec(ctx, `UPDATE alert_occurrences
			SET state = $2, recovered_at = $3, updated_at = $3 WHERE id = $1`,
			occ.ID, domain.OccurrenceRecovered, now); err != nil {
			return err
		}
		tid := ids.New()
		if _, err := tx.Exec(ctx, `INSERT INTO alert_transitions (id, organization_id, occurrence_id, from_state, to_state, event_id, actor, reason, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, occ.OrgID, occ.ID, from, domain.OccurrenceRecovered, ev.EventID, "system", "recovered by "+ev.Type, now); err != nil {
			return err
		}
		n, err := insertDeliveries(ctx, tx, t, occ, tid, domain.DeliveryRecovered, dests, now)
		if err != nil {
			return err
		}
		occ.State = domain.OccurrenceRecovered
		occ.RecoveredAt = &now
		res.Occurrence, res.Recovered, res.Deliveries = occ, true, n
		return nil
	})
	return res, err
}

// --- Metric triggers --------------------------------------------------------

// MetricState applies one metric evaluation step for one scope entity.
// The decision is recomputed inside the transaction on the locked row, so
// concurrent evaluators converge on one transition.
func (s *Store) MetricState(ctx context.Context, t *domain.Trigger, scopeKey string, value *float64, samples int, dests []*domain.Destination, now time.Time) (*EvalResult, error) {
	res := &EvalResult{}
	fp := t.ID + "|metric:" + scopeKey
	err := s.DB.WithTx(ctx, func(tx pgx.Tx) error {
		st, err := lockRuleState(ctx, tx, t, scopeKey)
		if err != nil {
			return err
		}
		act := metricDecision(st, t, value, samples, now)
		switch act.kind {
		case actionNone:
			if act.degrade {
				_, err = tx.Exec(ctx, `UPDATE alert_rule_states SET state = 'degraded', last_value = $3, last_evaluated_at = $2, version = version + 1
					WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey)
				return err
			}
			_, err = tx.Exec(ctx, `UPDATE alert_rule_states SET last_value = $3, last_evaluated_at = $2, version = version + 1
				WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey)
			return err
		case actionArm:
			if _, err := tx.Exec(ctx, `UPDATE alert_rule_states SET state = 'pending', pending_since = $2, last_value = $3, last_evaluated_at = $2, version = version + 1
				WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey); err != nil {
				return err
			}
			return nil
		case actionClear:
			if _, err := tx.Exec(ctx, `UPDATE alert_rule_states SET state = 'normal', pending_since = NULL, last_value = $3, last_evaluated_at = $2, version = version + 1
				WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey); err != nil {
				return err
			}
			return nil
		case actionRecoverArm:
			if _, err := tx.Exec(ctx, `UPDATE alert_rule_states SET pending_since = $2, last_value = $3, last_evaluated_at = $2, version = version + 1
				WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey); err != nil {
				return err
			}
			return nil
		case actionFire:
			occ, n, err := openMetricOccurrence(ctx, tx, t, fp, scopeKey, value, samples, dests, now)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE alert_rule_states SET state = 'firing', pending_since = NULL, last_value = $3, last_evaluated_at = $2, last_transition_at = $2, version = version + 1
				WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey); err != nil {
				return err
			}
			res.Occurrence, res.Fired, res.Deliveries = occ, true, n
			return nil
		case actionRepeat:
			occ, err := lockOpenOccurrence(ctx, tx, t.ID, fp)
			if err != nil {
				return err
			}
			if occ == nil {
				return nil
			}
			n, err := insertDeliveries(ctx, tx, t, occ, "", domain.DeliveryRepeat, dests, now)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE alert_occurrences SET occurrence_count = occurrence_count + 1, updated_at = $2 WHERE id = $1`, occ.ID, now); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE alert_rule_states SET last_transition_at = $2, last_value = $3, last_evaluated_at = $2, version = version + 1
				WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey); err != nil {
				return err
			}
			occ.OccurrenceCount++
			occ.UpdatedAt = now
			res.Occurrence, res.Repeated, res.Deliveries = occ, true, n
			return nil
		case actionRecover:
			occ, err := lockOpenOccurrence(ctx, tx, t.ID, fp)
			if err != nil {
				return err
			}
			if occ != nil {
				from := occ.State
				if _, err := tx.Exec(ctx, `UPDATE alert_occurrences
					SET state = $2, recovered_at = $3, updated_at = $3 WHERE id = $1`,
					occ.ID, domain.OccurrenceRecovered, now); err != nil {
					return err
				}
				tid := ids.New()
				if _, err := tx.Exec(ctx, `INSERT INTO alert_transitions (id, organization_id, occurrence_id, from_state, to_state, observed_value, actor, reason, created_at)
					VALUES ($1,$2,$3,$4,$5,$6,'system','metric recovered',$7)`,
					tid, occ.OrgID, occ.ID, from, domain.OccurrenceRecovered, valueOrNil(value), now); err != nil {
					return err
				}
				n, err := insertDeliveries(ctx, tx, t, occ, tid, domain.DeliveryRecovered, dests, now)
				if err != nil {
					return err
				}
				occ.State = domain.OccurrenceRecovered
				res.Occurrence, res.Recovered, res.Deliveries = occ, true, n
			}
			if _, err := tx.Exec(ctx, `UPDATE alert_rule_states SET state = 'normal', pending_since = NULL, last_value = $3, last_evaluated_at = $2, last_transition_at = $2, version = version + 1
				WHERE trigger_id = $1 AND scope_key = $4`, t.ID, now, valueOrNil(value), scopeKey); err != nil {
				return err
			}
			return nil
		}
		return nil
	})
	return res, err
}

// --- shared transactional helpers -------------------------------------------

// lockOpenOccurrence loads the firing/acknowledged occurrence for a rule
// fingerprint under a row lock. Returns nil when none is open.
func lockOpenOccurrence(ctx context.Context, tx pgx.Tx, triggerID, fp string) (*domain.Occurrence, error) {
	row := tx.QueryRow(ctx, `SELECT id, organization_id, trigger_id, fingerprint, state, severity, title, summary,
		COALESCE(site_id::text,''), COALESCE(asset_id::text,''), entity_type, entity_id, snapshot, evidence,
		occurrence_count, opened_at, acknowledged_at, recovered_at, updated_at
		FROM alert_occurrences WHERE trigger_id = $1 AND fingerprint = $2 AND state IN ('firing','acknowledged')
		FOR UPDATE`, triggerID, fp)
	o := &domain.Occurrence{}
	err := row.Scan(&o.ID, &o.OrgID, &o.TriggerID, &o.Fingerprint, &o.State, &o.Severity, &o.Title, &o.Summary,
		&o.SiteID, &o.AssetID, &o.EntityType, &o.EntityID, &o.Snapshot, &o.Evidence,
		&o.OccurrenceCount, &o.OpenedAt, &o.AcknowledgedAt, &o.RecoveredAt, &o.UpdatedAt)
	if err != nil {
		if err == errNoRows {
			return nil, nil
		}
		return nil, err
	}
	return o, nil
}

// lockRuleState loads (creating when absent) the evaluation state row under
// a lock.
func lockRuleState(ctx context.Context, tx pgx.Tx, t *domain.Trigger, scopeKey string) (*ruleState, error) {
	_, err := tx.Exec(ctx, `INSERT INTO alert_rule_states (trigger_id, scope_key, organization_id) VALUES ($1,$2,$3)
		ON CONFLICT (trigger_id, scope_key) DO NOTHING`, t.ID, scopeKey, t.OrgID)
	if err != nil {
		return nil, err
	}
	st := &ruleState{}
	err = tx.QueryRow(ctx, `SELECT state, pending_since, last_value, last_transition_at, last_event_id
		FROM alert_rule_states WHERE trigger_id = $1 AND scope_key = $2 FOR UPDATE`, t.ID, scopeKey).
		Scan(&st.state, &st.pendingSince, &st.lastValue, &st.lastTransition, &st.lastEventID)
	if err != nil {
		return nil, err
	}
	return st, nil
}

// openOccurrence creates the firing occurrence, its first transition, the
// delivery rows and the firing rule state, all on the caller's transaction.
func openOccurrence(ctx context.Context, tx pgx.Tx, t *domain.Trigger, fp string, ev *domain.TriggerEvent, dests []*domain.Destination, now time.Time) (*domain.Occurrence, int, error) {
	occ := &domain.Occurrence{
		ID:          ids.New(),
		OrgID:       t.OrgID,
		TriggerID:   t.ID,
		Fingerprint: fp,
		State:       domain.OccurrenceFiring,
		Severity:    t.Severity,
		Title:       t.Name,
		Summary:     eventSummary(ev),
		SiteID:      ev.SiteID,
		AssetID:     ev.AssetID,
		EntityType:  ev.EntityType,
		EntityID:    ev.EntityID,
		OpenedAt:    now,
		UpdatedAt:   now,
	}
	snapshot, _ := json.Marshal(map[string]any{
		"trigger":  map[string]any{"id": t.ID, "name": t.Name, "kind": t.Kind, "severity": t.Severity},
		"event":    map[string]any{"id": ev.EventID, "type": ev.Type, "source": ev.Source},
		"data":     json.RawMessage(ev.Data),
		"occurred": ev.OccurredAt,
	})
	occ.Snapshot = snapshot
	evidence, _ := json.Marshal([]map[string]any{{
		"kind": "event", "event_id": ev.EventID, "type": ev.Type, "at": ev.OccurredAt, "data": json.RawMessage(ev.Data),
	}})
	occ.Evidence = evidence

	_, err := tx.Exec(ctx, `INSERT INTO alert_occurrences (id, organization_id, trigger_id, fingerprint, state, severity,
		title, summary, site_id, asset_id, entity_type, entity_id, snapshot, evidence, opened_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$15)`,
		occ.ID, occ.OrgID, occ.TriggerID, occ.Fingerprint, occ.State, occ.Severity,
		occ.Title, occ.Summary, strNilPtr(occ.SiteID), strNilPtr(occ.AssetID), occ.EntityType, occ.EntityID,
		occ.Snapshot, occ.Evidence, now)
	if err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO alert_transitions (id, organization_id, occurrence_id, from_state, to_state, event_id, actor, reason, created_at)
		VALUES ($1,$2,$3,'normal','firing',$4,'system',$5,$6)`,
		ids.New(), occ.OrgID, occ.ID, ev.EventID, "fired by "+ev.Type, now); err != nil {
		return nil, 0, err
	}
	n, err := insertDeliveries(ctx, tx, t, occ, "", domain.DeliveryFired, dests, now)
	if err != nil {
		return nil, 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO alert_rule_states (trigger_id, scope_key, organization_id, state, last_event_id, last_transition_at, last_evaluated_at)
		VALUES ($1,$2,$3,'firing',$4,$6,$6)
		ON CONFLICT (trigger_id, scope_key) DO UPDATE SET state = 'firing', pending_since = NULL, last_event_id = $4, last_transition_at = $6, last_evaluated_at = $6, version = version + 1`,
		t.ID, metricScopeKeyOf(occ), t.OrgID, ev.EventID, now, now); err != nil {
		return nil, 0, err
	}
	return occ, n, nil
}

// metricScopeKeyOf derives the rule-state scope key from the occurrence —
// for event triggers the fingerprint base itself identifies the scope.
func metricScopeKeyOf(o *domain.Occurrence) string {
	if o.AssetID != "" {
		return o.AssetID
	}
	if o.EntityID != "" {
		return o.EntityID
	}
	return "org"
}

func openMetricOccurrence(ctx context.Context, tx pgx.Tx, t *domain.Trigger, fp, scopeKey string, value *float64, samples int, dests []*domain.Destination, now time.Time) (*domain.Occurrence, int, error) {
	occ := &domain.Occurrence{
		ID:          ids.New(),
		OrgID:       t.OrgID,
		TriggerID:   t.ID,
		Fingerprint: fp,
		State:       domain.OccurrenceFiring,
		Severity:    t.Severity,
		Title:       t.Name,
		Summary:     metricSummary(t, value, samples),
		AssetID:     scopeKey,
		EntityType:  "asset",
		EntityID:    scopeKey,
		OpenedAt:    now,
		UpdatedAt:   now,
	}
	snapshot, _ := json.Marshal(map[string]any{
		"trigger":     map[string]any{"id": t.ID, "name": t.Name, "kind": t.Kind, "severity": t.Severity},
		"metric":      t.MetricField,
		"aggregation": t.Aggregation,
		"operator":    t.Operator,
		"threshold":   t.Threshold,
		"window_secs": t.WindowSecs,
		"value":       value,
		"samples":     samples,
		"scope_key":   scopeKey,
	})
	occ.Snapshot = snapshot
	evidence, _ := json.Marshal([]map[string]any{{
		"kind": "metric", "field": t.MetricField, "value": value, "threshold": t.Threshold,
		"window_secs": t.WindowSecs, "samples": samples, "at": now,
	}})
	occ.Evidence = evidence
	_, err := tx.Exec(ctx, `INSERT INTO alert_occurrences (id, organization_id, trigger_id, fingerprint, state, severity,
		title, summary, asset_id, entity_type, entity_id, snapshot, evidence, opened_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$14)`,
		occ.ID, occ.OrgID, occ.TriggerID, occ.Fingerprint, occ.State, occ.Severity,
		occ.Title, occ.Summary, strNilPtr(occ.AssetID), occ.EntityType, occ.EntityID,
		occ.Snapshot, occ.Evidence, now)
	if err != nil {
		return nil, 0, err
	}
	tid := ids.New()
	if _, err := tx.Exec(ctx, `INSERT INTO alert_transitions (id, organization_id, occurrence_id, from_state, to_state, observed_value, actor, reason, created_at)
		VALUES ($1,$2,$3,'normal','firing',$4,'system',$5,$6)`,
		tid, occ.OrgID, occ.ID, valueOrNil(value), metricSummary(t, value, samples), now); err != nil {
		return nil, 0, err
	}
	n, err := insertDeliveries(ctx, tx, t, occ, tid, domain.DeliveryFired, dests, now)
	if err != nil {
		return nil, 0, err
	}
	return occ, n, nil
}

// insertDeliveries creates one delivery row per destination that subscribes
// to this kind of notification at or below the trigger severity.
func insertDeliveries(ctx context.Context, tx pgx.Tx, t *domain.Trigger, occ *domain.Occurrence, transitionID, kind string, dests []*domain.Destination, now time.Time) (int, error) {
	n := 0
	for _, d := range dests {
		if !destinationSubscribes(d, t.Severity, kind) {
			continue
		}
		payload, err := deliveryPayload(t, occ, kind, now)
		if err != nil {
			return n, err
		}
		idem := fmt.Sprintf("%s:%s:%s:%s", occ.ID, transitionID, d.ID, kind)
		if _, err := tx.Exec(ctx, `INSERT INTO alert_deliveries (id, organization_id, occurrence_id, destination_id, transition_id, kind, status, idempotency_key, payload, created_at)
			VALUES ($1,$2,$3,$4,$5,$6,'pending',$7,$8,$9)
			ON CONFLICT (idempotency_key) DO NOTHING`,
			ids.New(), occ.OrgID, occ.ID, d.ID, strNilPtr(transitionID), kind, idem, payload, now); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

// destinationSubscribes applies severity floor + event subscription filter.
func destinationSubscribes(d *domain.Destination, severity, kind string) bool {
	if !d.Enabled {
		return false
	}
	if severityRank(severity) < severityRank(d.MinSeverity) {
		return false
	}
	if len(d.Events) == 0 {
		return true
	}
	for _, e := range d.Events {
		if e == kind {
			return true
		}
	}
	return false
}

func severityRank(s string) int {
	switch s {
	case string(domain.SeverityCritical):
		return 5
	case string(domain.SeverityHigh):
		return 4
	case string(domain.SeverityMedium):
		return 3
	case string(domain.SeverityLow):
		return 2
	default:
		return 1
	}
}

func deliveryPayload(t *domain.Trigger, occ *domain.Occurrence, kind string, now time.Time) (json.RawMessage, error) {
	return json.Marshal(map[string]any{
		"schema_version": 1,
		"kind":           kind,
		"sent_at":        now,
		"trigger":        map[string]any{"id": t.ID, "name": t.Name, "kind": t.Kind, "severity": t.Severity},
		"occurrence": map[string]any{
			"id": occ.ID, "state": occ.State, "severity": occ.Severity, "title": occ.Title,
			"summary": occ.Summary, "asset_id": occ.AssetID, "site_id": occ.SiteID,
			"entity_type": occ.EntityType, "entity_id": occ.EntityID,
			"occurrence_count": occ.OccurrenceCount, "opened_at": occ.OpenedAt,
			"snapshot": json.RawMessage(occ.Snapshot), "evidence": json.RawMessage(occ.Evidence),
		},
	})
}

func eventSummary(ev *domain.TriggerEvent) string {
	s := ev.Type
	if ev.EntityType != "" && ev.EntityID != "" {
		s += fmt.Sprintf(" on %s %s", ev.EntityType, shortID(ev.EntityID))
	}
	if len(ev.Data) > 0 {
		var m map[string]any
		if err := json.Unmarshal(ev.Data, &m); err == nil {
			for _, k := range []string{"hostname", "product", "name", "cve_id", "state", "feed", "rule_title"} {
				if v, ok := m[k]; ok {
					s += fmt.Sprintf(" (%s: %v)", k, v)
					break
				}
			}
		}
	}
	return s
}

func metricSummary(t *domain.Trigger, value *float64, samples int) string {
	if value == nil {
		return fmt.Sprintf("%s (%s %s): no data in window (missing-data policy: %s)",
			t.Name, t.Aggregation, t.MetricField, t.MissingDataPolicy)
	}
	return fmt.Sprintf("%s %s %.1f %s %.0f over a %dm window (%d samples)",
		t.Aggregation, t.MetricField, *value, t.Operator, t.Threshold, t.WindowSecs/60, samples)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func valueOrNil(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

func strNilPtr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
