package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// strPtr lifts an empty-able string to a nullable pointer for UUID columns.
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// sha256Sum returns a stable content hash for revision documents.
func sha256Sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// This file implements persistence for the alert-trigger engine (outbox,
// triggers, destinations, occurrences, transitions, deliveries) and the
// vulnerability search-action plane (actions, runs, provenance, aliases).
// Transactional evaluation SQL lives in internal/alerting; everything here
// is single-statement CRUD/list used by both the engine and the HTTP API.

// ---------------------------------------------------------------------------
// Outbox

// OutboxRepo persists domain events next to the mutations that caused them.
type OutboxRepo struct{ db *DB }

func NewOutboxRepo(db *DB) *OutboxRepo { return &OutboxRepo{db: db} }

// DB exposes the underlying pool (emit helpers on services that only hold
// the repo).
func (r *OutboxRepo) DB() *DB { return r.db }

// Insert stores one event. It must be called in the same transaction (or at
// least the same logical write path) as the source mutation.
func (r *OutboxRepo) Insert(ctx context.Context, ev *domain.TriggerEvent) error {
	if ev.EventID == "" {
		ev.EventID = ids.New()
	}
	if ev.SchemaVersion == 0 {
		ev.SchemaVersion = 1
	}
	if ev.RecordedAt.IsZero() {
		ev.RecordedAt = time.Now().UTC()
	}
	if ev.OccurredAt.IsZero() {
		ev.OccurredAt = ev.RecordedAt
	}
	payload := ev.Data
	if len(payload) == 0 {
		payload = json.RawMessage("{}")
	}
	q := r.db.Insert("event_outbox").Columns(
		"id", "organization_id", "type", "schema_version", "subject_type", "subject_id",
		"site_id", "asset_id", "entity_type", "entity_id", "occurred_at", "recorded_at",
		"payload", "correlation_id", "causation_id", "dedup_key",
	).Values(
		ev.EventID, ev.OrganizationID, ev.Type, ev.SchemaVersion, ev.Source, ev.EntityID,
		nullPtrID(strPtr(ev.SiteID)), nullPtrID(strPtr(ev.AssetID)), ev.EntityType, ev.EntityID,
		ev.OccurredAt, ev.RecordedAt, payload, ev.CorrelationID, ev.CausationID, ev.DedupKey,
	)
	sql, args, err := q.ToSql()
	if err != nil {
		return fmt.Errorf("postgres: build outbox insert: %w", err)
	}
	_, err = r.db.Pool.Exec(ctx, sql, args...)
	return err
}

// ClaimUnpublished atomically claims a batch of unpublished events with
// FOR UPDATE SKIP LOCKED, bumping the attempt counter so a crashed relay
// cannot loop forever on the same row without progress.
func (r *OutboxRepo) ClaimUnpublished(ctx context.Context, limit int, now time.Time) ([]domain.OutboxEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	sql := `UPDATE event_outbox SET attempts = attempts + 1
                WHERE id IN (
                        SELECT id FROM event_outbox
                        WHERE published_at IS NULL AND next_attempt_at <= $1
                        ORDER BY next_attempt_at
                        LIMIT $2
                        FOR UPDATE SKIP LOCKED
                )
                RETURNING id, organization_id, type, schema_version, subject_type, subject_id,
                        site_id, asset_id, entity_type, entity_id, occurred_at, recorded_at,
                        payload, correlation_id, causation_id, dedup_key, published_at, attempts, next_attempt_at, last_error`
	rows, err := r.db.Pool.Query(ctx, sql, now, limit)
	if err != nil {
		return nil, fmt.Errorf("postgres: claim outbox: %w", err)
	}
	defer rows.Close()
	return scanOutboxRows(rows)
}

// MarkPublished records broker acknowledgment.
func (r *OutboxRepo) MarkPublished(ctx context.Context, ids []string, now time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	sql := `UPDATE event_outbox SET published_at = $2 WHERE id = ANY($1)`
	_, err := r.db.Pool.Exec(ctx, sql, ids, now)
	return err
}

// MarkFailed schedules the next relay attempt with backoff.
func (r *OutboxRepo) MarkFailed(ctx context.Context, id string, errMsg string, next time.Time) error {
	sql := `UPDATE event_outbox SET last_error = $2, next_attempt_at = $3 WHERE id = $1`
	_, err := r.db.Pool.Exec(ctx, sql, id, errMsg, next)
	return err
}

// DeletePublishedBefore prunes acknowledged outbox rows (retention).
func (r *OutboxRepo) DeletePublishedBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.db.Pool.Exec(ctx, `DELETE FROM event_outbox WHERE published_at IS NOT NULL AND recorded_at < $1`, cutoff)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// CountUnpublished reports the relay backlog (health/metrics).
func (r *OutboxRepo) CountUnpublished(ctx context.Context) (int64, int64, error) {
	var count int64
	var oldestMin int64
	sql := `SELECT count(*), COALESCE(EXTRACT(EPOCH FROM (now() - MIN(next_attempt_at))) / 60, 0)::bigint
                FROM event_outbox WHERE published_at IS NULL`
	err := r.db.Pool.QueryRow(ctx, sql).Scan(&count, &oldestMin)
	return count, oldestMin, err
}

func scanOutboxRows(rows pgx.Rows) ([]domain.OutboxEvent, error) {
	var out []domain.OutboxEvent
	for rows.Next() {
		var e domain.OutboxEvent
		var siteID, assetID *string
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Type, &e.SchemaVersion, &e.SubjectType, &e.SubjectID,
			&siteID, &assetID, &e.EntityType, &e.EntityID, &e.OccurredAt, &e.RecordedAt,
			&e.Payload, &e.CorrelationID, &e.CausationID, &e.DedupKey, &e.PublishedAt, &e.Attempts, &e.NextAttemptAt, &e.LastError); err != nil {
			return nil, err
		}
		if siteID != nil {
			e.SiteID = *siteID
		}
		if assetID != nil {
			e.AssetID = *assetID
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Alert triggers

type AlertTriggerRepo struct{ db *DB }

func NewAlertTriggerRepo(db *DB) *AlertTriggerRepo { return &AlertTriggerRepo{db: db} }

const triggerColumns = `id, organization_id, name, description, kind, enabled, lifecycle, severity,
        scope, conditions, event_types, recovery_event_types, metric_field, aggregation, operator,
        threshold, window_secs, group_by, activation_secs, recovery_secs, recovery_threshold,
        missing_data_policy, cooldown_secs, repeat_secs, destination_ids, revision, created_by,
        created_at, updated_at, last_evaluated_at, last_error`

func scanTrigger(row pgx.Row) (*domain.Trigger, error) {
	var t domain.Trigger
	var scopeRaw, condRaw []byte
	err := row.Scan(&t.ID, &t.OrgID, &t.Name, &t.Description, &t.Kind, &t.Enabled, &t.Lifecycle,
		&t.Severity, &scopeRaw, &condRaw, &t.EventTypes, &t.RecoveryEventTypes, &t.MetricField,
		&t.Aggregation, &t.Operator, &t.Threshold, &t.WindowSecs, &t.GroupBy, &t.ActivationSecs,
		&t.RecoverySecs, &t.RecoveryThreshold, &t.MissingDataPolicy, &t.CooldownSecs, &t.RepeatSecs,
		&t.DestinationIDs, &t.Revision, &t.CreatedBy, &t.CreatedAt, &t.UpdatedAt,
		&t.LastEvaluatedAt, &t.LastError)
	if err != nil {
		return nil, err
	}
	if len(scopeRaw) > 0 {
		_ = json.Unmarshal(scopeRaw, &t.Scope)
	}
	t.Conditions = json.RawMessage(condRaw)
	return &t, nil
}

// Create inserts a trigger.
func (r *AlertTriggerRepo) Create(ctx context.Context, t *domain.Trigger) error {
	if t.ID == "" {
		t.ID = ids.New()
	}
	if t.Revision == 0 {
		t.Revision = 1
	}
	scope, _ := json.Marshal(t.Scope)
	cond := t.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage("{}")
	}
	q := r.db.Insert("alert_triggers").Columns(
		"id", "organization_id", "name", "description", "kind", "enabled", "lifecycle", "severity",
		"scope", "conditions", "event_types", "recovery_event_types", "metric_field", "aggregation",
		"operator", "threshold", "window_secs", "group_by", "activation_secs", "recovery_secs",
		"recovery_threshold", "missing_data_policy", "cooldown_secs", "repeat_secs", "destination_ids",
		"revision", "created_by",
	).Values(
		t.ID, t.OrgID, t.Name, t.Description, t.Kind, t.Enabled, t.Lifecycle, t.Severity,
		scope, cond, nonNil(t.EventTypes), nonNil(t.RecoveryEventTypes), t.MetricField, t.Aggregation,
		t.Operator, t.Threshold, t.WindowSecs, t.GroupBy, t.ActivationSecs, t.RecoverySecs,
		t.RecoveryThreshold, t.MissingDataPolicy, t.CooldownSecs, t.RepeatSecs, nonNil(t.DestinationIDs),
		t.Revision, t.CreatedBy,
	)
	sql, args, err := q.ToSql()
	if err != nil {
		return fmt.Errorf("postgres: build trigger insert: %w", err)
	}
	_, err = r.db.Pool.Exec(ctx, sql, args...)
	return err
}

// Update replaces the mutable fields of a trigger. expectedRevision implements
// optimistic concurrency: a stale revision returns ErrConflict.
func (r *AlertTriggerRepo) Update(ctx context.Context, t *domain.Trigger, expectedRevision int) error {
	scope, _ := json.Marshal(t.Scope)
	cond := t.Conditions
	if len(cond) == 0 {
		cond = json.RawMessage("{}")
	}
	q := r.db.Update("alert_triggers").SetMap(map[string]any{
		"name": t.Name, "description": t.Description, "kind": t.Kind, "enabled": t.Enabled,
		"lifecycle": t.Lifecycle, "severity": t.Severity, "scope": scope, "conditions": cond,
		"event_types": nonNil(t.EventTypes), "recovery_event_types": nonNil(t.RecoveryEventTypes),
		"metric_field": t.MetricField, "aggregation": t.Aggregation, "operator": t.Operator,
		"threshold": t.Threshold, "window_secs": t.WindowSecs, "group_by": t.GroupBy,
		"activation_secs": t.ActivationSecs, "recovery_secs": t.RecoverySecs,
		"recovery_threshold": t.RecoveryThreshold, "missing_data_policy": t.MissingDataPolicy,
		"cooldown_secs": t.CooldownSecs, "repeat_secs": t.RepeatSecs,
		"destination_ids": nonNil(t.DestinationIDs),
		"revision":        expectedRevision + 1, "updated_at": time.Now().UTC(),
	}).Where(squirrel.Eq{"id": t.ID, "organization_id": t.OrgID, "revision": expectedRevision})
	sql, args, err := q.ToSql()
	if err != nil {
		return fmt.Errorf("postgres: build trigger update: %w", err)
	}
	tag, err := r.db.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrConflict
	}
	t.Revision = expectedRevision + 1
	return nil
}

// SetEnabled flips only the enabled flag (revision unaffected).
func (r *AlertTriggerRepo) SetEnabled(ctx context.Context, orgID, id string, enabled bool) error {
	q := r.db.Update("alert_triggers").SetMap(map[string]any{"enabled": enabled, "updated_at": time.Now().UTC()}).
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return r.db.ExecOne(ctx, q, "trigger set enabled")
}

// Delete removes a trigger. Occurrences are kept (disable-then-delete still
// preserves history; the plan forbids erasing alert evidence).
func (r *AlertTriggerRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("alert_triggers").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return r.db.ExecOne(ctx, q, "trigger delete")
}

// Get loads one trigger scoped to the org.
func (r *AlertTriggerRepo) Get(ctx context.Context, orgID, id string) (*domain.Trigger, error) {
	q := r.db.Select(triggerColumns).From("alert_triggers").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	t, err := scanTrigger(r.db.QueryRow(ctx, q))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return t, nil
}

// TriggerListFilter bounds the trigger list query.
type TriggerListFilter struct {
	Kind     string
	Enabled  *bool
	Severity string
	Search   string
	Limit    int
	Page     int
}

// List returns a filtered, paginated trigger list with total count.
func (r *AlertTriggerRepo) List(ctx context.Context, orgID string, f TriggerListFilter) ([]*domain.Trigger, int, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	page := f.Page
	if page < 1 {
		page = 1
	}
	pred := squirrel.Eq{"organization_id": orgID}
	if f.Kind != "" {
		pred["kind"] = f.Kind
	}
	if f.Enabled != nil {
		pred["enabled"] = *f.Enabled
	}
	if f.Severity != "" {
		pred["severity"] = f.Severity
	}
	if f.Search != "" {
		pred["name ILIKE"] = "%" + f.Search + "%"
	}
	countQ := r.db.Select("count(*)").From("alert_triggers").Where(pred)
	var total int
	if err := r.db.QueryRow(ctx, countQ).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := r.db.Select(triggerColumns).From("alert_triggers").Where(pred).
		OrderBy("created_at DESC").Limit(uint64(limit)).Offset(uint64((page - 1) * limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*domain.Trigger
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, t)
	}
	return out, total, rows.Err()
}

// EnabledEventTriggers returns enabled event triggers of one org listening
// to the given event type.
func (r *AlertTriggerRepo) EnabledEventTriggers(ctx context.Context, orgID, eventType string) ([]*domain.Trigger, error) {
	q := r.db.Select(triggerColumns).From("alert_triggers").
		Where(squirrel.Eq{"organization_id": orgID, "kind": domain.TriggerKindEvent, "enabled": true}).
		Where(squirrel.Expr("$1 = ANY(event_types)", eventType))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Trigger
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// EnabledMetricTriggers returns all enabled metric triggers (all orgs —
// the periodic evaluator is deployment-wide; every query it makes stays
// org-scoped).
func (r *AlertTriggerRepo) EnabledMetricTriggers(ctx context.Context) ([]*domain.Trigger, error) {
	q := r.db.Select(triggerColumns).From("alert_triggers").
		Where(squirrel.Eq{"kind": domain.TriggerKindMetric, "enabled": true})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Trigger
	for rows.Next() {
		t, err := scanTrigger(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TouchEvaluated records the last successful evaluation time.
func (r *AlertTriggerRepo) TouchEvaluated(ctx context.Context, id string) error {
	sql := `UPDATE alert_triggers SET last_evaluated_at = now() WHERE id = $1`
	_, err := r.db.Pool.Exec(ctx, sql, id)
	return err
}

// SetLastError records the last evaluation/delivery error on the trigger.
func (r *AlertTriggerRepo) SetLastError(ctx context.Context, id, msg string) error {
	sql := `UPDATE alert_triggers SET last_error = $2 WHERE id = $1`
	_, err := r.db.Pool.Exec(ctx, sql, id, msg)
	return err
}

// FiringCounts returns open occurrence counts per trigger.
func (r *AlertTriggerRepo) FiringCounts(ctx context.Context, orgID string) (map[string]int, error) {
	sql := `SELECT trigger_id, count(*) FROM alert_occurrences
                WHERE organization_id = $1 AND state IN ('firing','acknowledged')
                GROUP BY trigger_id`
	rows, err := r.db.Pool.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Destinations

type DestinationRepo struct{ db *DB }

func NewDestinationRepo(db *DB) *DestinationRepo { return &DestinationRepo{db: db} }

const destinationColumns = `id, organization_id, kind, name, url, secret, events, min_severity,
        enabled, created_by, created_at, updated_at, last_success_at, last_error`

func scanDestination(row pgx.Row) (*domain.Destination, error) {
	var d domain.Destination
	err := row.Scan(&d.ID, &d.OrgID, &d.Kind, &d.Name, &d.URL, &d.Secret, &d.Events,
		&d.MinSeverity, &d.Enabled, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt,
		&d.LastSuccessAt, &d.LastError)
	if err != nil {
		return nil, err
	}
	if d.Secret != "" {
		d.SecretMasked = maskSecret(d.Secret)
	}
	return &d, nil
}

func maskSecret(s string) string {
	if len(s) <= 6 {
		return "••••••"
	}
	return s[:3] + "••••••" + s[len(s)-3:]
}

// Create inserts a destination (secret is stored as-is, returned masked).
func (r *DestinationRepo) Create(ctx context.Context, d *domain.Destination) error {
	if d.ID == "" {
		d.ID = ids.New()
	}
	q := r.db.Insert("alert_destinations").Columns(
		"id", "organization_id", "kind", "name", "url", "secret", "events", "min_severity",
		"enabled", "created_by",
	).Values(d.ID, d.OrgID, d.Kind, d.Name, d.URL, d.Secret, nonNil(d.Events), d.MinSeverity,
		d.Enabled, d.CreatedBy)
	sql, args, err := q.ToSql()
	if err != nil {
		return fmt.Errorf("postgres: build destination insert: %w", err)
	}
	_, err = r.db.Pool.Exec(ctx, sql, args...)
	return err
}

// Update replaces mutable destination fields.
func (r *DestinationRepo) Update(ctx context.Context, d *domain.Destination) error {
	sets := map[string]any{
		"name": d.Name, "url": d.URL, "events": nonNil(d.Events),
		"min_severity": d.MinSeverity, "enabled": d.Enabled, "updated_at": time.Now().UTC(),
	}
	if d.Secret != "" {
		sets["secret"] = d.Secret // rotation; empty means keep current
	}
	q := r.db.Update("alert_destinations").SetMap(sets).
		Where(squirrel.Eq{"id": d.ID, "organization_id": d.OrgID})
	sql, args, err := q.ToSql()
	if err != nil {
		return fmt.Errorf("postgres: build destination update: %w", err)
	}
	tag, err := r.db.Pool.Exec(ctx, sql, args...)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a destination.
func (r *DestinationRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("alert_destinations").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return r.db.ExecOne(ctx, q, "destination delete")
}

// Get loads one destination.
func (r *DestinationRepo) Get(ctx context.Context, orgID, id string) (*domain.Destination, error) {
	q := r.db.Select(destinationColumns).From("alert_destinations").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	d, err := scanDestination(r.db.QueryRow(ctx, q))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return d, nil
}

// List returns all destinations of an org.
func (r *DestinationRepo) List(ctx context.Context, orgID string) ([]*domain.Destination, error) {
	q := r.db.Select(destinationColumns).From("alert_destinations").
		Where(squirrel.Eq{"organization_id": orgID}).OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Destination
	for rows.Next() {
		d, err := scanDestination(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// GetRaw loads one destination including its secret, for signing deliveries.
func (r *DestinationRepo) GetRaw(ctx context.Context, id string) (*domain.Destination, error) {
	q := r.db.Select(destinationColumns).From("alert_destinations").Where(squirrel.Eq{"id": id})
	d, err := scanDestination(r.db.QueryRow(ctx, q))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return d, nil
}

// MarkResult records the outcome of a delivery attempt on the destination.
func (r *DestinationRepo) MarkResult(ctx context.Context, id string, ok bool, errMsg string) error {
	if ok {
		sql := `UPDATE alert_destinations SET last_success_at = now(), last_error = '' WHERE id = $1`
		_, err := r.db.Pool.Exec(ctx, sql, id)
		return err
	}
	sql := `UPDATE alert_destinations SET last_error = $2 WHERE id = $1`
	_, err := r.db.Pool.Exec(ctx, sql, id, errMsg)
	return err
}

// ---------------------------------------------------------------------------
// Occurrences / transitions / deliveries (API read side; the engine owns
// the transactional write side in internal/alerting).

type AlertOccurrenceRepo struct{ db *DB }

func NewAlertOccurrenceRepo(db *DB) *AlertOccurrenceRepo { return &AlertOccurrenceRepo{db: db} }

const occurrenceColumns = `o.id, o.organization_id, o.trigger_id, o.fingerprint, o.state, o.severity,
        o.title, o.summary, o.site_id, o.asset_id, o.entity_type, o.entity_id, o.snapshot, o.evidence,
        o.occurrence_count, o.opened_at, o.acknowledged_at, o.recovered_at, o.updated_at, t.name`

func scanOccurrence(row pgx.Row) (*domain.Occurrence, error) {
	var o domain.Occurrence
	var siteID, assetID *string
	err := row.Scan(&o.ID, &o.OrgID, &o.TriggerID, &o.Fingerprint, &o.State, &o.Severity,
		&o.Title, &o.Summary, &siteID, &assetID, &o.EntityType, &o.EntityID, &o.Snapshot,
		&o.Evidence, &o.OccurrenceCount, &o.OpenedAt, &o.AcknowledgedAt, &o.RecoveredAt,
		&o.UpdatedAt, &o.TriggerName)
	if siteID != nil {
		o.SiteID = *siteID
	}
	if assetID != nil {
		o.AssetID = *assetID
	}
	return &o, err
}

// OccurrenceListFilter bounds occurrence queries.
type OccurrenceListFilter struct {
	State     string
	Severity  string
	TriggerID string
	SiteID    string
	AssetID   string
	Search    string
	Limit     int
	Page      int
}

// List returns a page of occurrences (open + resolved) with total count.
func (r *AlertOccurrenceRepo) List(ctx context.Context, orgID string, f OccurrenceListFilter) ([]*domain.Occurrence, int, error) {
	limit := f.Limit
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	page := f.Page
	if page < 1 {
		page = 1
	}
	pred := squirrel.Eq{"o.organization_id": orgID}
	if f.State != "" && f.State != "all" {
		if f.State == "active" {
			pred["o.state"] = []string{domain.OccurrenceFiring, domain.OccurrenceAcknowledged}
		} else {
			pred["o.state"] = f.State
		}
	}
	if f.Severity != "" {
		pred["o.severity"] = f.Severity
	}
	if f.TriggerID != "" {
		pred["o.trigger_id"] = f.TriggerID
	}
	if f.SiteID != "" {
		pred["o.site_id"] = f.SiteID
	}
	if f.AssetID != "" {
		pred["o.asset_id"] = f.AssetID
	}
	if f.Search != "" {
		pred["o.title ILIKE"] = "%" + f.Search + "%"
	}
	countQ := r.db.Select("count(*)").From("alert_occurrences o").Where(pred)
	var total int
	if err := r.db.QueryRow(ctx, countQ).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := r.db.Select(occurrenceColumns).From("alert_occurrences o").
		LeftJoin("alert_triggers t ON t.id = o.trigger_id").
		Where(pred).OrderBy("o.updated_at DESC").
		Limit(uint64(limit)).Offset(uint64((page - 1) * limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*domain.Occurrence
	for rows.Next() {
		o, err := scanOccurrence(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, o)
	}
	return out, total, rows.Err()
}

// Get loads one occurrence.
func (r *AlertOccurrenceRepo) Get(ctx context.Context, orgID, id string) (*domain.Occurrence, error) {
	q := r.db.Select(occurrenceColumns).From("alert_occurrences o").
		LeftJoin("alert_triggers t ON t.id = o.trigger_id").
		Where(squirrel.Eq{"o.id": id, "o.organization_id": orgID})
	o, err := scanOccurrence(r.db.QueryRow(ctx, q))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return o, nil
}

// Transitions returns the lifecycle history of one occurrence.
func (r *AlertOccurrenceRepo) Transitions(ctx context.Context, orgID, occurrenceID string) ([]*domain.Transition, error) {
	q := r.db.Select(`id, organization_id, occurrence_id, from_state, to_state, event_id,
                observed_value, actor, reason, request_id, created_at`).
		From("alert_transitions").
		Where(squirrel.Eq{"occurrence_id": occurrenceID, "organization_id": orgID}).
		OrderBy("created_at ASC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Transition
	for rows.Next() {
		var t domain.Transition
		if err := rows.Scan(&t.ID, &t.OrgID, &t.OccurrenceID, &t.FromState, &t.ToState,
			&t.EventID, &t.ObservedValue, &t.Actor, &t.Reason, &t.RequestID, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// DeliveriesFor returns delivery attempts of one occurrence.
func (r *AlertOccurrenceRepo) DeliveriesFor(ctx context.Context, orgID, occurrenceID string) ([]*domain.Delivery, error) {
	q := r.db.Select(`d.id, d.organization_id, d.occurrence_id, d.destination_id, d.transition_id,
                d.kind, d.status, d.attempts, d.next_attempt_at, d.last_status_code, d.last_error,
                d.idempotency_key, d.payload, d.created_at, d.sent_at, dest.name`).
		From("alert_deliveries d").
		LeftJoin("alert_destinations dest ON dest.id = d.destination_id").
		Where(squirrel.Eq{"d.occurrence_id": occurrenceID, "d.organization_id": orgID}).
		OrderBy("d.created_at ASC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Delivery
	for rows.Next() {
		var d domain.Delivery
		var transitionID *string
		if err := rows.Scan(&d.ID, &d.OrgID, &d.OccurrenceID, &d.DestinationID, &transitionID,
			&d.Kind, &d.Status, &d.Attempts, &d.NextAttemptAt, &d.LastStatusCode, &d.LastError,
			&d.IdempotencyKey, &d.Payload, &d.CreatedAt, &d.SentAt, &d.DestinationName); err != nil {
			return nil, err
		}
		if transitionID != nil {
			d.TransitionID = *transitionID
		}
		out = append(out, &d)
	}
	return out, rows.Err()
}

// DeliveryStats summarizes delivery health for the destinations view.
func (r *AlertOccurrenceRepo) DeliveryStats(ctx context.Context, orgID string) (map[string]map[string]int, error) {
	sql := `SELECT destination_id, status, count(*) FROM alert_deliveries
                WHERE organization_id = $1 GROUP BY destination_id, status`
	rows, err := r.db.Pool.Query(ctx, sql, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]map[string]int{}
	for rows.Next() {
		var dest, status string
		var n int
		if err := rows.Scan(&dest, &status, &n); err != nil {
			return nil, err
		}
		if out[dest] == nil {
			out[dest] = map[string]int{}
		}
		out[dest][status] = n
	}
	return out, rows.Err()
}

// SetOccurrenceState performs the API-driven lifecycle transitions
// (acknowledge/resolve/suppress) with a transition row, transactionally.
func (r *AlertOccurrenceRepo) SetOccurrenceState(ctx context.Context, orgID, id, toState, actor, reason, requestID string) (*domain.Occurrence, error) {
	var updated *domain.Occurrence
	err := r.db.WithTx(ctx, func(tx pgx.Tx) error {
		// Lock the occurrence row while transitioning.
		var curState string
		err := tx.QueryRow(ctx, `SELECT state FROM alert_occurrences WHERE id = $1 AND organization_id = $2 FOR UPDATE`, id, orgID).Scan(&curState)
		if err != nil {
			return mapNotFound(err)
		}
		now := time.Now().UTC()
		sets := map[string]any{"state": toState, "updated_at": now}
		switch toState {
		case domain.OccurrenceAcknowledged:
			sets["acknowledged_at"] = now
		case domain.OccurrenceRecovered:
			sets["recovered_at"] = now
		case domain.OccurrenceSuppressed:
			sets["recovered_at"] = now
		case domain.OccurrenceFiring:
			// reopen
		default:
			return fmt.Errorf("postgres: invalid occurrence state %q", toState)
		}
		q := r.db.Update("alert_occurrences").SetMap(sets).Where(squirrel.Eq{"id": id, "organization_id": orgID})
		sql, args, err := q.ToSql()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		tid := ids.New()
		_, err = tx.Exec(ctx, `INSERT INTO alert_transitions (id, organization_id, occurrence_id, from_state, to_state, actor, reason, request_id, created_at)
                        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
			tid, orgID, id, curState, toState, actor, reason, requestID, now)
		if err != nil {
			return err
		}
		o, err := scanOccurrence(tx.QueryRow(ctx, `SELECT `+occurrenceColumns+` FROM alert_occurrences o
                        LEFT JOIN alert_triggers t ON t.id = o.trigger_id WHERE o.id = $1 AND o.organization_id = $2`, id, orgID))
		if err != nil {
			return err
		}
		updated = o
		return nil
	})
	return updated, err
}

// ---------------------------------------------------------------------------
// Correlation jobs

type CorrelationJobRepo struct{ db *DB }

func NewCorrelationJobRepo(db *DB) *CorrelationJobRepo { return &CorrelationJobRepo{db: db} }

// Enqueue inserts a job; the idempotency key makes repeated enqueues
// (feed retries, double clicks) collapse into one row.
func (r *CorrelationJobRepo) Enqueue(ctx context.Context, orgID, kind string, payload json.RawMessage, idempotencyKey string) (string, error) {
	id := ids.New()
	var err error
	if idempotencyKey != "" {
		sql := `INSERT INTO correlation_jobs (id, organization_id, kind, payload, idempotency_key)
                        VALUES ($1,$2,$3,$4,$5)
                        ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO UPDATE SET id = correlation_jobs.id
                        RETURNING id`
		err = r.db.Pool.QueryRow(ctx, sql, id, orgID, kind, payload, idempotencyKey).Scan(&id)
		return id, err
	}
	sql := `INSERT INTO correlation_jobs (id, organization_id, kind, payload) VALUES ($1,$2,$3,$4) RETURNING id`
	err = r.db.Pool.QueryRow(ctx, sql, id, orgID, kind, payload).Scan(&id)
	return id, err
}

// Claim leases the next pending (or lease-expired) job.
func (r *CorrelationJobRepo) Claim(ctx context.Context, lease time.Duration) (*domain.CorrelationJob, error) {
	sql := `UPDATE correlation_jobs SET state = 'running', started_at = now(),
                        lease_until = now() + $1, attempts = attempts + 1
                WHERE id = (
                        SELECT id FROM correlation_jobs
                        WHERE (state = 'pending' OR (state = 'running' AND lease_until < now()))
                        ORDER BY created_at
                        LIMIT 1
                        FOR UPDATE SKIP LOCKED
                )
                RETURNING id, organization_id, kind, payload, state, attempts, lease_until, idempotency_key, last_error, created_at, started_at, finished_at`
	var j domain.CorrelationJob
	var payload []byte
	err := r.db.Pool.QueryRow(ctx, sql, lease).Scan(&j.ID, &j.OrgID, &j.Kind, &payload, &j.State,
		&j.Attempts, &j.LeaseUntil, &j.IdempotencyKey, &j.LastError, &j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	j.Payload = payload
	return &j, nil
}

// Finish marks a job done or failed (failed jobs retry up to a cap enforced
// by the worker).
func (r *CorrelationJobRepo) Finish(ctx context.Context, id string, failed bool, errMsg string) error {
	if failed {
		_, err := r.db.Pool.Exec(ctx, `UPDATE correlation_jobs SET state = 'pending', last_error = $2, lease_until = NULL WHERE id = $1`, id, errMsg)
		return err
	}
	_, err := r.db.Pool.Exec(ctx, `UPDATE correlation_jobs SET state = 'done', finished_at = now(), lease_until = NULL, last_error = '' WHERE id = $1`, id)
	return err
}

// ---------------------------------------------------------------------------
// Vulnerability search actions

type VulnSearchRepo struct{ db *DB }

func NewVulnSearchRepo(db *DB) *VulnSearchRepo { return &VulnSearchRepo{db: db} }

const actionColumns = `id, organization_id, name, description, target_kind, selector, mode,
        priority, enabled, version_policy, confidence_cap, revision, created_by, created_at, updated_at`

func scanAction(row pgx.Row) (*domain.VulnSearchAction, error) {
	var a domain.VulnSearchAction
	var selector, vp []byte
	err := row.Scan(&a.ID, &a.OrgID, &a.Name, &a.Description, &a.TargetKind, &selector, &a.Mode,
		&a.Priority, &a.Enabled, &vp, &a.ConfidenceCap, &a.Revision, &a.CreatedBy, &a.CreatedAt, &a.UpdatedAt)
	if err != nil {
		return nil, err
	}
	a.Selector = selector
	a.VersionPolicy = vp
	return &a, nil
}

// CreateAction inserts an action and its first immutable revision.
func (r *VulnSearchRepo) CreateAction(ctx context.Context, a *domain.VulnSearchAction) error {
	if a.ID == "" {
		a.ID = ids.New()
	}
	a.Revision = 1
	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		sql, args, err := r.db.Insert("vuln_search_actions").Columns(
			"id", "organization_id", "name", "description", "target_kind", "selector", "mode",
			"priority", "enabled", "version_policy", "confidence_cap", "revision", "created_by",
		).Values(a.ID, a.OrgID, a.Name, a.Description, a.TargetKind, a.Selector, a.Mode, a.Priority,
			a.Enabled, a.VersionPolicy, a.ConfidenceCap, a.Revision, a.CreatedBy).ToSql()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, sql, args...); err != nil {
			return err
		}
		return r.insertRevision(ctx, tx, a)
	})
}

func (r *VulnSearchRepo) insertRevision(ctx context.Context, tx pgx.Tx, a *domain.VulnSearchAction) error {
	doc, _ := json.Marshal(map[string]any{
		"name": a.Name, "description": a.Description, "target_kind": a.TargetKind,
		"selector": json.RawMessage(a.Selector), "mode": a.Mode, "priority": a.Priority,
		"version_policy": json.RawMessage(a.VersionPolicy), "confidence_cap": a.ConfidenceCap,
	})
	hash := hashJSON(doc)
	_, err := tx.Exec(ctx, `INSERT INTO vuln_search_action_revisions (id, action_id, organization_id, revision, document, hash, reason, author)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		ids.New(), a.ID, a.OrgID, a.Revision, doc, hash, "revision "+fmt.Sprint(a.Revision), a.CreatedBy)
	return err
}

// UpdateAction replaces an action and appends a new immutable revision.
func (r *VulnSearchRepo) UpdateAction(ctx context.Context, a *domain.VulnSearchAction, expectedRevision int) error {
	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		sql, args, err := r.db.Update("vuln_search_actions").SetMap(map[string]any{
			"name": a.Name, "description": a.Description, "target_kind": a.TargetKind,
			"selector": a.Selector, "mode": a.Mode, "priority": a.Priority, "enabled": a.Enabled,
			"version_policy": a.VersionPolicy, "confidence_cap": a.ConfidenceCap,
			"revision": expectedRevision + 1, "updated_at": time.Now().UTC(),
		}).Where(squirrel.Eq{"id": a.ID, "organization_id": a.OrgID, "revision": expectedRevision}).ToSql()
		if err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, sql, args...)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrConflict
		}
		a.Revision = expectedRevision + 1
		return r.insertRevision(ctx, tx, a)
	})
}

// DeleteAction removes an action (runs and revisions are retained).
func (r *VulnSearchRepo) DeleteAction(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("vuln_search_actions").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return r.db.ExecOne(ctx, q, "search action delete")
}

// GetAction loads one action.
func (r *VulnSearchRepo) GetAction(ctx context.Context, orgID, id string) (*domain.VulnSearchAction, error) {
	q := r.db.Select(actionColumns).From("vuln_search_actions").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	a, err := scanAction(r.db.QueryRow(ctx, q))
	if err != nil {
		return nil, mapNotFound(err)
	}
	return a, nil
}

// ListActions returns the actions of an org.
func (r *VulnSearchRepo) ListActions(ctx context.Context, orgID string) ([]*domain.VulnSearchAction, error) {
	q := r.db.Select(actionColumns).From("vuln_search_actions").
		Where(squirrel.Eq{"organization_id": orgID}).OrderBy("priority ASC, created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.VulnSearchAction
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// EnabledActions returns enabled actions of an org ordered by priority.
func (r *VulnSearchRepo) EnabledActions(ctx context.Context, orgID string) ([]*domain.VulnSearchAction, error) {
	q := r.db.Select(actionColumns).From("vuln_search_actions").
		Where(squirrel.Eq{"organization_id": orgID, "enabled": true}).OrderBy("priority ASC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.VulnSearchAction
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CreateRun inserts a run row (idempotent on the key).
func (r *VulnSearchRepo) CreateRun(ctx context.Context, run *domain.VulnSearchRun) error {
	if run.ID == "" {
		run.ID = ids.New()
	}
	if run.IdempotencyKey != "" {
		sql := `INSERT INTO vuln_search_runs (id, organization_id, action_id, revision, requester, idempotency_key)
                        VALUES ($1,$2,$3,$4,$5,$6)
                        ON CONFLICT (idempotency_key) WHERE idempotency_key IS NOT NULL DO UPDATE SET id = vuln_search_runs.id
                        RETURNING id, revision`
		return r.db.Pool.QueryRow(ctx, sql, run.ID, run.OrgID, run.ActionID, run.Revision,
			run.Requester, run.IdempotencyKey).Scan(&run.ID, &run.Revision)
	}
	sql := `INSERT INTO vuln_search_runs (id, organization_id, action_id, revision, requester)
                VALUES ($1,$2,$3,$4,$5)`
	_, err := r.db.Pool.Exec(ctx, sql, run.ID, run.OrgID, run.ActionID, run.Revision, run.Requester)
	return err
}

// UpdateRunState tracks run lifecycle.
func (r *VulnSearchRepo) UpdateRunState(ctx context.Context, id, state string, progress int) error {
	sets := map[string]any{"state": state, "progress": progress}
	if state == "running" {
		sets["started_at"] = time.Now().UTC()
	}
	if state == "completed" || state == "failed" {
		sets["finished_at"] = time.Now().UTC()
	}
	q := r.db.Update("vuln_search_runs").SetMap(sets).Where(squirrel.Eq{"id": id})
	return r.db.ExecOne(ctx, q, "run state update")
}

// FinishRun records final counters.
func (r *VulnSearchRepo) FinishRun(ctx context.Context, id, state string, candidates, matches, created int, errs json.RawMessage) error {
	sql := `UPDATE vuln_search_runs SET state = $2, progress = 100, candidates = $3, matches = $4,
                findings_created = $5, errors = $6, finished_at = now() WHERE id = $1`
	_, err := r.db.Pool.Exec(ctx, sql, id, state, candidates, matches, created, errs)
	return err
}

// GetRun loads one run.
func (r *VulnSearchRepo) GetRun(ctx context.Context, orgID, id string) (*domain.VulnSearchRun, error) {
	q := r.db.Select(`id, organization_id, action_id, revision, state, progress, requester,
                idempotency_key, candidates, matches, findings_created, errors, started_at, finished_at, created_at`).
		From("vuln_search_runs").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	var run domain.VulnSearchRun
	var errs []byte
	err := r.db.QueryRow(ctx, q).Scan(&run.ID, &run.OrgID, &run.ActionID, &run.Revision, &run.State,
		&run.Progress, &run.Requester, &run.IdempotencyKey, &run.Candidates, &run.Matches,
		&run.FindingsCreated, &errs, &run.StartedAt, &run.FinishedAt, &run.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	run.Errors = errs
	return &run, nil
}

// ListRuns returns recent runs of an action.
func (r *VulnSearchRepo) ListRuns(ctx context.Context, orgID, actionID string, limit int) ([]*domain.VulnSearchRun, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := r.db.Select(`id, organization_id, action_id, revision, state, progress, requester,
                idempotency_key, candidates, matches, findings_created, errors, started_at, finished_at, created_at`).
		From("vuln_search_runs").Where(squirrel.Eq{"organization_id": orgID, "action_id": actionID}).
		OrderBy("created_at DESC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.VulnSearchRun
	for rows.Next() {
		var run domain.VulnSearchRun
		var errs []byte
		if err := rows.Scan(&run.ID, &run.OrgID, &run.ActionID, &run.Revision, &run.State,
			&run.Progress, &run.Requester, &run.IdempotencyKey, &run.Candidates, &run.Matches,
			&run.FindingsCreated, &errs, &run.StartedAt, &run.FinishedAt, &run.CreatedAt); err != nil {
			return nil, err
		}
		run.Errors = errs
		out = append(out, &run)
	}
	return out, rows.Err()
}

// InsertProvenance records why one match exists.
func (r *VulnSearchRepo) InsertProvenance(ctx context.Context, p *domain.VulnMatchProvenance) error {
	if p.ID == "" {
		p.ID = ids.New()
	}
	sql := `INSERT INTO vuln_match_provenance (id, organization_id, finding_id, action_id, revision,
                run_id, target_type, target_id, origin, source, cpe_key, match_type, confidence, observed_identity, reason)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	_, err := r.db.Pool.Exec(ctx, sql, p.ID, p.OrgID, p.FindingID, p.ActionID, p.Revision, p.RunID,
		p.TargetType, p.TargetID, p.Origin, p.Source, p.CPEKey, p.MatchType, p.Confidence,
		p.ObservedIdentity, p.Reason)
	return err
}

// ProvenanceForFinding returns provenance rows of one finding.
func (r *VulnSearchRepo) ProvenanceForFinding(ctx context.Context, orgID, findingID string) ([]*domain.VulnMatchProvenance, error) {
	q := r.db.Select(`id, organization_id, finding_id, action_id, revision, run_id, target_type,
                target_id, origin, source, cpe_key, match_type, confidence, observed_identity, reason, created_at`).
		From("vuln_match_provenance").Where(squirrel.Eq{"organization_id": orgID, "finding_id": findingID}).
		OrderBy("created_at ASC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.VulnMatchProvenance
	for rows.Next() {
		var p domain.VulnMatchProvenance
		var actionID, runID *string
		var rev *int
		if err := rows.Scan(&p.ID, &p.OrgID, &p.FindingID, &actionID, &rev, &runID, &p.TargetType,
			&p.TargetID, &p.Origin, &p.Source, &p.CPEKey, &p.MatchType, &p.Confidence,
			&p.ObservedIdentity, &p.Reason, &p.CreatedAt); err != nil {
			return nil, err
		}
		if actionID != nil {
			p.ActionID = *actionID
		}
		if runID != nil {
			p.RunID = *runID
		}
		if rev != nil {
			p.Revision = *rev
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// Identity alias CRUD (compact: used by the search-action identity step).

func (r *VulnSearchRepo) UpsertAlias(ctx context.Context, a *domain.VulnIdentityAlias) error {
	if a.ID == "" {
		a.ID = ids.New()
	}
	sql := `INSERT INTO vuln_identity_aliases (id, organization_id, name, vendor, product, ecosystem,
                canonical_part, canonical_vendor, canonical_product, canonical_ecosystem, confidence, reason, created_by)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
                ON CONFLICT (organization_id, name, vendor, product) DO UPDATE SET
                        canonical_part = EXCLUDED.canonical_part, canonical_vendor = EXCLUDED.canonical_vendor,
                        canonical_product = EXCLUDED.canonical_product, canonical_ecosystem = EXCLUDED.canonical_ecosystem,
                        confidence = EXCLUDED.confidence, reason = EXCLUDED.reason`
	_, err := r.db.Pool.Exec(ctx, sql, a.ID, a.OrgID, a.Name, a.Vendor, a.Product, a.Ecosystem,
		a.CanonicalPart, a.CanonicalVendor, a.CanonicalProduct, a.CanonicalEcosystem,
		a.Confidence, a.Reason, a.CreatedBy)
	return err
}

// AliasFor resolves the operator-curated identity for an observed product.
func (r *VulnSearchRepo) AliasFor(ctx context.Context, orgID, name, vendor, product string) (*domain.VulnIdentityAlias, error) {
	q := r.db.Select(`id, organization_id, name, vendor, product, ecosystem, canonical_part,
                canonical_vendor, canonical_product, canonical_ecosystem, confidence, reason, created_by, created_at`).
		From("vuln_identity_aliases").Where(squirrel.Eq{"organization_id": orgID, "name": name})
	if vendor != "" {
		q = q.Where(squirrel.Eq{"vendor": vendor})
	}
	if product != "" {
		q = q.Where(squirrel.Eq{"product": product})
	}
	var a domain.VulnIdentityAlias
	err := r.db.QueryRow(ctx, q).Scan(&a.ID, &a.OrgID, &a.Name, &a.Vendor, &a.Product, &a.Ecosystem,
		&a.CanonicalPart, &a.CanonicalVendor, &a.CanonicalProduct, &a.CanonicalEcosystem,
		&a.Confidence, &a.Reason, &a.CreatedBy, &a.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &a, nil
}

// hashJSON returns a stable content hash of a revision document.
func hashJSON(b []byte) string { return sha256Sum(b) }

// ListRecent returns recent outbox events of one org (optionally filtered
// by type) — the bounded sample the trigger Test action replays.
func (r *OutboxRepo) ListRecent(ctx context.Context, orgID string, types []string, limit int) ([]domain.OutboxEvent, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := r.db.Select(`id, organization_id, type, schema_version, subject_type, subject_id,
		site_id, asset_id, entity_type, entity_id, occurred_at, recorded_at,
		payload, correlation_id, causation_id, dedup_key, published_at, attempts, next_attempt_at, last_error`).
		From("event_outbox").Where(squirrel.Eq{"organization_id": orgID})
	if len(types) > 0 {
		q = q.Where(squirrel.Expr("type = ANY($1)", pqTextArray(types)))
	}
	q = q.OrderBy("recorded_at DESC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.OutboxEvent
	for rows.Next() {
		var e domain.OutboxEvent
		var siteID, assetID *string
		if err := rows.Scan(&e.ID, &e.OrgID, &e.Type, &e.SchemaVersion, &e.SubjectType, &e.SubjectID,
			&siteID, &assetID, &e.EntityType, &e.EntityID, &e.OccurredAt, &e.RecordedAt,
			&e.Payload, &e.CorrelationID, &e.CausationID, &e.DedupKey, &e.PublishedAt, &e.Attempts,
			&e.NextAttemptAt, &e.LastError); err != nil {
			return nil, err
		}
		if siteID != nil {
			e.SiteID = *siteID
		}
		if assetID != nil {
			e.AssetID = *assetID
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// pqTextArray adapts []string for squirrel's Expr parameter.
func pqTextArray(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// DeadCount returns dead deliveries per destination for the org.
func (r *AlertOccurrenceRepo) DeadCount(ctx context.Context, orgID string) (int64, error) {
	var n int64
	err := r.db.QueryRow(ctx, r.db.Select("count(*)").From("alert_deliveries").
		Where(squirrel.Eq{"organization_id": orgID, "status": "dead"})).Scan(&n)
	return n, err
}
