package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== detection rules

type RuleRepo struct{ db *DB }

func NewRuleRepo(db *DB) *RuleRepo { return &RuleRepo{db: db} }

const ruleCols = `id, organization_id, title, identifier, status, description, refs,
author, tags, logsource, level, false_positives, type, event_type, conditions, threshold,
window_spec, group_by, enabled, created_at, updated_at`

func scanRule(row scanner) (*domain.DetectionRule, error) {
	var r domain.DetectionRule
	err := row.Scan(&r.ID, &r.OrgID, &r.Title, &r.Identifier, &r.Status, &r.Description,
		&r.References, &r.Author, &r.Tags, &r.LogSource, &r.Level, &r.FalsePositives,
		&r.Type, &r.EventType, &r.Conditions, &r.Threshold, &r.Window, &r.GroupBy,
		&r.Enabled, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &r, nil
}

func (r *RuleRepo) Upsert(ctx context.Context, rule *domain.DetectionRule) error {
	if rule.ID == "" {
		rule.ID = ids.New()
	}
	cond, _ := json.Marshal(rule.Conditions)
	thr, _ := json.Marshal(rule.Threshold)
	logsrc, _ := json.Marshal(rule.LogSource)
	q := r.db.Insert("detection_rules").
		Columns("id", "organization_id", "title", "identifier", "status", "description",
			"refs", "author", "tags", "logsource", "level", "false_positives",
			"type", "event_type", "conditions", "threshold", "window_spec", "group_by", "enabled").
		Values(rule.ID, rule.OrgID, rule.Title, rule.Identifier, rule.Status, rule.Description,
			nonNil(rule.References), rule.Author, nonNil(rule.Tags), logsrc, rule.Level, nonNil(rule.FalsePositives),
			rule.Type, rule.EventType, cond, thr, rule.Window, nonNil(rule.GroupBy), rule.Enabled).
		Suffix(`ON CONFLICT (organization_id, identifier) DO UPDATE SET
                        title = EXCLUDED.title, status = EXCLUDED.status, description = EXCLUDED.description,
                        refs = EXCLUDED.refs, author = EXCLUDED.author, tags = EXCLUDED.tags,
                        logsource = EXCLUDED.logsource, level = EXCLUDED.level,
                        false_positives = EXCLUDED.false_positives, type = EXCLUDED.type,
                        event_type = EXCLUDED.event_type, conditions = EXCLUDED.conditions,
                        threshold = EXCLUDED.threshold, window_spec = EXCLUDED.window_spec,
                        group_by = EXCLUDED.group_by, enabled = EXCLUDED.enabled, updated_at = now()
                        RETURNING id, created_at, updated_at`)
	return r.db.QueryRow(ctx, q).Scan(&rule.ID, &rule.CreatedAt, &rule.UpdatedAt)
}

func (r *RuleRepo) List(ctx context.Context, orgID string) ([]domain.DetectionRule, error) {
	q := r.db.Select(ruleCols).From("detection_rules").
		Where(squirrel.Eq{"organization_id": orgID}).OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.DetectionRule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rule)
	}
	return out, rows.Err()
}

func (r *RuleRepo) Enabled(ctx context.Context, orgID string) ([]domain.DetectionRule, error) {
	q := r.db.Select(ruleCols).From("detection_rules").
		Where(squirrel.Eq{"organization_id": orgID, "enabled": true})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.DetectionRule
	for rows.Next() {
		rule, err := scanRule(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *rule)
	}
	return out, rows.Err()
}

func (r *RuleRepo) SetEnabled(ctx context.Context, orgID, id string, enabled bool) error {
	q := r.db.Update("detection_rules").
		Set("enabled", enabled).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *RuleRepo) ByID(ctx context.Context, orgID, id string) (*domain.DetectionRule, error) {
	q := r.db.Select(ruleCols).From("detection_rules").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return scanRule(r.db.QueryRow(ctx, q))
}

// ==================================================================== detection matches

type MatchRepo struct{ db *DB }

func NewMatchRepo(db *DB) *MatchRepo { return &MatchRepo{db: db} }

func (r *MatchRepo) Insert(ctx context.Context, m *domain.DetectionMatch) error {
	if m.ID == "" {
		m.ID = ids.New()
	}
	tl, _ := json.Marshal(m.Timeline)
	q := r.db.Insert("detection_matches").
		Columns("id", "organization_id", "rule_id", "rule_title", "level", "site_id", "asset_id",
			"src_ip", "entity", "summary", "event_ids", "count", "timeline", "timestamp").
		Values(m.ID, m.OrgID, m.RuleID, m.RuleTitle, string(m.Level), nullStr(m.SiteID),
			nullStr(m.AssetID), nullStr(m.SrcIP), m.Entity, m.Summary, nonNil(m.Events), m.Count, tl, m.Timestamp)
	_, err := r.db.Exec(ctx, q)
	return err
}

// MatchFilter constrains match listings.
type MatchFilter struct {
	OrgID  string
	RuleID string
	Level  string
	Status string
	Limit  int
	Page   int
}

// SetStatus moves a match through the triage workflow; returns
// ErrNotFound when the row (org-scoped) does not exist.
func (r *MatchRepo) SetStatus(ctx context.Context, orgID, id string, status domain.MatchStatus) error {
	q := r.db.Update("detection_matches").
		Set("status", string(status)).
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	cmd, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *MatchRepo) List(ctx context.Context, f MatchFilter) ([]domain.DetectionMatch, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page < 1 {
		f.Page = 1
	}
	where := squirrel.Eq{"organization_id": f.OrgID}
	if f.RuleID != "" {
		where["rule_id"] = f.RuleID
	}
	if f.Level != "" {
		where["level"] = f.Level
	}
	if f.Status != "" {
		where["status"] = f.Status
	}
	q := r.db.Select(`id, organization_id, rule_id::text, rule_title, level, COALESCE(site_id::text,'') AS site_id,
                COALESCE(asset_id::text,'') AS asset_id, COALESCE(src_ip::text,'') AS src_ip, entity, summary, event_ids, count, timeline, timestamp, status`).
		From("detection_matches").Where(where)
	var total int64
	// count must be its own query: appending count(*) to the column list
	// would mix aggregates with plain columns (invalid without GROUP BY).
	cq := r.db.Select("count(*)").From("detection_matches").Where(where)
	if err := r.db.QueryRow(ctx, cq).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx, q.OrderBy("timestamp DESC").
		Limit(uint64(f.Limit)).Offset(uint64((f.Page-1)*f.Limit)))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.DetectionMatch
	for rows.Next() {
		var m domain.DetectionMatch
		if err := rows.Scan(&m.ID, &m.OrgID, &m.RuleID, &m.RuleTitle, &m.Level, &m.SiteID,
			&m.AssetID, &m.SrcIP, &m.Entity, &m.Summary, &m.Events, &m.Count, &m.Timeline,
			&m.Timestamp, &m.Status); err != nil {
			return nil, 0, err
		}
		out = append(out, m)
	}
	return out, total, rows.Err()
}

// ==================================================================== baselines

type BaselineRepo struct{ db *DB }

func NewBaselineRepo(db *DB) *BaselineRepo { return &BaselineRepo{db: db} }

func (r *BaselineRepo) Upsert(ctx context.Context, b *domain.Baseline) error {
	q := r.db.Insert("baselines").
		Columns("entity", "metric", "mean", "stddev", "sample_size", "window_days", "updated_at").
		Values(b.Entity, b.Metric, b.Mean, b.StdDev, b.SampleSize, b.WindowDays, time.Now().UTC()).
		Suffix(`ON CONFLICT (entity, metric) DO UPDATE SET
                        mean = EXCLUDED.mean, stddev = EXCLUDED.stddev,
                        sample_size = EXCLUDED.sample_size, updated_at = now()`)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *BaselineRepo) Get(ctx context.Context, entity, metric string) (*domain.Baseline, error) {
	q := r.db.Select("entity, metric, mean, stddev, sample_size, window_days, updated_at").
		From("baselines").Where(squirrel.Eq{"entity": entity, "metric": metric})
	var b domain.Baseline
	err := r.db.QueryRow(ctx, q).Scan(&b.Entity, &b.Metric, &b.Mean, &b.StdDev,
		&b.SampleSize, &b.WindowDays, &b.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &b, nil
}

// ==================================================================== webhooks

type WebhookRepo struct{ db *DB }

func NewWebhookRepo(db *DB) *WebhookRepo { return &WebhookRepo{db: db} }

func (r *WebhookRepo) Insert(ctx context.Context, w *domain.WebhookConfig) error {
	if w.ID == "" {
		w.ID = ids.New()
	}
	q := r.db.Insert("webhook_configs").
		Columns("id", "organization_id", "name", "url", "events", "enabled").
		Values(w.ID, w.OrgID, w.Name, w.URL, w.Events, w.Enabled)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *WebhookRepo) List(ctx context.Context, orgID string) ([]domain.WebhookConfig, error) {
	q := r.db.Select("id, organization_id, name, url, events, enabled, last_fired, created_at").
		From("webhook_configs").Where(squirrel.Eq{"organization_id": orgID}).OrderBy("created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.WebhookConfig
	for rows.Next() {
		var w domain.WebhookConfig
		if err := rows.Scan(&w.ID, &w.OrgID, &w.Name, &w.URL, &w.Events, &w.Enabled, &w.LastFired, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (r *WebhookRepo) Enabled(ctx context.Context, orgID string) ([]domain.WebhookConfig, error) {
	q := r.db.Select("id, organization_id, name, url, events, enabled, last_fired, created_at").
		From("webhook_configs").
		Where(squirrel.Eq{"organization_id": orgID, "enabled": true})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.WebhookConfig
	for rows.Next() {
		var w domain.WebhookConfig
		if err := rows.Scan(&w.ID, &w.OrgID, &w.Name, &w.URL, &w.Events, &w.Enabled, &w.LastFired, &w.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

func (r *WebhookRepo) MarkFired(ctx context.Context, id string) error {
	q := r.db.Update("webhook_configs").Set("last_fired", time.Now().UTC()).
		Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}
