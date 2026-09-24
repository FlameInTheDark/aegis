package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Masterminds/squirrel"
)

// SettingsRepo is the platform key/value settings store (migration 0034).
// Keys and their value shapes are defined by the settings API; the repo is
// shape-agnostic — it stores whatever JSONB the caller hands over.
type SettingsRepo struct{ db *DB }

func NewSettingsRepo(db *DB) *SettingsRepo { return &SettingsRepo{db: db} }

// SettingsEntry is one stored key with its decoded value.
type SettingsEntry struct {
	Key       string
	Value     json.RawMessage
	UpdatedAt time.Time
}

// Get returns the stored value for key; a missing key yields (nil, nil) —
// callers apply their documented defaults.
func (r *SettingsRepo) Get(ctx context.Context, key string) (json.RawMessage, error) {
	q := r.db.Select("value").From("settings").Where(squirrel.Eq{"key": key})
	var raw json.RawMessage
	if err := r.db.QueryRow(ctx, q).Scan(&raw); err != nil {
		if mapNotFound(err) == ErrNotFound {
			return nil, nil
		}
		return nil, err
	}
	return raw, nil
}

// List returns every stored entry (small table — no pagination needed).
func (r *SettingsRepo) List(ctx context.Context) ([]SettingsEntry, error) {
	q := r.db.Select("key", "value", "updated_at").From("settings").OrderBy("key")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SettingsEntry
	for rows.Next() {
		var e SettingsEntry
		if err := rows.Scan(&e.Key, &e.Value, &e.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// Set upserts one key. `value` must already be encoded JSON.
func (r *SettingsRepo) Set(ctx context.Context, key string, value json.RawMessage) error {
	q := r.db.Insert("settings").
		Columns("key", "value", "updated_at").
		Values(key, value, time.Now()).
		Suffix(`ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at`)
	_, err := r.db.Exec(ctx, q)
	return err
}
