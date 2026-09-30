package postgres

import (
	"context"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	"github.com/Masterminds/squirrel"
)

// ================================================================== saved views

type SavedViewRepo struct{ db *DB }

func NewSavedViewRepo(db *DB) *SavedViewRepo { return &SavedViewRepo{db: db} }

// List returns the calling user's views for one page, newest first.
func (r *SavedViewRepo) List(ctx context.Context, orgID, userID, page string) ([]domain.SavedView, error) {
	q := r.db.Select("id, organization_id::text, user_id::text, page, name, query, created_at").
		From("saved_views").
		Where(squirrel.Eq{"organization_id": orgID, "user_id": userID, "page": page}).
		OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SavedView
	for rows.Next() {
		var v domain.SavedView
		if err := rows.Scan(&v.ID, &v.OrgID, &v.UserID, &v.Page, &v.Name, &v.Query, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Create stores a named view; the (user, page, name) unique constraint makes
// re-saving an updated query an explicit delete + re-create.
func (r *SavedViewRepo) Create(ctx context.Context, v *domain.SavedView) error {
	if v.ID == "" {
		v.ID = ids.New()
	}
	if v.CreatedAt.IsZero() {
		v.CreatedAt = time.Now().UTC()
	}
	q := r.db.Insert("saved_views").
		Columns("id", "organization_id", "user_id", "page", "name", "query", "created_at").
		Values(v.ID, v.OrgID, v.UserID, v.Page, v.Name, v.Query, v.CreatedAt).
		Suffix("ON CONFLICT (user_id, page, name) DO UPDATE SET query = EXCLUDED.query, created_at = EXCLUDED.created_at")
	_, err := r.db.Exec(ctx, q)
	return err
}

// Delete removes one of the caller's views; the org filter keeps tenancy
// in the query, per the project's standing rule.
func (r *SavedViewRepo) Delete(ctx context.Context, orgID, userID, id string) error {
	q := r.db.Delete("saved_views").
		Where(squirrel.Eq{"id": id, "organization_id": orgID, "user_id": userID})
	_, err := r.db.Exec(ctx, q)
	return err
}
