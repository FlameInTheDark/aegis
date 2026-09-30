package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/ids"
)

// =============================================================== ingest tokens

// IngestToken is one sensor credential (F11). Hash is the SHA-256 of the
// plaintext token; the plaintext is returned exactly once at creation and
// never stored.
type IngestToken struct {
	ID         string     `json:"id"`
	OrgID      string     `json:"organization_id"`
	Name       string     `json:"name"`
	Hash       string     `json:"-"`
	Prefix     string     `json:"prefix,omitempty"`
	CreatedBy  string     `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// HashIngestToken derives the stored hash of a plaintext ingest token.
func HashIngestToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type IngestTokenRepo struct{ db *DB }

func NewIngestTokenRepo(db *DB) *IngestTokenRepo { return &IngestTokenRepo{db: db} }

// Create stores a new token; the plaintext rides back to the caller via
// the struct's Prefix + returned token, never persisted.
func (r *IngestTokenRepo) Create(ctx context.Context, t *IngestToken, plaintext string) error {
	if t.ID == "" {
		t.ID = ids.New()
	}
	t.Hash = HashIngestToken(plaintext)
	q := r.db.Insert("event_ingest_tokens").
		Columns("id", "organization_id", "name", "token_hash", "prefix", "created_by").
		Values(t.ID, t.OrgID, t.Name, t.Hash, t.Prefix, nullStr(t.CreatedBy))
	_, err := r.db.Exec(ctx, q)
	return err
}

// List returns the org's tokens, newest first.
func (r *IngestTokenRepo) List(ctx context.Context, orgID string) ([]IngestToken, error) {
	q := r.db.Select("id, organization_id::text, name, token_hash, COALESCE(prefix,''), COALESCE(created_by::text,''), created_at, revoked_at, last_used_at").
		From("event_ingest_tokens").
		Where(squirrel.Eq{"organization_id": orgID}).
		OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IngestToken
	for rows.Next() {
		var t IngestToken
		if err := rows.Scan(&t.ID, &t.OrgID, &t.Name, &t.Hash, &t.Prefix, &t.CreatedBy,
			&t.CreatedAt, &t.RevokedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// GetByHash resolves a presented token. Revoked tokens read as not found.
func (r *IngestTokenRepo) GetByHash(ctx context.Context, hash string) (*IngestToken, error) {
	q := r.db.Select("id, organization_id::text, name, token_hash, COALESCE(prefix,''), COALESCE(created_by::text,''), created_at, revoked_at, last_used_at").
		From("event_ingest_tokens").
		Where(squirrel.Eq{"token_hash": hash}).
		Where(squirrel.Expr("revoked_at IS NULL"))
	var t IngestToken
	err := r.db.QueryRow(ctx, q).Scan(&t.ID, &t.OrgID, &t.Name, &t.Hash, &t.Prefix, &t.CreatedBy,
		&t.CreatedAt, &t.RevokedAt, &t.LastUsedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return &t, nil
}

// Revoke marks a token revoked; further use fails immediately.
func (r *IngestTokenRepo) Revoke(ctx context.Context, orgID, id string) error {
	q := r.db.Update("event_ingest_tokens").
		Set("revoked_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id, "organization_id": orgID}).
		Where(squirrel.Expr("revoked_at IS NULL"))
	res, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if res.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchLastUsed records sensor liveness — the "last event received" age the
// sensor setup panel shows. Fire-and-forget from the ingest path.
func (r *IngestTokenRepo) TouchLastUsed(ctx context.Context, id string) {
	q := r.db.Update("event_ingest_tokens").
		Set("last_used_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id})
	_, _ = r.db.Exec(ctx, q)
}
