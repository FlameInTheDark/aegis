package postgres

import (
	"context"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// =============================================================== org integrations

type IntegrationRepo struct{ db *DB }

func NewIntegrationRepo(db *DB) *IntegrationRepo { return &IntegrationRepo{db: db} }

const integrationColumns = `id, organization_id, kind, COALESCE(config,'{}'::jsonb) AS config, secret, COALESCE(created_by::text,''), created_at, updated_at`

func scanIntegration(row scanner) (*domain.Integration, error) {
	var i domain.Integration
	if err := row.Scan(&i.ID, &i.OrgID, &i.Kind, &i.Config, &i.Secret, &i.CreatedBy, &i.CreatedAt, &i.UpdatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	if i.Secret != "" {
		i.SecretMasked = maskSecret(i.Secret)
	}
	return &i, nil
}

// Get returns one integration; ErrNotFound when the org has none of that kind.
func (r *IntegrationRepo) Get(ctx context.Context, orgID, kind string) (*domain.Integration, error) {
	q := r.db.Select(integrationColumns).From("org_integrations").
		Where(squirrel.Eq{"organization_id": orgID, "kind": kind})
	return scanIntegration(r.db.QueryRow(ctx, q))
}

// HasSecret reports whether the org's integration of kind carries a token
// (Get for the masked API surface must not leak configured-ness of nothing).
func (r *IntegrationRepo) Upsert(ctx context.Context, i *domain.Integration) error {
	if i.ID == "" {
		i.ID = ids.New()
	}
	now := time.Now().UTC()
	q := r.db.Insert("org_integrations").
		Columns("id", "organization_id", "kind", "config", "secret", "created_by", "created_at", "updated_at").
		Values(i.ID, i.OrgID, i.Kind, nullJSON(i.Config), i.Secret, nullStr(i.CreatedBy), now, now).
		Suffix(`ON CONFLICT (organization_id, kind) DO UPDATE SET
                        config = EXCLUDED.config,
                        updated_at = now(),
                        secret = CASE WHEN COALESCE(EXCLUDED.secret, '') <> '' THEN EXCLUDED.secret ELSE org_integrations.secret END`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// Delete removes an org's integration of one kind.
func (r *IntegrationRepo) Delete(ctx context.Context, orgID, kind string) error {
	q := r.db.Delete("org_integrations").
		Where(squirrel.Eq{"organization_id": orgID, "kind": kind})
	_, err := r.db.Exec(ctx, q)
	return err
}
