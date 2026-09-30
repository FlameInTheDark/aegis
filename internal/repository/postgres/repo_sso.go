package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ===================================================================== org sso

type SSORepo struct{ db *DB }

func NewSSORepo(db *DB) *SSORepo { return &SSORepo{db: db} }

const ssoColumns = `id, organization_id, issuer, client_id, client_secret, groups_claim,
role_mappings, default_role, allow_jit, enabled, created_at, updated_at`

func scanSSO(row scanner) (*domain.SSOConfig, error) {
	var c domain.SSOConfig
	var mappings []byte
	if err := row.Scan(&c.ID, &c.OrgID, &c.Issuer, &c.ClientID, &c.ClientSecret, &c.GroupsClaim,
		&mappings, &c.DefaultRole, &c.AllowJIT, &c.Enabled, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, mapNotFound(err)
	}
	if len(mappings) > 0 {
		_ = json.Unmarshal(mappings, &c.RoleMappings)
	}
	if c.GroupsClaim == "" {
		c.GroupsClaim = "groups"
	}
	if c.ClientSecret != "" {
		c.SecretMasked = maskSecret(c.ClientSecret)
	}
	return &c, nil
}

// Get returns the org's SSO config; ErrNotFound when none exists.
func (r *SSORepo) Get(ctx context.Context, orgID string) (*domain.SSOConfig, error) {
	q := r.db.Select(ssoColumns).From("org_sso").Where(squirrel.Eq{"organization_id": orgID})
	return scanSSO(r.db.QueryRow(ctx, q))
}

// ListEnabled returns every enabled config with its organization name for
// the public login-page provider list.
func (r *SSORepo) ListEnabled(ctx context.Context) ([]domain.SSOConfig, error) {
	q := r.db.Select(ssoColumns).From("org_sso").Where(squirrel.Eq{"enabled": true}).OrderBy("created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.SSOConfig
	for rows.Next() {
		c, err := scanSSO(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *c)
	}
	return out, rows.Err()
}

// Upsert stores or updates the org's SSO config; an empty secret keeps the
// existing one (same rotation rule as destinations).
func (r *SSORepo) Upsert(ctx context.Context, c *domain.SSOConfig) error {
	if c.ID == "" {
		c.ID = ids.New()
	}
	now := time.Now().UTC()
	mappings, _ := json.Marshal(c.RoleMappings)
	if mappings == nil {
		mappings = []byte(`{}`)
	}
	q := r.db.Insert("org_sso").
		Columns("id", "organization_id", "issuer", "client_id", "client_secret", "groups_claim", "role_mappings", "default_role", "allow_jit", "enabled", "created_at", "updated_at").
		Values(c.ID, c.OrgID, c.Issuer, c.ClientID, c.ClientSecret, c.GroupsClaim, mappings,
			c.DefaultRole, c.AllowJIT, c.Enabled, now, now).
		Suffix(`ON CONFLICT (organization_id) DO UPDATE SET
                        issuer = EXCLUDED.issuer, client_id = EXCLUDED.client_id,
                        client_secret = CASE WHEN COALESCE(EXCLUDED.client_secret, '') <> '' THEN EXCLUDED.client_secret ELSE org_sso.client_secret END,
                        groups_claim = EXCLUDED.groups_claim, role_mappings = EXCLUDED.role_mappings,
                        default_role = EXCLUDED.default_role, allow_jit = EXCLUDED.allow_jit,
                        enabled = EXCLUDED.enabled, updated_at = now()`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// Delete removes the org's SSO config.
func (r *SSORepo) Delete(ctx context.Context, orgID string) error {
	q := r.db.Delete("org_sso").Where(squirrel.Eq{"organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}
