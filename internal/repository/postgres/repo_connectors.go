package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// connectorCols renders nullable UUID/JSONB columns as text so scanning is
// a plain string/RawMessage affair (same pattern as repo_agents.go).
var connectorCols = []string{
	"id", "organization_id", "COALESCE(site_id::text,'') AS site_id", "kind", "name", "status",
	"hostname", "platform", "arch", "version",
	"COALESCE(capabilities::text,'[]') AS capabilities", "COALESCE(config::text,'{}') AS config",
	"config_version", "enrolled_at", "last_seen", "shutdown_at",
	"COALESCE(last_status::text,'') AS last_status",
	"COALESCE(created_by::text,'') AS created_by", "created_at", "updated_at",
}

func scanConnector(row pgx.Row) (*domain.Connector, error) {
	var c domain.Connector
	var enrolledAt, lastSeen, shutdownAt *time.Time
	var lastStatus string
	err := row.Scan(&c.ID, &c.OrganizationID, &c.SiteID, &c.Kind, &c.Name, &c.Status,
		&c.Hostname, &c.Platform, &c.Arch, &c.Version,
		&c.Capabilities, &c.Config,
		&c.ConfigVersion, &enrolledAt, &lastSeen, &shutdownAt,
		&lastStatus,
		&c.CreatedBy, &c.CreatedAt, &c.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if lastStatus != "" {
		c.LastStatus = json.RawMessage(lastStatus)
	}
	c.EnrolledAt, c.LastSeen, c.ShutdownAt = enrolledAt, lastSeen, shutdownAt
	return &c, nil
}

// ConnectorRepo persists external connector records (agents, scanners,
// collectors) — the unified registry behind aegis.connector.v1.
type ConnectorRepo struct{ db *DB }

// NewConnectorRepo builds a connector repository.
func NewConnectorRepo(db *DB) *ConnectorRepo { return &ConnectorRepo{db: db} }

// Create inserts a new connector in `pending` state.
func (r *ConnectorRepo) Create(ctx context.Context, c *domain.Connector) error {
	if c.ID == "" {
		c.ID = ids.New()
	}
	if len(c.Config) == 0 {
		c.Config = json.RawMessage(`{}`)
	}
	if len(c.Capabilities) == 0 {
		c.Capabilities = json.RawMessage(`[]`)
	}
	q := r.db.Insert("connectors").Columns(
		"id", "organization_id", "site_id", "kind", "name", "status",
		"capabilities", "config", "config_version", "created_by",
	).Values(
		c.ID, c.OrganizationID, nullStr(c.SiteID), string(c.Kind), c.Name,
		domain.ConnectorStatusPending, string(c.Capabilities), string(c.Config),
		c.ConfigVersion, nullStr(c.CreatedBy),
	)
	_, err := r.db.Exec(ctx, q)
	return err
}

// ByID fetches one connector. orgID may be empty for internal/gRPC use.
func (r *ConnectorRepo) ByID(ctx context.Context, orgID, id string) (*domain.Connector, error) {
	q := r.db.Select(connectorCols...).From("connectors").Where(squirrel.Eq{"id": id})
	if orgID != "" {
		q = q.Where(squirrel.Eq{"organization_id": orgID})
	}
	return scanConnector(r.db.QueryRow(ctx, q))
}

// List returns the organization's connectors, optionally filtered by kind.
func (r *ConnectorRepo) List(ctx context.Context, orgID, kind string) ([]*domain.Connector, error) {
	q := r.db.Select(connectorCols...).From("connectors").Where(squirrel.Eq{"organization_id": orgID})
	if kind != "" {
		q = q.Where(squirrel.Eq{"kind": kind})
	}
	q = q.OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Connector
	for rows.Next() {
		c, err := scanConnector(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Update patches mutable fields (name, site_id) with org scoping.
func (r *ConnectorRepo) Update(ctx context.Context, orgID, id string, fields map[string]any) error {
	if len(fields) == 0 {
		return nil
	}
	fields["updated_at"] = time.Now().UTC()
	q := r.db.Update("connectors").SetMap(fields).
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	tag, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes a connector and (via CASCADE) its tokens.
func (r *ConnectorRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("connectors").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	tag, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// UpdateConfig atomically replaces the role configuration and bumps the
// monotonically increasing config_version, returning the new version.
func (r *ConnectorRepo) UpdateConfig(ctx context.Context, orgID, id string, cfg json.RawMessage) (int64, error) {
	var version int64
	err := r.db.QueryRowSQL(ctx,
		`UPDATE connectors SET config = $3::jsonb, config_version = config_version + 1,
                 updated_at = now() WHERE id = $1 AND organization_id = $2
                 RETURNING config_version`,
		id, orgID, string(cfg)).Scan(&version)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNotFound
	}
	return version, err
}

// Enroll flips a pending (or reconnecting) connector to active and stores
// the freshly issued secret hash plus the reporting component's identity.
// Called AFTER the enrollment token has been atomically burned, so no
// additional claim is needed here; rows affected == 0 means the record is
// unknown or revoked.
func (r *ConnectorRepo) Enroll(ctx context.Context, connectorID, secretHash, hostname, platform, arch, version string, capabilities json.RawMessage, heartbeatSecs int) error {
	if len(capabilities) == 0 {
		capabilities = json.RawMessage(`[]`)
	}
	now := time.Now().UTC()
	tag, err := r.db.ExecSQL(ctx,
		`UPDATE connectors SET status = 'active', secret_hash = $2,
                 hostname = $3, platform = $4, arch = $5, version = $6,
                 capabilities = $7::jsonb,
                 config = jsonb_set(COALESCE(config, '{}'::jsonb), '{heartbeat_secs}', to_jsonb($8::int), true),
                 enrolled_at = COALESCE(enrolled_at, $9), last_seen = $9, updated_at = $9
                 WHERE id = $1 AND status <> 'revoked'`,
		connectorID, secretHash, hostname, platform, arch, version,
		string(capabilities), heartbeatSecs, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// TouchInfo carries what the heartbeat needs beyond the config version:
// the connector's kind, identity and settings so the service can cascade
// liveness for every ENABLED function (agent/scanner) without a second
// query.
type TouchInfo struct {
	ConfigVersion  int64
	Kind           domain.ConnectorKind
	OrganizationID string
	SiteID         string
	Name           string
	// Config is the connector's current settings JSON, so the service can
	// cascade liveness by ENABLED FUNCTIONS (agent/scanner toggles), not
	// just by the kind recorded at creation.
	Config json.RawMessage
}

// TouchSeen records a heartbeat and returns the server's current config
// version plus the connector identity, so the caller can detect drift
// against its local snapshot and cascade scanner liveness.
//
// state: "" or "running" clears any shutdown marker; "shutting_down"
// stamps shutdown_at (the derived UI state shows "shutting down" until
// the grace window passes, then offline).
func (r *ConnectorRepo) TouchSeen(ctx context.Context, id, version, state string, statusJSON json.RawMessage) (TouchInfo, error) {
	var info TouchInfo
	var lastStatus any
	if len(statusJSON) > 0 {
		lastStatus = string(statusJSON)
	}
	if state != "shutting_down" {
		state = "running" // anything unknown clears the shutdown marker
	}
	err := r.db.QueryRowSQL(ctx,
		`UPDATE connectors SET last_seen = now(),
                 version = CASE WHEN $2 <> '' THEN $2 ELSE version END,
                 last_status = COALESCE($3::jsonb, last_status),
                 shutdown_at = CASE WHEN $4 = 'shutting_down' THEN now() ELSE NULL END,
                 updated_at = now()
                 WHERE id = $1 AND status = 'active'
                 RETURNING config_version, kind, organization_id, COALESCE(site_id::text,''), name, COALESCE(config::text,'')`,
		id, version, lastStatus, state).
		Scan(&info.ConfigVersion, &info.Kind, &info.OrganizationID, &info.SiteID, &info.Name, &info.Config)
	if errors.Is(err, pgx.ErrNoRows) {
		return info, ErrNotFound
	}
	return info, err
}

// AuthState returns the stored secret hash and lifecycle status for
// credential verification (gRPC interceptor path).
func (r *ConnectorRepo) AuthState(ctx context.Context, id string) (secretHash, status string, err error) {
	err = r.db.QueryRowSQL(ctx,
		`SELECT secret_hash, status FROM connectors WHERE id = $1`, id).Scan(&secretHash, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", ErrNotFound
	}
	return secretHash, status, err
}

// Revoke flips the record to revoked; continued connections are rejected.
func (r *ConnectorRepo) Revoke(ctx context.Context, orgID, id string) error {
	return r.updateStatus(ctx, orgID, id, domain.ConnectorStatusRevoked)
}

// Activate re-arms a revoked connector for a reconnect flow.
func (r *ConnectorRepo) Activate(ctx context.Context, orgID, id string) error {
	return r.updateStatus(ctx, orgID, id, domain.ConnectorStatusActive)
}

func (r *ConnectorRepo) updateStatus(ctx context.Context, orgID, id, status string) error {
	q := r.db.Update("connectors").SetMap(map[string]any{
		"status": status, "updated_at": time.Now().UTC(),
	}).Where(squirrel.Eq{"id": id, "organization_id": orgID})
	tag, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ClearSecret removes the stored credential (reconnect preparation).
func (r *ConnectorRepo) ClearSecret(ctx context.Context, orgID, id string) error {
	q := r.db.Update("connectors").SetMap(map[string]any{
		"secret_hash": "", "updated_at": time.Now().UTC(),
	}).Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ---------------------------------------------------------------------------
// Enrollment tokens

var connTokenCols = []string{
	"id", "organization_id", "connector_id", "token_hash",
	"COALESCE(created_by::text,'') AS created_by", "created_at", "expires_at", "used_at", "revoked",
}

func scanConnToken(row pgx.Row) (*domain.ConnectorEnrollToken, error) {
	var t domain.ConnectorEnrollToken
	var usedAt *time.Time
	err := row.Scan(&t.ID, &t.OrganizationID, &t.ConnectorID, &t.TokenHash,
		&t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &usedAt, &t.Revoked)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	t.UsedAt = usedAt
	return &t, nil
}

// ConnectorTokenRepo persists one-time enrollment tokens for connectors.
type ConnectorTokenRepo struct{ db *DB }

// NewConnectorTokenRepo builds a connector token repository.
func NewConnectorTokenRepo(db *DB) *ConnectorTokenRepo { return &ConnectorTokenRepo{db: db} }

// Create persists a new one-time token (hash only — the raw token is never
// stored).
func (r *ConnectorTokenRepo) Create(ctx context.Context, t *domain.ConnectorEnrollToken) error {
	if t.ID == "" {
		t.ID = ids.New()
	}
	q := r.db.Insert("connector_enroll_tokens").Columns(
		"id", "organization_id", "connector_id", "token_hash", "created_by", "expires_at",
	).Values(t.ID, t.OrganizationID, t.ConnectorID, t.TokenHash, nullStr(t.CreatedBy), t.ExpiresAt)
	_, err := r.db.Exec(ctx, q)
	return err
}

// ByHash fetches a token by its stored hash.
func (r *ConnectorTokenRepo) ByHash(ctx context.Context, hash string) (*domain.ConnectorEnrollToken, error) {
	q := r.db.Select(connTokenCols...).From("connector_enroll_tokens").Where(squirrel.Eq{"token_hash": hash})
	return scanConnToken(r.db.QueryRow(ctx, q))
}

// Burn atomically consumes a single-use token. ErrNotFound means the token
// is unknown, already used, revoked or expired — enrollment must be
// rejected. This claim-first update is what makes concurrent replays of
// the same token safe.
func (r *ConnectorTokenRepo) Burn(ctx context.Context, hash string) (*domain.ConnectorEnrollToken, error) {
	tag, err := r.db.ExecSQL(ctx,
		`UPDATE connector_enroll_tokens SET used_at = now()
                 WHERE token_hash = $1 AND used_at IS NULL AND revoked = false AND expires_at > now()`,
		hash)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, ErrNotFound
	}
	return r.ByHash(ctx, hash)
}

// InvalidateConnector revokes all still-unexpired unused tokens for a
// connector (issued a fresh connect command → old ones must not work).
func (r *ConnectorTokenRepo) InvalidateConnector(ctx context.Context, connectorID string) error {
	q := r.db.Update("connector_enroll_tokens").SetMap(map[string]any{
		"revoked": true,
	}).Where(squirrel.And{
		squirrel.Eq{"connector_id": connectorID},
		squirrel.Eq{"revoked": false},
		squirrel.Expr("used_at IS NULL"),
		squirrel.Gt{"expires_at": time.Now().UTC()},
	})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ListForConnector returns token metadata (never raw material) for audit.
func (r *ConnectorTokenRepo) ListForConnector(ctx context.Context, connectorID string) ([]*domain.ConnectorEnrollToken, error) {
	q := r.db.Select(connTokenCols...).From("connector_enroll_tokens").
		Where(squirrel.Eq{"connector_id": connectorID}).OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ConnectorEnrollToken
	for rows.Next() {
		t, err := scanConnToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}
