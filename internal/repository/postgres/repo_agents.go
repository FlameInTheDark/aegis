package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== agents

type AgentRepo struct{ db *DB }

func NewAgentRepo(db *DB) *AgentRepo { return &AgentRepo{db: db} }

const agentCols = `id, organization_id, COALESCE(site_id::text,'') AS site_id, asset_id::text, hostname, platform,
platform_version, arch, agent_version, status, cert_serial, cert_not_after, capabilities,
last_seen, enrolled_at, revoked`

func scanAgent(row scanner) (*domain.Agent, error) {
	var a domain.Agent
	err := row.Scan(&a.ID, &a.OrganizationID, &a.SiteID, &a.AssetID, &a.Hostname, &a.Platform,
		&a.PlatformVer, &a.Arch, &a.AgentVersion, &a.Status, &a.CertSerial, &a.CertNotAfter,
		&a.Capabilities, &a.LastSeen, &a.EnrolledAt, &a.Revoked)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &a, nil
}

// Enroll creates the agent record after successful certificate issuance.
func (r *AgentRepo) Enroll(ctx context.Context, a *domain.Agent) error {
	if a.ID == "" {
		a.ID = ids.New()
	}
	q := r.db.Insert("agents").
		Columns("id", "organization_id", "site_id", "hostname", "platform", "platform_version",
			"arch", "agent_version", "status", "cert_serial", "cert_not_after", "capabilities").
		Values(a.ID, a.OrganizationID, nullStr(a.SiteID), a.Hostname, a.Platform,
			a.PlatformVer, a.Arch, a.AgentVersion, "online", a.CertSerial, a.CertNotAfter, nonNil(a.Capabilities))
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AgentRepo) ByID(ctx context.Context, orgID, id string) (*domain.Agent, error) {
	q := r.db.Select(agentCols).From("agents").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return scanAgent(r.db.QueryRow(ctx, q))
}

func (r *AgentRepo) List(ctx context.Context, orgID string) ([]domain.Agent, error) {
	q := r.db.Select(agentCols).From("agents").
		Where(squirrel.Eq{"organization_id": orgID}).OrderBy("last_seen DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Agent
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

func (r *AgentRepo) TouchSeen(ctx context.Context, id, version string) error {
	set := map[string]any{"last_seen": time.Now().UTC(), "status": "online"}
	if version != "" {
		set["agent_version"] = version
	}
	q := r.db.Update("agents")
	for k, v := range set {
		q = q.Set(k, v)
	}
	q = q.Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AgentRepo) Revoke(ctx context.Context, orgID, id string) error {
	q := r.db.Update("agents").
		Set("revoked", true).
		Set("status", "offline").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AgentRepo) MarkOffline(ctx context.Context, staleBefore time.Time) error {
	q := r.db.Update("agents").
		Set("status", "offline").
		Where(squirrel.Lt{"last_seen": staleBefore}).
		Where(squirrel.NotEq{"status": "offline"})
	_, err := r.db.Exec(ctx, q)
	return err
}

// LinkAsset attaches the agent to an asset record.
func (r *AgentRepo) LinkAsset(ctx context.Context, agentID, assetID string) error {
	q := r.db.Update("agents").Set("asset_id", assetID).Where(squirrel.Eq{"id": agentID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ==================================================================== agent tasks

type AgentTaskRepo struct{ db *DB }

func NewAgentTaskRepo(db *DB) *AgentTaskRepo { return &AgentTaskRepo{db: db} }

func (r *AgentTaskRepo) Create(ctx context.Context, t *domain.AgentTask) error {
	if t.ID == "" {
		t.ID = ids.New()
	}
	args, _ := json.Marshal(t.Args)
	q := r.db.Insert("agent_tasks").
		Columns("id", "agent_id", "type", "issued_by", "expires_at", "args").
		Values(t.ID, t.AgentID, string(t.Type), t.IssuedBy, t.ExpiresAt, args)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AgentTaskRepo) PendingForAgent(ctx context.Context, agentID string) ([]domain.AgentTask, error) {
	q := r.db.Select("id, agent_id::text, type, issued_by::text, issued_at, expires_at, args, state").
		From("agent_tasks").
		Where(squirrel.Eq{"agent_id": agentID, "state": "pending"}).
		Where(squirrel.Gt{"expires_at": time.Now().UTC()}).
		OrderBy("issued_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AgentTask
	for rows.Next() {
		var t domain.AgentTask
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Type, &t.IssuedBy, &t.IssuedAt,
			&t.ExpiresAt, &t.Args, &t.State); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *AgentTaskRepo) Complete(ctx context.Context, id string, result map[string]any, errMsg string) error {
	state := "succeeded"
	if errMsg != "" {
		state = "failed"
	}
	res, _ := json.Marshal(result)
	q := r.db.Update("agent_tasks").
		Set("state", state).
		Set("result", res).
		Set("error", nullStr(errMsg)).
		Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AgentTaskRepo) ExpireStale(ctx context.Context) error {
	q := r.db.Update("agent_tasks").
		Set("state", "expired").
		Where(squirrel.Eq{"state": "pending"}).
		Where(squirrel.Lt{"expires_at": time.Now().UTC()})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AgentTaskRepo) ListForAgent(ctx context.Context, agentID string, limit int) ([]domain.AgentTask, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := r.db.Select(`id, agent_id::text, type, issued_by::text, issued_at, expires_at, args,
                state, result, error`).
		From("agent_tasks").Where(squirrel.Eq{"agent_id": agentID}).
		OrderBy("issued_at DESC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AgentTask
	for rows.Next() {
		var t domain.AgentTask
		if err := rows.Scan(&t.ID, &t.AgentID, &t.Type, &t.IssuedBy, &t.IssuedAt,
			&t.ExpiresAt, &t.Args, &t.State, &t.Result, &t.Error); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ==================================================================== enrollment tokens

type EnrollmentRepo struct{ db *DB }

func NewEnrollmentRepo(db *DB) *EnrollmentRepo { return &EnrollmentRepo{db: db} }

func (r *EnrollmentRepo) Create(ctx context.Context, t *domain.EnrollmentToken) error {
	if t.ID == "" {
		t.ID = ids.New()
	}
	q := r.db.Insert("enrollment_tokens").
		Columns("id", "organization_id", "site_id", "token_hash", "prefix", "created_by", "expires_at").
		Values(t.ID, t.OrganizationID, t.SiteID, t.TokenHash, t.Prefix, t.CreatedBy, t.ExpiresAt)
	_, err := r.db.Exec(ctx, q)
	return err
}

// ByHash returns a valid, unused token for enrollment.
func (r *EnrollmentRepo) ByHash(ctx context.Context, hash string) (*domain.EnrollmentToken, error) {
	q := r.db.Select("id, organization_id, COALESCE(site_id::text,'') AS site_id, token_hash, prefix, COALESCE(created_by::text,'') AS created_by, created_at, expires_at, used_at, revoked").
		From("enrollment_tokens").Where(squirrel.Eq{"token_hash": hash})
	var t domain.EnrollmentToken
	err := r.db.QueryRow(ctx, q).Scan(&t.ID, &t.OrganizationID, &t.SiteID, &t.TokenHash,
		&t.Prefix, &t.CreatedBy, &t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &t.Revoked)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &t, nil
}

// MarkUsed makes the token single-use (spec §16).
func (r *EnrollmentRepo) MarkUsed(ctx context.Context, id string) error {
	q := r.db.Update("enrollment_tokens").Set("used_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *EnrollmentRepo) Revoke(ctx context.Context, orgID, id string) error {
	q := r.db.Update("enrollment_tokens").Set("revoked", true).
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *EnrollmentRepo) List(ctx context.Context, orgID string) ([]domain.EnrollmentToken, error) {
	q := r.db.Select("id, organization_id, COALESCE(site_id::text,'') AS site_id, prefix, COALESCE(created_by::text,'') AS created_by, created_at, expires_at, used_at, revoked").
		From("enrollment_tokens").Where(squirrel.Eq{"organization_id": orgID}).
		OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.EnrollmentToken
	for rows.Next() {
		var t domain.EnrollmentToken
		if err := rows.Scan(&t.ID, &t.OrganizationID, &t.SiteID, &t.Prefix, &t.CreatedBy,
			&t.CreatedAt, &t.ExpiresAt, &t.UsedAt, &t.Revoked); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ==================================================================== agent events

type AgentEventRepo struct{ db *DB }

func NewAgentEventRepo(db *DB) *AgentEventRepo { return &AgentEventRepo{db: db} }

func (r *AgentEventRepo) Insert(ctx context.Context, agentID, typ string, payload map[string]any, occurred time.Time) error {
	b, _ := json.Marshal(payload)
	q := r.db.Insert("agent_events").
		Columns("id", "agent_id", "type", "payload", "occurred_at").
		Values(ids.New(), agentID, typ, b, occurred)
	_, err := r.db.Exec(ctx, q)
	return err
}

// ListForAgent returns recent agent telemetry events (bounded).
func (r *AgentEventRepo) ListForAgent(ctx context.Context, agentID string, limit int) ([]map[string]any, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	q := r.db.Select("id", "type", "payload", "occurred_at").
		From("agent_events").Where(squirrel.Eq{"agent_id": agentID}).
		OrderBy("occurred_at DESC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id, typ string
		var payload []byte
		var occurred time.Time
		if err := rows.Scan(&id, &typ, &payload, &occurred); err != nil {
			continue
		}
		var m map[string]any
		_ = json.Unmarshal(payload, &m)
		if m == nil {
			m = map[string]any{}
		}
		m["id"] = id
		m["type"] = typ
		m["occurred_at"] = occurred
		out = append(out, m)
	}
	return out, rows.Err()
}
