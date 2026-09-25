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
COALESCE(connector_id::text,'') AS connector_id,
last_seen, enrolled_at, revoked`

func scanAgent(row scanner) (*domain.Agent, error) {
	var a domain.Agent
	err := row.Scan(&a.ID, &a.OrganizationID, &a.SiteID, &a.AssetID, &a.Hostname, &a.Platform,
		&a.PlatformVer, &a.Arch, &a.AgentVersion, &a.Status, &a.CertSerial, &a.CertNotAfter,
		&a.Capabilities, &a.ConnectorID, &a.LastSeen, &a.EnrolledAt, &a.Revoked)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &a, nil
}

// Enroll creates the device record after successful certificate issuance.
// connector_id binds it 1:1 to the agent-kind connector that owns it.
func (r *AgentRepo) Enroll(ctx context.Context, a *domain.Agent) error {
	if a.ID == "" {
		a.ID = ids.New()
	}
	q := r.db.Insert("agents").
		Columns("id", "organization_id", "site_id", "connector_id", "hostname", "platform", "platform_version",
			"arch", "agent_version", "status", "cert_serial", "cert_not_after", "capabilities").
		Values(a.ID, a.OrganizationID, nullStr(a.SiteID), nullStr(a.ConnectorID), a.Hostname, a.Platform,
			a.PlatformVer, a.Arch, a.AgentVersion, "online", a.CertSerial, a.CertNotAfter, nonNil(a.Capabilities))
	_, err := r.db.Exec(ctx, q)
	return err
}

// ByConnector returns the device record bound to a connector (nil-site and
// revoked rows included: binding is the identity, not the lifecycle).
func (r *AgentRepo) ByConnector(ctx context.Context, connectorID string) (*domain.Agent, error) {
	q := r.db.Select(agentCols).From("agents").
		Where(squirrel.Eq{"connector_id": connectorID})
	return scanAgent(r.db.QueryRow(ctx, q))
}

// UpdateDevice refreshes the bound device's identity fields after a
// BindDevice call (re-enrollment of the same endpoint).
func (r *AgentRepo) UpdateDevice(ctx context.Context, a *domain.Agent) error {
	q := r.db.Update("agents").
		Set("hostname", a.Hostname).
		Set("platform", a.Platform).
		Set("platform_version", a.PlatformVer).
		Set("arch", a.Arch).
		Set("agent_version", a.AgentVersion).
		Set("cert_serial", a.CertSerial).
		Set("cert_not_after", a.CertNotAfter).
		Set("status", "online").
		Set("last_seen", time.Now().UTC()).
		Where(squirrel.Eq{"id": a.ID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AgentRepo) ByID(ctx context.Context, orgID, id string) (*domain.Agent, error) {
	q := r.db.Select(agentCols).From("agents").
		Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return scanAgent(r.db.QueryRow(ctx, q))
}

// ByIDAnyOrg resolves a device by id alone. For server-internal callers
// that already authenticated the request (connector credentials -> bound
// device), so re-checking the org would only duplicate the transport's
// work — and callers without an org id on the wire MUST use this variant.
func (r *AgentRepo) ByIDAnyOrg(ctx context.Context, id string) (*domain.Agent, error) {
	q := r.db.Select(agentCols).From("agents").
		Where(squirrel.Eq{"id": id})
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

// AgentIDsForAsset lists the devices bound to an asset. Identity adoption
// uses it to skip assets another device already claims: two machines
// reporting the same address must not fight over one asset.
func (r *AgentRepo) AgentIDsForAsset(ctx context.Context, assetID string) ([]string, error) {
	q := r.db.Select("id").From("agents").Where(squirrel.Eq{"asset_id": assetID})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
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

// AgentOffline describes one device that just transitioned to offline.
type AgentOffline struct {
	ID      string
	OrgID   string
	SiteID  string
	AssetID string
}

// MarkOfflineReturning flips stale agents to offline and returns exactly
// the rows it transitioned, so the liveness sweep can emit one
// agent.state_changed event per device (re-running the sweep emits nothing).
func (r *AgentRepo) MarkOfflineReturning(ctx context.Context, staleBefore time.Time) ([]AgentOffline, error) {
	rows, err := r.db.Pool.Query(ctx, `UPDATE agents SET status = 'offline'
		WHERE last_seen < $1 AND status <> 'offline'
		RETURNING id, organization_id, COALESCE(site_id::text,''), COALESCE(asset_id::text,'')`, staleBefore)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentOffline
	for rows.Next() {
		var a AgentOffline
		if err := rows.Scan(&a.ID, &a.OrgID, &a.SiteID, &a.AssetID); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
