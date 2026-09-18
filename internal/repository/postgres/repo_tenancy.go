package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

func mapNotFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

// ==================================================================== orgs

type OrgRepo struct{ db *DB }

func NewOrgRepo(db *DB) *OrgRepo { return &OrgRepo{db: db} }

const orgCols = "id, name, slug, created_at, updated_at"

func scanOrg(row pgx.Row) (*domain.Organization, error) {
	var o domain.Organization
	err := row.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &o, nil
}

func (r *OrgRepo) Create(ctx context.Context, name, slug string) (*domain.Organization, error) {
	q := r.db.Insert("organizations").
		Columns("id", "name", "slug").
		Values(ids.New(), name, slug).
		Suffix("RETURNING " + orgCols)
	return scanOrg(r.db.QueryRow(ctx, q))
}

func (r *OrgRepo) ByID(ctx context.Context, id string) (*domain.Organization, error) {
	q := r.db.Select(orgCols).From("organizations").Where(squirrel.Eq{"id": id})
	return scanOrg(r.db.QueryRow(ctx, q))
}

func (r *OrgRepo) BySlug(ctx context.Context, slug string) (*domain.Organization, error) {
	q := r.db.Select(orgCols).From("organizations").Where(squirrel.Eq{"slug": slug})
	return scanOrg(r.db.QueryRow(ctx, q))
}

// Rename updates an organization's display name; the slug is immutable so
// existing external references keep resolving.
func (r *OrgRepo) Rename(ctx context.Context, id, name string) (*domain.Organization, error) {
	q := r.db.Update("organizations").
		Set("name", name).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id}).
		Suffix("RETURNING " + orgCols)
	return scanOrg(r.db.QueryRow(ctx, q))
}

func (r *OrgRepo) List(ctx context.Context) ([]domain.Organization, error) {
	q := r.db.Select(orgCols).From("organizations").OrderBy("created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Organization
	for rows.Next() {
		var o domain.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ==================================================================== users

type UserRepo struct{ db *DB }

func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

const userCols = "id, email, name, password_hash, disabled, last_login_at, created_at, updated_at"

func scanUser(row pgx.Row) (*domain.User, error) {
	var u domain.User
	err := row.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Disabled, &u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &u, nil
}

func (r *UserRepo) Create(ctx context.Context, email, name, passwordHash string) (*domain.User, error) {
	q := r.db.Insert("users").
		Columns("id", "email", "name", "password_hash").
		Values(ids.New(), email, name, passwordHash).
		Suffix("RETURNING " + userCols)
	return scanUser(r.db.QueryRow(ctx, q))
}

func (r *UserRepo) ByEmail(ctx context.Context, email string) (*domain.User, error) {
	q := r.db.Select(userCols).From("users").Where(squirrel.Eq{"email": email})
	return scanUser(r.db.QueryRow(ctx, q))
}

func (r *UserRepo) ByID(ctx context.Context, id string) (*domain.User, error) {
	q := r.db.Select(userCols).From("users").Where(squirrel.Eq{"id": id})
	return scanUser(r.db.QueryRow(ctx, q))
}

func (r *UserRepo) TouchLogin(ctx context.Context, id string) error {
	q := r.db.Update("users").Set("last_login_at", time.Now().UTC()).Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *UserRepo) SetDisabled(ctx context.Context, id string, disabled bool) error {
	q := r.db.Update("users").
		Set("disabled", disabled).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

// SetPassword replaces a user's credential hash (self-service change and
// administrator resets). Sessions are revoked by the caller.
func (r *UserRepo) SetPassword(ctx context.Context, id, passwordHash string) error {
	q := r.db.Update("users").
		Set("password_hash", passwordHash).
		Set("updated_at", time.Now().UTC()).
		Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *UserRepo) List(ctx context.Context) ([]domain.User, error) {
	q := r.db.Select(userCols).From("users").OrderBy("created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.User
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.Name, &u.PasswordHash, &u.Disabled,
			&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ==================================================================== memberships

type MembershipRepo struct{ db *DB }

func NewMembershipRepo(db *DB) *MembershipRepo { return &MembershipRepo{db: db} }

func (r *MembershipRepo) Add(ctx context.Context, userID, orgID string, role domain.Role) error {
	q := r.db.Insert("memberships").
		Columns("id", "user_id", "organization_id", "role").
		Values(ids.New(), userID, orgID, role)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *MembershipRepo) RoleFor(ctx context.Context, userID, orgID string) (domain.Role, error) {
	q := r.db.Select("role").From("memberships").
		Where(squirrel.Eq{"user_id": userID, "organization_id": orgID})
	var role domain.Role
	err := r.db.QueryRow(ctx, q).Scan(&role)
	return role, mapNotFound(err)
}

func (r *MembershipRepo) OrgsFor(ctx context.Context, userID string) ([]domain.Organization, error) {
	q := r.db.Select("o.id, o.name, o.slug, o.created_at, o.updated_at").
		From("memberships m").
		Join("organizations o ON o.id = m.organization_id").
		Where(squirrel.Eq{"m.user_id": userID}).
		OrderBy("o.created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Organization
	for rows.Next() {
		var o domain.Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

func (r *MembershipRepo) ListForOrg(ctx context.Context, orgID string) ([]domain.Membership, error) {
	q := r.db.Select("m.id, m.user_id, m.organization_id, m.role, m.created_at").
		From("memberships m").
		Where(squirrel.Eq{"m.organization_id": orgID})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Membership
	for rows.Next() {
		var m domain.Membership
		if err := rows.Scan(&m.ID, &m.UserID, &m.OrganizationID, &m.Role, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// SetRole updates the org membership role (user management).
func (r *MembershipRepo) SetRole(ctx context.Context, userID, orgID string, role domain.Role) error {
	q := r.db.Update("memberships").
		Set("role", string(role)).
		Where(squirrel.Eq{"user_id": userID, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ==================================================================== sessions

type SessionRepo struct{ db *DB }

func NewSessionRepo(db *DB) *SessionRepo { return &SessionRepo{db: db} }

func (r *SessionRepo) Create(ctx context.Context, id, userID, orgID, refreshHash, ip, ua string, expires time.Time) error {
	q := r.db.Insert("sessions").
		Columns("id", "user_id", "organization_id", "refresh_hash", "ip", "user_agent", "expires_at").
		Values(id, userID, orgID, refreshHash, ip, ua, expires)
	_, err := r.db.Exec(ctx, q)
	return err
}

// Session is a login session: one rotating refresh-token family. The
// presented token's hash selects the row: either it matches refresh_hash
// (the live token) or a key in the retired ledger (a just-superseded
// token — grace-window race) or the caller treats it as reuse.
type Session struct {
	ID             string
	UserID         string
	OrganizationID string
	RefreshHash    string
	// RetiredAtMs is the retirement timestamp of a RETIRED token (ms
	// epoch); only set by ByRetiredHash.
	RetiredAtMs int64
	RotatedAt   time.Time
	ExpiresAt   time.Time
}

const sessionCols = "id, user_id, organization_id, refresh_hash, rotated_at, expires_at"

// ByRefreshHash returns the LIVE session whose CURRENT refresh token hash
// matches. Revoked and expired sessions never match.
func (r *SessionRepo) ByRefreshHash(ctx context.Context, hash string) (*Session, error) {
	var s Session
	q := r.db.Select(sessionCols).From("sessions").
		Where(squirrel.Eq{"refresh_hash": hash, "revoked": false}).
		Where(squirrel.Gt{"expires_at": time.Now().UTC()})
	err := r.db.QueryRow(ctx, q).Scan(&s.ID, &s.UserID, &s.OrganizationID, &s.RefreshHash, &s.RotatedAt, &s.ExpiresAt)
	return &s, mapNotFound(err)
}

// ByRetiredHash returns the LIVE session whose retired ledger contains the
// hash, together with the time it was retired. Within the grace window the
// caller rotates forward (concurrent-refresh race); beyond it the caller
// revokes the family (reuse detection). Revoked/expired sessions never match.
func (r *SessionRepo) ByRetiredHash(ctx context.Context, hash string) (*Session, error) {
	var s Session
	q := `SELECT id, user_id, organization_id, refresh_hash, (retired->>$2)::bigint, rotated_at, expires_at
              FROM sessions
              WHERE retired ? $1 AND revoked = false AND expires_at > now()`
	err := r.db.QueryRowSQL(ctx, q, hash, hash).Scan(&s.ID, &s.UserID, &s.OrganizationID, &s.RefreshHash, &s.RetiredAtMs, &s.RotatedAt, &s.ExpiresAt)
	return &s, mapNotFound(err)
}

// rotateSQL atomically retires the row's CURRENT hash plus the presented
// hash and installs newHash. Running the UPDATE inside one statement makes
// concurrent rotations serialize on the row lock and re-read the latest
// version (Postgres EvalPlanQual), so a racing rotation retires the token
// the previous rotation just issued — the browser's shared cookie jar can
// never end up holding a hash the server does not accept. The ledger keeps
// entries for the reuse-detection window (1h) capped at 200.
const rotateSQL = `
UPDATE sessions SET
  retired = (
    SELECT COALESCE(jsonb_object_agg(k, v), '{}'::jsonb) FROM (
      SELECT d.k, d.v FROM jsonb_each_text(
        sessions.retired
        || jsonb_build_object(sessions.refresh_hash, (EXTRACT(EPOCH FROM now()) * 1000)::bigint)
        || jsonb_build_object($2::text,                    (EXTRACT(EPOCH FROM now()) * 1000)::bigint)
      ) AS d(k, v)
      WHERE (d.v)::bigint > (EXTRACT(EPOCH FROM now() - interval '1 hour') * 1000)::bigint
      ORDER BY (d.v)::bigint DESC
      LIMIT 200
    ) sub
  ),
  refresh_hash = $3,
  rotated_at = now(),
  last_seen_at = now()
WHERE id = $1`

// Rotate retires the presented token (and the row's current token — the
// union covers the concurrent-rotation interleave) and stores newHash.
func (r *SessionRepo) Rotate(ctx context.Context, id, presentedHash, newHash string) error {
	cmd, err := r.db.ExecSQL(ctx, rotateSQL, id, presentedHash, newHash)
	if err != nil {
		return err
	}
	if cmd.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *SessionRepo) Revoke(ctx context.Context, sessionID string) error {
	q := r.db.Update("sessions").Set("revoked", true).Where(squirrel.Eq{"id": sessionID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *SessionRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	q := r.db.Update("sessions").Set("revoked", true).Where(squirrel.Eq{"user_id": userID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// RevokeOthersForUser revokes every session of a user EXCEPT keepSessionID —
// used after a self-service password change so the current device stays
// signed in while other devices are forced out.
func (r *SessionRepo) RevokeOthersForUser(ctx context.Context, userID, keepSessionID string) error {
	q := r.db.Update("sessions").Set("revoked", true).
		Where(squirrel.Eq{"user_id": userID}).
		Where(squirrel.NotEq{"id": keepSessionID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ==================================================================== sites & networks

type SiteRepo struct{ db *DB }

func NewSiteRepo(db *DB) *SiteRepo { return &SiteRepo{db: db} }

const siteCols = "id, organization_id, name, description, site_type, created_at, updated_at"

func (r *SiteRepo) Create(ctx context.Context, s *domain.Site) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	q := r.db.Insert("sites").
		Columns("id", "organization_id", "name", "description", "site_type").
		Values(s.ID, s.OrganizationID, s.Name, s.Description, s.SiteType)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *SiteRepo) ByID(ctx context.Context, orgID, id string) (*domain.Site, error) {
	where := squirrel.Eq{"id": id}
	if orgID != "" {
		// Empty org = no org filter (scanner resolving its site's org).
		where["organization_id"] = orgID
	}
	q := r.db.Select(siteCols).From("sites").Where(where)
	var s domain.Site
	err := r.db.QueryRow(ctx, q).Scan(&s.ID, &s.OrganizationID, &s.Name, &s.Description,
		&s.SiteType, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

func (r *SiteRepo) List(ctx context.Context, orgID string) ([]domain.Site, error) {
	q := r.db.Select(siteCols).From("sites").
		Where(squirrel.Eq{"organization_id": orgID}).OrderBy("name")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Site
	for rows.Next() {
		var s domain.Site
		if err := rows.Scan(&s.ID, &s.OrganizationID, &s.Name, &s.Description,
			&s.SiteType, &s.CreatedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *SiteRepo) Update(ctx context.Context, orgID, id string, fields map[string]any) error {
	q := r.db.Update("sites").Set("updated_at", time.Now().UTC())
	for k, v := range fields {
		q = q.Set(k, v)
	}
	q = q.Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *SiteRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("sites").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

type NetworkRepo struct{ db *DB }

func NewNetworkRepo(db *DB) *NetworkRepo { return &NetworkRepo{db: db} }

// gateway (INET) is nullable; COALESCE keeps the string scan target NULL-safe.
const netCols = "id, site_id, organization_id, cidr::text, vlan_id, name, COALESCE(gateway::text,'') AS gateway, exposure, created_at, updated_at"

func scanNetwork(row pgx.Row) (*domain.Network, error) {
	var n domain.Network
	err := row.Scan(&n.ID, &n.SiteID, &n.OrganizationID, &n.CIDR, &n.VLANID, &n.Name,
		&n.Gateway, &n.Exposure, &n.CreatedAt, &n.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &n, nil
}

func (r *NetworkRepo) Create(ctx context.Context, n *domain.Network) error {
	if n.ID == "" {
		n.ID = ids.New()
	}
	q := r.db.Insert("networks").
		Columns("id", "site_id", "organization_id", "cidr", "vlan_id", "name", "gateway", "exposure").
		Values(n.ID, n.SiteID, n.OrganizationID, n.CIDR, n.VLANID, n.Name, nullStr(n.Gateway), n.Exposure)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *NetworkRepo) ByID(ctx context.Context, orgID, id string) (*domain.Network, error) {
	q := r.db.Select(netCols).From("networks").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	return scanNetwork(r.db.QueryRow(ctx, q))
}

func (r *NetworkRepo) ListBySite(ctx context.Context, siteID string) ([]domain.Network, error) {
	q := r.db.Select(netCols).From("networks").Where(squirrel.Eq{"site_id": siteID}).OrderBy("cidr")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Network
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (r *NetworkRepo) ListByOrg(ctx context.Context, orgID string) ([]domain.Network, error) {
	q := r.db.Select(netCols).From("networks").
		Where(squirrel.Eq{"organization_id": orgID}).OrderBy("site_id, cidr")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Network
	for rows.Next() {
		n, err := scanNetwork(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *n)
	}
	return out, rows.Err()
}

func (r *NetworkRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("networks").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// First returns the earliest-created site — used by scanner deployments that
// don't pin AEGIS_SCANNER_SITE_ID (single-site/demo convenience). Returns
// ErrNotFound when no sites exist yet.
func (r *SiteRepo) First(ctx context.Context) (*domain.Site, error) {
	q := r.db.Select(siteCols).From("sites").OrderBy("created_at, id").Limit(1)
	var s domain.Site
	err := r.db.QueryRow(ctx, q).Scan(&s.ID, &s.OrganizationID, &s.Name, &s.Description,
		&s.SiteType, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

// ==================================================================== audit

type AuditRepo struct{ db *DB }

func NewAuditRepo(db *DB) *AuditRepo { return &AuditRepo{db: db} }

func (r *AuditRepo) Insert(ctx context.Context, e *domain.AuditEntry) error {
	if e.ID == "" {
		e.ID = ids.New()
	}
	// organization_id is NOT NULL UUID: pre-auth/unscoped entries carry the
	// nil UUID. Nullable UUID columns (actor_id, site_id) must get SQL NULL
	// rather than "" (empty string is not a valid uuid literal).
	orgID := e.OrgID
	if orgID == "" {
		orgID = "00000000-0000-0000-0000-000000000000"
	}
	q := r.db.Insert("audit_logs").
		Columns("id", "organization_id", "actor_id", "actor_name", "actor_ip", "action",
			"target", "site_id", "before_state", "after_state", "result", "detail").
		Values(e.ID, orgID, nullStr(e.ActorID), e.ActorName, e.ActorIP, e.Action,
			e.Target, nullStr(e.SiteID), e.Before, e.After, e.Result, e.Detail)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *AuditRepo) List(ctx context.Context, orgID string, p Page) ([]domain.AuditEntry, int64, error) {
	// actor_id/site_id (UUID) and actor_name/actor_ip/target (TEXT) are
	// nullable; COALESCE keeps the plain-string scan targets NULL-safe
	// (pgx: "cannot scan NULL into *string").
	base := r.db.Select(`id, organization_id, COALESCE(actor_id::text,''), COALESCE(actor_name,''), COALESCE(actor_ip,''), action, COALESCE(target,''), COALESCE(site_id::text,''), before_state, after_state, result, detail, created_at`).
		From("audit_logs").Where(squirrel.Eq{"organization_id": orgID})

	if p.Action != "" {
		base = base.Where(squirrel.Like{"action": p.Action + "%"})
	}
	if !p.From.IsZero() {
		base = base.Where(squirrel.GtOrEq{"created_at": p.From})
	}

	// Separate count query: a window-function count returns no rows on an
	// empty table, which made the whole list 500 on fresh deployments.
	var total int64
	cq := r.db.Select("count(*)").From("audit_logs").Where(squirrel.Eq{"organization_id": orgID})
	if p.Action != "" {
		cq = cq.Where(squirrel.Like{"action": p.Action + "%"})
	}
	if !p.From.IsZero() {
		cq = cq.Where(squirrel.GtOrEq{"created_at": p.From})
	}
	if err := r.db.QueryRow(ctx, cq).Scan(&total); err != nil {
		return nil, 0, err
	}

	q := base.OrderBy("created_at DESC").Limit(uint64(p.Limit)).Offset(uint64((p.Page - 1) * p.Limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.AuditEntry
	for rows.Next() {
		var e domain.AuditEntry
		if err := rows.Scan(&e.ID, &e.OrgID, &e.ActorID, &e.ActorName, &e.ActorIP, &e.Action,
			&e.Target, &e.SiteID, &e.Before, &e.After, &e.Result, &e.Detail, &e.CreatedAt); err != nil {
			return nil, 0, err
		}
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// Page carries list query parameters for repos.
type Page struct {
	Limit  int
	Page   int
	Action string
	From   time.Time
}

var _ = fmt.Sprintf
