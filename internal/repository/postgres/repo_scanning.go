package postgres

import (
	"context"
	"encoding/json"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== scan profiles

type ProfileRepo struct{ db *DB }

func NewProfileRepo(db *DB) *ProfileRepo { return &ProfileRepo{db: db} }

// Sync ensures all built-in profiles exist (idempotent bootstrap).
func (r *ProfileRepo) Sync(ctx context.Context, profiles map[domain.ScanProfile]domain.ProfileDefinition) error {
	for name, p := range profiles {
		spec, _ := json.Marshal(p)
		q := r.db.Insert("scan_profiles").
			Columns("name", "description", "spec").
			Values(string(name), p.Description, spec).
			Suffix(`ON CONFLICT (name) DO UPDATE SET description = EXCLUDED.description, spec = EXCLUDED.spec`)
		if _, err := r.db.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

func (r *ProfileRepo) Exists(ctx context.Context, name string) (bool, error) {
	q := r.db.Select("1").From("scan_profiles").Where(squirrel.Eq{"name": name})
	var one int
	err := r.db.QueryRow(ctx, q).Scan(&one)
	return err == nil, nil
}

// GetByName resolves a profile by its key — built-ins live in the static
// registry, so this targets the scan_profiles table (which Sync keeps
// seeded with built-ins and CreateCustom extends with org presets).
func (r *ProfileRepo) GetByName(ctx context.Context, name string) (*domain.ProfileDefinition, error) {
	q := r.db.Select("name", "spec").From("scan_profiles").Where(squirrel.Eq{"name": name})
	var n, spec string
	if err := r.db.QueryRow(ctx, q).Scan(&n, &spec); err != nil {
		return nil, mapNotFound(err)
	}
	var def domain.ProfileDefinition
	if err := json.Unmarshal([]byte(spec), &def); err != nil {
		return nil, err
	}
	def.Name = domain.ScanProfile(n)
	return &def, nil
}

// ListCustom returns the org's custom presets (is_builtin = false).
func (r *ProfileRepo) ListCustom(ctx context.Context, orgID string) ([]domain.ProfileDefinition, error) {
	q := r.db.Select("name", "spec").From("scan_profiles").
		Where(squirrel.Eq{"is_builtin": false, "org_id": orgID}).
		OrderBy("name")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ProfileDefinition
	for rows.Next() {
		var n, spec string
		if err := rows.Scan(&n, &spec); err != nil {
			return nil, err
		}
		var def domain.ProfileDefinition
		if err := json.Unmarshal([]byte(spec), &def); err != nil {
			return nil, err
		}
		def.Name = domain.ScanProfile(n)
		def.Builtin = false
		out = append(out, def)
	}
	return out, rows.Err()
}

// CreateCustom inserts one org-owned preset.
func (r *ProfileRepo) CreateCustom(ctx context.Context, orgID string, def *domain.ProfileDefinition) error {
	spec, _ := json.Marshal(def)
	q := r.db.Insert("scan_profiles").
		Columns("name", "description", "spec", "is_builtin", "org_id").
		Values(string(def.Name), def.Description, spec, false, orgID)
	_, err := r.db.Exec(ctx, q)
	return err
}

// UpdateCustom replaces the knobs of one org-owned preset.
func (r *ProfileRepo) UpdateCustom(ctx context.Context, orgID string, def *domain.ProfileDefinition) error {
	spec, _ := json.Marshal(def)
	q := r.db.Update("scan_profiles").
		Set("description", def.Description).
		Set("spec", spec).
		Where(squirrel.Eq{"name": string(def.Name), "is_builtin": false, "org_id": orgID})
	tag, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteCustom removes one org-owned preset. A preset referenced by scans
// (FK scans.profile -> scan_profiles.name) fails at the DB level; handlers
// map that to a 409.
func (r *ProfileRepo) DeleteCustom(ctx context.Context, orgID, name string) error {
	q := r.db.Delete("scan_profiles").
		Where(squirrel.Eq{"name": name, "is_builtin": false, "org_id": orgID})
	tag, err := r.db.Exec(ctx, q)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// ==================================================================== scanners

type ScannerRepo struct{ db *DB }

func NewScannerRepo(db *DB) *ScannerRepo { return &ScannerRepo{db: db} }

func (r *ScannerRepo) Upsert(ctx context.Context, s *domain.Scanner) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	q := r.db.Insert("scanners").
		Columns("id", "organization_id", "site_id", "name", "version", "capabilities", "interfaces", "health", "last_seen").
		Values(s.ID, s.OrganizationID, nullStr(s.SiteID), s.Name, s.Version, nonNil(s.Capabilities), nonNil(s.Interfaces), s.Health, time.Now().UTC()).
		Suffix(`ON CONFLICT (organization_id, name) DO UPDATE SET
                        site_id = EXCLUDED.site_id, version = EXCLUDED.version,
                        capabilities = EXCLUDED.capabilities, interfaces = EXCLUDED.interfaces,
                        health = EXCLUDED.health, last_seen = now() RETURNING id, created_at`)
	return r.db.QueryRow(ctx, q).Scan(&s.ID, &s.CreatedAt)
}

func (r *ScannerRepo) ByID(ctx context.Context, orgID, id string) (*domain.Scanner, error) {
	q := r.db.Select("id, organization_id, COALESCE(site_id::text,'') AS site_id, name, version, capabilities, interfaces, health, COALESCE(transport,'nats') AS transport, is_default, last_seen, created_at").
		From("scanners").Where(squirrel.Eq{"id": id, "organization_id": orgID})
	var s domain.Scanner
	err := r.db.QueryRow(ctx, q).Scan(&s.ID, &s.OrganizationID, &s.SiteID, &s.Name,
		&s.Version, &s.Capabilities, &s.Interfaces, &s.Health, &s.Transport, &s.IsDefault, &s.LastSeen, &s.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

func (r *ScannerRepo) List(ctx context.Context, orgID string) ([]domain.Scanner, error) {
	q := r.db.Select("id, organization_id, COALESCE(site_id::text,'') AS site_id, name, version, capabilities, interfaces, health, COALESCE(transport,'nats') AS transport, is_default, last_seen, created_at").
		From("scanners").Where(squirrel.Eq{"organization_id": orgID}).OrderBy("name")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Scanner
	for rows.Next() {
		var s domain.Scanner
		if err := rows.Scan(&s.ID, &s.OrganizationID, &s.SiteID, &s.Name, &s.Version,
			&s.Capabilities, &s.Interfaces, &s.Health, &s.Transport, &s.IsDefault, &s.LastSeen, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// scannerCols includes hub columns; scanning into domain.Scanner needs the
// base fields only, so hub-only columns are selected explicitly per query.
const scannerHubCols = `id, organization_id, COALESCE(site_id::text,'') AS site_id, name, version,
capabilities, interfaces, health, last_seen, created_at`

func scanHubScanner(row scanner) (*domain.Scanner, error) {
	var s domain.Scanner
	err := row.Scan(&s.ID, &s.OrganizationID, &s.SiteID, &s.Name, &s.Version,
		&s.Capabilities, &s.Interfaces, &s.Health, &s.LastSeen, &s.CreatedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

// ByTokenHash resolves a scanner by the SHA-256 of its enrollment token.
func (r *ScannerRepo) ByTokenHash(ctx context.Context, tokenHash string) (*domain.Scanner, error) {
	q := r.db.Select(scannerHubCols).From("scanners").Where(squirrel.Eq{"token_hash": tokenHash, "transport": "grpc"})
	return scanHubScanner(r.db.QueryRow(ctx, q))
}

// UpdateAgent refreshes registration fields for hub-connected scanners.
func (r *ScannerRepo) UpdateAgent(ctx context.Context, s *domain.Scanner) error {
	q := r.db.Update("scanners").
		Set("name", s.Name).Set("version", s.Version).Set("capabilities", nonNil(s.Capabilities)).
		Set("transport", s.Transport).Set("health", s.Health).Set("last_seen", s.LastSeen).
		Where(squirrel.Eq{"id": s.ID})
	_, err := r.db.Exec(ctx, q)
	return err
}

// Touch refreshes last_seen (hub heartbeats).
func (r *ScannerRepo) Touch(ctx context.Context, id string) error {
	q := r.db.Update("scanners").Set("last_seen", time.Now().UTC()).Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

// DefaultForOrg returns the org's default hub scanner, if any.
func (r *ScannerRepo) DefaultForOrg(ctx context.Context, orgID string) (*domain.Scanner, error) {
	q := r.db.Select(scannerHubCols).From("scanners").
		Where(squirrel.Eq{"organization_id": orgID, "is_default": true, "transport": "grpc"}).
		Limit(1)
	return scanHubScanner(r.db.QueryRow(ctx, q))
}

// SetDefault marks one scanner the org default (clearing the previous one).
func (r *ScannerRepo) SetDefault(ctx context.Context, orgID, id string, isDefault bool) error {
	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		if isDefault {
			u1 := squirrel.Update("scanners").Set("is_default", false).Where(squirrel.Eq{"organization_id": orgID})
			q1, a1, err := u1.PlaceholderFormat(squirrel.Dollar).ToSql()
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, q1, a1...); err != nil {
				return err
			}
		}
		u2 := squirrel.Update("scanners").Set("is_default", isDefault).
			Where(squirrel.Eq{"organization_id": orgID, "id": id})
		q2, a2, err := u2.PlaceholderFormat(squirrel.Dollar).ToSql()
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, q2, a2...)
		return err
	})
}

// Enroll creates a hub scanner placeholder with a hashed enrollment token.
func (r *ScannerRepo) Enroll(ctx context.Context, s *domain.Scanner, tokenHash string) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	q := r.db.Insert("scanners").
		Columns("id", "organization_id", "site_id", "name", "version", "capabilities", "interfaces", "health", "last_seen", "token_hash", "transport").
		Values(s.ID, s.OrganizationID, nullStr(s.SiteID), s.Name, s.Version, nonNil(s.Capabilities), nonNil(s.Interfaces), "offline", time.Now().UTC(), tokenHash, "grpc").
		Suffix(`ON CONFLICT (organization_id, name) DO UPDATE SET
			site_id = EXCLUDED.site_id, token_hash = EXCLUDED.token_hash,
			transport = 'grpc', health = 'offline' RETURNING id, created_at`)
	return r.db.QueryRow(ctx, q).Scan(&s.ID, &s.CreatedAt)
}

func (r *ScannerRepo) MarkOffline(ctx context.Context, staleBefore time.Time) error {
	q := r.db.Update("scanners").Set("health", "offline").
		Where(squirrel.Lt{"last_seen": staleBefore}).
		Where(squirrel.NotEq{"health": "offline"})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ==================================================================== scans

type ScanRepo struct{ db *DB }

func NewScanRepo(db *DB) *ScanRepo { return &ScanRepo{db: db} }

// Nullable columns (scanner_id, created_by, error, schedule_cron) are
// COALESCEd so scanning NULL into plain string fields cannot fail.
const scanCols = `id, organization_id, site_id, name, profile, engine, COALESCE(scanner_id::text,'') AS scanner_id, COALESCE(created_by::text,'') AS created_by,
state, progress, phase, config, stats, COALESCE(error,'') AS error, kill_switch, scheduled, COALESCE(schedule_cron,'') AS schedule_cron, created_at,
started_at, completed_at`

func scanScan(row scanner) (*domain.Scan, error) {
	var s domain.Scan
	err := row.Scan(&s.ID, &s.OrganizationID, &s.SiteID, &s.Name, &s.Profile, &s.Engine,
		&s.ScannerID, &s.CreatedBy, &s.State, &s.Progress, &s.Phase, &s.Config, &s.Stats,
		&s.Error, &s.KillSwitch, &s.Scheduled, &s.ScheduleCRON, &s.CreatedAt,
		&s.StartedAt, &s.CompletedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &s, nil
}

func (r *ScanRepo) Create(ctx context.Context, s *domain.Scan, scope *domain.ScanScope) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	cfgJSON, _ := json.Marshal(s.Config)
	statsJSON, _ := json.Marshal(s.Stats)
	err := r.db.WithTx(ctx, func(tx pgx.Tx) error {
		q := r.db.Insert("scans").
			Columns("id", "organization_id", "site_id", "name", "profile", "engine",
				"scanner_id", "created_by", "state", "config", "stats", "scheduled", "schedule_cron").
			Values(s.ID, s.OrganizationID, s.SiteID, s.Name, s.Profile, s.Engine,
				nullStr(s.ScannerID), nullStr(s.CreatedBy), s.State, cfgJSON, statsJSON,
				s.Scheduled, nullStr(s.ScheduleCRON))
		if err := r.db.ExecTx(ctx, tx, q); err != nil {
			return err
		}
		if scope != nil {
			sq := r.db.Insert("scan_scopes").
				Columns("id", "scan_id", "cidrs", "ip_ranges", "hostnames", "allowlist", "denylist", "exclude_hosts").
				Values(ids.New(), s.ID, nonNil(scope.CIDRs), nonNil(scope.IPRanges), nonNil(scope.Hostnames),
					nonNil(scope.Allowlist), nonNil(scope.Denylist), nonNil(scope.ExcludeHosts))
			if err := r.db.ExecTx(ctx, tx, sq); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (r *ScanRepo) ByID(ctx context.Context, orgID, id string) (*domain.Scan, error) {
	where := squirrel.Eq{"id": id}
	if orgID != "" {
		// Internal callers (scanner kill-switch checks) pass an empty org;
		// HTTP handlers always pass the claims-derived organization.
		where["organization_id"] = orgID
	}
	q := r.db.Select(scanCols).From("scans").Where(where)
	return scanScan(r.db.QueryRow(ctx, q))
}

func (r *ScanRepo) Scope(ctx context.Context, scanID string) (*domain.ScanScope, error) {
	q := r.db.Select("cidrs, ip_ranges, hostnames, allowlist, denylist, exclude_hosts").
		From("scan_scopes").Where(squirrel.Eq{"scan_id": scanID})
	var sc domain.ScanScope
	err := r.db.QueryRow(ctx, q).Scan(&sc.CIDRs, &sc.IPRanges, &sc.Hostnames,
		&sc.Allowlist, &sc.Denylist, &sc.ExcludeHosts)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &sc, nil
}

// ScanListFilter constrains scan listings.
type ScanListFilter struct {
	OrgID  string
	SiteID string
	State  string
	Limit  int
	Page   int
}

func (r *ScanRepo) List(ctx context.Context, f ScanListFilter) ([]domain.Scan, int64, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page < 1 {
		f.Page = 1
	}
	where := squirrel.Eq{}
	if f.OrgID != "" {
		where["organization_id"] = f.OrgID
	}
	if f.SiteID != "" {
		where["site_id"] = f.SiteID
	}
	if f.State != "" {
		where["state"] = f.State
	}
	q := r.db.Select(scanCols).From("scans").Where(where).OrderBy("created_at DESC")
	total, err := r.count(ctx, where)
	if err != nil {
		return nil, 0, err
	}
	rows, err := r.db.Query(ctx, q.Limit(uint64(f.Limit)).Offset(uint64((f.Page-1)*f.Limit)))
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []domain.Scan
	for rows.Next() {
		s, err := scanScan(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *s)
	}
	return out, total, rows.Err()
}

func (r *ScanRepo) count(ctx context.Context, where squirrel.Eq) (int64, error) {
	q := r.db.Select("count(*)").From("scans").Where(where)
	var n int64
	err := r.db.QueryRow(ctx, q).Scan(&n)
	return n, err
}

// AssignScanner records which hub scanner took (or was defaulted to) a scan.
func (r *ScanRepo) AssignScanner(ctx context.Context, scanID, scannerID string) error {
	q := r.db.Update("scans").Set("scanner_id", scannerID).Where(squirrel.Eq{"id": scanID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ScanRepo) UpdateState(ctx context.Context, id string, state domain.ScanState, phase string, progress float64) error {
	fields := squirrel.Eq{}
	set := map[string]any{"state": state, "phase": phase, "progress": progress}
	if state == domain.ScanRunning {
		set["started_at"] = time.Now().UTC()
	}
	if state == domain.ScanCompleted || state == domain.ScanFailed || state == domain.ScanCancelled {
		set["completed_at"] = time.Now().UTC()
	}
	for k, v := range set {
		fields[k] = v
	}
	q := r.db.Update("scans")
	for k, v := range fields {
		q = q.Set(k, v)
	}
	q = q.Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ScanRepo) UpdateStats(ctx context.Context, id string, stats domain.ScanStats) error {
	b, _ := json.Marshal(stats)
	q := r.db.Update("scans").Set("stats", b).Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ScanRepo) SetError(ctx context.Context, id, msg string) error {
	q := r.db.Update("scans").Set("error", msg).Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ScanRepo) SetKillSwitch(ctx context.Context, id string) error {
	q := r.db.Update("scans").Set("kill_switch", true).Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ActiveBySite returns running scans for a site.
func (r *ScanRepo) ActiveBySite(ctx context.Context, siteID string) ([]domain.Scan, error) {
	q := r.db.Select(scanCols).From("scans").
		Where(squirrel.Eq{"site_id": siteID}).
		Where(squirrel.Eq{"state": domain.ScanRunning})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Scan
	for rows.Next() {
		s, err := scanScan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *s)
	}
	return out, rows.Err()
}

// ==================================================================== scan tasks

type TaskRepo struct{ db *DB }

func NewTaskRepo(db *DB) *TaskRepo { return &TaskRepo{db: db} }

func (r *TaskRepo) Create(ctx context.Context, t *domain.ScanTask) error {
	if t.ID == "" {
		t.ID = ids.New()
	}
	q := r.db.Insert("scan_tasks").
		Columns("id", "scan_id", "type", "state", "scanner_id", "target", "attempt", "payload").
		Values(t.ID, t.ScanID, t.Type, t.State, nullStr(t.ScannerID), nullStr(t.Target), t.Attempt, t.Payload)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *TaskRepo) UpdateState(ctx context.Context, id string, state domain.TaskState, errMsg string) error {
	set := map[string]any{"state": state}
	if errMsg != "" {
		set["error"] = errMsg
	}
	switch state {
	case domain.TaskRunning:
		set["started_at"] = time.Now().UTC()
	case domain.TaskSucceeded, domain.TaskFailed, domain.TaskCancelled:
		set["finished_at"] = time.Now().UTC()
	}
	q := r.db.Update("scan_tasks")
	for k, v := range set {
		q = q.Set(k, v)
	}
	q = q.Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *TaskRepo) ListForScan(ctx context.Context, scanID string) ([]domain.ScanTask, error) {
	q := r.db.Select("id, scan_id, type, state, COALESCE(scanner_id::text,'') AS scanner_id, COALESCE(target::text,'') AS target, attempt, COALESCE(error,'') AS error, created_at, started_at, finished_at").
		From("scan_tasks").Where(squirrel.Eq{"scan_id": scanID}).OrderBy("created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScanTask
	for rows.Next() {
		var t domain.ScanTask
		if err := rows.Scan(&t.ID, &t.ScanID, &t.Type, &t.State, &t.ScannerID, &t.Target,
			&t.Attempt, &t.Error, &t.CreatedAt, &t.StartedAt, &t.FinishedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (r *TaskRepo) CountByState(ctx context.Context, scanID string) (done, failed, total int64, err error) {
	q := r.db.Select(
		"count(*) FILTER (WHERE state IN ('succeeded'))",
		"count(*) FILTER (WHERE state IN ('failed','retrying'))",
		"count(*)").
		From("scan_tasks").Where(squirrel.Eq{"scan_id": scanID})
	err = r.db.QueryRow(ctx, q).Scan(&done, &failed, &total)
	return
}

// ==================================================================== observations

type ObservationRepo struct{ db *DB }

func NewObservationRepo(db *DB) *ObservationRepo { return &ObservationRepo{db: db} }

func (r *ObservationRepo) Insert(ctx context.Context, o *domain.Observation) error {
	if o.ID == "" {
		o.ID = ids.New()
	}
	norm, _ := json.Marshal(o.Normalized)
	q := r.db.Insert("scan_observations").
		Columns("id", "scan_id", "task_id", "site_id", "organization_id", "target",
			"observation_type", "observed_at", "source", "payload", "normalized", "confidence", "error").
		Values(o.ID, o.ScanID, nullStr(o.TaskID), o.SiteID, o.OrganizationID, o.Target,
			o.ObservationType, o.Timestamp, string(o.Source), o.Payload, norm,
			float64(o.Confidence), o.Error)
	_, err := r.db.Exec(ctx, q)
	return err
}

// ==================================================================== schedules

type ScheduleRepo struct{ db *DB }

func NewScheduleRepo(db *DB) *ScheduleRepo { return &ScheduleRepo{db: db} }

func (r *ScheduleRepo) Create(ctx context.Context, s *domain.ScanSchedule) error {
	if s.ID == "" {
		s.ID = ids.New()
	}
	q := r.db.Insert("scan_schedules").
		Columns("id", "organization_id", "site_id", "name", "profile", "cron", "scope", "engine", "created_by").
		Values(s.ID, s.OrganizationID, s.SiteID, s.Name, s.Profile, s.CRON, nonNil(s.Scope), s.Engine, nullStr(s.CreatedBy))
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ScheduleRepo) Due(ctx context.Context, now time.Time) ([]domain.ScanSchedule, error) {
	q := r.db.Select("id, organization_id, site_id::text, name, profile, cron, scope, engine, enabled, COALESCE(created_by::text,'') AS created_by, last_run_at, next_run_at, created_at").
		From("scan_schedules").
		Where(squirrel.Eq{"enabled": true}).
		Where(squirrel.Or{
			squirrel.LtOrEq{"next_run_at": now},
			squirrel.Expr("next_run_at IS NULL"),
		})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScanSchedule
	for rows.Next() {
		var s domain.ScanSchedule
		if err := rows.Scan(&s.ID, &s.OrganizationID, &s.SiteID, &s.Name, &s.Profile,
			&s.CRON, &s.Scope, &s.Engine, &s.Enabled, &s.CreatedBy, &s.LastRunAt,
			&s.NextRunAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (r *ScheduleRepo) MarkRun(ctx context.Context, id string, last, next time.Time) error {
	q := r.db.Update("scan_schedules").
		Set("last_run_at", last).
		Set("next_run_at", next).
		Where(squirrel.Eq{"id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ScheduleRepo) List(ctx context.Context, orgID string) ([]domain.ScanSchedule, error) {
	q := r.db.Select("id, organization_id, site_id::text, name, profile, cron, scope, engine, enabled, COALESCE(created_by::text,'') AS created_by, last_run_at, next_run_at, created_at").
		From("scan_schedules").Where(squirrel.Eq{"organization_id": orgID}).OrderBy("created_at DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.ScanSchedule
	for rows.Next() {
		var s domain.ScanSchedule
		if err := rows.Scan(&s.ID, &s.OrganizationID, &s.SiteID, &s.Name, &s.Profile,
			&s.CRON, &s.Scope, &s.Engine, &s.Enabled, &s.CreatedBy, &s.LastRunAt,
			&s.NextRunAt, &s.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ==================================================================== changes

type ChangeRepo struct{ db *DB }

func NewChangeRepo(db *DB) *ChangeRepo { return &ChangeRepo{db: db} }

func (r *ChangeRepo) Insert(ctx context.Context, c *domain.Change) error {
	if c.ID == "" {
		c.ID = ids.New()
	}
	q := r.db.Insert("scan_changes").
		Columns("id", "scan_id", "site_id", "type", "asset_id", "entity", "before_value", "after_value").
		Values(c.ID, c.ScanID, c.SiteID, string(c.Type), nullStr(c.AssetID), c.Entity, c.Before, c.After)
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *ChangeRepo) ListForSite(ctx context.Context, siteID string, limit int) ([]domain.Change, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	q := r.db.Select("id, scan_id::text, site_id::text, type, COALESCE(asset_id::text,'') AS asset_id, COALESCE(entity,'') AS entity, COALESCE(before_value,'') AS before_value, COALESCE(after_value,'') AS after_value, created_at").
		From("scan_changes").Where(squirrel.Eq{"site_id": siteID}).
		OrderBy("created_at DESC").Limit(uint64(limit))
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Change
	for rows.Next() {
		var c domain.Change
		if err := rows.Scan(&c.ID, &c.ScanID, &c.SiteID, &c.Type, &c.AssetID, &c.Entity,
			&c.Before, &c.After, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (r *ChangeRepo) ListForScan(ctx context.Context, scanID string) ([]domain.Change, error) {
	q := r.db.Select("id, scan_id::text, site_id::text, type, COALESCE(asset_id::text,'') AS asset_id, COALESCE(entity,'') AS entity, COALESCE(before_value,'') AS before_value, COALESCE(after_value,'') AS after_value, created_at").
		From("scan_changes").Where(squirrel.Eq{"scan_id": scanID}).OrderBy("created_at")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Change
	for rows.Next() {
		var c domain.Change
		if err := rows.Scan(&c.ID, &c.ScanID, &c.SiteID, &c.Type, &c.AssetID, &c.Entity,
			&c.Before, &c.After, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Delete removes a schedule owned by an org.
func (r *ScheduleRepo) Delete(ctx context.Context, orgID, id string) error {
	q := r.db.Delete("scan_schedules").Where(squirrel.Eq{"organization_id": orgID, "id": id})
	_, err := r.db.Exec(ctx, q)
	return err
}
