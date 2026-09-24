package postgres

import (
	"context"
	"time"

	"github.com/Masterminds/squirrel"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== OS advisories

// AdvisoryRepo is the read/write side of the os_advisories table: the
// distro advisory data plane behind OS-package correlation.
type AdvisoryRepo struct{ db *DB }

func NewAdvisoryRepo(db *DB) *AdvisoryRepo { return &AdvisoryRepo{db: db} }

const advisoryCols = "id, family, release, package_name, COALESCE(source_package,'') AS source_package, " +
	"COALESCE(fixed_version,'') AS fixed_version, not_fixed_yet, cve_id, advisory_id, " +
	"COALESCE(advisory_url,'') AS advisory_url, COALESCE(severity,'') AS severity, " +
	"published_at, source, COALESCE(source_version,'') AS source_version, ingested_at"

func scanAdvisory(row scanner) (*domain.OSAdvisory, error) {
	var a domain.OSAdvisory
	err := row.Scan(&a.ID, &a.Family, &a.Release, &a.PackageName, &a.SourcePackage,
		&a.FixedVersion, &a.NotFixedYet, &a.CVEID, &a.AdvisoryID,
		&a.AdvisoryURL, &a.Severity, &a.PublishedAt, &a.Source, &a.SourceVersion, &a.IngestedAt)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// UpsertAdvisory inserts or updates one advisory row. Identity is
// (family, release, package, cve, advisory) — the same statement re-ingested
// with a newer fixed version updates in place.
func (r *AdvisoryRepo) UpsertAdvisory(ctx context.Context, a *domain.OSAdvisory) error {
	if a.ID == "" {
		a.ID = ids.New()
	}
	if a.IngestedAt.IsZero() {
		a.IngestedAt = time.Now().UTC()
	}
	q := r.db.Insert("os_advisories").
		Columns("id", "family", "release", "package_name", "source_package",
			"fixed_version", "not_fixed_yet", "cve_id", "advisory_id",
			"advisory_url", "severity", "published_at", "source", "source_version", "ingested_at").
		Values(a.ID, a.Family, a.Release, a.PackageName, nullStr(a.SourcePackage),
			nullStr(a.FixedVersion), a.NotFixedYet, a.CVEID, a.AdvisoryID,
			nullStr(a.AdvisoryURL), nullStr(a.Severity), a.PublishedAt, a.Source,
			nullStr(a.SourceVersion), a.IngestedAt).
		Suffix(`ON CONFLICT (family, release, package_name, cve_id, advisory_id) DO UPDATE SET
			source_package = EXCLUDED.source_package,
			fixed_version = EXCLUDED.fixed_version,
			not_fixed_yet = EXCLUDED.not_fixed_yet,
			advisory_url = COALESCE(EXCLUDED.advisory_url, os_advisories.advisory_url),
			severity = COALESCE(EXCLUDED.severity, os_advisories.severity),
			published_at = COALESCE(EXCLUDED.published_at, os_advisories.published_at),
			source = EXCLUDED.source,
			source_version = EXCLUDED.source_version,
			ingested_at = now()`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// UpsertAdvisoryBatch inserts a batch in chunks (feed bootstrap scale:
// full OVAL snapshots are tens of thousands of rows).
func (r *AdvisoryRepo) UpsertAdvisoryBatch(ctx context.Context, list []*domain.OSAdvisory) error {
	const chunk = 250
	for i := 0; i < len(list); i += chunk {
		end := i + chunk
		if end > len(list) {
			end = len(list)
		}
		for _, a := range list[i:end] {
			if err := r.UpsertAdvisory(ctx, a); err != nil {
				return err
			}
		}
	}
	return nil
}

// ForPackage returns every advisory statement for one (family, release,
// package). This is the correlator's hot path — one indexed lookup per
// installed package during a sweep.
func (r *AdvisoryRepo) ForPackage(ctx context.Context, family, release, pkg string) ([]domain.OSAdvisory, error) {
	if family == "" || release == "" || pkg == "" {
		return nil, nil
	}
	q := r.db.Select(advisoryCols).From("os_advisories").
		Where(squirrel.Eq{"family": family, "release": release, "package_name": pkg}).
		OrderBy("cve_id", "advisory_id")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]domain.OSAdvisory, 0)
	for rows.Next() {
		a, err := scanAdvisory(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *a)
	}
	return out, rows.Err()
}

// CountByFamily reports advisory volume per family (ops/observability).
func (r *AdvisoryRepo) CountByFamily(ctx context.Context) (map[string]int64, error) {
	q := r.db.Select("family", "count(*)").From("os_advisories").GroupBy("family")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var fam string
		var n int64
		if err := rows.Scan(&fam, &n); err != nil {
			return nil, err
		}
		out[fam] = n
	}
	return out, rows.Err()
}
