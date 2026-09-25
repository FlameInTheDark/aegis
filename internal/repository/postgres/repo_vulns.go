package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// ==================================================================== CVE store

type VulnRepo struct{ db *DB }

func NewVulnRepo(db *DB) *VulnRepo { return &VulnRepo{db: db} }

// UpsertCVE preserves provenance and never silently overwrites upstream data
// without bumping source_version.
func (r *VulnRepo) UpsertCVE(ctx context.Context, v *domain.Vulnerability) error {
	q := r.db.Insert("vulnerabilities").
		Columns("cve_id", "state", "published_at", "updated_at", "description",
			"cvss_v2", "cvss_v3", "cvss_v4", "cwe", "affected", "source", "source_record",
			"source_version", "ingested_at", "raw_ref").
		Values(v.CVEID, v.State, v.PublishedAt, v.UpdatedAt, v.Description,
			v.CVSSv2, v.CVSSv3, v.CVSSv4, nonNil(v.CWE), affectedJSON(v.Affected), v.Source, v.SourceRecord,
			v.SourceVersion, time.Now().UTC(), v.RawRef).
		Suffix(`ON CONFLICT (cve_id) DO UPDATE SET
                        state = EXCLUDED.state,
                        published_at = COALESCE(EXCLUDED.published_at, vulnerabilities.published_at),
                        updated_at = COALESCE(EXCLUDED.updated_at, vulnerabilities.updated_at),
                        description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE vulnerabilities.description END,
                        cvss_v2 = COALESCE(EXCLUDED.cvss_v2, vulnerabilities.cvss_v2),
                        cvss_v3 = COALESCE(EXCLUDED.cvss_v3, vulnerabilities.cvss_v3),
                        cvss_v4 = COALESCE(EXCLUDED.cvss_v4, vulnerabilities.cvss_v4),
                        cwe = CASE WHEN array_length(EXCLUDED.cwe,1) > 0 THEN EXCLUDED.cwe ELSE vulnerabilities.cwe END,
                        affected = CASE WHEN EXCLUDED.affected <> '[]'::jsonb THEN EXCLUDED.affected ELSE vulnerabilities.affected END,
                        source = EXCLUDED.source,
                        source_record = EXCLUDED.source_record,
                        source_version = EXCLUDED.source_version,
                        ingested_at = now()`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// affectedJSON marshals the affected-product list for the JSONB column;
// an empty list marshals to '[]' so the conflict clause can detect "no data
// this round" and keep whatever a richer ingest stored before.
func affectedJSON(list []domain.AffectedProduct) []byte {
	if len(list) == 0 {
		return []byte("[]")
	}
	b, err := json.Marshal(list)
	if err != nil {
		return []byte("[]")
	}
	return b
}

// UpsertCVEBatch inserts or updates a batch of CVE records in one statement
// per chunk. Built for the cvelistV5 bootstrap (~300k records): single-row
// upserts at that scale take minutes; batched they take seconds.
func (r *VulnRepo) UpsertCVEBatch(ctx context.Context, list []*domain.Vulnerability) error {
	const chunk = 250
	for start := 0; start < len(list); start += chunk {
		end := start + chunk
		if end > len(list) {
			end = len(list)
		}
		batch := list[start:end]
		q := r.db.Insert("vulnerabilities").
			Columns("cve_id", "state", "published_at", "updated_at", "description",
				"cvss_v2", "cvss_v3", "cvss_v4", "cwe", "affected", "source", "source_record",
				"source_version", "ingested_at", "raw_ref")
		for _, v := range batch {
			q = q.Values(v.CVEID, v.State, v.PublishedAt, v.UpdatedAt, v.Description,
				v.CVSSv2, v.CVSSv3, v.CVSSv4, nonNil(v.CWE), affectedJSON(v.Affected), v.Source, v.SourceRecord,
				v.SourceVersion, time.Now().UTC(), v.RawRef)
		}
		q = q.Suffix(`ON CONFLICT (cve_id) DO UPDATE SET
                        state = EXCLUDED.state,
                        published_at = COALESCE(EXCLUDED.published_at, vulnerabilities.published_at),
                        updated_at = COALESCE(EXCLUDED.updated_at, vulnerabilities.updated_at),
                        description = CASE WHEN EXCLUDED.description <> '' THEN EXCLUDED.description ELSE vulnerabilities.description END,
                        cvss_v2 = COALESCE(EXCLUDED.cvss_v2, vulnerabilities.cvss_v2),
                        cvss_v3 = COALESCE(EXCLUDED.cvss_v3, vulnerabilities.cvss_v3),
                        cvss_v4 = COALESCE(EXCLUDED.cvss_v4, vulnerabilities.cvss_v4),
                        cwe = CASE WHEN array_length(EXCLUDED.cwe,1) > 0 THEN EXCLUDED.cwe ELSE vulnerabilities.cwe END,
                        affected = CASE WHEN EXCLUDED.affected <> '[]'::jsonb THEN EXCLUDED.affected ELSE vulnerabilities.affected END,
                        source = EXCLUDED.source,
                        source_record = EXCLUDED.source_record,
                        source_version = EXCLUDED.source_version,
                        ingested_at = now()`)
		if _, err := r.db.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// ReplaceCPEMatchesBatch refreshes CPE applicability for many CVEs, one
// transaction per CVE (delete + one multi-row insert). Chunked calls keep
// individual transactions small during full-feed bootstrap.
func (r *VulnRepo) ReplaceCPEMatchesBatch(ctx context.Context, matches map[string][]domain.CPEMatch) error {
	for cveID, ms := range matches {
		if len(ms) == 0 {
			continue
		}
		err := r.db.WithTx(ctx, func(tx pgx.Tx) error {
			del := r.db.Delete("vulnerability_cpe_matches").Where(squirrel.Eq{"cve_id": cveID})
			if err := r.db.ExecTx(ctx, tx, del); err != nil {
				return err
			}
			q := r.db.Insert("vulnerability_cpe_matches").
				Columns("id", "cve_id", "cpe", "vendor", "product", "version",
					"version_start_incl", "version_start_excl", "version_end_incl", "version_end_excl", "version_type")
			for _, m := range ms {
				q = q.Values(ids.New(), cveID, m.CPE, m.Vendor, m.Product, m.Version,
					m.VersionStartIncl, m.VersionStartExcl, m.VersionEndIncl, m.VersionEndExcl, m.VersionType)
			}
			if err := r.db.ExecTx(ctx, tx, q); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// CVE loads one record hydrated with CPE matches, EPSS and KEV evidence.
func (r *VulnRepo) CVE(ctx context.Context, cveID string) (*domain.Vulnerability, error) {
	m, err := r.CVEs(ctx, []string{cveID})
	if err != nil {
		return nil, err
	}
	v := m[cveID]
	if v == nil {
		return nil, mapNotFound(pgx.ErrNoRows)
	}
	return v, nil
}

// CVEs batch-loads full records — the read path of the matching engine.
// Candidates used to load one CVE+CPES query pair per candidate (N+1);
// correlation over a product's candidate set now costs a fixed number of
// round trips. Every record is hydrated with CPE matches, the latest EPSS
// snapshot and KEV status: risk scoring reads those fields and the old
// hydrate-only-when-listed behavior left them empty on the match path.
func (r *VulnRepo) CVEs(ctx context.Context, cveIDs []string) (map[string]*domain.Vulnerability, error) {
	out := make(map[string]*domain.Vulnerability, len(cveIDs))
	const chunk = 200
	for start := 0; start < len(cveIDs); start += chunk {
		end := start + chunk
		if end > len(cveIDs) {
			end = len(cveIDs)
		}
		if err := r.loadCVEChunk(ctx, cveIDs[start:end], out); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (r *VulnRepo) loadCVEChunk(ctx context.Context, ids []string, out map[string]*domain.Vulnerability) error {
	q := r.db.Select(`cve_id, state, published_at, updated_at, description,
                cvss_v2, cvss_v3, cvss_v4, cwe, affected, source, source_record, source_version, ingested_at, raw_ref`).
		From("vulnerabilities").Where(squirrel.Eq{"cve_id": ids})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return err
	}
	var affectedByCve = map[string][]byte{}
	for rows.Next() {
		v := &domain.Vulnerability{}
		var affected []byte
		if err := rows.Scan(&v.CVEID, &v.State, &v.PublishedAt, &v.UpdatedAt,
			&v.Description, &v.CVSSv2, &v.CVSSv3, &v.CVSSv4, &v.CWE, &affected, &v.Source,
			&v.SourceRecord, &v.SourceVersion, &v.IngestedAt, &v.RawRef); err != nil {
			rows.Close()
			return err
		}
		affectedByCve[v.CVEID] = affected
		out[v.CVEID] = v
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}

	// CPE matches (the matching engine's evaluation input).
	cq := r.db.Select(`cve_id, cpe, vendor, product, version, version_start_incl, version_start_excl,
                version_end_incl, version_end_excl, version_type`).
		From("vulnerability_cpe_matches").Where(squirrel.Eq{"cve_id": ids})
	crows, err := r.db.Query(ctx, cq)
	if err != nil {
		return err
	}
	defer crows.Close()
	for crows.Next() {
		var cveID string
		var m domain.CPEMatch
		var cpe string
		if err := crows.Scan(&cveID, &cpe, &m.Vendor, &m.Product, &m.Version,
			&m.VersionStartIncl, &m.VersionStartExcl, &m.VersionEndIncl, &m.VersionEndExcl, &m.VersionType); err != nil {
			return err
		}
		m.CPE = cpe
		if v := out[cveID]; v != nil {
			v.CPEMatches = append(v.CPEMatches, m)
		}
	}
	if err := crows.Err(); err != nil {
		return err
	}

	// Latest EPSS snapshot per CVE.
	eq := r.db.Select("DISTINCT ON (cve_id) cve_id, date::text, epss, percentile").
		From("vulnerability_epss").Where(squirrel.Eq{"cve_id": ids}).
		OrderBy("cve_id, date DESC")
	erows, err := r.db.Query(ctx, eq)
	if err != nil {
		return err
	}
	defer erows.Close()
	for erows.Next() {
		var cveID, date string
		var epss, percentile float64
		if err := erows.Scan(&cveID, &date, &epss, &percentile); err != nil {
			return err
		}
		if v := out[cveID]; v != nil {
			v.EPSS = &domain.EPSSRecord{CVEID: cveID, Date: date, EPSS: epss, Percentile: percentile, Source: "first"}
		}
	}
	if err := erows.Err(); err != nil {
		return err
	}

	// KEV status.
	kq := r.db.Select(`cve_id, known_exploited, date_added, due_date, ransomware_use, required_action`).
		From("vulnerability_kev").Where(squirrel.Eq{"cve_id": ids})
	krows, err := r.db.Query(ctx, kq)
	if err != nil {
		return err
	}
	defer krows.Close()
	for krows.Next() {
		var cveID string
		var rec domain.KEVRecord
		if err := krows.Scan(&cveID, &rec.KnownExploited, &rec.DateAdded, &rec.DueDate,
			&rec.RansomwareUse, &rec.RequiredAction); err != nil {
			return err
		}
		if v := out[cveID]; v != nil {
			rec.CVEID = cveID
			rec.Source = "cisa_kev"
			v.KnownExploited = &rec
		}
	}
	if err := krows.Err(); err != nil {
		return err
	}

	// Apply the affected statements collected above.
	for cveID, affected := range affectedByCve {
		if len(affected) > 0 {
			_ = json.Unmarshal(affected, &out[cveID].Affected)
		}
	}
	return nil
}

// ReplaceCPERefreshes the CPE match set of one CVE within a transaction.
func (r *VulnRepo) ReplaceCPERefreshes(ctx context.Context, cveID string, matches []domain.CPEMatch) error {
	return r.db.WithTx(ctx, func(tx pgx.Tx) error {
		del := r.db.Delete("vulnerability_cpe_matches").Where(squirrel.Eq{"cve_id": cveID})
		if err := r.db.ExecTx(ctx, tx, del); err != nil {
			return err
		}
		for _, m := range matches {
			ins := r.db.Insert("vulnerability_cpe_matches").
				Columns("id", "cve_id", "cpe", "vendor", "product", "version",
					"version_start_incl", "version_start_excl", "version_end_incl", "version_end_excl", "version_type").
				Values(ids.New(), cveID, m.CPE, m.Vendor, m.Product, m.Version,
					m.VersionStartIncl, m.VersionStartExcl, m.VersionEndIncl, m.VersionEndExcl, m.VersionType)
			if err := r.db.ExecTx(ctx, tx, ins); err != nil {
				return err
			}
		}
		return nil
	})
}

// CPESForCVE returns all CPE matches for a CVE.
func (r *VulnRepo) CPESForCVE(ctx context.Context, cveID string) ([]domain.CPEMatch, error) {
	q := r.db.Select(`cpe, vendor, product, version, version_start_incl, version_start_excl,
                version_end_incl, version_end_excl, version_type`).
		From("vulnerability_cpe_matches").Where(squirrel.Eq{"cve_id": cveID})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.CPEMatch
	for rows.Next() {
		var m domain.CPEMatch
		var cpe string
		if err := rows.Scan(&cpe, &m.Vendor, &m.Product, &m.Version,
			&m.VersionStartIncl, &m.VersionStartExcl, &m.VersionEndIncl, &m.VersionEndExcl, &m.VersionType); err != nil {
			return nil, err
		}
		m.CPE = cpe
		out = append(out, m)
	}
	return out, rows.Err()
}

// CandidateCVEsByProduct returns CVEs whose CPE matches the vendor/product pair.
func (r *VulnRepo) CandidateCVEsByProduct(ctx context.Context, vendor, product string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 200
	}
	q := r.db.Select("DISTINCT cve_id").From("vulnerability_cpe_matches").
		Where(squirrel.Eq{"vendor": vendor, "product": product}).
		// Newest first: without a deterministic order PostgreSQL returns
		// rows in heap order, so for products with more matches than the
		// limit (linux kernel, openssl, ...) the LIMIT silently truncated
		// away the most recently published - and most relevant - CVEs.
		OrderBy("cve_id DESC").
		Limit(uint64(limit))
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

// BackfillCPEIdentity parses the raw CPE criteria of stored applicability
// rows into the indexed vendor/product/version columns. Feeds before the
// identity fix stored blank identities, leaving CandidateCVEsByProduct
// blind to nearly every NVD row (99%+ of the corpus). Idempotent and
// cursor-driven: populated rows are skipped and unparseable criteria are
// stepped past, so repeated runs converge and never loop forever. Runs in
// the background at startup; returns the number of rows whose identity was
// filled.
func (r *VulnRepo) BackfillCPEIdentity(ctx context.Context, batchSize int) (int, error) {
	if batchSize <= 0 {
		batchSize = 2000
	}
	total := 0
	var lastID string
	for {
		q := r.db.Select("id, cpe").From("vulnerability_cpe_matches").
			Where(squirrel.Eq{"product": ""}).
			OrderBy("id").Limit(uint64(batchSize))
		if lastID != "" {
			q = q.Where(squirrel.Gt{"id": lastID})
		}
		rows, err := r.db.Query(ctx, q)
		if err != nil {
			return total, err
		}
		type row struct {
			id  string
			cpe string
		}
		var batch []row
		for rows.Next() {
			var rec row
			if err := rows.Scan(&rec.id, &rec.cpe); err != nil {
				rows.Close()
				return total, err
			}
			batch = append(batch, rec)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return total, err
		}
		if len(batch) == 0 {
			return total, nil
		}
		lastID = batch[len(batch)-1].id
		for _, rec := range batch {
			p, ok := fingerprinting.ParseCPE(rec.cpe)
			if !ok {
				continue // unparseable criteria: stepped past, stays blank
			}
			uq := r.db.Update("vulnerability_cpe_matches").
				Set("vendor", p.Vendor).Set("product", p.Product).Set("version", p.Version).
				Where(squirrel.Eq{"id": rec.id})
			if _, err := r.db.Exec(ctx, uq); err != nil {
				return total, err
			}
			total++
		}
	}
}

// AddReferences stores reference links for a CVE.
func (r *VulnRepo) AddReferences(ctx context.Context, cveID string, refs []string) error {
	for _, u := range refs {
		q := r.db.Insert("vulnerability_references").
			Columns("id", "cve_id", "url").
			Values(ids.New(), cveID, u).
			Suffix("ON CONFLICT DO NOTHING")
		if _, err := r.db.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// AddReferencesBatch inserts reference rows for many CVEs in chunked
// multi-row statements. The NVD sync carries ~3 references per record across
// ~280k records — the per-record loop used to take longer than the API crawl
// itself.
func (r *VulnRepo) AddReferencesBatch(ctx context.Context, refs map[string][]string) error {
	const chunk = 500
	for cveID, urls := range refs {
		if len(urls) == 0 {
			continue
		}
		for start := 0; start < len(urls); start += chunk {
			end := start + chunk
			if end > len(urls) {
				end = len(urls)
			}
			q := r.db.Insert("vulnerability_references").Columns("id", "cve_id", "url")
			n := 0
			for _, u := range urls[start:end] {
				if u == "" {
					continue
				}
				q = q.Values(ids.New(), cveID, u)
				n++
			}
			if n == 0 {
				continue
			}
			q = q.Suffix("ON CONFLICT DO NOTHING")
			if _, err := r.db.Exec(ctx, q); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *VulnRepo) References(ctx context.Context, cveID string) ([]string, error) {
	q := r.db.Select("url").From("vulnerability_references").
		Where(squirrel.Eq{"cve_id": cveID}).OrderBy("url")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UpsertEPSS stores a daily EPSS snapshot.
func (r *VulnRepo) UpsertEPSS(ctx context.Context, rec *domain.EPSSRecord) error {
	q := r.db.Insert("vulnerability_epss").
		Columns("cve_id", "date", "epss", "percentile", "source", "ingested_at").
		Values(rec.CVEID, rec.Date, rec.EPSS, rec.Percentile, rec.Source, time.Now().UTC()).
		Suffix(`ON CONFLICT (cve_id, date) DO UPDATE SET epss = EXCLUDED.epss, percentile = EXCLUDED.percentile`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// UpsertEPSSBatch inserts EPSS rows in chunked multi-row statements. The
// FIRST corpus is ~250k records/day — single-row upserts made the daily sync
// crawl for hours.
func (r *VulnRepo) UpsertEPSSBatch(ctx context.Context, recs []*domain.EPSSRecord) error {
	const chunk = 250
	for start := 0; start < len(recs); start += chunk {
		end := start + chunk
		if end > len(recs) {
			end = len(recs)
		}
		q := r.db.Insert("vulnerability_epss").
			Columns("cve_id", "date", "epss", "percentile", "source", "ingested_at")
		for _, rec := range recs[start:end] {
			q = q.Values(rec.CVEID, rec.Date, rec.EPSS, rec.Percentile, rec.Source, time.Now().UTC())
		}
		q = q.Suffix(`ON CONFLICT (cve_id, date) DO UPDATE SET epss = EXCLUDED.epss, percentile = EXCLUDED.percentile`)
		if _, err := r.db.Exec(ctx, q); err != nil {
			return err
		}
	}
	return nil
}

// LatestEPSS returns the most recent EPSS record for a CVE.
func (r *VulnRepo) LatestEPSS(ctx context.Context, cveID string) (*domain.EPSSRecord, error) {
	q := r.db.Select("cve_id, date::text, epss, percentile, source, ingested_at").
		From("vulnerability_epss").Where(squirrel.Eq{"cve_id": cveID}).
		OrderBy("date DESC").Limit(1)
	var rec domain.EPSSRecord
	err := r.db.QueryRow(ctx, q).Scan(&rec.CVEID, &rec.Date, &rec.EPSS, &rec.Percentile,
		&rec.Source, &rec.IngestedAt)
	if err != nil {
		return nil, mapNotFound(err)
	}
	return &rec, nil
}

// EPSSForCVEs returns latest EPSS values for a batch of CVEs.
func (r *VulnRepo) EPSSForCVEs(ctx context.Context, cveIDs []string) (map[string]float64, error) {
	out := map[string]float64{}
	if len(cveIDs) == 0 {
		return out, nil
	}
	q := r.db.Select("DISTINCT ON (cve_id) cve_id, epss").
		From("vulnerability_epss").
		Where(squirrel.Eq{"cve_id": cveIDs}).
		OrderBy("cve_id", "date DESC")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var epss float64
		if err := rows.Scan(&id, &epss); err != nil {
			return out, err
		}
		out[id] = epss
	}
	return out, rows.Err()
}

// UpsertKEV stores a KEV entry.
func (r *VulnRepo) UpsertKEV(ctx context.Context, rec *domain.KEVRecord) error {
	q := r.db.Insert("vulnerability_kev").
		Columns("cve_id", "known_exploited", "date_added", "due_date", "ransomware_use", "required_action", "source", "ingested_at").
		Values(rec.CVEID, rec.KnownExploited, rec.DateAdded, rec.DueDate, rec.RansomwareUse, rec.RequiredAction, rec.Source, time.Now().UTC()).
		Suffix(`ON CONFLICT (cve_id) DO UPDATE SET
                        known_exploited = EXCLUDED.known_exploited,
                        date_added = EXCLUDED.date_added,
                        due_date = EXCLUDED.due_date,
                        ransomware_use = EXCLUDED.ransomware_use,
                        required_action = EXCLUDED.required_action,
                        ingested_at = now()`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// KEVSet returns the set of known-exploited CVE ids.
func (r *VulnRepo) KEVSet(ctx context.Context) (map[string]bool, error) {
	q := r.db.Select("cve_id").From("vulnerability_kev").Where(squirrel.Eq{"known_exploited": true})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// UpsertOSV stores a normalized OSV record.
func (r *VulnRepo) UpsertOSV(ctx context.Context, rec *domain.OSVRecord) error {
	// JSONB columns are NOT NULL: marshal explicitly so nil slices become
	// jsonb 'null' values instead of SQL NULL.
	severities, _ := json.Marshal(rec.Severities)
	refs, _ := json.Marshal(rec.References)
	ranges, _ := json.Marshal(rec.AffectedRanges)
	q := r.db.Insert("osv_records").
		Columns("id", "cve_ids", "summary", "details", "ecosystem", "package_name",
			"severities", "refs", "affected_ranges", "published", "modified", "source", "ingested_at").
		Values(rec.ID, nonNil(rec.CVEIDs), rec.Summary, rec.Details, rec.Ecosystem, rec.PackageName,
			severities, refs, ranges, rec.Published, rec.Modified,
			rec.Source, time.Now().UTC()).
		Suffix(`ON CONFLICT (id) DO UPDATE SET
                        summary = EXCLUDED.summary, details = EXCLUDED.details,
                        modified = EXCLUDED.modified, ingested_at = now()`)
	_, err := r.db.Exec(ctx, q)
	return err
}

// OSVForPackage returns OSV records for an ecosystem package.
func (r *VulnRepo) OSVForPackage(ctx context.Context, ecosystem, name string) ([]domain.OSVRecord, error) {
	q := r.db.Select(`id, cve_ids, summary, details, ecosystem, package_name, severities,
                refs, affected_ranges, published, modified, source, ingested_at`).
		From("osv_records").
		Where(squirrel.Eq{"ecosystem": ecosystem, "package_name": name})
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.OSVRecord
	for rows.Next() {
		var rec domain.OSVRecord
		if err := rows.Scan(&rec.ID, &rec.CVEIDs, &rec.Summary, &rec.Details, &rec.Ecosystem,
			&rec.PackageName, &rec.Severities, &rec.References, &rec.AffectedRanges,
			&rec.Published, &rec.Modified, &rec.Source, &rec.IngestedAt); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

// ==================================================================== feeds

type FeedRepo struct{ db *DB }

func NewFeedRepo(db *DB) *FeedRepo { return &FeedRepo{db: db} }

func (r *FeedRepo) EnsureSource(ctx context.Context, name, license string) error {
	q := r.db.Insert("feed_sources").Columns("name", "license").
		Values(name, license).
		Suffix("ON CONFLICT (name) DO NOTHING")
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *FeedRepo) Sources(ctx context.Context) ([]domain.FeedSource, error) {
	// last_error is nullable TEXT; COALESCE keeps the string scan NULL-safe.
	q := r.db.Select("name, enabled, last_sync_at, last_status, records_ingested, records_new, records_updated, COALESCE(last_error,'') AS last_error, license").
		From("feed_sources").OrderBy("name")
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.FeedSource
	for rows.Next() {
		var f domain.FeedSource
		if err := rows.Scan(&f.Name, &f.Enabled, &f.LastSyncAt, &f.LastStatus,
			&f.RecordsIngest, &f.RecordsNew, &f.RecordsUpdated, &f.LastError, &f.License); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// records_total is the live count of what each feed owns in the local
	// index — read from the tables the feed writes, never accumulated from
	// sync runs. records_ingested is the LAST RUN's processed counter (KEV
	// re-processes its ~1.7k catalog every tick), so it must never be
	// presented as the size of a 79k-record vulnerability index.
	counts, cerr := r.feedRecordTotals(ctx)
	if cerr == nil {
		for i := range out {
			out[i].RecordsTotal = int(counts[out[i].Name])
		}
	}
	return out, nil
}

// feedRecordTotals counts, in one round-trip, the rows each known feed owns
// in the tables it writes. Feeds without a table here map to 0.
func (r *FeedRepo) feedRecordTotals(ctx context.Context) (map[string]int64, error) {
	sql := `SELECT
                (SELECT COUNT(*) FROM vulnerability_kev),
                (SELECT COUNT(DISTINCT cve_id) FROM vulnerability_epss),
                (SELECT COUNT(*) FROM vulnerabilities WHERE source = 'nvd'),
                (SELECT COUNT(*) FROM vulnerabilities WHERE source = 'cvelistv5'),
                (SELECT COUNT(*) FROM osv_records),
                (SELECT COUNT(*) FROM os_advisories),
                (SELECT COUNT(*) FROM vulnerability_sources WHERE source = 'vulnrichment')`
	var kev, epss, nvd, cvelist, osv, advisories, vulnrich int64
	if err := r.db.QueryRowSQL(ctx, sql).Scan(&kev, &epss, &nvd, &cvelist, &osv, &advisories, &vulnrich); err != nil {
		return nil, err
	}
	return map[string]int64{
		"kev":          kev,
		"epss":         epss,
		"nvd":          nvd,
		"cvelistv5":    cvelist,
		"osv":          osv,
		"advisories":   advisories,
		"vulnrichment": vulnrich,
	}, nil
}

func (r *FeedRepo) SetEnabled(ctx context.Context, name string, enabled bool) error {
	q := r.db.Update("feed_sources").Set("enabled", enabled).Where(squirrel.Eq{"name": name})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *FeedRepo) StartRun(ctx context.Context, feed string) (string, error) {
	id := ids.New()
	q := r.db.Insert("feed_sync_runs").Columns("id", "feed").Values(id, feed)
	if _, err := r.db.Exec(ctx, q); err != nil {
		return "", err
	}
	return id, nil
}

func (r *FeedRepo) FinishRun(ctx context.Context, runID, status, errMsg string, processed, created, updated, rejected int) error {
	q := r.db.Update("feed_sync_runs").
		Set("finished_at", time.Now().UTC()).
		Set("status", status).
		Set("processed", processed).
		Set("created", created).
		Set("updated", updated).
		Set("rejected", rejected).
		Set("error", nullStr(errMsg)).
		Where(squirrel.Eq{"id": runID})
	_, err := r.db.Exec(ctx, q)
	return err
}

func (r *FeedRepo) UpdateStatus(ctx context.Context, name string, status string, lastSync time.Time, ingested, created, updated int64, lastErr string) error {
	q := r.db.Update("feed_sources").
		Set("last_status", status).
		Set("last_sync_at", lastSync).
		Set("records_ingested", ingested).
		Set("records_new", created).
		Set("records_updated", updated).
		Set("last_error", nullStr(lastErr)).
		Where(squirrel.Eq{"name": name})
	_, err := r.db.Exec(ctx, q)
	return err
}

// MarkRunning flips the visible status to 'running' without touching
// last_sync_at or counters, so a multi-hour bootstrap is observable in the
// feeds API instead of reading as an indefinite 'never_synced'.
func (r *FeedRepo) MarkRunning(ctx context.Context, name string) error {
	q := r.db.Update("feed_sources").Set("last_status", "running").Where(squirrel.Eq{"name": name})
	_, err := r.db.Exec(ctx, q)
	return err
}

// ClearRunning resets 'running' rows left behind by an unclean worker stop.
// Feeds that had already ingested data become 'stale' (honest: data present
// but old); never-completed bootstraps return to 'never_synced' and re-run.
func (r *FeedRepo) ClearRunning(ctx context.Context) (int64, error) {
	q := r.db.Update("feed_sources").
		Set("last_status", squirrel.Expr("CASE WHEN records_ingested > 0 THEN 'stale' ELSE 'never_synced' END")).
		Where(squirrel.Eq{"last_status": "running"})
	res, err := r.db.Exec(ctx, q)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected(), nil
}

// LastSyncAt exposes the previous successful sync time for incremental
// windows (NVD lastModStartDate). Zero time when the feed never synced.
func (r *FeedRepo) LastSyncAt(ctx context.Context, name string) (time.Time, error) {
	q := r.db.Select("COALESCE(last_sync_at, '0001-01-01T00:00:00Z'::timestamptz)").
		From("feed_sources").Where(squirrel.Eq{"name": name})
	var t time.Time
	err := r.db.QueryRow(ctx, q).Scan(&t)
	return t, err
}

// GetMeta returns a feed_meta value. A missing key reads as ("", nil) —
// callers distinguish "not set" (ingest schema never recorded) from
// storage errors, which surface as a real error.
func (r *FeedRepo) GetMeta(ctx context.Context, key string) (string, error) {
	q := r.db.Select("value").From("feed_meta").Where(squirrel.Eq{"key": key})
	var v string
	err := r.db.QueryRow(ctx, q).Scan(&v)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return "", err
	}
	return v, nil
}

// SetMeta upserts a feed_meta value.
func (r *FeedRepo) SetMeta(ctx context.Context, key, value string) error {
	q := r.db.Insert("feed_meta").
		Columns("key", "value", "updated_at").
		Values(key, value, time.Now().UTC()).
		Suffix("ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()")
	_, err := r.db.Exec(ctx, q)
	return err
}

// VulnListFilter filters the vulnerability index listing. Search matches
// substrings anywhere in the CVE id ("CVE-2005-24"), the description text
// and reference URLs — case-insensitive, trigram-indexed (migration 0010).
type VulnListFilter struct {
	Search   string
	Severity string // critical|high|medium|low (maps to CVSS bands)
	KEV      bool
	State    string  // PUBLISHED|REJECTED|RESERVED|DISPUTED
	Source   string  // nvd|cve|osv|manual
	MinScore float64 // CVSS v3 lower bound (0 = unset)
	MaxScore float64 // CVSS v3 upper bound (0 = unset)
	// Sort/Order: whitelist-driven server-side ordering. Sort keys:
	// published_at | updated_at | cve_id | cvss_score | known_exploited.
	// Order: asc|desc ("" = sensible default per key). Anything else falls
	// back to the default relevance order — user input never reaches SQL.
	Sort  string
	Order string
	// Published window (either bound optional). Values may be RFC3339 or a
	// bare YYYY-MM-DD (treated as that calendar day, UTC).
	PublishedAfter  string
	PublishedBefore string
	Limit           int
	Page            int
}

// VulnListRow is one vulnerability list row with org-relative counters.
type VulnListRow struct {
	CVEID          string     `json:"cve_id"`
	State          string     `json:"state"`
	Description    string     `json:"description"`
	CVSSScore      float64    `json:"cvss_score"`
	CVSSVector     string     `json:"cvss_vector,omitempty"`
	PublishedAt    *time.Time `json:"published_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
	KnownExploited bool       `json:"known_exploited"`
	AffectedAssets int64      `json:"affected_assets"`
	OpenFindings   int64      `json:"open_findings"`
	Source         string     `json:"source"`
}

// ListVulns returns a page of the local vulnerability index enriched with
// KEV state and per-org affected-asset counts (columns).
func (r *VulnRepo) ListVulns(ctx context.Context, orgID string, f VulnListFilter) (struct {
	Items []VulnListRow `json:"items"`
	Total int64         `json:"total"`
}, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Page < 1 {
		f.Page = 1
	}
	where := squirrel.Eq{}
	var searchCond squirrel.Sqlizer
	// Substring search across CVE id, description and reference URLs
	// (case-insensitive). Escaped LIKE metacharacters; the pg_trgm GIN
	// indexes (migration 0010) keep '%…%' scans fast at CVE-index size.
	if s := strings.TrimSpace(f.Search); s != "" {
		pat := "%" + escapeLike(s) + "%"
		searchCond = squirrel.Expr(
			"(v.cve_id ILIKE ? OR v.description ILIKE ? OR EXISTS (SELECT 1 FROM vulnerability_references vr WHERE vr.cve_id = v.cve_id AND vr.url ILIKE ?))",
			pat, pat, pat)
	}
	if f.State != "" {
		where["v.state"] = strings.ToUpper(f.State)
	}
	if f.Source != "" {
		where["v.source"] = strings.ToLower(f.Source)
	}
	// CVSS v3 score bounds are applied to both the page and the count
	// queries via this closure (raw SQL with args — never Eq map keys).
	applyScore := func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		if f.MinScore > 0 {
			b = b.Where("COALESCE(v.cvss_v3->>'score','0')::float8 >= ?", f.MinScore)
		}
		if f.MaxScore > 0 {
			b = b.Where("COALESCE(v.cvss_v3->>'score','0')::float8 <= ?", f.MaxScore)
		}
		return b
	}
	// Published-date window ("by date published" filtering), also shared
	// by the count query so totals match the visible page.
	applyPublished := func(b squirrel.SelectBuilder) squirrel.SelectBuilder {
		if t, ok := parsePublishedBound(f.PublishedAfter, false); ok {
			b = b.Where("v.published_at >= ?", t)
		}
		if t, ok := parsePublishedBound(f.PublishedBefore, true); ok {
			b = b.Where("v.published_at <= ?", t)
		}
		return b
	}
	// Base query over vulnerabilities with joins for kev + counts.
	q := r.db.Select(
		"v.cve_id", "v.state", "v.description", "v.published_at", "v.updated_at",
		"COALESCE(v.cvss_v3->>'score','0')::float8 AS cvss_score",
		"COALESCE(v.cvss_v3->>'vector','') AS cvss_vector",
		"CASE WHEN k.cve_id IS NULL THEN false ELSE true END AS known_exploited",
		"COALESCE(fc.affected, 0) AS affected_assets",
		"COALESCE(fc.open_findings, 0) AS open_findings",
		"v.source",
	).From("vulnerabilities v").
		LeftJoin("vulnerability_kev k ON k.cve_id = v.cve_id").
		LeftJoin("(SELECT cve_id, count(DISTINCT asset_id) AS affected, count(*) FILTER (WHERE status IN ('open','acknowledged','in_progress')) AS open_findings FROM findings WHERE organization_id = ? GROUP BY cve_id) fc ON fc.cve_id = v.cve_id", orgID)
	if len(where) > 0 {
		q = q.Where(where)
	}
	if searchCond != nil {
		q = q.Where(searchCond)
	}
	q = applyScore(q)
	if f.KEV {
		q = q.Where("k.cve_id IS NOT NULL")
	}
	if f.Severity != "" {
		switch strings.ToLower(f.Severity) {
		case "critical":
			q = q.Where("COALESCE(v.cvss_v3->>'score','0')::float8 >= 9")
		case "high":
			q = q.Where("COALESCE(v.cvss_v3->>'score','0')::float8 >= 7 AND COALESCE(v.cvss_v3->>'score','0')::float8 < 9")
		case "medium":
			q = q.Where("COALESCE(v.cvss_v3->>'score','0')::float8 >= 4 AND COALESCE(v.cvss_v3->>'score','0')::float8 < 7")
		case "low":
			q = q.Where("COALESCE(v.cvss_v3->>'score','0')::float8 > 0 AND COALESCE(v.cvss_v3->>'score','0')::float8 < 4")
		}
	}
	q = applyPublished(q)
	q = q.OrderBy(vulnOrderClause(f.Sort, f.Order)).Limit(uint64(f.Limit)).Offset(uint64((f.Page - 1) * f.Limit))

	var out struct {
		Items []VulnListRow `json:"items"`
		Total int64         `json:"total"`
	}
	rows, err := r.db.Query(ctx, q)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var row VulnListRow
		if err := rows.Scan(&row.CVEID, &row.State, &row.Description, &row.PublishedAt, &row.UpdatedAt,
			&row.CVSSScore, &row.CVSSVector, &row.KnownExploited, &row.AffectedAssets, &row.OpenFindings, &row.Source); err == nil {
			out.Items = append(out.Items, row)
		}
	}
	// Total count honoring the SAME filters (search/severity/kev/state/
	// source/score) so pagination reflects what the user is looking at.
	var total int64
	cq := r.db.Select("count(*)").From("vulnerabilities v").
		LeftJoin("vulnerability_kev k ON k.cve_id = v.cve_id")
	if len(where) > 0 {
		cq = cq.Where(where)
	}
	if searchCond != nil {
		cq = cq.Where(searchCond)
	}
	cq = applyScore(cq)
	if f.KEV {
		cq = cq.Where("k.cve_id IS NOT NULL")
	}
	if f.Severity != "" {
		switch strings.ToLower(f.Severity) {
		case "critical":
			cq = cq.Where("COALESCE(v.cvss_v3->>'score','0')::float8 >= 9")
		case "high":
			cq = cq.Where("COALESCE(v.cvss_v3->>'score','0')::float8 >= 7 AND COALESCE(v.cvss_v3->>'score','0')::float8 < 9")
		case "medium":
			cq = cq.Where("COALESCE(v.cvss_v3->>'score','0')::float8 >= 4 AND COALESCE(v.cvss_v3->>'score','0')::float8 < 7")
		case "low":
			cq = cq.Where("COALESCE(v.cvss_v3->>'score','0')::float8 > 0 AND COALESCE(v.cvss_v3->>'score','0')::float8 < 4")
		}
	}
	cq = applyPublished(cq)
	if err := r.db.QueryRow(ctx, cq).Scan(&total); err == nil {
		out.Total = total
	}
	return out, rows.Err()
}

// vulnOrderClause maps the whitelist sort key to ORDER BY SQL. Anything
// unknown returns the default relevance order (KEV first, then CVSS). NULL
// published/updated dates sort last regardless of direction so reserved CVEs
// never dominate a "newest first" view. Every returned string is composed
// from fixed literals — user input only selects between them.
func vulnOrderClause(sort, order string) string {
	// Normalize case and the UI's friendly aliases ("published", "name",
	// "cvss", "kev") onto the whitelist keys - the browser sent exactly
	// those spellings, every option missed the whitelist and silently
	// degraded to the default clause, so sorting appeared dead. Unknown
	// keys keep their value, miss every case below and still land on
	// the default relevance order; user input never reaches SQL.
	switch strings.ToLower(strings.TrimSpace(sort)) {
	case "published":
		sort = "published_at"
	case "updated":
		sort = "updated_at"
	case "name":
		sort = "cve_id"
	case "cvss":
		sort = "cvss_score"
	case "kev":
		sort = "known_exploited"
	default:
		sort = strings.ToLower(strings.TrimSpace(sort))
	}
	dir := "DESC"
	if strings.EqualFold(order, "asc") {
		dir = "ASC"
	} else if order == "" {
		switch sort {
		case "cve_id":
			dir = "ASC" // "by name" reads A→Z by default
		}
	}
	switch sort {
	case "published_at":
		return fmt.Sprintf("v.published_at %s NULLS LAST, known_exploited DESC, cvss_score DESC", dir)
	case "updated_at":
		return fmt.Sprintf("v.updated_at %s NULLS LAST, known_exploited DESC, cvss_score DESC", dir)
	case "cve_id":
		return fmt.Sprintf("v.cve_id %s", dir)
	case "cvss_score":
		return fmt.Sprintf("cvss_score %s, known_exploited DESC, v.cve_id ASC", dir)
	case "known_exploited":
		return fmt.Sprintf("known_exploited %s, cvss_score DESC, v.cve_id ASC", dir)
	}
	return "known_exploited DESC, cvss_score DESC"
}

// parsePublishedBound accepts RFC3339 timestamps or a bare YYYY-MM-DD (that
// calendar day, UTC; endOfDay shifts a date to 23:59:59 so a "before" filter
// includes the whole day it names).
func parsePublishedBound(v string, endOfDay bool) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, v); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", v); err == nil {
		if endOfDay {
			return t.Add(24*time.Hour - time.Second), true
		}
		return t, true
	}
	return time.Time{}, false
}
