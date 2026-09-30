package feeds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/vulnerabilities"
)

// OSVJob implements F14: when software rows carry a PURL, query the OSV API
// for that name and ecosystem, cache the advisories in the local index, and
// stamp the per-row status so "queried, clean" becomes evidence rather than
// ignorance. Queries are grouped per (ecosystem, package, version) and
// bounded per run; the job resumes where it stopped on the next tick.
type OSVJob struct {
	Client   *http.Client
	Vulns    *pg.VulnRepo
	Software *pg.SoftwareRepo
	Log      *slog.Logger
	// APIBase overrides https://api.osv.dev (tests).
	APIBase string
	// MaxQueries bounds one run (default 200); pending groups are picked
	// most-recently-seen first, so the backlog drains over ticks.
	MaxQueries int
	// QueryPause throttles the API between queries (default 200ms).
	QueryPause time.Duration
}

// OSVEcosystems is the allowlist of language ecosystems this job queries.
// OS distro packages are deliberately out of scope — the OVAL advisory plane
// covers them — and OSV's per-release OS ecosystem names ("Debian:12") would
// add a mapping layer for little gain.
var OSVEcosystems = []string{"npm", "PyPI", "Go", "Cargo", "RubyGems", "Maven", "NuGet"}

func (j *OSVJob) Name() string    { return "osv" }
func (j *OSVJob) License() string { return "OSV.dev data (api.osv.dev)" }

// osvQueryResponse is the subset of POST /v1/query the job consumes.
type osvQueryResponse struct {
	Vulns []osvVuln `json:"vulns"`
}

type osvVuln struct {
	ID        string   `json:"id"`
	Summary   string   `json:"summary"`
	Details   string   `json:"details"`
	Aliases   []string `json:"aliases"`
	Published string   `json:"published"`
	Modified  string   `json:"modified"`
	Severity  []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Ranges []domain.VersionRange `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

func (j *OSVJob) Sync(ctx context.Context, _full bool) (processed, created, updated, rejected int, err error) {
	max := j.MaxQueries
	if max <= 0 {
		max = 200
	}
	pause := j.QueryPause
	if pause <= 0 {
		pause = 200 * time.Millisecond
	}
	groups, err := j.Software.PendingOSVGroups(ctx, OSVEcosystems, max)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("pending osv groups: %w", err)
	}
	cache := map[string][]domain.OSVRecord{}
	for _, g := range groups {
		if ctx.Err() != nil {
			return processed, created, updated, rejected, ctx.Err()
		}
		if g.Version == "" {
			// No version → no verdict possible; skip so the row stays honestly
			// 'not_queried' instead of being claimed clean.
			continue
		}
		key := g.Ecosystem + "|" + g.Name
		recs, ok := cache[key]
		if !ok {
			recs, err = j.queryPackage(ctx, g.Ecosystem, g.Name)
			if err != nil {
				// One failed query must not burn the whole run; leave the group
				// pending and continue.
				j.Log.Warn("osv query failed", "ecosystem", g.Ecosystem, "package", g.Name, "err", err)
				rejected++
				continue
			}
			cache[key] = recs
			created += len(recs)
			for i := range recs {
				if uerr := j.Vulns.UpsertOSV(ctx, &recs[i]); uerr != nil {
					j.Log.Warn("osv upsert failed", "id", recs[i].ID, "err", uerr)
					updated--
				}
			}
			select {
			case <-ctx.Done():
				return processed, created, updated, rejected, ctx.Err()
			case <-time.After(pause):
			}
		}
		affected := vulnerabilities.PackageAffected(recs, g.Name, g.Version)
		if aerr := j.Software.ApplyOSVResult(ctx, g.Ecosystem, g.Name, g.Version, affected); aerr != nil {
			j.Log.Warn("osv status apply failed", "ecosystem", g.Ecosystem, "package", g.Name, "err", aerr)
			continue
		}
		processed++
		if affected {
			updated++
		}
	}
	return processed, created, 0, rejected, nil
}

func (j *OSVJob) queryPackage(ctx context.Context, ecosystem, name string) ([]domain.OSVRecord, error) {
	base := j.APIBase
	if base == "" {
		base = "https://api.osv.dev"
	}
	payload, _ := json.Marshal(map[string]any{
		"package": map[string]string{"ecosystem": ecosystem, "name": name},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(base, "/")+"/v1/query", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := j.Client
	if client == nil {
		client = &http.Client{Timeout: 20 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // unknown package: a clean answer, not an error
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("osv api status %d", resp.StatusCode)
	}
	var parsed osvQueryResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("osv response: %w", err)
	}
	out := make([]domain.OSVRecord, 0, len(parsed.Vulns))
	for _, v := range parsed.Vulns {
		rec := domain.OSVRecord{
			ID:         v.ID,
			Summary:    v.Summary,
			Details:    v.Details,
			Source:     "osv_api",
			IngestedAt: time.Now().UTC(),
		}
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") {
				rec.CVEIDs = append(rec.CVEIDs, a)
			}
		}
		for _, sev := range v.Severity {
			// OSV carries the vector string in "score" ("CVSS:3.1/AV:...").
			rec.Severities = append(rec.Severities, domain.CVSS{Version: sev.Type, Vector: sev.Score})
		}
		for _, r := range v.References {
			rec.References = append(rec.References, r.URL)
		}
		for _, aff := range v.Affected {
			if rec.Ecosystem == "" && aff.Package.Ecosystem != "" {
				rec.Ecosystem = aff.Package.Ecosystem
			}
			if rec.PackageName == "" && aff.Package.Name != "" {
				rec.PackageName = aff.Package.Name
			}
			rec.AffectedRanges = append(rec.AffectedRanges, aff.Ranges...)
		}
		if t := parseRFC3339(v.Published); t != nil {
			rec.Published = t
		}
		if t := parseRFC3339(v.Modified); t != nil {
			rec.Modified = t
		}
		if rec.PackageName == "" {
			rec.PackageName = name
		}
		if rec.Ecosystem == "" {
			rec.Ecosystem = ecosystem
		}
		out = append(out, rec)
	}
	return out, nil
}

func parseRFC3339(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	return nil
}
