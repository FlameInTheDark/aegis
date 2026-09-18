// cvelist.go implements the CVE List v5 (cvelistV5) feed job: the CVE
// Program's authoritative record repository
// (https://github.com/CVEProject/cvelistV5). It is the primary source for
// newly published CVEs — records appear here before NVD enrichment catches
// up — and carries machine-readable CPE applicability per affected product.
//
// Upstream publishes hourly GitHub releases tagged cve_YYYY-MM-DD_HH00Z with
// two assets (the old monolithic cvelistV5.zip asset was retired — it now
// 404s):
//
//	{date}_all_CVEs_at_midnight.zip.zip   full list as of that day's 00:00 UTC
//	{date}_delta_CVEs_at_HH00Z.zip        every record changed that day so far
//
// The delta is cumulative for the UTC day, so the sync plan is:
//
//	never synced / last sync before today -> midnight snapshot + today's delta
//	last sync already today               -> today's delta only (~3 MB)
//
// Asset names are discovered from the latest release page HTML (CDN-served,
// no GitHub API token or rate limit). If discovery fails the sync falls back
// to the legacy release asset URL, then to the git branch archive
// (archive/refs/heads/main.zip), which carries the same cves/ tree.
package feeds

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

const (
	// cvelistRepoBase is the repo root for release-page scraping (tests point
	// it at an httptest server via CVEListV5Job.BaseURL).
	cvelistRepoBase = "https://github.com/CVEProject/cvelistV5"
	// cvelistLegacyAssetURL is the pre-rename release asset. It 404s since the
	// CVE Program switched to dated asset names, but stays first in the
	// fallback chain in case upstream restores it.
	cvelistLegacyAssetURL = cvelistRepoBase + "/releases/latest/download/cvelistV5.zip"
	// cvelistBranchArchive is the always-buildable git branch archive. Larger
	// than the release assets but immune to release-layout changes.
	cvelistBranchArchive = cvelistRepoBase + "/archive/refs/heads/main.zip"
)

// DefaultCVEListURL is kept for compatibility with older configurations that
// pinned the monolithic release asset via AEGIS_FEED_CVELIST_URL.
const DefaultCVEListURL = cvelistLegacyAssetURL

// MetaStore persists small feed bookkeeping values (feed_meta table).
type MetaStore interface {
	GetMeta(ctx context.Context, key string) (string, error)
	SetMeta(ctx context.Context, key, value string) error
}

const (
	// cvelistIngestVersionKey is the feed_meta key holding the ingest schema
	// version of the cvelistv5 corpus.
	cvelistIngestVersionKey = "cvelistv5_ingest_version"
	// cvelistIngestVersion bumps whenever the affected→CPE-match materializer
	// changes shape. Stored rows keep their old bounds, so a version change
	// forces one full re-ingest to rebuild affected products and ranges.
	// v2: affected parsing (defaultStatus, start bounds, exact pins,
	// changes) + per-range CPE match fan-out with versionType.
	cvelistIngestVersion = "2"
)

// CVEListV5Job syncs the CVE List v5 repository.
type CVEListV5Job struct {
	Client *Client
	Vulns  *pg.VulnRepo
	Log    *slog.Logger
	// URL overrides asset discovery entirely: when set, exactly this artifact
	// is downloaded and ingested (release zip, branch archive or a bare CVE
	// JSON 5.0 record for tests/manual imports).
	URL string
	// LastSyncFn exposes the previous successful sync time so syncs can pull
	// only today's cumulative delta instead of re-ingesting the full corpus.
	LastSyncFn func(context.Context) time.Time
	// BaseURL overrides the GitHub repo base for asset discovery (tests).
	BaseURL string
	// FallbackURLs overrides the static fallback chain used when release
	// discovery fails (tests). Defaults to the legacy release asset, then
	// the git branch archive.
	FallbackURLs []cvelistDownload
	// TmpDir overrides the temp directory for the streamed archive (tests).
	TmpDir string
	// Meta persists the ingest schema version. When the stored version is
	// older than cvelistIngestVersion the job force-rebootstraps the full
	// corpus once, so records ingested by an older parser get their affected
	// products and version ranges rebuilt (feed_meta table).
	Meta MetaStore
}

func (j *CVEListV5Job) Name() string { return "cvelistv5" }
func (j *CVEListV5Job) License() string {
	return "CVE Program cvelistV5 (CVE TOU, attribution required)"
}

// decodeCVE5 unmarshals one CVE JSON 5.0 record.
func decodeCVE5(data []byte) (*cve5Record, error) {
	var rec cve5Record
	if err := json.Unmarshal(data, &rec); err != nil {
		return nil, fmt.Errorf("cvelistv5 parse: %w", err)
	}
	return &rec, nil
}

// cvssEntry is one CVSS metric value. cvelistV5 records put baseScore and
// vectorString directly on the metric object; NVD-style nested "cvssData"
// also appears in the wild — both shapes are accepted.
type cvssEntry struct {
	CVSSData struct {
		BaseScore    float64 `json:"baseScore"`
		VectorString string  `json:"vectorString"`
	} `json:"cvssData"`
	DirectScore  float64 `json:"baseScore"`
	DirectVector string  `json:"vectorString"`
}

// score returns the CVSS base score regardless of the JSON shape used.
func (c cvssEntry) score() float64 {
	if c.CVSSData.BaseScore > 0 {
		return c.CVSSData.BaseScore
	}
	return c.DirectScore
}

func (c cvssEntry) vector() string {
	if c.CVSSData.VectorString != "" {
		return c.CVSSData.VectorString
	}
	return c.DirectVector
}

// cvssList accepts a single CVSS object or an array of them — CVE JSON 5.0
// allows both shapes for cvssV3_1 and friends.
type cvssList []cvssEntry

func (c *cvssList) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var list []cvssEntry
		if err := json.Unmarshal(data, &list); err != nil {
			return err
		}
		*c = list
		return nil
	}
	var one cvssEntry
	if err := json.Unmarshal(data, &one); err != nil {
		return err
	}
	*c = []cvssEntry{one}
	return nil
}

// cve5Record is the lean view of a CVE JSON 5.0 record we consume.
type cve5Record struct {
	DataType    string `json:"dataType"`
	CVEMetadata struct {
		ID        string `json:"cveId"`
		State     string `json:"state"`
		Published string `json:"datePublished"`
		Updated   string `json:"dateUpdated"`
	} `json:"cveMetadata"`
	Containers struct {
		CNA struct {
			Metrics []struct {
				CVSSV40 cvssList `json:"cvssV4_0"`
				CVSSV31 cvssList `json:"cvssV3_1"`
				CVSSV30 cvssList `json:"cvssV3_0"`
				CVSSV20 cvssList `json:"cvssV2_0"`
			} `json:"metrics"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Weaknesses []struct {
				Description []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
			Affected   []cve5Affected `json:"affected"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cna"`
		ADP []struct {
			Metrics []struct {
				CVSSV31 cvssList `json:"cvssV3_1"`
				CVSSV30 cvssList `json:"cvssV3_0"`
			} `json:"metrics"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
		} `json:"adp"`
	} `json:"containers"`
}

// cve5Affected is one affected product entry with optional machine-readable
// version ranges ("versions") and official CPE strings ("cpes").
type cve5Affected struct {
	Vendor        string        `json:"vendor"`
	Product       string        `json:"product"`
	DefaultStatus string        `json:"defaultStatus"` // affected | unaffected | unknown
	CPEs          []string      `json:"cpes"`
	Platforms     []string      `json:"platforms"`
	Versions      []cve5Version `json:"versions"`
}

// cve5Version is one version statement. An entry with only "version" pins
// that exact version; "lessThan"/"lessThanOrEqual" turn it into a range
// with an exclusive/inclusive end. "changes" flips the status from a
// version onward inside the range.
type cve5Version struct {
	Version         string `json:"version"`
	Status          string `json:"status"` // affected | unaffected | unknown
	LessThan        string `json:"lessThan"`
	LessThanOrEqual string `json:"lessThanOrEqual"`
	VersionType     string `json:"versionType"`
	Changes         []struct {
		At     string `json:"at"`
		Status string `json:"status"`
	} `json:"changes"`
}

// cvelistDownload is one artifact to ingest with its size cap.
type cvelistDownload struct {
	URL      string
	MaxBytes int64
}

// cvelistAssets are the discovered artifacts of the latest upstream release.
type cvelistAssets struct {
	Tag        string
	FullAsset  string // {date}_all_CVEs_at_midnight.zip(.zip)
	DeltaAsset string // {date}_delta_CVEs_at_HH00Z.zip
}

// resolveAssets discovers the latest release's asset names by scraping the
// GitHub release pages. The REST API is avoided deliberately: unauthenticated
// API quota (60 req/h per IP) is shared with everything else egressing the
// same address, while the HTML endpoints are CDN-served and unmetered.
func (j *CVEListV5Job) resolveAssets(ctx context.Context) (*cvelistAssets, error) {
	base := j.BaseURL
	if base == "" {
		base = cvelistRepoBase
	}
	tag, err := cvelistLatestTag(ctx, base)
	if err != nil {
		return nil, err
	}
	// The release page lazy-loads its asset list from this fragment.
	htmlBody, err := cvelistGetString(ctx, base+"/releases/expanded_assets/"+tag, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("cvelistv5 assets page: %w", err)
	}
	assets := &cvelistAssets{Tag: tag}
	for _, href := range cvelistAssetHrefs(htmlBody) {
		name := path.Base(href)
		lower := strings.ToLower(name)
		// Self-consistent absolute URL built from the discovered tag
		// (the href is root-relative; never trust it verbatim).
		url := base + "/releases/download/" + tag + "/" + name
		switch {
		case strings.Contains(lower, "_all_cves_at_midnight"):
			if assets.FullAsset == "" || len(name) > len(path.Base(assets.FullAsset)) {
				assets.FullAsset = url
			}
		case strings.Contains(lower, "_delta_cves_at_"):
			if assets.DeltaAsset == "" || name > path.Base(assets.DeltaAsset) {
				assets.DeltaAsset = url // lexicographic = later hour
			}
		case lower == "cvelistv5.zip":
			assets.FullAsset = url // legacy layout
		}
	}
	if assets.FullAsset == "" && assets.DeltaAsset == "" {
		return nil, fmt.Errorf("cvelistv5 release %s exposes no usable assets", tag)
	}
	return assets, nil
}

// cvelistLatestTag follows the /releases/latest redirect and returns the tag
// it landed on (…/releases/tag/cve_2026-09-16_1800Z).
func cvelistLatestTag(ctx context.Context, base string) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "aegis-platform/1.0 (vulnerability-feed)")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("cvelistv5 latest release: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("cvelistv5 latest release: HTTP %d", resp.StatusCode)
	}
	final := ""
	if resp.Request != nil && resp.Request.URL != nil {
		final = resp.Request.URL.Path
	}
	const marker = "/releases/tag/"
	if i := strings.Index(final, marker); i >= 0 {
		return strings.TrimPrefix(final[i+len(marker):], "/"), nil
	}
	return "", fmt.Errorf("cvelistv5 latest release: no tag in %q", final)
}

// cvelistGetString fetches a small text resource (release pages).
func cvelistGetString(ctx context.Context, url string, maxBytes int64) (string, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "aegis-platform/1.0 (vulnerability-feed)")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// cvelistAssetRe extracts release-asset download links from the
// expanded_assets HTML fragment.
var cvelistAssetRe = regexp.MustCompile(`href="([^"]*/releases/download/[^"]+)"`)

func cvelistAssetHrefs(body string) []string {
	var out []string
	for _, m := range cvelistAssetRe.FindAllStringSubmatch(body, -1) {
		out = append(out, html.UnescapeString(m[1]))
	}
	return out
}

// cvelistPlan decides which artifacts the sync needs. The daily delta is
// cumulative from 00:00 UTC, so a sync that already ran today only needs the
// delta; anything older needs the midnight snapshot to cover the gap plus the
// delta to be current through now. An empty plan with skip=true means "we
// synced today and the upstream has not published a delta yet — nothing new".
func cvelistPlan(now, last time.Time, assets *cvelistAssets) (plan []cvelistDownload, skip bool) {
	if assets == nil {
		return nil, false
	}
	today := now.UTC().Truncate(24 * time.Hour)
	sameDay := !last.IsZero() && last.After(today)
	full := cvelistDownload{URL: assets.FullAsset, MaxBytes: 1 << 30}     // ~350 MB snapshot
	delta := cvelistDownload{URL: assets.DeltaAsset, MaxBytes: 256 << 20} // few MB
	switch {
	case sameDay && assets.DeltaAsset != "":
		return []cvelistDownload{delta}, false
	case sameDay:
		return nil, true
	case assets.FullAsset != "":
		if assets.DeltaAsset != "" {
			return []cvelistDownload{full, delta}, false
		}
		return []cvelistDownload{full}, false
	case assets.DeltaAsset != "":
		// Release without a midnight snapshot (should not happen) — the
		// day delta alone is still better than nothing for a fresh install.
		return []cvelistDownload{delta}, false
	default:
		return nil, false
	}
}

// Sync downloads and ingests cvelistV5. full=true forces the full snapshot
// regardless of the stored sync position (manual re-bootstrap). The ingest
// schema version gate: after a parser upgrade the first sync re-bootstraps
// the corpus once so previously ingested records get rebuilt affected data.
func (j *CVEListV5Job) Sync(ctx context.Context, full bool) (int, int, int, int, error) {
	if !full && j.Meta != nil {
		if v, err := j.Meta.GetMeta(ctx, cvelistIngestVersionKey); err == nil && v != cvelistIngestVersion {
			j.Log.Info("cvelistv5 ingest schema upgraded; forcing one full corpus re-ingest",
				"stored", v, "want", cvelistIngestVersion)
			full = true
		}
	}
	p, c, u, r, err := j.syncInternal(ctx, full)
	if err == nil && j.Meta != nil {
		if merr := j.Meta.SetMeta(ctx, cvelistIngestVersionKey, cvelistIngestVersion); merr != nil {
			j.Log.Warn("cvelistv5 ingest version persist failed", "err", merr)
		}
	}
	return p, c, u, r, err
}

// syncInternal is the sync body (plan → artifact ingest, with fallbacks).
func (j *CVEListV5Job) syncInternal(ctx context.Context, full bool) (int, int, int, int, error) {
	// Explicit URL override: single artifact, ingested as-is (zip archive
	// or bare CVE JSON 5.0 record). Deterministic for tests and air-gapped
	// mirrors.
	if url := j.URL; url != "" {
		return j.ingestArtifact(ctx, cvelistDownload{URL: url, MaxBytes: 1024 << 20})
	}

	last := time.Time{}
	if j.LastSyncFn != nil {
		last = j.LastSyncFn(ctx)
	}
	assets, aerr := j.resolveAssets(ctx)
	if aerr == nil {
		if full {
			// Forced bootstrap: midnight snapshot, plus the delta so the
			// result includes today's changes.
			dl := []cvelistDownload{}
			if assets.FullAsset != "" {
				dl = append(dl, cvelistDownload{URL: assets.FullAsset, MaxBytes: 1 << 30})
			}
			if assets.DeltaAsset != "" {
				dl = append(dl, cvelistDownload{URL: assets.DeltaAsset, MaxBytes: 256 << 20})
			}
			if len(dl) > 0 {
				return j.ingestAll(ctx, dl)
			}
		} else if plan, skip := cvelistPlan(time.Now(), last, assets); skip {
			j.Log.Info("cvelistv5 already synced today; upstream delta not published yet, skipping",
				"last_sync", last.Format(time.RFC3339))
			return 0, 0, 0, 0, nil
		} else if len(plan) > 0 {
			return j.ingestAll(ctx, plan)
		}
	} else {
		j.Log.Warn("cvelistv5 release discovery failed; trying static fallback URLs", "err", aerr)
		// Synced already today? A full-corpus fallback download every hour
		// is not worth it — wait for the next cycle.
		if !last.IsZero() && last.After(time.Now().UTC().Truncate(24*time.Hour)) && !full {
			j.Log.Info("cvelistv5 already synced today; skipping fallback re-bootstrap",
				"last_sync", last.Format(time.RFC3339))
			return 0, 0, 0, 0, nil
		}
	}

	// Fallback chain for discovery failures and layout surprises: the
	// legacy release asset, then the git branch archive (always buildable,
	// carries the same cves/ tree — just larger).
	fallbacks := j.FallbackURLs
	if fallbacks == nil {
		fallbacks = []cvelistDownload{
			{URL: cvelistLegacyAssetURL, MaxBytes: 1 << 30},
			{URL: cvelistBranchArchive, MaxBytes: 3 << 30},
		}
	}
	var lastErr error
	if aerr != nil {
		lastErr = aerr
	}
	for _, dl := range fallbacks {
		processed, created, updated, rejected, err := j.ingestArtifact(ctx, dl)
		if err == nil {
			return processed, created, updated, rejected, nil
		}
		j.Log.Warn("cvelistv5 fallback download failed", "url", dl.URL, "err", err)
		lastErr = err
	}
	return 0, 0, 0, 0, lastErr
}

// ingestAll ingests a sequence of artifacts, aborting on the first error.
func (j *CVEListV5Job) ingestAll(ctx context.Context, dls []cvelistDownload) (int, int, int, int, error) {
	tp, tc, tu, tr := 0, 0, 0, 0
	for _, dl := range dls {
		p, c, u, r, err := j.ingestArtifact(ctx, dl)
		tp += p
		tc += c
		tu += u
		tr += r
		if err != nil {
			return tp, tc, tu, tr, err
		}
	}
	return tp, tc, tu, tr, nil
}

// ingestArtifact downloads one cvelistV5 artifact and ingests it: a bare CVE
// JSON 5.0 record, or a zip whose record files live under cves/ (full
// snapshots, branch archives) or deltaCves/ (daily cumulative deltas).
func (j *CVEListV5Job) ingestArtifact(ctx context.Context, dl cvelistDownload) (int, int, int, int, error) {
	// Artifacts are streamed to a temp file instead of buffered in RAM: the
	// old path read the whole body under the client's 90s whole-request
	// timeout (download failed outright) and a 768 MB bytes.Buffer can OOM
	// small deployments.
	path, cleanup, err := j.Client.FetchToFile(ctx, dl.URL, dl.MaxBytes, 2, j.TmpDir)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	defer cleanup()

	// Single-record URL support (tests, manual one-off imports).
	if strings.HasSuffix(strings.ToLower(dl.URL), ".json") || awaitJSONFile(path) {
		data, rerr := os.ReadFile(path)
		if rerr != nil {
			return 0, 0, 0, 0, rerr
		}
		var rec cve5Record
		if err := json.Unmarshal(data, &rec); err != nil {
			return 0, 0, 0, 0, fmt.Errorf("cvelistv5 parse: %w", err)
		}
		if v, matches := cve5ToDomain(&rec); v != nil {
			if err := j.Vulns.UpsertCVEBatch(ctx, []*domain.Vulnerability{v}); err != nil {
				return 0, 0, 0, 0, err
			}
			if err := j.Vulns.ReplaceCPEMatchesBatch(ctx, map[string][]domain.CPEMatch{v.CVEID: matches}); err != nil {
				return 0, 0, 0, 0, err
			}
			return 1, 1, 0, 0, nil
		}
		return 1, 0, 0, 1, nil
	}

	zr, err := zip.OpenReader(path)
	if err != nil {
		return 0, 0, 0, 0, fmt.Errorf("cvelistv5 zip: %w", err)
	}
	defer zr.Close()
	processed, created, rejected := 0, 0, 0
	const batchRecords = 200
	vbatch := make([]*domain.Vulnerability, 0, batchRecords)
	cpeBatch := make(map[string][]domain.CPEMatch, batchRecords)
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !strings.HasSuffix(strings.ToLower(f.Name), ".json") {
			continue
		}
		// Only CVE record files; skip repo metadata/docs. Full snapshots
		// and branch archives use cves/YYYY/..., the daily cumulative
		// deltas use deltaCves/CVE-*.json.
		if !isCVELISTRecordPath(f.Name) {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(rc, 8<<20))
		rc.Close()
		if err != nil {
			continue
		}
		var rec cve5Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			rejected++
			continue
		}
		processed++
		// Progress beacon: the bootstrap ingests ~290k records; without a
		// periodic log line a multi-minute ingest looks wedged.
		if processed%20000 == 0 {
			j.Log.Info("cvelistv5 ingest progress", "processed", processed)
		}
		v, matches := cve5ToDomain(&rec)
		if v == nil {
			// RESERVED records carry no usable data yet; REJECTED are kept.
			if rec.CVEMetadata.State == "RESERVED" {
				rejected++
			}
			continue
		}
		vbatch = append(vbatch, v)
		if len(matches) > 0 {
			cpeBatch[v.CVEID] = matches
		}
		if len(vbatch) >= batchRecords {
			if err := j.Vulns.UpsertCVEBatch(ctx, vbatch); err != nil {
				return processed, created, 0, rejected, err
			}
			if err := j.Vulns.ReplaceCPEMatchesBatch(ctx, cpeBatch); err != nil {
				return processed, created, 0, rejected, err
			}
			created += len(vbatch)
			vbatch = vbatch[:0]
			cpeBatch = make(map[string][]domain.CPEMatch, batchRecords)
		}
	}
	if len(vbatch) > 0 {
		if err := j.Vulns.UpsertCVEBatch(ctx, vbatch); err != nil {
			return processed, created, 0, rejected, err
		}
		if err := j.Vulns.ReplaceCPEMatchesBatch(ctx, cpeBatch); err != nil {
			return processed, created, 0, rejected, err
		}
		created += len(vbatch)
	}
	return processed, created, 0, rejected, nil
}

// isCVELISTRecordPath reports whether a zip entry is a CVE record file.
// Full snapshots and git branch archives nest records under cves/YYYY/,
// the daily cumulative deltas use deltaCves/.
func isCVELISTRecordPath(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "/cves/") || strings.HasPrefix(lower, "cves/") ||
		strings.Contains(lower, "deltacves/")
}

// awaitJSONFile reports whether the downloaded file is a bare JSON document
// (single-record import) rather than a zip archive — URLs without a .json
// suffix still get one-record handling.
func awaitJSONFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [1]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == '{'
}

// cve5ToDomain maps a CVE JSON 5.0 record to the Aegis vulnerability model.
// Returns (nil, nil) for records without a usable identity (RESERVED, empty).
func cve5ToDomain(rec *cve5Record) (*domain.Vulnerability, []domain.CPEMatch) {
	if rec == nil || rec.CVEMetadata.ID == "" {
		return nil, nil
	}
	state := domain.CVEStatePublished
	if rec.CVEMetadata.State == "REJECTED" {
		state = domain.CVEStateRejected
	}
	// RESERVED records carry no usable data yet — never ingest them.
	if rec.CVEMetadata.State == "RESERVED" {
		return nil, nil
	}
	v := &domain.Vulnerability{
		CVEID: rec.CVEMetadata.ID, State: state,
		Source: "cvelistv5", SourceRecord: rec.CVEMetadata.ID, IngestedAt: time.Now().UTC(),
	}
	if t, err := time.Parse(time.RFC3339, rec.CVEMetadata.Published); err == nil {
		v.PublishedAt = &t
	}
	if t, err := time.Parse(time.RFC3339, rec.CVEMetadata.Updated); err == nil {
		v.UpdatedAt = &t
	}
	for _, d := range rec.Containers.CNA.Descriptions {
		if strings.EqualFold(d.Lang, "en") && d.Value != "" {
			v.Description = d.Value
			break
		}
	}
	if v.Description == "" && len(rec.Containers.ADP) > 0 {
		for _, d := range rec.Containers.ADP[0].Descriptions {
			if strings.EqualFold(d.Lang, "en") && d.Value != "" {
				v.Description = d.Value
				break
			}
		}
	}
	cna := rec.Containers.CNA
	for _, m := range cna.Metrics {
		if v.CVSSv4 == nil && len(m.CVSSV40) > 0 {
			v.CVSSv4 = &domain.CVSS{Vector: m.CVSSV40[0].vector(), Version: "4.0", Score: m.CVSSV40[0].score(), Source: "cvelistv5"}
		}
		if v.CVSSv3 == nil && len(m.CVSSV31) > 0 {
			v.CVSSv3 = &domain.CVSS{Vector: m.CVSSV31[0].vector(), Version: "3.1", Score: m.CVSSV31[0].score(), Source: "cvelistv5"}
		}
		if v.CVSSv3 == nil && len(m.CVSSV30) > 0 {
			v.CVSSv3 = &domain.CVSS{Vector: m.CVSSV30[0].vector(), Version: "3.0", Score: m.CVSSV30[0].score(), Source: "cvelistv5"}
		}
		if v.CVSSv2 == nil && len(m.CVSSV20) > 0 {
			v.CVSSv2 = &domain.CVSS{Vector: m.CVSSV20[0].vector(), Version: "2.0", Score: m.CVSSV20[0].score(), Source: "cvelistv5"}
		}
	}
	// ADP containers (CISA-ADP enrichment) fill missing v3 scores.
	if v.CVSSv3 == nil {
		for _, adp := range rec.Containers.ADP {
			for _, m := range adp.Metrics {
				if len(m.CVSSV31) > 0 {
					v.CVSSv3 = &domain.CVSS{Vector: m.CVSSV31[0].vector(), Version: "3.1", Score: m.CVSSV31[0].score(), Source: "cisa-adp"}
					break
				}
				if len(m.CVSSV30) > 0 {
					v.CVSSv3 = &domain.CVSS{Vector: m.CVSSV30[0].vector(), Version: "3.0", Score: m.CVSSV30[0].score(), Source: "cisa-adp"}
					break
				}
			}
			if v.CVSSv3 != nil {
				break
			}
		}
	}
	seenCWE := map[string]bool{}
	for _, w := range cna.Weaknesses {
		for _, d := range w.Description {
			if d.Value != "" && !seenCWE[d.Value] {
				seenCWE[d.Value] = true
				v.CWE = append(v.CWE, d.Value)
			}
		}
	}
	for _, r := range cna.References {
		if r.URL != "" {
			v.References = append(v.References, r.URL)
		}
	}

	// Affected products: stored verbatim for the CVE page (vendor, product,
	// defaultStatus, ranges with statuses/versionTypes/changes) and
	// materialized into CPE matches with correct per-range bounds — the
	// matching engine's candidate set. See affected.go.
	v.Affected = affectedToDomain(cna.Affected)
	return v, affectedToCPEMatches(cna.Affected)
}

// sanitizeCPEComponent lowercases and drops characters not allowed in CPE
// components (spaces, slashes and friends become underscores).
func sanitizeCPEComponent(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-' || r == '~':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "*"
	}
	return out
}
