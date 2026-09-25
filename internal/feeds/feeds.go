// Package feeds implements the vulnerability intelligence synchronization
// worker: scheduled jobs with initial bootstrap, incremental
// sync, retry/backoff, outage tolerance, metrics and provenance for every
// record. Feeds never run inside user requests.
package feeds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/FlameInTheDark/aegis/internal/alerting"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
	"github.com/FlameInTheDark/aegis/internal/platform"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// SyncRequestSubject is the NATS trigger channel: the server's
// POST /api/v1/feeds/:name/sync publishes a request here and the feed-worker
// kicks the named feed without waiting for the next tick.
const SyncRequestSubject = platform.SubFeedSync

// Client is a hardened HTTP client for feed fetches (SSRF-safe: fixed
// endpoints, no user-supplied URLs except administrative configuration).
type Client struct {
	HTTP *http.Client
	Log  *slog.Logger
}

// NewClient builds the default feed client with sane timeouts.
func NewClient(log *slog.Logger) *Client {
	return &Client{HTTP: &http.Client{Timeout: 90 * time.Second}, Log: log}
}

// FetchJSON retrieves a URL with retry/backoff.
func (c *Client) FetchJSON(ctx context.Context, url string, maxBytes int64, retries int) ([]byte, error) {
	return c.FetchJSONHdr(ctx, url, maxBytes, retries, nil)
}

// FetchJSONHdr is FetchJSON with per-request headers (the NVD apiKey) and
// rate-limit awareness: NVD signals throttling with 403/429 plus a
// Retry-After header — honoring it instead of burning the retry budget
// keeps multi-hour pagination loops alive.
func (c *Client) FetchJSONHdr(ctx context.Context, url string, maxBytes int64, retries int, headers map[string]string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 2 * time.Second
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "aegis-platform/1.0 (vulnerability-feed)")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			ra := resp.Header.Get("Retry-After")
			resp.Body.Close()
			lastErr = fmt.Errorf("feed %s: HTTP %d (rate limited, retry-after=%q)", url, resp.StatusCode, ra)
			wait := 10 * time.Second
			if secs, perr := strconv.Atoi(ra); perr == nil && secs > 0 && secs <= 120 {
				wait = time.Duration(secs) * time.Second
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(wait):
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("feed %s: HTTP %d", url, resp.StatusCode)
			continue
		}
		if err != nil {
			lastErr = err
			continue
		}
		return data, nil
	}
	return nil, lastErr
}

// FetchToFile streams a large artifact to a temp file and returns its path
// plus a cleanup func. cvelistV5 ships a ~350 MB zip: FetchJSON's 90s client
// timeout is a whole-request deadline including the body read (the download
// failed outright on anything but a fat pipe) and buffering it in RAM spiked
// RSS by ~2x (OOM on small deployments). The dedicated client bounds the
// whole download at 30 minutes instead.
func (c *Client) FetchToFile(ctx context.Context, url string, maxBytes int64, retries int, dir string) (string, func(), error) {
	if dir == "" {
		dir = os.TempDir()
	}
	tmp, err := os.CreateTemp(dir, "aegis-feed-*.zip")
	if err != nil {
		return "", func() {}, fmt.Errorf("feed temp file: %w", err)
	}
	path := tmp.Name()
	cleanup := func() { _ = os.Remove(path) }

	client := &http.Client{Timeout: 30 * time.Minute}
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			backoff := time.Duration(1<<uint(attempt-1)) * 2 * time.Second
			select {
			case <-ctx.Done():
				return "", cleanup, ctx.Err()
			case <-time.After(backoff):
			}
		}
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return "", cleanup, err
		}
		if err := tmp.Truncate(0); err != nil {
			return "", cleanup, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", cleanup, err
		}
		req.Header.Set("User-Agent", "aegis-platform/1.0 (vulnerability-feed)")
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("feed %s: HTTP %d", url, resp.StatusCode)
			continue
		}
		written, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBytes))
		resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("feed %s: download: %w", url, err)
			continue
		}
		if written >= maxBytes {
			return "", cleanup, fmt.Errorf("feed %s: artifact exceeds %d byte cap", url, maxBytes)
		}
		if err := tmp.Close(); err != nil {
			return "", cleanup, err
		}
		c.Log.Info("feed artifact downloaded", "url", url, "bytes", written)
		return path, cleanup, nil
	}
	tmp.Close()
	return "", cleanup, lastErr
}

// FeedJob is one synchronized source.
type FeedJob interface {
	Name() string
	License() string
	// Sync performs bootstrap or incremental sync; returns counts.
	Sync(ctx context.Context, full bool) (processed, created, updated, rejected int, err error)
}

// Runner executes feed jobs and maintains feed_sources/feed_sync_runs.
type Runner struct {
	Repo  *pg.FeedRepo
	Vulns *pg.VulnRepo
	Store *platform.ObjectStore
	Log   *slog.Logger
	Jobs  []FeedJob
	// DB enables feed.sync.* / feed.recovered / vulnerability.index.updated
	// emission into the alert outbox (events fan out per organization,
	// because feeds are deployment-global); nil disables emission.
	DB *pg.DB

	mu      sync.Mutex
	running map[string]bool // per-feed single-flight guard
}

func (r *Runner) tryClaim(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running == nil {
		r.running = map[string]bool{}
	}
	if r.running[name] {
		return false
	}
	r.running[name] = true
	return true
}

func (r *Runner) release(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running != nil {
		delete(r.running, name)
	}
}

// RunAll executes every job concurrently. Sequential execution used to
// starve everything queued behind a slow feed: the NVD full pull runs tens
// of minutes, so cvelistv5 sat at "never_synced" for hours behind it. A feed
// that is already running (boot sync + ticker overlap, or a manual trigger)
// is skipped — the in-flight run covers it.
func (r *Runner) RunAll(ctx context.Context, full bool) {
	var wg sync.WaitGroup
	for _, job := range r.Jobs {
		if !r.tryClaim(job.Name()) {
			r.Log.Warn("feed sync already running, skipping", "feed", job.Name())
			continue
		}
		wg.Add(1)
		go func(job FeedJob) {
			defer wg.Done()
			defer r.release(job.Name())
			if err := r.RunOne(ctx, job, full); err != nil {
				r.Log.Error("feed sync failed", "feed", job.Name(), "err", err)
			}
		}(job)
	}
	wg.Wait()
}

// RunFeed triggers a single feed by name (the POST /api/v1/feeds/:name/sync
// path). Returns an error for unknown feeds and for feeds that already have
// a sync in flight.
func (r *Runner) RunFeed(ctx context.Context, name string, full bool) error {
	for _, job := range r.Jobs {
		if job.Name() != name {
			continue
		}
		if !r.tryClaim(name) {
			return fmt.Errorf("feed %s already running", name)
		}
		go func(job FeedJob) {
			defer r.release(name)
			if err := r.RunOne(ctx, job, full); err != nil {
				r.Log.Error("feed sync failed", "feed", name, "err", err)
			}
		}(job)
		return nil
	}
	return fmt.Errorf("unknown feed %q", name)
}

// RunOne runs one feed job with full bookkeeping.
func (r *Runner) RunOne(ctx context.Context, job FeedJob, full bool) (err error) {
	started := time.Now().UTC()
	runID, runErr := r.Repo.StartRun(ctx, job.Name())
	if runErr != nil {
		r.Log.Warn("start run bookkeeping failed", "feed", job.Name(), "err", runErr)
		runID = ""
	}
	// Visible 'running' marker: a multi-hour bootstrap must be observable in
	// GET /api/v1/feeds instead of reading as an indefinite 'never_synced'.
	if merr := r.Repo.MarkRunning(ctx, job.Name()); merr != nil {
		r.Log.Warn("running marker failed", "feed", job.Name(), "err", merr)
	}
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("feed panic: %v", p)
			r.Log.Error("feed sync panicked", "feed", job.Name(), "panic", p)
		}
	}()
	processed, created, updated, rejected, syncErr := job.Sync(ctx, full)
	err = syncErr
	status := "completed"
	errMsg := ""
	if syncErr != nil {
		if processed > 0 {
			status = "partial"
		} else {
			status = "failed"
		}
		errMsg = syncErr.Error()
	}
	finished := time.Now().UTC()
	if runID != "" {
		if ferr := r.Repo.FinishRun(ctx, runID, status, errMsg, processed, created, updated, rejected); ferr != nil {
			r.Log.Warn("finish run bookkeeping failed", "err", ferr)
		}
	}
	// A partial run ingested data but did not finish — 'stale' with the
	// error surfaced is more honest than a green 'healthy'.
	lastStatus := "healthy"
	switch status {
	case "failed":
		lastStatus = "failed"
	case "partial":
		lastStatus = "stale"
	}
	if uerr := r.Repo.UpdateStatus(ctx, job.Name(), lastStatus, finished, int64(processed), int64(created), int64(updated), errMsg); uerr != nil {
		r.Log.Warn("status update failed", "feed", job.Name(), "err", uerr)
	}
	r.Log.Info("feed synced", "feed", job.Name(), "status", status, "processed", processed, "created", created, "updated", updated, "rejected", rejected, "took", time.Since(started).Round(time.Millisecond))
	if r.DB != nil {
		r.emitCompletion(ctx, job.Name(), status, int64(processed), errMsg)
	}
	return err
}

// emitCompletion fans the feed outcome out per organization: feeds are
// deployment-global, alert triggers are org-scoped. The stable
// feed-health dedup key means the recovery event resolves an open
// feed.stale occurrence and is a harmless no-op otherwise.
func (r *Runner) emitCompletion(ctx context.Context, feed, status string, records int64, errMsg string) {
	orgs, err := pg.NewOrgRepo(r.DB).List(ctx)
	if err != nil {
		r.Log.Warn("feed event fan-out failed", "err", err)
		return
	}
	for _, org := range orgs {
		_ = alerting.EmitFeedSync(ctx, r.DB, org.ID, feed, status, records, errMsg)
		_ = alerting.EmitFeedStaleness(ctx, r.DB, org.ID, feed, false)
	}
}

// storeRaw keeps the original upstream payload for provenance.
func (r *Runner) storeRaw(ctx context.Context, name string, day time.Time, data []byte) string {
	if r.Store == nil {
		return ""
	}
	key := fmt.Sprintf("feeds/%s/%s.json", name, day.Format("2006-01-02"))
	if err := r.Store.Put(ctx, key, data, "application/json"); err != nil {
		r.Log.Warn("raw snapshot store failed", "err", err)
		return ""
	}
	return key
}

// ---------------------------------------------------------------------------
// KEV

// KEVJob syncs CISA Known Exploited Vulnerabilities.
type KEVJob struct {
	Client *Client
	Vulns  *pg.VulnRepo
	Store  *platform.ObjectStore
	Log    *slog.Logger
	URL    string
}

func (j *KEVJob) Name() string    { return "kev" }
func (j *KEVJob) License() string { return "U.S. Government public domain (CISA)" }

type kevFeed struct {
	Title           string `json:"title"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CVEID              string `json:"cveID"`
		DateAdded          string `json:"dateAdded"`
		DueDate            string `json:"dueDate"`
		KnownRansomwareUse string `json:"knownRansomwareCampaignUse"`
		RequiredAction     string `json:"requiredAction"`
	} `json:"vulnerabilities"`
}

func (j *KEVJob) Sync(ctx context.Context, full bool) (int, int, int, int, error) {
	url := j.URL
	if url == "" {
		url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}
	data, err := j.Client.FetchJSON(ctx, url, 32<<20, 2)
	if err != nil {
		return 0, 0, 0, 0, err
	}
	var feed kevFeed
	if err := json.Unmarshal(data, &feed); err != nil {
		return 0, 0, 0, 0, fmt.Errorf("kev parse: %w", err)
	}
	created, updated, rejected := 0, 0, 0
	now := time.Now().UTC()
	for _, v := range feed.Vulnerabilities {
		if v.CVEID == "" {
			rejected++
			continue
		}
		rec := domain.KEVRecord{CVEID: v.CVEID, KnownExploited: true, RansomwareUse: v.KnownRansomwareUse, RequiredAction: v.RequiredAction, Source: "cisa_kev", IngestedAt: now}
		if len(v.DateAdded) >= 10 {
			if t, err := time.Parse("2006-01-02", v.DateAdded[:10]); err == nil {
				rec.DateAdded = &t
			}
		}
		if len(v.DueDate) >= 10 {
			if t, err := time.Parse("2006-01-02", v.DueDate[:10]); err == nil {
				rec.DueDate = &t
			}
		}
		if err := j.Vulns.UpsertKEV(ctx, &rec); err != nil {
			j.Log.Warn("kev upsert failed", "cve", v.CVEID, "err", err)
			rejected++
			continue
		}
		created++
	}
	return len(feed.Vulnerabilities), created, updated, rejected, nil
}

// ---------------------------------------------------------------------------
// EPSS

// EPSSJob syncs FIRST EPSS daily snapshots (daily snapshots, not severity).
type EPSSJob struct {
	Client *Client
	Vulns  *pg.VulnRepo
	Log    *slog.Logger
	URL    string
	// LastSyncFn exposes the previous successful sync time; EPSS refreshes
	// once per day, so a same-day sync is skipped entirely instead of
	// re-pulling ~2.5k pages every cycle.
	LastSyncFn func(context.Context) time.Time
}

func (j *EPSSJob) Name() string    { return "epss" }
func (j *EPSSJob) License() string { return "FIRST EPSS, CC-BY (attribution required)" }

type epssResp struct {
	Data []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
	Total int `json:"total"` // not always present; len(data)<limit terminates too
}

func (j *EPSSJob) Sync(ctx context.Context, full bool) (int, int, int, int, error) {
	url := j.URL
	if url == "" {
		url = "https://api.first.org/data/v1/epss"
	}
	// EPSS refreshes daily (UTC). The FIRST API returns at most 100 records
	// per page and the corpus is ~250k rows — without pagination the sync
	// ingested exactly one page (100 records) and reported healthy.
	if !full && j.LastSyncFn != nil {
		if ls := j.LastSyncFn(ctx); !ls.IsZero() && ls.After(time.Now().UTC().Truncate(24*time.Hour)) {
			j.Log.Info("epss already synced today; skipping", "last_sync", ls.Format(time.RFC3339))
			return 0, 0, 0, 0, nil
		}
	}
	const limit = 100
	const maxPages = 4000 // hard safety bound (~400k records)
	processed, created, rejected := 0, 0, 0
	offset := 0
	pending := make([]*domain.EPSSRecord, 0, 500)
	flush := func() error {
		if len(pending) == 0 {
			return nil
		}
		if err := j.Vulns.UpsertEPSSBatch(ctx, pending); err != nil {
			return fmt.Errorf("epss batch upsert: %w", err)
		}
		created += len(pending)
		pending = pending[:0]
		return nil
	}
	for page := 0; page < maxPages; page++ {
		data, err := j.Client.FetchJSON(ctx, fmt.Sprintf("%s?limit=%d&offset=%d", url, limit, offset), 32<<20, 2)
		if err != nil {
			return processed, created, 0, rejected, err
		}
		var resp epssResp
		if err := json.Unmarshal(data, &resp); err != nil {
			return processed, created, 0, rejected, fmt.Errorf("epss parse: %w", err)
		}
		now := time.Now().UTC()
		for _, d := range resp.Data {
			processed++
			if d.CVE == "" || d.Date == "" {
				rejected++
				continue
			}
			var score, pct float64
			fmt.Sscanf(d.EPSS, "%g", &score)
			fmt.Sscanf(d.Percentile, "%g", &pct)
			pending = append(pending, &domain.EPSSRecord{CVEID: d.CVE, Date: d.Date, EPSS: score, Percentile: pct, Source: "first_epss", IngestedAt: now})
			if len(pending) >= 500 {
				if err := flush(); err != nil {
					return processed, created, 0, rejected, err
				}
			}
		}
		if len(resp.Data) < limit {
			break
		}
		offset += len(resp.Data)
		if resp.Total > 0 && offset >= resp.Total {
			break
		}
		// Gentle pacing: the FIRST API is free but unauthenticated.
		select {
		case <-ctx.Done():
			return processed, created, 0, rejected, ctx.Err()
		case <-time.After(150 * time.Millisecond):
		}
	}
	if err := flush(); err != nil {
		return processed, created, 0, rejected, err
	}
	return processed, created, 0, rejected, nil
}

// ---------------------------------------------------------------------------
// NVD

// NVDJob syncs NVD CVE records (API 2.0, incremental by lastModStartDate).
type NVDJob struct {
	Client  *Client
	Vulns   *pg.VulnRepo
	Store   *platform.ObjectStore
	Log     *slog.Logger
	URL     string
	APIKey  string
	LastMod time.Time
	// LastSyncFn returns the previous successful sync time from the feed
	// bookkeeping; incremental runs pull only records modified since then.
	// It is read at sync start (never persisted in-process), so worker
	// restarts keep their incremental position. Nil or zero time → full pull.
	LastSyncFn func(context.Context) time.Time
}

func (j *NVDJob) Name() string    { return "nvd" }
func (j *NVDJob) License() string { return "NVD public domain (NIST); CVE data under CVE TOU" }

type nvdResp struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Status       string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics struct {
		CVSSV31 []struct {
			CVSSData struct {
				VectorString string  `json:"vectorString"`
				BaseScore    float64 `json:"baseScore"`
			} `json:"cvssData"`
			Source string `json:"source"`
		} `json:"cvssMetricV31"`
		CVSSV30 []struct {
			CVSSData struct {
				VectorString string  `json:"vectorString"`
				BaseScore    float64 `json:"baseScore"`
			} `json:"cvssData"`
			Source string `json:"source"`
		} `json:"cvssMetricV30"`
		CVSSV2 []struct {
			CVSSData struct {
				VectorString string  `json:"vectorString"`
				BaseScore    float64 `json:"baseScore"`
			} `json:"cvssData"`
			Source string `json:"source"`
		} `json:"cvssMetricV2"`
	} `json:"metrics"`
	Weaknesses []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Configurations []struct {
		Nodes []struct {
			CPEMatch []struct {
				Criteria string `json:"criteria"`
				// Vulnerable defaults to true when NVD omits it;
				// explicit false marks a negated match (what the
				// CVE does NOT affect) and must never create
				// applicability.
				Vulnerable            *bool  `json:"vulnerable"`
				VersionStartIncluding string `json:"versionStartIncluding"`
				VersionStartExcluding string `json:"versionStartExcluding"`
				VersionEndIncluding   string `json:"versionEndIncluding"`
				VersionEndExcluding   string `json:"versionEndExcluding"`
			} `json:"cpeMatch"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// nvdState maps NVD's workflow-oriented vulnStatus field (for example,
// "Analyzed" and "Undergoing Analysis") to the canonical CVE states stored by
// Aegis. NVD statuses must not be persisted verbatim: they are not values of
// vulnerabilities_state_check.
func nvdState(status string) domain.CVEState {
	if status == "Rejected" {
		return domain.CVEStateRejected
	}
	return domain.CVEStatePublished
}

// parseNVDTime accepts NVD's zone-less ISO timestamps ("2023-10-11T19:15:09.947",
// UTC implied) as well as full RFC3339. RFC3339 alone silently nulled every
// published_at/updated_at in the corpus.
func parseNVDTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02T15:04:05.999",
		"2006-01-02T15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// nvdWindow builds the incremental query parameters from the last successful
// sync time. NVD requires ISO-8601 timestamps with a UTC offset — formatted
// with "+00:00" the '+' must be query-escaped, otherwise NVD parses it as a
// space and rejects the request. url.Values handles the encoding.
func nvdWindow(lastSync time.Time, now time.Time) url.Values {
	q := url.Values{}
	if lastSync.IsZero() {
		return q // full pull
	}
	start := lastSync.UTC().Add(-2 * time.Hour) // overlap: late-arriving edits
	end := now.UTC().Add(time.Minute)           // clock-skew headroom
	q.Set("lastModStartDate", start.Format("2006-01-02T15:04:05.000-07:00"))
	q.Set("lastModEndDate", end.Format("2006-01-02T15:04:05.000-07:00"))
	return q
}

func (j *NVDJob) Sync(ctx context.Context, full bool) (int, int, int, int, error) {
	base := j.URL
	if base == "" {
		base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	}
	// Without an API key NVD allows 5 requests per 30s; with one, 50. The
	// key travels in the apiKey header (AEGIS_NVD_API_KEY).
	headers := map[string]string{}
	pacing := 6 * time.Second
	if j.APIKey != "" {
		headers["apiKey"] = j.APIKey
		pacing = 700 * time.Millisecond
	}
	lastSync := time.Time{}
	if !j.LastMod.IsZero() {
		lastSync = j.LastMod // explicit override wins (tests, manual runs)
	} else if j.LastSyncFn != nil {
		lastSync = j.LastSyncFn(ctx)
	}
	window := nvdWindow(lastSync, time.Now())
	if lastSync.IsZero() {
		j.Log.Info("nvd full sync starting (no previous sync position)", "pacing", pacing.String())
	} else {
		j.Log.Info("nvd incremental sync starting", "since", lastSync.Format(time.RFC3339), "pacing", pacing.String())
	}

	processed, created, updated, rejected := 0, 0, 0, 0
	startIndex := 0
	var lastRequest time.Time
	for {
		// Pace requests rather than exhausting the rate limit and abandoning
		// the run (the client additionally honors Retry-After on 403/429).
		if !lastRequest.IsZero() {
			wait := pacing - time.Since(lastRequest)
			if wait > 0 {
				select {
				case <-ctx.Done():
					return processed, created, updated, rejected, ctx.Err()
				case <-time.After(wait):
				}
			}
		}
		q := url.Values{}
		for k, v := range window {
			q[k] = v
		}
		q.Set("resultsPerPage", "2000")
		q.Set("startIndex", strconv.Itoa(startIndex))
		endpoint := base + "?" + q.Encode()
		data, err := j.Client.FetchJSONHdr(ctx, endpoint, 512<<20, 2, headers)
		lastRequest = time.Now()
		if err != nil {
			return processed, created, updated, rejected, err
		}
		var resp nvdResp
		if err := json.Unmarshal(data, &resp); err != nil {
			return processed, created, updated, rejected, fmt.Errorf("nvd parse: %w", err)
		}
		now := time.Now().UTC()
		// Batch the page: single-row upserts ran 3-4 statements per record
		// across ~280k records — the crawl itself was faster than the writes.
		batch := make([]*domain.Vulnerability, 0, len(resp.Vulnerabilities))
		cpeBatch := make(map[string][]domain.CPEMatch, len(resp.Vulnerabilities))
		refBatch := make(map[string][]string, len(resp.Vulnerabilities))
		for _, wrap := range resp.Vulnerabilities {
			processed++
			c := wrap.CVE
			if c.ID == "" || c.Status == "Rejected" {
				rejected++
				continue
			}
			v := nvdToDomain(c, now)
			batch = append(batch, v)
			if len(v.CPEMatches) > 0 {
				cpeBatch[v.CVEID] = v.CPEMatches
			}
			if len(v.References) > 0 {
				refBatch[v.CVEID] = v.References
			}
		}
		if len(batch) > 0 {
			if err := j.Vulns.UpsertCVEBatch(ctx, batch); err != nil {
				return processed, created, updated, rejected, fmt.Errorf("nvd batch upsert: %w", err)
			}
			if err := j.Vulns.ReplaceCPEMatchesBatch(ctx, cpeBatch); err != nil {
				return processed, created, updated, rejected, fmt.Errorf("nvd cpe batch: %w", err)
			}
			if err := j.Vulns.AddReferencesBatch(ctx, refBatch); err != nil {
				return processed, created, updated, rejected, fmt.Errorf("nvd references batch: %w", err)
			}
			// New-vs-updated is approximated by the previous sync position
			// (documented assumption).
			if lastSync.IsZero() {
				created += len(batch)
			} else {
				updated += len(batch)
			}
		}
		startIndex += resp.ResultsPerPage
		if startIndex >= resp.TotalResults || resp.ResultsPerPage == 0 {
			break
		}
	}
	return processed, created, updated, rejected, nil
}

// nvdToDomain maps one NVD API 2.0 record to the Aegis vulnerability model.
func nvdToDomain(c nvdCVE, now time.Time) *domain.Vulnerability {
	v := domain.Vulnerability{
		CVEID: c.ID, Source: "nvd", SourceRecord: c.ID, IngestedAt: now, State: nvdState(c.Status),
	}
	v.PublishedAt = parseNVDTime(c.Published)
	v.UpdatedAt = parseNVDTime(c.LastModified)
	for _, d := range c.Descriptions {
		if d.Lang == "en" {
			v.Description = d.Value
			break
		}
	}
	if len(c.Metrics.CVSSV31) > 0 {
		m := c.Metrics.CVSSV31[0]
		v.CVSSv3 = &domain.CVSS{Vector: m.CVSSData.VectorString, Version: "3.1", Score: m.CVSSData.BaseScore, Source: m.Source}
	} else if len(c.Metrics.CVSSV30) > 0 {
		m := c.Metrics.CVSSV30[0]
		v.CVSSv3 = &domain.CVSS{Vector: m.CVSSData.VectorString, Version: "3.0", Score: m.CVSSData.BaseScore, Source: m.Source}
	}
	if len(c.Metrics.CVSSV2) > 0 {
		m := c.Metrics.CVSSV2[0]
		v.CVSSv2 = &domain.CVSS{Vector: m.CVSSData.VectorString, Version: "2.0", Score: m.CVSSData.BaseScore, Source: m.Source}
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			v.CWE = append(v.CWE, d.Value)
		}
	}
	for _, r := range c.References {
		v.References = append(v.References, r.URL)
	}
	seenCriteria := map[string]bool{}
	for _, cfg := range c.Configurations {
		for _, node := range cfg.Nodes {
			for _, cm := range node.CPEMatch {
				// Negated matches declare what the CVE does NOT
				// affect; they must never become applicability rows.
				if cm.Vulnerable != nil && !*cm.Vulnerable {
					continue
				}
				// NVD repeats the same expression across AND/OR
				// nodes; one applicability row per distinct
				// criteria+bounds tuple.
				key := cm.Criteria + "|" + cm.VersionStartIncluding + "|" + cm.VersionStartExcluding + "|" + cm.VersionEndIncluding + "|" + cm.VersionEndExcluding
				if seenCriteria[key] {
					continue
				}
				seenCriteria[key] = true
				m := domain.CPEMatch{
					CPE: cm.Criteria, VersionStartIncl: cm.VersionStartIncluding,
					VersionStartExcl: cm.VersionStartExcluding, VersionEndIncl: cm.VersionEndIncluding,
					VersionEndExcl: cm.VersionEndExcluding,
				}
				// Index the identity so vendor/product candidate
				// queries reach the row — the raw criteria alone
				// left 99%+ of NVD applicability unsearchable. The
				// matcher still evaluates against the full raw CPE.
				if p, ok := fingerprinting.ParseCPE(cm.Criteria); ok {
					m.Vendor = p.Vendor
					m.Product = p.Product
					m.Version = p.Version
				}
				v.CPEMatches = append(v.CPEMatches, m)
			}
		}
	}
	return &v
}
