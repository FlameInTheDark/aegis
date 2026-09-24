// OVAL advisory feed.
// Downloads distro OVAL definitions snapshots, parses them into os_advisories
// rows (ParseOVAL) and upserts them. Sources are configured explicitly —
// full snapshots are large, so nothing is enabled implicitly:
//
//	AEGIS_FEED_OVAL_SOURCES=ubuntu:22.04:https://...oval.xml.bz2:bz2,debian:12:https://...oval.xml
//
// Format per source: family:release:URL[:compression] with compression in
// {bz2, gz, none} (default: none — inferred from the URL suffix when
// omitted).
package feeds

import (
	"archive/zip"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// OvalSource is one distro OVAL snapshot to ingest.
type OvalSource struct {
	Family  string // canonical family (debian, ubuntu, alpine, rhel, ...)
	Release string // advisory release key ("12", "22.04", "9", "3.18")
	URL     string
	// Compress is "" (plain xml), "bz2", "gz", or "zip" (RHEL OVAL v2
	// ships .xml.zip). Inferred from the URL when empty.
	Compress string
}

// OvalJob syncs distro advisory snapshots into the os_advisories plane.
type OvalJob struct {
	Client     *Client
	Advisories *pg.AdvisoryRepo
	Log        *slog.Logger
	Sources    []OvalSource
	// LastSyncFn optionally exposes the last successful "advisories" run;
	// OVAL snapshots refresh daily, so a same-day incremental sync skips
	// the heavy downloads entirely.
	LastSyncFn func(context.Context) time.Time
	// MaxBytes caps one snapshot download (default 3 GiB).
	MaxBytes int64
}

func (j *OvalJob) Name() string { return "advisories" }
func (j *OvalJob) License() string {
	return "Distro security metadata (OVAL): Debian, Ubuntu, Red Hat, Alpine — respective licenses"
}

// ParseOvalSources parses the AEGIS_FEED_OVAL_SOURCES configuration value.
func ParseOvalSources(raw string) []OvalSource {
	out := []OvalSource{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// family:release:URL[:compression] — the URL itself contains
		// "://", so only the first two separators are field separators,
		// and a trailing compression suffix is recognized only when it
		// exactly matches a known value after the URL's final colon.
		head := strings.SplitN(part, ":", 3)
		if len(head) < 3 {
			continue
		}
		src := OvalSource{Family: strings.TrimSpace(head[0]), Release: strings.TrimSpace(head[1]), URL: strings.TrimSpace(head[2])}
		for _, ext := range []string{"bz2", "gz", "gzip", "zip", "none"} {
			if suffix := ":" + ext; strings.HasSuffix(src.URL, suffix) {
				src.URL = strings.TrimSuffix(src.URL, suffix)
				src.Compress = ext
				break
			}
		}
		if src.Compress == "" {
			switch {
			case strings.HasSuffix(src.URL, ".bz2"):
				src.Compress = "bz2"
			case strings.HasSuffix(src.URL, ".gz"):
				src.Compress = "gz"
			case strings.HasSuffix(src.URL, ".zip"):
				src.Compress = "zip"
			}
		}
		out = append(out, src)
	}
	return out
}

func (j *OvalJob) Sync(ctx context.Context, full bool) (int, int, int, int, error) {
	if j.Advisories == nil {
		return 0, 0, 0, 0, fmt.Errorf("advisories repo not configured")
	}
	if !full && j.LastSyncFn != nil {
		if last := j.LastSyncFn(ctx); time.Since(last) < 23*time.Hour {
			j.Log.Info("advisories snapshot refreshed recently, skipping", "last", last.Format(time.RFC3339))
			return 0, 0, 0, 0, nil
		}
	}
	processed, rejected := 0, 0
	for _, src := range j.Sources {
		if err := j.syncSource(ctx, src, &processed, &rejected); err != nil {
			j.Log.Error("oval source failed", "family", src.Family, "release", src.Release, "err", err)
			rejected++
			continue // one broken distro feed never starves the others
		}
	}
	return processed, processed, 0, rejected, nil
}

func (j *OvalJob) syncSource(ctx context.Context, src OvalSource, processed, rejected *int) error {
	maxBytes := j.MaxBytes
	if maxBytes <= 0 {
		maxBytes = int64(3) << 30
	}
	path, cleanup, err := j.Client.FetchToFile(ctx, src.URL, maxBytes, 2, "")
	if err != nil {
		return err
	}
	defer cleanup()

	f, err := os.Open(path) // #nosec G304 -- path from FetchToFile
	if err != nil {
		return err
	}
	defer f.Close()

	stream, err := decompress(f, effectiveCompress(src))
	if err != nil {
		return err
	}
	rows, err := ParseOVAL(stream, src.Family, src.Release, "oval", "")
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		j.Log.Warn("oval source yielded no advisories", "family", src.Family, "release", src.Release)
		return nil
	}
	// Chunked upsert keeps memory flat on the big feeds.
	const chunk = 1000
	for i := 0; i < len(rows); i += chunk {
		end := i + chunk
		if end > len(rows) {
			end = len(rows)
		}
		batch := make([]*domain.OSAdvisory, 0, end-i)
		for _, r := range rows[i:end] {
			batch = append(batch, &domain.OSAdvisory{
				Family: r.Family, Release: r.Release, PackageName: r.PackageName,
				SourcePackage: r.SourcePackage, FixedVersion: r.FixedVersion,
				NotFixedYet: r.NotFixedYet, CVEID: r.CVEID, AdvisoryID: r.AdvisoryID,
				AdvisoryURL: r.AdvisoryURL, Severity: r.Severity, PublishedAt: r.PublishedAt,
				Source: r.Source, SourceVersion: r.SourceVersion, IngestedAt: time.Now().UTC(),
			})
		}
		if err := j.Advisories.UpsertAdvisoryBatch(ctx, batch); err != nil {
			return err
		}
		*processed += len(batch)
	}
	j.Log.Info("oval source ingested", "family", src.Family, "release", src.Release, "rows", len(rows))
	return nil
}

func effectiveCompress(src OvalSource) string {
	switch strings.ToLower(strings.TrimSpace(src.Compress)) {
	case "bz2":
		return "bz2"
	case "gz", "gzip":
		return "gz"
	case "zip":
		return "zip"
	default:
		return "none"
	}
}

func decompress(r io.Reader, kind string) (io.Reader, error) {
	switch kind {
	case "bz2":
		return bzip2.NewReader(r), nil
	case "gz":
		return gzip.NewReader(r)
	case "zip":
		zr, err := zip.NewReader(r.(io.ReaderAt), sizeOf(r))
		if err != nil {
			return nil, fmt.Errorf("oval zip: %w", err)
		}
		for _, f := range zr.File {
			if strings.HasSuffix(f.Name, ".xml") {
				return f.Open()
			}
		}
		return nil, fmt.Errorf("oval zip: no xml member")
	default:
		return r, nil
	}
}

func sizeOf(r io.Reader) int64 {
	if f, ok := r.(*os.File); ok {
		if st, err := f.Stat(); err == nil {
			return st.Size()
		}
	}
	return 0
}
