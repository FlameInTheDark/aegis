// Package joblog persists and streams structured job logs (scan job
// logging, v1.13.0) and runs the browser-facing fan-out registry.
//
// Flow: scanners emit domain.JobLogEvent / domain.ScanStateEvent over
// core-NATS broadcast subjects; the Streamer (one q-group writer per
// deployment) persists log lines here while every server replica feeds its
// local Hub, which pushes events to subscribed WebSocket connections.
// REST history (Store.List) lets the UI replay what happened before the
// socket connected — persistence + push, no short polling.
package joblog

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/Masterminds/squirrel"
	"github.com/jackc/pgx/v5"
)

// Store persists job log lines.
type Store struct {
	db *pg.DB
}

// NewStore builds a Store over the shared Postgres pool.
func NewStore(db *pg.DB) *Store { return &Store{db: db} }

// Append persists a batch of events (already normalized by the emitter or
// the streamer). One INSERT per event keeps the code simple; the streamer
// batches calls so a busy scan produces a handful of single-row writes per
// second at most. Seq values are assigned by BIGSERIAL and written back
// into the event slices in order.
func (s *Store) Append(ctx context.Context, evts []*domain.JobLogEvent) error {
	if len(evts) == 0 {
		return nil
	}
	for _, e := range evts {
		e.Normalize()
		var fields []byte
		if len(e.Fields) > 0 {
			b, err := json.Marshal(e.Fields)
			if err == nil && len(b) <= domain.MaxJobLogFields {
				fields = b
			}
		}
		q := s.db.Insert("scan_job_logs").Columns(
			"scan_id", "task_id", "scanner_id", "org_id", "ts", "level", "source", "msg", "fields",
		).Values(e.ScanID, e.TaskID, e.ScannerID, e.OrgID, e.Ts, e.Level, e.Source, e.Msg, fields).
			Suffix("RETURNING seq")
		if err := s.db.QueryRow(ctx, q).Scan(&e.Seq); err != nil {
			return fmt.Errorf("joblog: append: %w", err)
		}
	}
	return nil
}

const jobLogCols = "seq, scan_id, task_id, scanner_id, org_id, ts, level, source, msg, fields"

// scanLogRow scans one scan_job_logs row.
func scanLogRow(row pgx.Row) (*domain.JobLogEvent, error) {
	var e domain.JobLogEvent
	var fields []byte
	if err := row.Scan(&e.Seq, &e.ScanID, &e.TaskID, &e.ScannerID, &e.OrgID,
		&e.Ts, &e.Level, &e.Source, &e.Msg, &fields); err != nil {
		return nil, err
	}
	if len(fields) > 0 {
		_ = json.Unmarshal(fields, &e.Fields)
	}
	return &e, nil
}

// List returns log lines of one scan in ascending seq order. before == 0
// means "the newest tail": the query takes the HIGHEST seqs and reverses
// them, which is what the initial page load wants. before > 0 pages
// strictly older than that seq ("load older"). Org scoping is enforced by
// the caller (handlers resolve + authorize the scan first).
func (s *Store) List(ctx context.Context, scanID string, before int64, limit int) ([]*domain.JobLogEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	q := s.db.Select(jobLogCols).From("scan_job_logs").Where(squirrel.Eq{"scan_id": scanID})
	if before > 0 {
		q = q.Where(squirrel.Lt{"seq": before})
	}
	// Newest-first fetch (index idx_joblogs_scan_seq is (scan_id, seq DESC))
	// then flip to ascending for the caller.
	q = q.OrderByClause("seq DESC").Limit(uint64(limit))
	rows, err := s.db.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("joblog: list: %w", err)
	}
	defer rows.Close()
	out := make([]*domain.JobLogEvent, 0, limit)
	for rows.Next() {
		e, err := scanLogRow(rows)
		if err != nil {
			return nil, fmt.Errorf("joblog: scan row: %w", err)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("joblog: rows: %w", err)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// DeleteBefore removes log lines older than the cutoff (retention sweep;
// the worker calls it periodically). Returns the number of rows removed.
func (s *Store) DeleteBefore(ctx context.Context, cutoff time.Time) (int64, error) {
	q := s.db.Delete("scan_job_logs").Where(squirrel.Lt{"ts": cutoff})
	tag, err := s.db.Exec(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("joblog: retention: %w", err)
	}
	return tag.RowsAffected(), nil
}
