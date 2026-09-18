// Package clickhouse implements high-volume event storage and analytics
// queries (spec §23, §60).
package clickhouse

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"

	ch "github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/google/uuid"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/observability"
)

// DB wraps the ClickHouse client.
type DB struct {
	conn driver.Conn
}

// Connect parses a clickhouse:// URL and opens a native connection,
// applying the embedded schema first.
//
// The schema creates the `aegis` database itself, so the very first boot
// cannot connect with Auth.Database set (the database does not exist yet).
// We therefore bootstrap the schema over a default-database connection and
// then open the real connection honoring the URL's ?database= parameter.
func Connect(ctx context.Context, rawURL string, schemaFS func() ([]byte, error)) (*DB, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: parse url: %w", err)
	}
	q := u.Query()
	opts := &ch.Options{
		Addr:            []string{u.Host},
		DialTimeout:     5 * time.Second,
		Compression:     &ch.Compression{Method: ch.CompressionLZ4},
		MaxOpenConns:    8,
		MaxIdleConns:    4,
		ConnMaxLifetime: time.Hour,
		Protocol:        ch.Native,
	}
	if u.User != nil {
		opts.Auth.Username = u.User.Username()
		opts.Auth.Password, _ = u.User.Password()
	}
	if db := q.Get("database"); db != "" {
		opts.Auth.Database = db
	}
	d := &DB{}
	if schemaFS != nil {
		sql, err := schemaFS()
		if err != nil {
			return nil, err
		}
		boot := *opts
		boot.Auth.Database = "" // connect to `default`, which always exists
		bootConn, err := ch.Open(&boot)
		if err != nil {
			return nil, fmt.Errorf("clickhouse: connect (bootstrap): %w", err)
		}
		err = applySchema(ctx, bootConn, sql)
		bootConn.Close()
		if err != nil {
			return nil, fmt.Errorf("clickhouse: schema: %w", err)
		}
	}
	conn, err := ch.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("clickhouse: connect: %w", err)
	}
	d.conn = conn
	return d, nil
}

// applySchema executes a multi-statement DDL file. The native protocol takes
// exactly one statement per Exec, so the script must be split safely — a
// naive `split(';')` cuts a statement in half at the first `;` inside a
// trailing comment (e.g. "-- JSON, bounded; large payloads go to object
// storage"), which ClickHouse then rejects as a syntax error.
func applySchema(ctx context.Context, conn driver.Conn, sql []byte) error {
	for _, stmt := range splitStatements(string(sql)) {
		if err := conn.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("exec %q: %w", firstLine(stmt), err)
		}
	}
	return nil
}

// splitStatements splits a multi-statement SQL script into individual
// statements. It is comment- and quote-aware:
//   - '--' line comments (full-line or trailing) are dropped;
//   - a ';' inside a single-quoted string literal never splits;
//   - a ';' inside a comment never splits.
func splitStatements(s string) []string {
	var out []string
	var stmt strings.Builder
	inString := false
	flush := func() {
		if t := strings.TrimSpace(stmt.String()); t != "" {
			out = append(out, t)
		}
		stmt.Reset()
	}
	runes := []rune(s)
	for i := 0; i < len(runes); i++ {
		c := runes[i]
		switch {
		case inString:
			stmt.WriteRune(c)
			if c == '\'' {
				if i+1 < len(runes) && runes[i+1] == '\'' {
					stmt.WriteRune('\'') // '' escaped quote
					i++
				} else {
					inString = false
				}
			}
		case c == '\'':
			inString = true
			stmt.WriteRune(c)
		case c == '-' && i+1 < len(runes) && runes[i+1] == '-':
			for i < len(runes) && runes[i] != '\n' { // drop comment to EOL
				i++
			}
			if i < len(runes) {
				stmt.WriteRune('\n') // preserve line structure
			}
		case c == ';':
			flush()
		default:
			stmt.WriteRune(c)
		}
	}
	flush()
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
}

// InsertEvents batch-inserts normalized events into security_events.
func (d *DB) InsertEvents(ctx context.Context, events []domain.Event) error {
	if len(events) == 0 {
		return nil
	}
	batch, err := d.conn.PrepareBatch(ctx, "INSERT INTO security_events")
	if err != nil {
		return fmt.Errorf("clickhouse: prepare batch: %w", err)
	}
	for _, e := range events {
		if err := batch.Append(
			mustUUID(e.EventID), mustUUID(e.TenantID), mustUUID(e.SiteID),
			e.SensorID, mustUUID(e.AgentID), e.Timestamp, e.EventType, e.Source,
			e.SourceVersion, e.SchemaVersion, mustUUID(e.SrcAssetID),
			parseIP(e.SrcIP), uint16(e.SrcPort), mustUUID(e.DstAssetID),
			parseIP(e.DstIP), uint16(e.DstPort), e.Protocol, e.Direction,
			string(e.Severity), e.Action, e.RuleID, e.RuleName, e.Application,
			e.Hostname, e.User, e.Process, marshalJSON(e.PayloadMeta), e.RawReference, e.Tags,
		); err != nil {
			_ = batch.Abort()
			return fmt.Errorf("clickhouse: append: %w", err)
		}
	}
	return batch.Send()
}

// EventFilter constrains event queries.
type EventFilter struct {
	TenantID  string
	SiteID    string
	EventType string
	Severity  string
	Source    string
	SrcIP     string
	DstIP     string
	Port      int
	Protocol  string
	From, To  time.Time
	Limit     int
	CursorTS  time.Time
	CursorID  string
}

// QueryEvents returns a page of events matching the filter (cursor by time).
func (d *DB) QueryEvents(ctx context.Context, f EventFilter) ([]domain.Event, error) {
	where := "tenant_id = ?"
	args := []any{mustUUID(f.TenantID)}
	if f.SiteID != "" {
		where += " AND site_id = ?"
		args = append(args, mustUUID(f.SiteID))
	}
	if f.EventType != "" {
		where += " AND event_type = ?"
		args = append(args, f.EventType)
	}
	if f.Severity != "" {
		where += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.Source != "" {
		where += " AND source = ?"
		args = append(args, f.Source)
	}
	if f.Port > 0 {
		where += " AND (src_port = ? OR dst_port = ?)"
		args = append(args, f.Port, f.Port)
	}
	if f.Protocol != "" {
		where += " AND protocol = ?"
		args = append(args, f.Protocol)
	}
	if !f.From.IsZero() {
		where += " AND timestamp >= ?"
		args = append(args, f.From)
	}
	if !f.To.IsZero() {
		where += " AND timestamp <= ?"
		args = append(args, f.To)
	}
	if !f.CursorTS.IsZero() {
		where += " AND (timestamp, event_id) < (?, ?)"
		args = append(args, f.CursorTS, mustUUID(f.CursorID))
	}
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}
	rows, err := d.conn.Query(ctx,
		"SELECT event_id, site_id, sensor_id, agent_id, timestamp, event_type, source, src_ip, src_port, dst_ip, dst_port, protocol, direction, severity, action, rule_id, rule_name, hostname FROM security_events WHERE "+where+" ORDER BY timestamp DESC, event_id DESC LIMIT ?",
		append(args, f.Limit)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.Event
	for rows.Next() {
		var e domain.Event
		var srcIP, dstIP string
		var agentID, siteID uuid.UUID
		var srcPort, dstPort uint16 // UInt16 columns; domain.Event uses int
		if err := rows.Scan(&e.EventID, &siteID, &e.SensorID, &agentID, &e.Timestamp,
			&e.EventType, &e.Source, &srcIP, &srcPort, &dstIP, &dstPort,
			&e.Protocol, &e.Direction, &e.Severity, &e.Action, &e.RuleID, &e.RuleName, &e.Hostname); err != nil {
			return nil, err
		}
		e.SrcPort = int(srcPort)
		e.DstPort = int(dstPort)
		e.SiteID = uuidStr(siteID)
		e.AgentID = uuidStr(agentID)
		e.SrcIP = formatIP(srcIP)
		e.DstIP = formatIP(dstIP)
		out = append(out, e)
	}
	return out, rows.Err()
}

// EventVolume aggregates event counts per interval for charts.
type VolumePoint struct {
	Bucket time.Time `json:"bucket"`
	Count  uint64    `json:"count"`
}

// EventVolume returns event counts bucketed by minute/hour.
func (d *DB) EventVolume(ctx context.Context, tenantID string, from time.Time, interval string) ([]VolumePoint, error) {
	if interval == "" {
		interval = "hour"
	}
	rows, err := d.conn.Query(ctx,
		"SELECT toStartOfInterval(timestamp, INTERVAL ? "+interval+") AS bucket, count() AS c FROM security_events WHERE tenant_id = ? AND timestamp >= ? GROUP BY bucket ORDER BY bucket",
		1, mustUUID(tenantID), from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VolumePoint
	for rows.Next() {
		var p VolumePoint
		if err := rows.Scan(&p.Bucket, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TopPorts returns most contacted destination ports in the window.
func (d *DB) TopPorts(ctx context.Context, tenantID string, from time.Time, limit int) ([]PortCount, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := d.conn.Query(ctx,
		"SELECT dst_port, count() AS c FROM network_connections WHERE tenant_id = ? AND timestamp >= ? GROUP BY dst_port ORDER BY c DESC LIMIT ?",
		mustUUID(tenantID), from, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PortCount
	for rows.Next() {
		var p PortCount
		if err := rows.Scan(&p.Port, &p.Count); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PortCount is a port aggregation row.
type PortCount struct {
	Port  uint16 `json:"port"`
	Count uint64 `json:"count"`
}

// Health implements observability.Checker.
func (d *DB) CheckHealth(ctx context.Context) observability.DependencyHealth {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := d.conn.Ping(ctx); err != nil {
		return observability.DependencyHealth{Name: "clickhouse", Status: "down", Detail: err.Error()}
	}
	return observability.DependencyHealth{Name: "clickhouse", Status: "ok"}
}

// Close closes the connection.
func (d *DB) Close() error { return d.conn.Close() }
