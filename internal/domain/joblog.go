// Package domain — job log and realtime event types.
//
// These events power the streaming surface of the platform: scanners emit
// JobLogEvent / ScanStateEvent while a job runs, the server persists logs
// and fans everything out to browser subscribers over the WebSocket
// endpoint (docs/API.md "WebSocket streaming"). NotificationEvent covers
// the user-facing bell/toast surface (scan lifecycle, findings raised).
package domain

import (
	"strings"
	"time"
)

// Job log levels. Anything unknown normalizes to LevelInfo so a future
// scanner emitting a new level can never break the persistence or the UI.
const (
	LevelDebug = "debug"
	LevelInfo  = "info"
	LevelWarn  = "warn"
	LevelError = "error"
)

// Job log sources. The source answers "who said this" at a glance:
// exec = pipeline phases, engine = raw engine output (nmap stderr),
// ssh = authenticated collection, corr = vulnerability correlation,
// server = control-plane (state transitions outside scanners).
const (
	SourceExec       = "exec"
	SourceEngine     = "engine"
	SourceSSH        = "ssh"
	SourceCorrelator = "corr"
	SourceServer     = "server"
)

// JobLogEvent is one structured log line of a running job (today: scans).
// Events are fire-and-forget from the scanner's point of view — the server
// assigns Seq on persistence; zero Seq means "not persisted yet".
type JobLogEvent struct {
	Seq       int64          `json:"seq,omitempty"`
	ScanID    string         `json:"scan_id"`
	TaskID    string         `json:"task_id,omitempty"`
	ScannerID string         `json:"scanner_id,omitempty"`
	OrgID     string         `json:"org_id,omitempty"`
	Ts        time.Time      `json:"ts"`
	Level     string         `json:"level"`
	Source    string         `json:"source"`
	Msg       string         `json:"msg"`
	Fields    map[string]any `json:"fields,omitempty"`
}

// MaxJobLogMsg bounds one log line; scanners truncate before emitting and
// the server clamps on ingest so a pathological engine cannot bloat rows.
const MaxJobLogMsg = 4 << 10 // 4 KiB

// MaxJobLogFields bounds the serialized fields object the same way.
const MaxJobLogFields = 8 << 10 // 8 KiB

// Normalize clamps a event into its persistence-safe form: unknown levels
// become info, empty sources become exec, timestamps get UTC, the message
// and fields are size-bounded. It returns the event for call-site brevity.
func (e *JobLogEvent) Normalize() *JobLogEvent {
	switch e.Level {
	case LevelDebug, LevelInfo, LevelWarn, LevelError:
	default:
		e.Level = LevelInfo
	}
	if e.Source == "" {
		e.Source = SourceExec
	}
	if e.Ts.IsZero() {
		e.Ts = time.Now().UTC()
	} else {
		e.Ts = e.Ts.UTC()
	}
	e.Msg = strings.ToValidUTF8(e.Msg, "\uFFFD")
	if len(e.Msg) > MaxJobLogMsg {
		e.Msg = e.Msg[:MaxJobLogMsg] + " …[truncated]"
	}
	if len(e.Fields) > 32 {
		e.Fields = nil
	}
	return e
}

// ScanStateEvent announces a scan lifecycle transition (state/phase/
// progress/stats). It is ephemeral: the scan row in Postgres remains the
// authority, the event exists so browsers stop short-polling for it.
type ScanStateEvent struct {
	ScanID string `json:"scan_id"`
	OrgID  string `json:"org_id,omitempty"`
	SiteID string `json:"site_id,omitempty"`
	State  string `json:"state,omitempty"`
	Phase  string `json:"phase,omitempty"`
	// Progress is a pointer so "absent" and "zero" differ: absent keeps the
	// value the browser already shows, zero legitimately resets it. The
	// hub's internal -1 keep-current sentinel therefore never reaches the wire.
	Progress  *float64   `json:"progress,omitempty"`
	Error     string     `json:"error,omitempty"`
	Stats     *ScanStats `json:"stats,omitempty"`
	Ts        time.Time  `json:"ts"`
	ScannerID string     `json:"scanner_id,omitempty"`
}

// NotificationEvent is a user-facing realtime notification. Ephemeral by
// design (the bell's unread count still derives from its own queries);
// the event only triggers toasts, badges and cache invalidation.
type NotificationEvent struct {
	ID       string            `json:"id"`
	OrgID    string            `json:"org_id"`
	Type     string            `json:"type"` // scan.completed | scan.failed | findings.created | ...
	Title    string            `json:"title"`
	Body     string            `json:"body,omitempty"`
	Severity string            `json:"severity,omitempty"` // info|low|medium|high|critical
	Ref      map[string]string `json:"ref,omitempty"`      // e.g. scan_id, asset_id, findings count
	Ts       time.Time         `json:"ts"`
}

// Notification types published by the platform today.
const (
	NotifyScanCompleted   = "scan.completed"
	NotifyScanFailed      = "scan.failed"
	NotifyFindingsCreated = "findings.created"
	NotifyScannerOffline  = "scanner.offline"
	NotifyAgentOffline    = "agent.offline"
)
