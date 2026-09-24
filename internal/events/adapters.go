// Package events contains sensor adapters that normalize external IDS /
// network-monitor output into the platform's common event model
// . The engines are never reimplemented — their output is
// parsed, bounded and preserved.
package events

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// maxRawBytes bounds any single raw record kept for evidence.
const maxRawBytes = 1 << 20

// Envelope builds a normalized event with schema version and id.
func Envelope(e *domain.Event) *domain.Event {
	if e.EventID == "" {
		e.EventID = ids.New()
	}
	e.SchemaVersion = domain.EventSchemaVersion
	if e.Timestamp.IsZero() {
		e.Timestamp = time.Now().UTC()
	}
	return e
}

// ParseTime accepts common sensor timestamps.
func ParseTime(s string) time.Time {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000-0700", "2006-01-02 15:04:05.999999-0700", time.UnixDate} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// severityFromSuricata maps Suricata 1-4 severity to platform labels.
func severityFromSuricata(n float64) domain.Severity {
	switch int(n) {
	case 1:
		return domain.SeverityCritical
	case 2:
		return domain.SeverityHigh
	case 3:
		return domain.SeverityMedium
	default:
		return domain.SeverityLow
	}
}

// SuricataAdapter parses Suricata EVE JSON.
type SuricataAdapter struct{}

func (SuricataAdapter) Source() string { return string(domain.SourceSuricata) }

// Parse normalizes one EVE JSON line. Unknown event types are passed
// through as generic alerts with the raw preserved by reference.
func (SuricataAdapter) Parse(line []byte, tenantID, siteID, sensorID string) (*domain.Event, error) {
	if len(line) > maxRawBytes {
		return nil, fmt.Errorf("suricata: line exceeds %d bytes", maxRawBytes)
	}
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("suricata: %w", err)
	}
	evType, _ := raw["event_type"].(string)
	ev := &domain.Event{
		TenantID: tenantID, SiteID: siteID, SensorID: sensorID,
		EventType: evType, Source: string(domain.SourceSuricata),
		PayloadMeta: map[string]any{"event_type": evType},
	}
	if ts, _ := raw["timestamp"].(string); ts != "" {
		ev.Timestamp = ParseTime(ts)
	}
	// Flow tuple appears at top level or under "flow".
	srcIP, _ := raw["src_ip"].(string)
	dstIP, _ := raw["dest_ip"].(string)
	srcPort := numOf(raw["src_port"])
	dstPort := numOf(raw["dest_port"])
	proto, _ := raw["proto"].(string)
	if srcIP == "" {
		if f, ok := raw["flow"].(map[string]any); ok {
			srcIP, _ = f["src_ip"].(string)
			dstIP, _ = f["dest_ip"].(string)
			srcPort = numOf(f["src_port"])
			dstPort = numOf(f["dest_port"])
		}
	}
	ev.SrcIP, ev.DstIP, ev.SrcPort, ev.DstPort, ev.Protocol = srcIP, dstIP, int(srcPort), int(dstPort), proto

	switch evType {
	case "alert":
		if a, ok := raw["alert"].(map[string]any); ok {
			ev.RuleID = intLike(a["signature_id"])
			ev.RuleName, _ = a["signature"].(string)
			ev.Severity = severityFromSuricata(numOf(a["severity"]))
			ev.Action, _ = a["action"].(string)
			if cat, ok := a["category"].(string); ok {
				ev.PayloadMeta["category"] = cat
			}
			ev.EventType = "alert"
		}
	case "dns":
		ev.Application = "dns"
		if dns, ok := raw["dns"].(map[string]any); ok {
			if rrname, _ := dns["rrname"].(string); rrname != "" {
				ev.Hostname = rrname
			}
			ev.PayloadMeta["dns_type"] = fmt.Sprint(dns["type"])
			if rdata, _ := dns["rdata"].(string); rdata != "" {
				ev.PayloadMeta["rdata"] = rdata
			}
		}
	case "http":
		ev.Application = "http"
		if h, ok := raw["http"].(map[string]any); ok {
			ev.PayloadMeta["http_method"], _ = h["http_method"].(string)
			ev.PayloadMeta["hostname"], _ = h["hostname"].(string)
			ev.PayloadMeta["url"], _ = h["url"].(string)
			ev.PayloadMeta["status"] = numOf(h["status"])
			if host, _ := h["hostname"].(string); host != "" {
				ev.Hostname = host
			}
		}
	case "tls":
		ev.Application = "tls"
		if t, ok := raw["tls"].(map[string]any); ok {
			ev.PayloadMeta["sni"], _ = t["sni"].(string)
			ev.PayloadMeta["version"], _ = t["tls_version"].(string)
			if sni, _ := t["sni"].(string); sni != "" {
				ev.Hostname = sni
			}
		}
	case "ssh":
		ev.Application = "ssh"
	case "fileinfo":
		ev.Application = "fileinfo"
		if f, ok := raw["fileinfo"].(map[string]any); ok {
			ev.PayloadMeta["filename"], _ = f["filename"].(string)
			ev.PayloadMeta["md5"], _ = f["md5"].(string)
			ev.PayloadMeta["sha256"], _ = f["sha256"].(string)
		}
	case "anomaly":
		ev.EventType = "anomaly"
		ev.Severity = domain.SeverityMedium
	case "flow":
		ev.EventType = "flow"
	default:
		// Unknown EVE type: keep going with generic metadata.
		ev.Severity = domain.SeverityInfo
	}
	ev.PayloadMeta["raw_size"] = len(line)
	return Envelope(ev), nil
}

// intLike renders numeric IDs without scientific notation (JSON numbers
// are float64; signature ids must stay integer-formatted).
func intLike(v any) string {
	switch x := v.(type) {
	case float64:
		return strconv.FormatInt(int64(x), 10)
	default:
		return fmt.Sprint(v)
	}
}

func numOf(v any) float64 {
	switch x := v.(type) {
	case float64:
		return x
	case int:
		return float64(x)
	}
	return 0
}

// ZeekAdapter parses Zeek JSON logs.
type ZeekAdapter struct{}

func (ZeekAdapter) Source() string { return string(domain.SourceZeek) }

// Parse normalizes one Zeek JSON log record. Zeek-specific fields are kept
// in payload metadata without destroying them.
func (ZeekAdapter) Parse(line []byte, tenantID, siteID, sensorID string) (*domain.Event, error) {
	if len(line) > maxRawBytes {
		return nil, fmt.Errorf("zeek: line exceeds %d bytes", maxRawBytes)
	}
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("zeek: %w", err)
	}
	ev := &domain.Event{
		TenantID: tenantID, SiteID: siteID, SensorID: sensorID,
		Source: string(domain.SourceZeek), PayloadMeta: map[string]any{},
	}
	// Zeek JSON uses "_path" for the log type and "_write_ts"/"ts" for time.
	path, _ := raw["_path"].(string)
	ev.EventType = path
	if ts, _ := raw["ts"].(string); ts != "" {
		ev.Timestamp = ParseTime(ts)
	}
	if tsn, ok := raw["ts"].(float64); ok && ev.Timestamp.IsZero() {
		ev.Timestamp = time.Unix(int64(tsn), 0).UTC()
	}
	ev.SrcIP, _ = raw["id.orig_h"].(string)
	ev.DstIP, _ = raw["id.resp_h"].(string)
	ev.SrcPort = int(numOf(raw["id.orig_p"]))
	ev.DstPort = int(numOf(raw["id.resp_p"]))
	if proto, _ := raw["proto"].(string); proto != "" {
		ev.Protocol = strings.ToLower(proto)
	}

	// Preserve Zeek-native fields under their original names.
	keep := func(keys ...string) {
		for _, k := range keys {
			if v, ok := raw[k]; ok {
				ev.PayloadMeta[k] = v
			}
		}
	}
	switch path {
	case "conn":
		keep("conn_state", "duration", "orig_bytes", "resp_bytes", "history", "service")
		if app, _ := raw["service"].(string); app != "" {
			ev.Application = app
		}
		if ib, ok := raw["orig_ip_bytes"].(float64); ok {
			ev.PayloadMeta["orig_ip_bytes"] = ib
		}
	case "dns":
		ev.Application = "dns"
		keep("query", "answers", "qtype_name", "rcode_name", "rejected")
		if q, _ := raw["query"].(string); q != "" {
			ev.Hostname = q
		}
	case "http":
		ev.Application = "http"
		keep("host", "uri", "method", "status_code", "user_agent", "resp_mime_types")
		if h, _ := raw["host"].(string); h != "" {
			ev.Hostname = h
		}
	case "ssl":
		ev.Application = "tls"
		keep("server_name", "version", "cipher", "subject", "issuer", "validation_status")
		if s, _ := raw["server_name"].(string); s != "" {
			ev.Hostname = s
		}
	case "ssh":
		ev.Application = "ssh"
		keep("client", "server", "version", "auth_attempts", "auth_success")
	case "files":
		keep("filename", "md5", "sha256", "mime_type")
	case "smtp":
		ev.Application = "smtp"
		keep("mailfrom", "rcptto", "subject")
	case "dhcp":
		keep("assigned_addr", "hostname", "client_message", "server_message")
	case "notice":
		ev.EventType = "alert"
		keep("note", "msg", "sub", "actions")
		if note, _ := raw["note"].(string); note != "" {
			ev.RuleName = note
		}
		if msg, _ := raw["msg"].(string); msg != "" {
			ev.PayloadMeta["message"] = msg
		}
		ev.Severity = domain.SeverityHigh
	case "known_hosts":
		keep("host")
	default:
		// Unknown log: keep everything under metadata, bounded.
		boundMeta(raw, ev.PayloadMeta, 64)
	}
	ev.PayloadMeta["raw_size"] = len(line)
	return Envelope(ev), nil
}

func boundMeta(src, dst map[string]any, max int) {
	i := 0
	for k, v := range src {
		if i >= max {
			return
		}
		if !strings.HasPrefix(k, "_") {
			dst[k] = v
			i++
		}
	}
}

// SnortAdapter parses Snort 3 JSON alert output.
type SnortAdapter struct{}

func (SnortAdapter) Source() string { return string(domain.SourceSnort) }

// Parse normalizes one Snort 3 alert record.
func (SnortAdapter) Parse(line []byte, tenantID, siteID, sensorID string) (*domain.Event, error) {
	if len(line) > maxRawBytes {
		return nil, fmt.Errorf("snort: line exceeds %d bytes", maxRawBytes)
	}
	var raw map[string]any
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil, fmt.Errorf("snort: %w", err)
	}
	ev := &domain.Event{
		TenantID: tenantID, SiteID: siteID, SensorID: sensorID,
		EventType: "alert", Source: string(domain.SourceSnort),
		Severity: domain.SeverityMedium, PayloadMeta: map[string]any{},
	}
	if ts, _ := raw["timestamp"].(string); ts != "" {
		ev.Timestamp = ParseTime(ts)
	}
	if pk, ok := raw["packet"].(map[string]any); ok {
		ev.SrcIP, _ = pk["src_ip"].(string)
		ev.DstIP, _ = pk["dst_ip"].(string)
		ev.SrcPort = int(numOf(pk["src_port"]))
		ev.DstPort = int(numOf(pk["dst_port"]))
		ev.Protocol = strings.ToLower(fmt.Sprint(pk["protocol"]))
	}
	if rule, ok := raw["rule"].(map[string]any); ok {
		ev.RuleID = fmt.Sprint(rule["id"])
		ev.RuleName, _ = rule["message"].(string)
		ev.PayloadMeta["classification"], _ = rule["classification"].(string)
		ev.PayloadMeta["action"], _ = rule["action"].(string)
		if rev, ok := rule["revision"].(float64); ok {
			ev.PayloadMeta["rule_revision"] = rev
		}
	}
	if cls, _ := ev.PayloadMeta["classification"].(string); strings.Contains(strings.ToLower(cls), "high") {
		ev.Severity = domain.SeverityHigh
	}
	if action, _ := ev.PayloadMeta["action"].(string); action != "" {
		ev.Action = action
	}
	ev.PayloadMeta["raw_size"] = len(line)
	return Envelope(ev), nil
}

// Adapter is the common sensor adapter interface.
type Adapter interface {
	Source() string
	Parse(line []byte, tenantID, siteID, sensorID string) (*domain.Event, error)
}

// AdapterFor returns the adapter for a source name.
func AdapterFor(source string) (Adapter, error) {
	switch strings.ToLower(source) {
	case "suricata":
		return SuricataAdapter{}, nil
	case "zeek":
		return ZeekAdapter{}, nil
	case "snort", "snort3":
		return SnortAdapter{}, nil
	default:
		return nil, fmt.Errorf("unknown sensor source %q", source)
	}
}
