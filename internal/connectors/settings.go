// Function settings for external connections. A connection's settings carry
// two SEPARATE sections — `agent` (endpoint collection on the host the
// connector runs on) and `scanner` (remote scanning) — each with an
// `enabled` toggle that decides what the connector performs. A flat layout
// (top-level `engine`, `ssh_*`, `collection_level`, ...) is accepted as
// well: it is applied to the function matching the connection's kind.
package connectors

import (
	"encoding/json"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// sectionReader extracts a named sub-object of the settings JSON. A missing
// or malformed section yields nil (defaults apply); malformed JSON anywhere
// must never panic a heartbeat path.
func sectionReader(cfg json.RawMessage, name string) map[string]any {
	if len(cfg) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(cfg, &m); err != nil {
		return nil
	}
	sec, _ := m[name].(map[string]any)
	return sec
}

// boolSetting reads a boolean key from a section map.
func sectionBool(sec map[string]any, key string) (v, ok bool) {
	if sec == nil {
		return false, false
	}
	v, ok = sec[key].(bool)
	return v, ok
}

// AgentEnabled reports whether this connection performs ENDPOINT COLLECTION
// (the agent function: device binding, inventory, typed tasks). Default:
// agent-kind connections; an explicit `agent.enabled` toggle overrides.
func AgentEnabled(kind domain.ConnectorKind, cfg json.RawMessage) bool {
	enabled := kind == domain.ConnectorAgent
	if v, ok := sectionBool(sectionReader(cfg, "agent"), "enabled"); ok {
		return v
	}
	return enabled
}

// ScannerEnabled reports whether this connection performs REMOTE SCANNING
// (drives scan dispatch eligibility through the linked scanners row).
// Default: scanner-kind connections; an explicit `scanner.enabled` toggle
// overrides.
func ScannerEnabled(kind domain.ConnectorKind, cfg json.RawMessage) bool {
	enabled := kind == domain.ConnectorScanner
	if v, ok := sectionBool(sectionReader(cfg, "scanner"), "enabled"); ok {
		return v
	}
	return enabled
}

// Functions lists the enabled function names of a connection ("agent",
// "scanner") in stable order — used for logging and UI summaries.
func Functions(kind domain.ConnectorKind, cfg json.RawMessage) []string {
	var f []string
	if AgentEnabled(kind, cfg) {
		f = append(f, "agent")
	}
	if ScannerEnabled(kind, cfg) {
		f = append(f, "scanner")
	}
	return f
}
