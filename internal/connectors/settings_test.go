package connectors

import (
	"encoding/json"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

// v1.25.0: connection settings carry separate agent/scanner sections with
// `enabled` toggles deciding what the connection performs. Defaults follow
// the kind recorded at creation; explicit toggles override.

func mustCfg(t *testing.T, s string) json.RawMessage {
	t.Helper()
	if s == "" {
		return nil
	}
	return json.RawMessage(s)
}

func TestAgentEnabledDefaultsAndToggles(t *testing.T) {
	cases := []struct {
		name string
		kind domain.ConnectorKind
		cfg  string
		want bool
	}{
		{"agent kind defaults on", domain.ConnectorAgent, ``, true},
		{"scanner kind defaults off", domain.ConnectorScanner, ``, false},
		{"collector kind defaults off", domain.ConnectorCollector, ``, false},
		{"explicit toggle wins over kind", domain.ConnectorScanner, `{"agent":{"enabled":true}}`, true},
		{"agent kind can be toggled off", domain.ConnectorAgent, `{"agent":{"enabled":false}}`, false},
		{"malformed config falls back to kind", domain.ConnectorAgent, `{invalid`, true},
		{"section not an object falls back", domain.ConnectorAgent, `{"agent":"oops"}`, true},
		{"missing toggle falls back to kind", domain.ConnectorAgent, `{"agent":{"collection_level":"full"}}`, true},
	}
	for _, tc := range cases {
		if got := AgentEnabled(tc.kind, mustCfg(t, tc.cfg)); got != tc.want {
			t.Fatalf("%s: AgentEnabled=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestScannerEnabledDefaultsAndToggles(t *testing.T) {
	cases := []struct {
		name string
		kind domain.ConnectorKind
		cfg  string
		want bool
	}{
		{"scanner kind defaults on", domain.ConnectorScanner, ``, true},
		{"agent kind defaults off", domain.ConnectorAgent, ``, false},
		{"agent kind can opt into scanning", domain.ConnectorAgent, `{"scanner":{"enabled":true}}`, true},
		{"scanner kind can be turned off", domain.ConnectorScanner, `{"scanner":{"enabled":false}}`, false},
		{"malformed config falls back to kind", domain.ConnectorScanner, `{`, true},
	}
	for _, tc := range cases {
		if got := ScannerEnabled(tc.kind, mustCfg(t, tc.cfg)); got != tc.want {
			t.Fatalf("%s: ScannerEnabled=%v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestFunctionsListsEnabledInStableOrder(t *testing.T) {
	got := Functions(domain.ConnectorAgent, mustCfg(t, `{"scanner":{"enabled":true}}`))
	if len(got) != 2 || got[0] != "agent" || got[1] != "scanner" {
		t.Fatalf("hybrid functions = %v, want [agent scanner]", got)
	}
	if got := Functions(domain.ConnectorCollector, nil); got != nil {
		t.Fatalf("collector has no agent/scanner functions, got %v", got)
	}
}

func TestValidateSettingsAcceptsSectionsAndLegacy(t *testing.T) {
	valid := []string{
		``,
		`{}`,
		`{"heartbeat_secs":30}`,
		// legacy flat layout must keep validating
		`{"engine":"auto","nmap_path":"/usr/bin/nmap","ssh_hosts":["h1","h2"],"ssh_timeout_secs":30}`,
		// full section layout
		`{"heartbeat_secs":60,` +
			`"agent":{"enabled":true,"collection_level":"standard","probe_rate_ms":1000,"pull_rate_ms":30000},` +
			`"scanner":{"enabled":false,"engine":"nmap","nmap_path":"/opt/nmap","ssh_user":"scan","ssh_password":"p","ssh_key_path":"/k","ssh_timeout_secs":60,"ssh_insecure":false,"ssh_pinned_key":"ssh-ed25519 x","ssh_hosts":["a@h:22"]}}`,
		// empty sections
		`{"agent":{},"scanner":{}}`,
		// metrics cadence bounds
		`{"agent":{"probe_rate_ms":100,"pull_rate_ms":3600000}}`,
	}
	for _, s := range valid {
		if err := ValidateSettings(mustCfg(t, s)); err != nil {
			t.Fatalf("ValidateSettings(%s) = %v, want nil", s, err)
		}
	}
}

func TestValidateSettingsRejectsBadSections(t *testing.T) {
	invalid := map[string]string{
		"agent section type":      `{"agent":"yes"}`,
		"agent.enabled type":      `{"agent":{"enabled":"yes"}}`,
		"collection_level type":   `{"agent":{"collection_level":3}}`,
		"collection_level enum":   `{"agent":{"collection_level":"everything"}}`,
		"scanner section type":    `{"scanner":[]}`,
		"scanner.enabled type":    `{"scanner":{"enabled":1}}`,
		"scanner.engine enum":     `{"scanner":{"engine":"masscan"}}`,
		"scanner.engine type":     `{"scanner":{"engine":5}}`,
		"scanner.nmap_path type":  `{"scanner":{"nmap_path":true}}`,
		"scanner.ssh_hosts type":  `{"scanner":{"ssh_hosts":"h"}}`,
		"scanner.ssh_timeout":     `{"scanner":{"ssh_timeout_secs":0}}`,
		"scanner.ssh_insecure":    `{"scanner":{"ssh_insecure":"yes"}}`,
		"legacy engine still bad": `{"engine":"masscan"}`,
		"legacy ssh_hosts":        `{"ssh_hosts":[1]}`,
		"probe_rate type":         `{"agent":{"probe_rate_ms":"fast"}}`,
		"probe_rate too fast":     `{"agent":{"probe_rate_ms":50}}`,
		"probe_rate too slow":     `{"agent":{"probe_rate_ms":7200000}}`,
		"probe_rate fractional":   `{"agent":{"probe_rate_ms":1.5}}`,
		"pull_rate type":          `{"agent":{"pull_rate_ms":[]}}`,
		"pull_rate too slow":      `{"agent":{"pull_rate_ms":3600001}}`,
		"pull faster than probe":  `{"agent":{"probe_rate_ms":5000,"pull_rate_ms":1000}}`,
	}
	for name, s := range invalid {
		if err := ValidateSettings(mustCfg(t, s)); err == nil {
			t.Fatalf("%s: ValidateSettings(%s) must fail", name, s)
		}
	}
}
