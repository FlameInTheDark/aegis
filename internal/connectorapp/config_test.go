package connectorapp

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParseConnectTarget(t *testing.T) {
	cases := []struct {
		in       string
		endpoint string
		token    string
		tls      bool
		wantErr  bool
	}{
		{in: "host:9090/aegis_conn_e_x", endpoint: "host:9090", token: "aegis_conn_e_x"},
		{in: "tls://host:9090/tok", endpoint: "host:9090", token: "tok", tls: true},
		{in: "host:9090/tok/extra", endpoint: "host:9090", token: "tok/extra"},
		{in: "host/tok", endpoint: "host:9090", token: "tok"},
		{in: "tls://host/tok", endpoint: "host:443", token: "tok", tls: true},
		{in: "", wantErr: true},
		{in: "host:9090/", endpoint: "host:9090"}, // no token part
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			ep, tok, useTLS, err := ParseConnectTarget(tc.in)
			if (err != nil) != tc.wantErr {
				t.Fatalf("err=%v wantErr=%v", err, tc.wantErr)
			}
			if err != nil {
				return
			}
			if ep != tc.endpoint || tok != tc.token || useTLS != tc.tls {
				t.Fatalf("got (%q,%q,%v) want (%q,%q,%v)", ep, tok, useTLS, tc.endpoint, tc.token, tc.tls)
			}
		})
	}
}

func TestLocalConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "config.json")
	cfg := &LocalConfig{
		Server: "1.2.3.4:9090", TLS: true, ConnectorID: "id-1",
		Secret: "aegis_conn_s_deadbeef", Kind: "agent", Name: "edge",
		ConfigVersion: 7, HeartbeatSecs: 30,
	}
	if err := Save(path, cfg); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Fatalf("config file mode %v, want 0600", perm)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConnectorID != "id-1" || got.Secret != cfg.Secret || got.ConfigVersion != 7 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	b, _ := json.Marshal(got)
	if len(b) == 0 {
		t.Fatal("marshal failed")
	}
}

func TestLoadMissing(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err != ErrNoConfig {
		t.Fatalf("want ErrNoConfig, got %v", err)
	}
}

func TestDefaultPathPriority(t *testing.T) {
	t.Setenv("AEGIS_CONNECTOR_CONFIG", "")
	if got := DefaultPath("/explicit"); got != "/explicit" {
		t.Fatalf("explicit flag ignored: %q", got)
	}
	t.Setenv("AEGIS_CONNECTOR_CONFIG", "/from-env")
	if got := DefaultPath(""); got != "/from-env" {
		t.Fatalf("env var ignored: %q", got)
	}
}
