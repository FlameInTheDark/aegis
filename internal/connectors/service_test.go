package connectors

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestValidateSettings(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty ok", "", false},
		{"object ok", `{"a":1}`, false},
		{"heartbeat bounds ok", `{"heartbeat_secs":60}`, false},
		{"heartbeat low", `{"heartbeat_secs":5}`, true},
		{"heartbeat high", `{"heartbeat_secs":4000}`, true},
		{"heartbeat fractional", `{"heartbeat_secs":10.5}`, true},
		{"heartbeat string", `{"heartbeat_secs":"60"}`, true},
		{"array rejected", `[1,2,3]`, true},
		{"garbage rejected", `{nope`, true},
		{"engine ok", `{"engine":"nmap"}`, false},
		{"engine bad", `{"engine":"hydra"}`, true},
		{"engine type", `{"engine":3}`, true},
		{"nmap_path ok", `{"nmap_path":"/usr/local/bin/nmap"}`, false},
		{"nmap_path type", `{"nmap_path":7}`, true},
		{"nmap_path long", `{"nmap_path":"` + strings.Repeat("p", 600) + `"}`, true},
		{"ssh_timeout ok", `{"ssh_timeout_secs":30}`, false},
		{"ssh_timeout bad", `{"ssh_timeout_secs":0}`, true},
		{"ssh_insecure type", `{"ssh_insecure":"yes"}`, true},
		{"ssh_hosts ok", `{"ssh_hosts":["root@10.0.0.1"]}`, false},
		{"ssh_hosts type", `{"ssh_hosts":"root@10.0.0.1"}`, true},
		{"ssh_hosts item type", `{"ssh_hosts":[42]}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateSettings(json.RawMessage(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("ValidateSettings(%s) err=%v wantErr=%v", tc.input, err, tc.wantErr)
			}
		})
	}
}

func TestValidateSettingsSize(t *testing.T) {
	big := `{"blob":"` + strings.Repeat("x", MaxConfigBytes) + `"}`
	if err := ValidateSettings(json.RawMessage(big)); err == nil {
		t.Fatal("oversized config accepted")
	}
}

func TestTokenHashShape(t *testing.T) {
	h := TokenHash("aegis_conn_e_abc")
	if len(h) != 64 {
		t.Fatalf("hash length %d, want 64 hex chars", len(h))
	}
	if h != TokenHash("aegis_conn_e_abc") {
		t.Fatal("hash not deterministic")
	}
	if h == TokenHash("aegis_conn_e_abd") {
		t.Fatal("hash collision on single char change")
	}
}

func TestConnectCommand(t *testing.T) {
	got := ConnectCommand("aegis.example.com:9090", "tok123")
	want := "aegis-connector --connect aegis.example.com:9090/tok123"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
	if !strings.Contains(ConnectCommand("", "tok"), "<aegis-grpc-host>:9090") {
		t.Fatal("empty public addr must render a placeholder")
	}
}

func TestOnlineWindow(t *testing.T) {
	cases := []struct {
		name string
		cfg  string
		want time.Duration
	}{
		{"default (no config)", ``, domain.DefaultHeartbeatSecs * 2 * time.Second},
		{"garbage falls back", `{nope`, domain.DefaultHeartbeatSecs * 2 * time.Second},
		{"two intervals", `{"heartbeat_secs":60}`, 120 * time.Second},
		{"floor at 30s", `{"heartbeat_secs":10}`, 30 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.OnlineWindow(json.RawMessage(tc.cfg)); got != tc.want {
				t.Fatalf("OnlineWindow(%s) = %v, want %v", tc.cfg, got, tc.want)
			}
		})
	}
}

func TestConnState(t *testing.T) {
	now := time.Now().UTC()
	hbCfg := json.RawMessage(`{"heartbeat_secs":60}`) // window: 120s

	active := func(mut func(*domain.Connector)) *domain.Connector {
		c := &domain.Connector{Status: domain.ConnectorStatusActive, Config: hbCfg}
		mut(c)
		return c
	}

	cases := []struct {
		name string
		c    *domain.Connector
		want string
	}{
		{"fresh heartbeat", active(func(c *domain.Connector) { c.LastSeen = ptrTime(now.Add(-10 * time.Second)) }), domain.ConnStateOnline},
		{"stale heartbeat", active(func(c *domain.Connector) { c.LastSeen = ptrTime(now.Add(-5 * time.Minute)) }), domain.ConnStateOffline},
		{"never seen", active(func(c *domain.Connector) {}), domain.ConnStateOffline},
		{"graceful stop fresh", active(func(c *domain.Connector) {
			c.LastSeen = ptrTime(now.Add(-2 * time.Second))
			c.ShutdownAt = ptrTime(now.Add(-2 * time.Second))
		}), domain.ConnStateShuttingDown},
		{"graceful stop expired degrades to offline", active(func(c *domain.Connector) {
			c.LastSeen = ptrTime(now.Add(-10 * time.Minute))
			c.ShutdownAt = ptrTime(now.Add(-10 * time.Minute))
		}), domain.ConnStateOffline},
		{"pending is offline regardless", func() *domain.Connector {
			c := active(func(c *domain.Connector) { c.LastSeen = ptrTime(now) })
			c.Status = domain.ConnectorStatusPending
			return c
		}(), domain.ConnStateOffline},
		{"revoked is offline regardless", func() *domain.Connector {
			c := active(func(c *domain.Connector) { c.LastSeen = ptrTime(now) })
			c.Status = domain.ConnectorStatusRevoked
			return c
		}(), domain.ConnStateOffline},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.ConnState(now); got != tc.want {
				t.Fatalf("ConnState = %q, want %q", got, tc.want)
			}
		})
	}

	// Online must agree with ConnState for the plain online case and flip
	// false while shutting down (it was true before the shutdown marker).
	online := active(func(c *domain.Connector) { c.LastSeen = ptrTime(now.Add(-10 * time.Second)) })
	if !online.Online(now) {
		t.Fatal("fresh active connector must be online")
	}
	online.ShutdownAt = ptrTime(now.Add(-time.Second))
	if online.Online(now) {
		t.Fatal("connector in shutting_down state must not report online")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
