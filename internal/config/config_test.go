package config

import (
	"testing"
)

func TestInfraURLDualKeyPrecedence(t *testing.T) {
	t.Setenv("AEGIS_DATABASE_URL", "postgres://aegis:aegis@aegis-prefixed:5432/aegis")
	t.Setenv("DATABASE_URL", "postgres://bare:5432/db")
	t.Setenv("AEGIS_REDIS_URL", "redis://aegis-prefixed:6379/0")
	t.Setenv("S3_ENDPOINT", "http://bare-s3:9000")

	c, err := Load("worker")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.DatabaseURL != "postgres://aegis:aegis@aegis-prefixed:5432/aegis" {
		t.Errorf("AEGIS_ prefix must win over bare name, got %q", c.DatabaseURL)
	}
	if c.RedisURL != "redis://aegis-prefixed:6379/0" {
		t.Errorf("AEGIS_ prefix must win over default, got %q", c.RedisURL)
	}
	if c.S3.Endpoint != "http://bare-s3:9000" {
		t.Errorf("bare fallback must apply when prefixed unset, got %q", c.S3.Endpoint)
	}
}

func TestBareNamesStillWork(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://aegis:aegis@localhost:5432/aegis?sslmode=disable")
	t.Setenv("NATS_URL", "nats://localhost:4222")
	t.Setenv("AEGIS_JWT_SECRET", "change-me-32-bytes-min-secret-key")
	t.Setenv("AEGIS_BOOTSTRAP_ADMIN_EMAIL", "admin@aegis.local")

	c, err := Load("server")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.DatabaseURL == "" {
		t.Fatal("bare DATABASE_URL must be accepted for native development")
	}
	if c.Auth.BootstrapAdminEmail != "admin@aegis.local" {
		t.Errorf("bootstrap admin email not read, got %q", c.Auth.BootstrapAdminEmail)
	}
}

func TestMissingDatabaseURLErrorNamesCanonicalKey(t *testing.T) {
	t.Setenv("AEGIS_DATABASE_URL", "")
	t.Setenv("DATABASE_URL", "")

	_, err := Load("worker")
	if err == nil {
		t.Fatal("expected error for missing database URL")
	}
	if !contains(err.Error(), "AEGIS_DATABASE_URL") {
		t.Errorf("error should name the canonical AEGIS_DATABASE_URL key, got: %v", err)
	}
}

// Agent CA paths must never default to empty: with an empty path ca.Load
// cannot generate a dev CA and enrollment silently stays disabled
// (os.ReadFile("") produces the confusing `open :` error on Windows).
func TestAgentCADefaults(t *testing.T) {
	t.Setenv("AEGIS_AGENT_CA_CERT", "")
	t.Setenv("AEGIS_AGENT_CA_KEY", "")

	c, err := Load("server")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.AgentCA.CertPath == "" || c.AgentCA.KeyPath == "" {
		t.Fatalf("CA paths must default to ./certs files, got cert=%q key=%q",
			c.AgentCA.CertPath, c.AgentCA.KeyPath)
	}
}

func TestAgentCAEnvOverride(t *testing.T) {
	t.Setenv("AEGIS_AGENT_CA_CERT", "/etc/aegis/ca.crt")
	t.Setenv("AEGIS_AGENT_CA_KEY", "/etc/aegis/ca.key")

	c, err := Load("server")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.AgentCA.CertPath != "/etc/aegis/ca.crt" || c.AgentCA.KeyPath != "/etc/aegis/ca.key" {
		t.Fatalf("explicit CA env must win, got cert=%q key=%q",
			c.AgentCA.CertPath, c.AgentCA.KeyPath)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
