package postgres

// Integration test for SettingsRepo — the platform settings KV backing the
// metrics retention knob (v1.28.0). Pins the upsert contract, the
// missing-key default contract (nil, nil) and round-trip of JSONB values.
// Proven against real Postgres (skipped unless AEGIS_TEST_PG_URL is set).

import (
	"context"
	"encoding/json"
	"testing"
)

func TestIntegrationSettingsRepo(t *testing.T) {
	url := testURL(t)
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	db, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	repo := NewSettingsRepo(db)

	// Missing key → (nil, nil): callers apply documented defaults.
	raw, err := repo.Get(ctx, "metrics.retention_days")
	if err != nil || raw != nil {
		t.Fatalf("missing key: got (%s, %v), want (nil, nil)", raw, err)
	}

	// Set then read back — JSONB round-trips as raw JSON.
	if err := repo.Set(ctx, "metrics.retention_days", json.RawMessage("45")); err != nil {
		t.Fatalf("set: %v", err)
	}
	raw, err = repo.Get(ctx, "metrics.retention_days")
	if err != nil || string(raw) != "45" {
		t.Fatalf("after set: got (%s, %v), want (45, nil)", raw, err)
	}

	// Upsert overwrites.
	if err := repo.Set(ctx, "metrics.retention_days", json.RawMessage("0")); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	raw, _ = repo.Get(ctx, "metrics.retention_days")
	if string(raw) != "0" {
		t.Fatalf("after overwrite: got %s, want 0", raw)
	}

	// List exposes every entry.
	entries, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Key == "metrics.retention_days" {
			found = true
		}
	}
	if !found {
		t.Fatal("list: retention key missing")
	}

	// Non-string JSON (object values) round-trip too.
	obj := json.RawMessage(`{"nested":[1,2]}`)
	if err := repo.Set(ctx, "test.object", obj); err != nil {
		t.Fatalf("set object: %v", err)
	}
	raw, _ = repo.Get(ctx, "test.object")
	if string(raw) != `{"nested":[1,2]}` {
		t.Fatalf("object round-trip: got %s", raw)
	}
}
