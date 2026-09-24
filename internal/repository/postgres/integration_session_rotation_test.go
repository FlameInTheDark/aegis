package postgres

import (
	"context"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

// TestIntegrationSessionRotation drives the full refresh-token rotation
// lifecycle against a real PostgreSQL: create → rotate → grace-window
// acceptance of the retired token → reuse rejection after the grace window.
// Run with:
//
//	AEGIS_TEST_PG_URL=postgres://postgres@127.0.0.1:5433/aegis_it?sslmode=disable go test ./internal/repository/postgres/ -run TestIntegrationSessionRotation
func TestIntegrationSessionRotation(t *testing.T) {
	url := testURL(t)
	if err := MigrateUp(url); err != nil {
		t.Fatalf("migrate up: %v", err)
	}
	ctx := context.Background()
	db, err := Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	repo := NewSessionRepo(db)

	t1, err := auth.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	// Dynamic session id: a fixed one collides with the row a previous
	// suite run left behind (Revoke retires a session, it does not delete it).
	sid := ids.New()
	uid := "00000000-0000-4000-8000-00000000c017"
	oid := "00000000-0000-4000-8000-000000000001"
	// The sessions table has FKs to users; users are FK-free. Seed the
	// parent rows directly (the migrations-fresh test may have wiped the
	// demo seed) and drop them again on cleanup.
	if _, err := db.Pool.Exec(ctx, `INSERT INTO organizations (id, name, slug) VALUES ($1, 'rotation-it', 'rotation-it') ON CONFLICT (id) DO NOTHING`, oid); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if _, err := db.Pool.Exec(ctx, `INSERT INTO users (id, email, name, password_hash) VALUES ($1, 'rotation-it@aegis.test', 'Rotation IT', 'x') ON CONFLICT (id) DO NOTHING`, uid); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, uid)
		_, _ = db.Pool.Exec(ctx, `DELETE FROM organizations WHERE id = $1`, oid)
	})
	if err := repo.Create(ctx, sid, uid, oid, t1, "127.0.0.1", "it", time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatalf("create session: %v", err)
	}
	t.Cleanup(func() { _ = repo.Revoke(ctx, sid) })

	// Current-token lookup must find it.
	s, err := repo.ByRefreshHash(ctx, t1)
	if err != nil || s.ID != sid {
		t.Fatalf("ByRefreshHash: %v %+v", err, s)
	}

	// Rotate T1 → T2.
	t2, err := auth.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Rotate(ctx, sid, t1, t2); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := repo.ByRefreshHash(ctx, t1); err == nil {
		t.Fatal("T1 must no longer be the current token")
	}
	s2, err := repo.ByRefreshHash(ctx, t2)
	if err != nil || s2.ID != sid {
		t.Fatalf("ByRefreshHash(T2): %v %+v", err, s2)
	}

	// Retired T1 is inside the grace window: ByRetiredHash finds it and
	// the grace math in the handler rotates forward.
	r1, err := repo.ByRetiredHash(ctx, t1)
	if err != nil || r1.ID != sid {
		t.Fatalf("ByRetiredHash(T1): %v %+v", err, r1)
	}
	if r1.RetiredAtMs <= 0 || time.Now().UnixMilli()-r1.RetiredAtMs > 30_000 {
		t.Fatalf("T1 retirement timestamp out of grace range: %d", r1.RetiredAtMs)
	}

	// Simulate a second, racing rotation from the SAME retired token (the
	// multi-tab interleave): Rotate retires the CURRENT hash too, so both
	// issued tokens stay acceptable until one lands in the cookie jar.
	t3, err := auth.NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Rotate(ctx, sid, t1, t3); err != nil {
		t.Fatalf("racing rotate: %v", err)
	}
	// T2 — issued by the first rotation and possibly the last one to land
	// in the browser jar — must still be found (retired within grace).
	if _, err := repo.ByRetiredHash(ctx, t2); err != nil {
		t.Fatalf("raced-out T2 must remain within grace: %v", err)
	}

	// Reuse detection data: age the retirement of T1 beyond the grace
	// window, then the handler must treat its presentation as reuse.
	old := time.Now().Add(-2 * time.Minute).UnixMilli()
	if _, err := db.ExecSQL(ctx, `UPDATE sessions SET retired = jsonb_set(retired, ARRAY[$2], to_jsonb($3::bigint)) WHERE id = $1`, sid, t1, old); err != nil {
		t.Fatalf("age retired entry: %v", err)
	}
	stale, err := repo.ByRetiredHash(ctx, t1)
	if err != nil {
		t.Fatalf("stale lookup: %v", err)
	}
	if time.Now().UnixMilli()-stale.RetiredAtMs <= 30_000 {
		t.Fatalf("stale entry must be beyond grace: %d", stale.RetiredAtMs)
	}

	// An unknown hash matches nothing.
	if _, err := repo.ByRefreshHash(ctx, "nope"); err == nil {
		t.Fatal("unknown hash must not match")
	}
	if _, err := repo.ByRetiredHash(ctx, "nope"); err == nil {
		t.Fatal("unknown hash must not match retired")
	}
}
