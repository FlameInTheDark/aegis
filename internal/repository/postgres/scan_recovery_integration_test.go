package postgres

// Integration test for startup scan recovery (v1.28.1): a system restart
// while a scan was active used to leave the row running forever, because
// the executor claim loop only picks up queued scans. FailStaleActive
// closes running/cancelling scans as failed with the recovery reason,
// FailStaleByScans fails their non-terminal tasks, and (re)entering
// running clears a stale error so a surviving executor's progress reports
// heal a swept scan. Proven against real Postgres (skipped unless
// AEGIS_TEST_PG_URL is set).

import (
	"context"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
)

func TestIntegrationScanRecovery(t *testing.T) {
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

	org, err := NewOrgRepo(db).Create(ctx, "recovery-org-"+ids.New(), "rec-"+ids.New())
	if err != nil {
		t.Fatalf("create org: %v", err)
	}

	scans := NewScanRepo(db)
	tasks := NewTaskRepo(db)
	const reason = "interrupted by restart"

	newScan := func(t *testing.T, name string) *domain.Scan {
		t.Helper()
		s := &domain.Scan{ID: ids.New(), OrganizationID: org.ID, Name: name,
			State: domain.ScanQueued, Profile: domain.ProfileInventory, Engine: "nmap"}
		if err := scans.Create(ctx, s, &domain.ScanScope{CIDRs: []string{"10.50.0.0/28"}}); err != nil {
			t.Fatalf("create scan %s: %v", name, err)
		}
		return s
	}

	// Running scan → swept.
	running := newScan(t, "was-running")
	if err := scans.UpdateState(ctx, running.ID, domain.ScanRunning, "discovery", 5); err != nil {
		t.Fatalf("running: %v", err)
	}
	// Cancelling scan → swept (the executor that would observe the kill
	// switch died with the restart).
	cancelling := newScan(t, "was-cancelling")
	if err := scans.UpdateState(ctx, cancelling.ID, domain.ScanRunning, "discovery", 5); err != nil {
		t.Fatalf("running: %v", err)
	}
	if err := scans.UpdateState(ctx, cancelling.ID, domain.ScanCancelling, "cancelling", 5); err != nil {
		t.Fatalf("cancelling: %v", err)
	}
	// Queued scan → untouched (re-claimed after restart).
	queued := newScan(t, "still-queued")
	// Completed scan → untouched.
	completed := newScan(t, "already-done")
	if err := scans.UpdateState(ctx, completed.ID, domain.ScanRunning, "discovery", 5); err != nil {
		t.Fatalf("running: %v", err)
	}
	if err := scans.UpdateState(ctx, completed.ID, domain.ScanCompleted, "completed", 100); err != nil {
		t.Fatalf("completed: %v", err)
	}

	// Tasks of the running scan: non-terminal ones swept, terminal kept.
	for _, st := range []struct {
		id    string
		state domain.TaskState
	}{
		{ids.New(), domain.TaskSucceeded},
		{ids.New(), domain.TaskFailed},
		{ids.New(), domain.TaskRunning},
		{ids.New(), domain.TaskPending},
	} {
		if err := tasks.Create(ctx, &domain.ScanTask{ID: st.id, ScanID: running.ID,
			Type: domain.TaskDiscoverHosts, State: st.state, Attempt: 1}); err != nil {
			t.Fatalf("create task %s: %v", st.state, err)
		}
	}

	swept, err := scans.FailStaleActive(ctx, reason)
	if err != nil {
		t.Fatalf("FailStaleActive: %v", err)
	}
	sweptIDs := map[string]bool{}
	for _, s := range swept {
		sweptIDs[s.ID] = true
	}
	if len(swept) != 2 || !sweptIDs[running.ID] || !sweptIDs[cancelling.ID] {
		t.Fatalf("swept = %v, want exactly the running and cancelling scans", swept)
	}
	for _, id := range []string{queued.ID, completed.ID} {
		if sweptIDs[id] {
			t.Errorf("scan %s must not be swept", id)
		}
	}

	// Swept rows: failed with reason + completion timestamp.
	got, err := scans.ByID(ctx, org.ID, running.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ScanFailed || got.Error != reason || got.CompletedAt == nil {
		t.Fatalf("swept scan = state=%s error=%q completed=%v, want failed/%q/set",
			got.State, got.Error, got.CompletedAt, reason)
	}

	// Untouched rows keep their state.
	if q, err := scans.ByID(ctx, org.ID, queued.ID); err != nil || q.State != domain.ScanQueued {
		t.Fatalf("queued scan survived sweep: state=%v err=%v", q.State, err)
	}
	if c, err := scans.ByID(ctx, org.ID, completed.ID); err != nil || c.State != domain.ScanCompleted {
		t.Fatalf("completed scan survived sweep: state=%v err=%v", c.State, err)
	}

	// Tasks: non-terminal → failed with reason; terminal untouched.
	after, err := tasks.ListForScan(ctx, running.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tk := range after {
		switch tk.State {
		case domain.TaskFailed:
			if tk.Error != reason {
				t.Errorf("task %s failed without the recovery reason: %q", tk.ID, tk.Error)
			}
		case domain.TaskSucceeded:
		default:
			t.Errorf("task %s left in %s after the sweep", tk.ID, tk.State)
		}
	}

	// A surviving executor re-enters running on its next progress report,
	// which must clear the stored recovery reason.
	if err := scans.UpdateState(ctx, running.ID, domain.ScanRunning, "discovery", 10); err != nil {
		t.Fatalf("re-enter running: %v", err)
	}
	if got, err = scans.ByID(ctx, org.ID, running.ID); err != nil {
		t.Fatal(err)
	}
	if got.State != domain.ScanRunning || got.Error != "" {
		t.Fatalf("re-entered scan = state=%s error=%q, want running with cleared error",
			got.State, got.Error)
	}
}
