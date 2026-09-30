package scanning

import (
	"testing"
	"time"
)

// Base clock: 2026-09-27 is a Sunday, 10:15:30 UTC.
var cronBase = time.Date(2026, 9, 27, 10, 15, 30, 0, time.UTC)

func mustNext(t *testing.T, expr string, after time.Time) time.Time {
	t.Helper()
	spec, err := ParseCron(expr)
	if err != nil {
		t.Fatalf("ParseCron(%q): %v", expr, err)
	}
	return spec.NextAfter(after)
}

func TestCronDaily(t *testing.T) {
	next := mustNext(t, "30 2 * * *", cronBase)
	want := time.Date(2026, 9, 28, 2, 30, 0, 0, time.UTC) // 02:30 already passed today
	if !next.Equal(want) {
		t.Fatalf("daily: got %v want %v", next, want)
	}
	early := time.Date(2026, 9, 27, 0, 5, 0, 0, time.UTC)
	if got := mustNext(t, "30 2 * * *", early); !got.Equal(time.Date(2026, 9, 27, 2, 30, 0, 0, time.UTC)) {
		t.Fatalf("daily same-day: got %v", got)
	}
}

func TestCronWeeklyMonday(t *testing.T) {
	// The old parser degraded weekly schedules to daily; this pins the fix.
	next := mustNext(t, "0 3 * * 1", cronBase) // Monday 03:00, base is Sunday
	want := time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("weekly: got %v want %v", next, want)
	}
}

func TestCronMonthly(t *testing.T) {
	next := mustNext(t, "0 3 1 * *", cronBase)
	want := time.Date(2026, 10, 1, 3, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("monthly: got %v want %v", next, want)
	}
}

func TestCronDOMAndDOWUnion(t *testing.T) {
	// Both restricted: fires on the 13th OR any Friday (Vixie semantics).
	next := mustNext(t, "0 0 13 * 5", cronBase)          // base is Sunday 10:15
	want := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC) // Friday Oct 2 beats the 13th
	if !next.Equal(want) {
		t.Fatalf("union: got %v want %v", next, want)
	}
}

func TestCronDOWOnly(t *testing.T) {
	next := mustNext(t, "0 12 * * 0", cronBase) // Sunday 12:00 — still ahead today
	want := time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("dow 0: got %v want %v", next, want)
	}
	if got := mustNext(t, "0 12 * * 7", cronBase); !got.Equal(want) {
		t.Fatalf("dow 7 should equal Sunday: got %v", got)
	}
}

func TestCronStepsAndRanges(t *testing.T) {
	next := mustNext(t, "*/15 * * * *", cronBase)
	want := time.Date(2026, 9, 27, 10, 30, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("step: got %v want %v", next, want)
	}
	// 09,11,13,15,17 hours on weekdays.
	next = mustNext(t, "0 9-17/2 * * mon-fri", cronBase)
	want = time.Date(2026, 9, 28, 9, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("range-step names: got %v want %v", next, want)
	}
}

func TestCronMonthNames(t *testing.T) {
	next := mustNext(t, "0 0 1 jan,jul *", cronBase) // Jul 1 2026 passed
	want := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("month names: got %v want %v", next, want)
	}
}

func TestCronLeapDay(t *testing.T) {
	next := mustNext(t, "0 0 29 2 *", cronBase)
	want := time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC)
	if !next.Equal(want) {
		t.Fatalf("leap day: got %v want %v", next, want)
	}
}

func TestCronEvery(t *testing.T) {
	next := mustNext(t, "@every 90m", cronBase)
	want := cronBase.Add(90 * time.Minute)
	if !next.Equal(want) {
		t.Fatalf("@every: got %v want %v", next, want)
	}
}

func TestCronInvalid(t *testing.T) {
	for _, expr := range []string{
		"", "60 * * * *", "* * * *", "* * * * * *", "*/0 * * * *",
		"@every 30s", "@reboot", "0 0 * mon-fri *", "0 5 x * *", "fri-mon 5 * * *",
	} {
		if err := ValidateCron(expr); err == nil {
			t.Fatalf("ValidateCron(%q) = nil, want error", expr)
		}
	}
	for _, expr := range []string{
		"30 2 * * *", "0 3 * * 1", "0 3 1 * *", "*/15,45 8 * * *",
		"0 9-17/2 * * mon-fri", "@every 6h", "0 0 29 2 *", "15 14 * * 7",
	} {
		if err := ValidateCron(expr); err != nil {
			t.Fatalf("ValidateCron(%q) = %v, want nil", expr, err)
		}
	}
}

func TestNextRunsAfter(t *testing.T) {
	runs, err := NextRunsAfter(cronBase, "0 3 * * 1", 3)
	if err != nil {
		t.Fatalf("NextRunsAfter: %v", err)
	}
	want := []time.Time{
		time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 5, 3, 0, 0, 0, time.UTC),
		time.Date(2026, 10, 12, 3, 0, 0, 0, time.UTC),
	}
	if len(runs) != len(want) {
		t.Fatalf("got %d runs, want %d", len(runs), len(want))
	}
	for i := range want {
		if !runs[i].Equal(want[i]) {
			t.Fatalf("run %d: got %v want %v", i, runs[i], want[i])
		}
	}
	if _, err := NextRunsAfter(cronBase, "not a cron", 3); err == nil {
		t.Fatal("expected error for invalid expression")
	}
}

func TestNextRunAfterBackwardCompatible(t *testing.T) {
	// Unparseable expressions keep the conservative daily fallback so the
	// scheduler never stalls, while valid ones route through the full parser.
	if got := NextRunAfter(cronBase, "nonsense"); !got.Equal(cronBase.Add(24 * time.Hour)) {
		t.Fatalf("fallback: got %v", got)
	}
	if got := NextRunAfter(cronBase, "0 3 * * 1"); got.Weekday() != time.Monday {
		t.Fatalf("weekly via NextRunAfter: got %v (%v)", got, got.Weekday())
	}
}
