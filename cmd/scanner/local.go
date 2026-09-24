package main

import (
	"context"
	"encoding/json"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/joblog"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/FlameInTheDark/aegis/internal/scanexec"
	"github.com/FlameInTheDark/aegis/internal/scanning"
)

// localOrch adapts the server-side scanning.Orchestrator to the shared
// scanexec.Orch surface: the embedded scanner owns its database, so every
// call goes straight through.
type localOrch struct{ o *scanning.Orchestrator }

func (l localOrch) RecordObservation(ctx context.Context, obs *domain.Observation) error {
	return l.o.RecordObservation(ctx, obs)
}

func (l localOrch) ResolveProfile(ctx context.Context, orgID string, p domain.ScanProfile) (*domain.ProfileDefinition, error) {
	return l.o.ResolveProfile(ctx, orgID, p)
}

func (l localOrch) Scope(ctx context.Context, scanID string) (*domain.ScanScope, error) {
	return l.o.Scans.Scope(ctx, scanID)
}

func (l localOrch) ScanByID(ctx context.Context, orgID, scanID string) (*domain.Scan, error) {
	return l.o.Scans.ByID(ctx, orgID, scanID)
}

func (l localOrch) QueueScans(ctx context.Context) ([]domain.Scan, error) {
	scans, _, err := l.o.Scans.List(ctx, pg.ScanListFilter{OrgID: "", State: string(domain.ScanQueued), Limit: 5})
	return scans, err
}

func (l localOrch) UpdateScanState(ctx context.Context, scanID string, state domain.ScanState, phase string, progress float64) error {
	return l.o.Scans.UpdateState(ctx, scanID, state, phase, progress)
}

func (l localOrch) UpdateScanStats(ctx context.Context, scanID string, stats domain.ScanStats) error {
	return l.o.Scans.UpdateStats(ctx, scanID, stats)
}

func (l localOrch) SetScanError(ctx context.Context, scanID, msg string) error {
	return l.o.Scans.SetError(ctx, scanID, msg)
}

func (l localOrch) CreateTask(ctx context.Context, t *domain.ScanTask) error {
	return l.o.Tasks.Create(ctx, t)
}

func (l localOrch) UpdateTaskState(ctx context.Context, taskID string, state domain.TaskState, msg string) error {
	return l.o.Tasks.UpdateState(ctx, taskID, state, msg)
}

func (l localOrch) PublishScanResult(ctx context.Context, scanID string, state domain.ScanState) error {
	if l.o.Bus == nil {
		return nil
	}
	// organization_id rides along so server-side post-scan correlation can
	// run without a second lookup (the subscriber still falls back to the
	// scan row for events that omit it).
	orgID := ""
	if scan, err := l.o.Scans.ByID(ctx, "", scanID); err == nil {
		orgID = scan.OrganizationID
	}
	evt, _ := json.Marshal(map[string]any{"scan_id": scanID, "organization_id": orgID, "state": string(state)})
	return l.o.Bus.Publish(ctx, scanning.SubjectScanResult, evt)
}

// EmitJobLog broadcasts one structured job log event to the platform.
func (l localOrch) EmitJobLog(ctx context.Context, e *domain.JobLogEvent) {
	joblog.PublishLog(ctx, l.o.Bus, e)
}

// EmitState broadcasts a scan lifecycle/progress event. Events that
// arrive without an org id (caller shortcuts) get it resolved here.
func (l localOrch) EmitState(ctx context.Context, e *domain.ScanStateEvent) {
	if e == nil || e.ScanID == "" {
		return
	}
	if e.OrgID == "" {
		if scan, err := l.o.Scans.ByID(ctx, "", e.ScanID); err == nil {
			e.OrgID = scan.OrganizationID
		}
	}
	joblog.PublishState(ctx, l.o.Bus, e)
}

// compile-time check: the local adapter satisfies the shared Orch surface
// and the streaming sink.
var _ scanexec.Orch = localOrch{}
var _ scanexec.JobLogSink = localOrch{}
