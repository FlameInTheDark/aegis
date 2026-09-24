// Package audit provides the audit logging service :
// every security-relevant action records who/what/when/where/result with
// structured before/after where applicable.
package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/ids"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
)

// Service writes audit entries.
type Service struct {
	Repo *pg.AuditRepo
	Log  *slog.Logger
	// FailOpen controls whether audit write failures fail the caller's
	// request (default false: audit is best-effort but always logged).
	FailOpen bool
}

// Action type constants keep the vocabulary consistent across services.
const (
	ActionLogin          = "auth.login"
	ActionLogout         = "auth.logout"
	ActionTokenRevoke    = "auth.token_revoked"
	ActionConfigChange   = "config.changed"
	ActionScanCreate     = "scan.created"
	ActionScanCancel     = "scan.cancelled"
	ActionScopeChange    = "scope.changed"
	ActionAgentEnroll    = "agent.enrolled"
	ActionAgentTask      = "agent.task_executed"
	ActionFeedConfig     = "feed.configured"
	ActionFindingStatus  = "finding.status_changed"
	ActionReportGenerate = "report.generated"
	ActionUserCreated    = "user.created"
	ActionUserUpdated    = "user.updated"
	ActionUserDisabled   = "user.disabled"
	ActionUserEnabled    = "user.enabled"
	ActionPasswordReset  = "user.password_reset"
	ActionPasswordChange = "auth.password_changed"
)

// Entry records one audited action.
func (s *Service) Entry(ctx context.Context, orgID, userID, action, resource, ip, ua, result string, detail map[string]any) {
	e := &domain.AuditEntry{
		ID: ids.New(), OrgID: orgID, ActorID: userID, Action: action,
		Target: resource, ActorIP: ip, Result: result,
		Detail: detail, CreatedAt: time.Now().UTC(),
	}
	if err := s.Repo.Insert(ctx, e); err != nil {
		s.Log.Error("audit write failed", "action", action, "err", err)
	}
}

// EntryElevated records actions that require elevated permission
// (active validation scans, scope changes) with mandatory reason.
func (s *Service) EntryElevated(ctx context.Context, orgID, userID, action, resource, ip, ua, reason string, detail map[string]any) {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["reason"] = reason
	detail["elevated"] = true
	s.Entry(ctx, orgID, userID, action, resource, ip, ua, "ok", detail)
}
