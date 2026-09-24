package httpx

import (
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/audit"
	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/gofiber/fiber/v2"
)

// User management: administrators create and manage users;
// every signed-in user can change their own password. Managers (analysts,
// operators, viewers) have NO user:manage permission, so they can only use
// the self-service endpoints below.

// passwordPolicy is the shared password rule for creation and changes.
func passwordPolicy(p string) error {
	if len(p) < 10 {
		return fiber.NewError(fiber.StatusBadRequest, "password must be at least 10 characters")
	}
	if len(p) > 128 {
		return fiber.NewError(fiber.StatusBadRequest, "password too long")
	}
	if strings.TrimSpace(p) == "" {
		return fiber.NewError(fiber.StatusBadRequest, "password must not be blank")
	}
	return nil
}

// assignableRoles are the roles an administrator may grant. "owner" is
// reserved for the bootstrap account (granting it via the API would let an
// administrator escalate beyond their own scope).
func assignableRole(r domain.Role) bool {
	switch r {
	case domain.RoleAdministrator, domain.RoleSecurityAnalyst, domain.RoleOperator, domain.RoleViewer:
		return true
	}
	return false
}

type userView struct {
	ID          string      `json:"id"`
	Email       string      `json:"email"`
	Name        string      `json:"name"`
	Role        domain.Role `json:"role"`
	Disabled    bool        `json:"disabled"`
	LastLoginAt *time.Time  `json:"last_login_at,omitempty"`
	CreatedAt   time.Time   `json:"created_at"`
	MemberSince time.Time   `json:"member_since"`
}

func (a *App) handleListUsers(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermUserManage); he != nil {
		return he
	}
	ctx := Context(c)
	claims := a.claimsFrom(c)
	members, err := a.svc.Memberships.ListForOrg(ctx, claims.OrganizationID)
	if err != nil {
		return Internal("could not list users")
	}
	out := make([]userView, 0, len(members))
	for _, m := range members {
		u, err := a.svc.Users.ByID(ctx, m.UserID)
		if err != nil || u == nil {
			continue // membership row without a user row; skip silently
		}
		out = append(out, userView{
			ID: u.ID, Email: u.Email, Name: u.Name, Role: m.Role,
			Disabled: u.Disabled, LastLoginAt: u.LastLoginAt,
			CreatedAt: u.CreatedAt, MemberSince: m.CreatedAt,
		})
	}
	return c.JSON(fiber.Map{"items": out})
}

func (a *App) handleCreateUser(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermUserManage); he != nil {
		return he
	}
	var req struct {
		Email    string      `json:"email"`
		Name     string      `json:"name"`
		Password string      `json:"password"`
		Role     domain.Role `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.Name = strings.TrimSpace(req.Name)
	if req.Email == "" || !strings.Contains(req.Email, "@") || len(req.Email) > 254 {
		return BadRequest("a valid email is required")
	}
	if req.Name == "" || len(req.Name) > 128 {
		return BadRequest("name is required (max 128 chars)")
	}
	if err := passwordPolicy(req.Password); err != nil {
		return err
	}
	if !assignableRole(req.Role) {
		return BadRequest("role must be one of administrator, security_analyst, operator, viewer")
	}
	ctx := Context(c)
	if existing, err := a.svc.Users.ByEmail(ctx, req.Email); err == nil && existing != nil {
		return Conflict("a user with this email already exists")
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return Internal("could not hash password")
	}
	u, err := a.svc.Users.Create(ctx, req.Email, req.Name, hash)
	if err != nil {
		return Internal("could not create user")
	}
	claims := a.claimsFrom(c)
	if err := a.svc.Memberships.Add(ctx, u.ID, claims.OrganizationID, req.Role); err != nil {
		return Internal("could not add membership")
	}
	a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionUserCreated,
		"user:"+u.ID, c.IP(), string(c.Request().Header.UserAgent()), "success",
		map[string]any{"email": req.Email, "role": string(req.Role)})
	return c.Status(fiber.StatusCreated).JSON(userView{
		ID: u.ID, Email: u.Email, Name: u.Name, Role: req.Role,
		Disabled: false, CreatedAt: u.CreatedAt, MemberSince: u.CreatedAt,
	})
}

func (a *App) handleUpdateUser(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermUserManage); he != nil {
		return he
	}
	var req struct {
		Role     *domain.Role `json:"role"`
		Disabled *bool        `json:"disabled"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	ctx := Context(c)
	claims := a.claimsFrom(c)
	targetID := c.Params("id")
	if targetID == claims.Subject {
		return BadRequest("use the account panel to change your own role state or ask another administrator")
	}
	role, err := a.svc.Memberships.RoleFor(ctx, targetID, claims.OrganizationID)
	if err != nil {
		return NotFound("user not found in this organization")
	}
	if role == domain.RoleOwner {
		return BadRequest("the owner account cannot be modified")
	}
	if req.Role != nil {
		if !assignableRole(*req.Role) {
			return BadRequest("role must be one of administrator, security_analyst, operator, viewer")
		}
		if err := a.svc.Memberships.SetRole(ctx, targetID, claims.OrganizationID, *req.Role); err != nil {
			return Internal("could not update role")
		}
		a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionUserUpdated,
			"user:"+targetID, c.IP(), string(c.Request().Header.UserAgent()), "success",
			map[string]any{"role": string(*req.Role)})
	}
	if req.Disabled != nil {
		if err := a.svc.Users.SetDisabled(ctx, targetID, *req.Disabled); err != nil {
			return Internal("could not update user")
		}
		if *req.Disabled {
			_ = a.svc.Sessions.RevokeAllForUser(ctx, targetID)
			a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionUserDisabled,
				"user:"+targetID, c.IP(), string(c.Request().Header.UserAgent()), "success", nil)
		} else {
			a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionUserEnabled,
				"user:"+targetID, c.IP(), string(c.Request().Header.UserAgent()), "success", nil)
		}
	}
	return c.SendStatus(204)
}

func (a *App) handleResetUserPassword(c *fiber.Ctx) error {
	if he := a.requirePerm(c, domain.PermUserManage); he != nil {
		return he
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	if err := passwordPolicy(req.Password); err != nil {
		return err
	}
	ctx := Context(c)
	claims := a.claimsFrom(c)
	targetID := c.Params("id")
	role, err := a.svc.Memberships.RoleFor(ctx, targetID, claims.OrganizationID)
	if err != nil {
		return NotFound("user not found in this organization")
	}
	if role == domain.RoleOwner {
		return BadRequest("the owner password cannot be reset from user management")
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return Internal("could not hash password")
	}
	if err := a.svc.Users.SetPassword(ctx, targetID, hash); err != nil {
		return Internal("could not set password")
	}
	// The reset must take effect immediately: kill every session the target
	// user holds (their refresh tokens are useless afterwards).
	_ = a.svc.Sessions.RevokeAllForUser(ctx, targetID)
	a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionPasswordReset,
		"user:"+targetID, c.IP(), string(c.Request().Header.UserAgent()), "success", nil)
	return c.SendStatus(204)
}

// handleChangeOwnPassword is available to EVERY signed-in user regardless of
// role — managers cannot manage users, but they can always change their own
// credentials.
func (a *App) handleChangeOwnPassword(c *fiber.Ctx) error {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	if err := passwordPolicy(req.NewPassword); err != nil {
		return err
	}
	ctx := Context(c)
	claims := a.claimsFrom(c)
	u, err := a.svc.Users.ByID(ctx, claims.Subject)
	if err != nil || u == nil {
		return Unauthorized("authentication required")
	}
	if !auth.VerifyPassword(req.CurrentPassword, u.PasswordHash) {
		a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionPasswordChange,
			"user:"+claims.Subject, c.IP(), string(c.Request().Header.UserAgent()), "denied", nil)
		return Unauthorized("current password is incorrect")
	}
	hash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		return Internal("could not hash password")
	}
	if err := a.svc.Users.SetPassword(ctx, u.ID, hash); err != nil {
		return Internal("could not set password")
	}
	// Keep the current device signed in; force every other session out.
	_ = a.svc.Sessions.RevokeOthersForUser(ctx, u.ID, claims.SessionID)
	a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject, audit.ActionPasswordChange,
		"user:"+u.ID, c.IP(), string(c.Request().Header.UserAgent()), "success", nil)
	return c.SendStatus(204)
}
