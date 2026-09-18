package httpx

import (
	"errors"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/audit"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// authenticate validates the Bearer JWT and loads claims (§7).
func (a *App) authenticate() fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if len(header) < 8 || header[:7] != "Bearer " {
			return Unauthorized("missing or malformed Authorization header")
		}
		issuer := auth.NewTokenIssuer(a.svc.Cfg.Auth.JWTSecret, a.svc.Cfg.Auth.AccessTokenTTL, a.svc.Cfg.Auth.RefreshTokenTTL)
		claims, err := issuer.ParseAccess(header[7:])
		if err != nil {
			return Unauthorized("invalid or expired token")
		}
		if claims.HasAudience("refresh") {
			return Unauthorized("refresh tokens are not access tokens")
		}
		c.Locals("claims", claims)
		c.Locals("request_id", RequestIDFromCtx(c))
		return c.Next()
	}
}

// claimsFrom returns authenticated claims or nil.
func (a *App) claimsFrom(c *fiber.Ctx) *auth.Claims {
	if v, ok := c.Locals("claims").(*auth.Claims); ok {
		return v
	}
	return ClaimsFromCtx(c)
}

// requirePerm guards a handler with a permission check.
func (a *App) requirePerm(c *fiber.Ctx, perm domain.Permission) *HTTPError {
	claims := a.claimsFrom(c)
	if claims == nil {
		return Unauthorized("authentication required")
	}
	if !auth.HasPermission(claims.Role, perm) {
		return Forbidden("insufficient role for " + string(perm))
	}
	return nil
}

// auditContext extracts actor/ip/ua for audit entries.
func (a *App) auditContext(c *fiber.Ctx) (userID, ip, ua string) {
	claims := a.claimsFrom(c)
	if claims != nil {
		userID = claims.Subject
	}
	return userID, c.IP(), string(c.Request().Header.UserAgent())
}

// ---------------------------------------------------------------------------
// Auth handlers
//
// Token architecture (docs/AUTH.md):
//   - Access token: short-lived JWT, returned in the JSON body, held in
//     SPA memory only, presented via the Authorization header.
//   - Refresh token: opaque 256-bit string in an HttpOnly + SameSite=Lax
//     (+ Secure in production) cookie. JavaScript never sees it. Stored
//     server-side as a SHA-256 hash and ROTATED on every refresh.
//   - Rotation + reuse detection: the sessions row keeps the current and
//     the immediately-retired hash. A retired token presented within the
//     grace window is a concurrent refresh race (multi-tab, 401 retry
//     waves) and rotates forward; presented after the window it is reuse
//     of a possibly-stolen token and revokes the whole session family.

const (
	// refreshRotationGrace bounds how long a just-retired refresh token
	// may still be exchanged. Wide enough for multi-tab 401 retry waves,
	// far shorter than an attacker-friendly window.
	refreshRotationGrace = 30 * time.Second
	// xhrHeaderName is required on the cookie-authenticated endpoints
	// (refresh/logout). A cross-site attacker cannot attach a custom
	// header without a successful CORS preflight, and the platform's CORS
	// policy only allows the deployed origin — so this header is a CSRF
	// defense on top of SameSite=Lax (which already keeps the cookie off
	// cross-site POSTs).
	xhrHeaderName  = "X-Requested-With"
	xhrHeaderValue = "XMLHttpRequest"
)

// requireXHR is the CSRF gate for cookie-authenticated endpoints.
func requireXHR(c *fiber.Ctx) bool {
	return c.Get(xhrHeaderName) == xhrHeaderValue
}

// refreshCookieName uses the __Host- prefix whenever the cookie is Secure:
// browsers then enforce Path=/, no Domain attribute and Secure, so a
// compromised subdomain cannot plant a overwrite cookie for this origin.
func (a *App) refreshCookieName() string {
	if a.svc.Cfg.Auth.CookieSecure {
		return "__Host-aegis_rt"
	}
	return "aegis_rt"
}

func (a *App) setRefreshCookie(c *fiber.Ctx, token string) {
	c.Cookie(&fiber.Cookie{
		Name:     a.refreshCookieName(),
		Value:    token,
		Path:     "/",
		MaxAge:   int(a.svc.Cfg.Auth.RefreshTokenTTL.Seconds()),
		HTTPOnly: true,
		Secure:   a.svc.Cfg.Auth.CookieSecure,
		SameSite: "Lax",
	})
}

func (a *App) clearRefreshCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name:     a.refreshCookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Now().Add(-time.Hour),
		HTTPOnly: true,
		Secure:   a.svc.Cfg.Auth.CookieSecure,
		SameSite: "Lax",
	})
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// tokenResponse deliberately carries NO refresh token: the refresh token
// travels exclusively in the HttpOnly cookie.
type tokenResponse struct {
	AccessToken string     `json:"access_token"`
	ExpiresIn   int        `json:"expires_in"`
	User        *tokenUser `json:"user"`
}

type tokenUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// nilUUID is used as organization_id for org-less users (the column is
// NOT NULL UUID; there is no meaningful org to attribute the session to).
const nilUUID = "00000000-0000-0000-0000-000000000000"

// handleLogin verifies credentials, creates a rotating session family and
// answers with the access JWT in the body + the refresh cookie. The audit
// trail records every attempt (§7/§85).
func (a *App) handleLogin(c *fiber.Ctx) error {
	var req loginRequest
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid JSON body")
	}
	if req.Email == "" || req.Password == "" {
		return BadRequest("email and password are required")
	}
	ctx := Context(c)
	user, err := a.svc.Users.ByEmail(ctx, req.Email)
	if err != nil && !errors.Is(err, pg.ErrNotFound) {
		// A user-store outage must NOT read as "invalid credentials"
		// — that would tell clients the credentials were wrong and
		// lock real users out while the DB recovers.
		a.svc.Log.Error("login user lookup failed", "err", err)
		return Unavailable("user store unavailable; try again shortly")
	}
	if err != nil || user == nil {
		a.svc.AuditService.Entry(ctx, "", "", audit.ActionLogin, "user:"+req.Email, c.IP(), "", "denied", nil)
		return Unauthorized("invalid credentials")
	}
	if user.Disabled || !auth.VerifyPassword(req.Password, user.PasswordHash) {
		a.svc.AuditService.Entry(ctx, "", user.ID, audit.ActionLogin, "user:"+user.ID, c.IP(), "", "denied", nil)
		return Unauthorized("invalid credentials")
	}
	orgs, _ := a.svc.Memberships.OrgsFor(ctx, user.ID)
	role := domain.RoleViewer
	var orgID string
	if len(orgs) > 0 {
		orgID = orgs[0].ID
		if r, err := a.svc.Memberships.RoleFor(ctx, user.ID, orgID); err == nil {
			role = r
		}
	}
	if orgID == "" {
		// sessions.organization_id is NOT NULL UUID; org-less users get
		// the nil UUID rather than a failing insert.
		orgID = nilUUID
	}
	perms := permStrings(auth.PermissionsFor(role))
	issuer := auth.NewTokenIssuer(a.svc.Cfg.Auth.JWTSecret, a.svc.Cfg.Auth.AccessTokenTTL, a.svc.Cfg.Auth.RefreshTokenTTL)
	sessionID := uuid.NewString()
	access, err := issuer.IssueAccess(user.ID, orgID, role, perms, sessionID)
	if err != nil {
		return Internal("token issuance failed")
	}
	refresh, err := auth.NewRefreshToken()
	if err != nil {
		return Internal("token issuance failed")
	}
	err = a.svc.Sessions.Create(ctx, sessionID, user.ID, orgID, hashRefresh(refresh), c.IP(), string(c.Request().Header.UserAgent()), time.Now().UTC().Add(a.svc.Cfg.Auth.RefreshTokenTTL))
	if err != nil {
		return Internal("session persistence failed")
	}
	_ = a.svc.Users.TouchLogin(ctx, user.ID)
	a.svc.AuditService.Entry(ctx, orgID, user.ID, audit.ActionLogin, "user:"+user.ID, c.IP(), "", "success", nil)
	a.setRefreshCookie(c, refresh)
	return c.JSON(tokenResponse{
		AccessToken: access,
		ExpiresIn:   int(a.svc.Cfg.Auth.AccessTokenTTL.Seconds()),
		User:        &tokenUser{ID: user.ID, Email: user.Email, Name: user.Name},
	})
}

func hashRefresh(s string) string {
	// Refresh tokens are stored hashed (never plaintext, §7).
	return sha256Sum(s)
}

// permStrings converts role permissions to wire form.
func permStrings(perms []domain.Permission) []string {
	out := make([]string, 0, len(perms))
	for _, p := range perms {
		out = append(out, string(p))
	}
	return out
}

// authorName resolves a display name for notes.
func (a *App) authorName(c *fiber.Ctx) string {
	claims := a.claimsFrom(c)
	if claims == nil {
		return ""
	}
	if u, err := a.svc.Users.ByID(Context(c), claims.Subject); err == nil && u != nil {
		return u.Name
	}
	return strings.SplitN(claims.Subject, "-", 2)[0]
}

// handleRefresh rotates the refresh token and issues a fresh access JWT.
//
// The refresh token arrives ONLY via the HttpOnly cookie (never a JSON
// body), so JavaScript can present but never read it. Rotation is anchored
// to the presented token's hash, which makes the multi-tab race safe: every
// tab shares one cookie jar, the first refresh rotates, the losers present
// the just-retired token inside the grace window and rotate forward again —
// everyone converges on the live row. A retired token presented after the
// grace window is reuse (theft indicator) and revokes the family.
//
// Authorization is re-resolved from the DATABASE (role/membership), never
// from client-presentable data — role downgrades and disabled accounts take
// effect on the next refresh, not after a 30-day token TTL.
func (a *App) handleRefresh(c *fiber.Ctx) error {
	if !requireXHR(c) {
		return Forbidden("missing " + xhrHeaderName + " header")
	}
	token := c.Cookies(a.refreshCookieName())
	if token == "" {
		return Unauthorized("not signed in")
	}
	hash := hashRefresh(token)
	ctx := Context(c)
	s, err := a.svc.Sessions.ByRefreshHash(ctx, hash)
	if errors.Is(err, pg.ErrNotFound) {
		s, err = a.svc.Sessions.ByRetiredHash(ctx, hash)
		if errors.Is(err, pg.ErrNotFound) {
			return Unauthorized("session expired or revoked")
		}
		if err != nil {
			a.svc.Log.Error("refresh session lookup failed", "err", err)
			return Unavailable("session store unavailable; try again shortly")
		}
		// The presented token is a retired one. Inside the grace window
		// this is the multi-tab race — rotate forward so the racing tab
		// gets its own successor and everyone converges (the rotation
		// retires the current token too, so no interleave strands a
		// tab). After the window this is REUSE: revoke the family and
		// force a login.
		if time.Now().UnixMilli()-s.RetiredAtMs > refreshRotationGrace.Milliseconds() {
			_ = a.svc.Sessions.Revoke(ctx, s.ID)
			a.svc.AuditService.Entry(ctx, s.OrganizationID, s.UserID, audit.ActionLogout, "user:"+s.UserID, c.IP(), "", "denied",
				map[string]any{"reason": "refresh token reuse detected; session family revoked"})
			return Unauthorized("session revoked")
		}
	}
	if err != nil {
		a.svc.Log.Error("refresh session lookup failed", "err", err)
		return Unavailable("session store unavailable; try again shortly")
	}
	// Fresh authorization: the session itself may be live, but its user
	// must still exist and be enabled.
	user, err := a.svc.Users.ByID(ctx, s.UserID)
	if errors.Is(err, pg.ErrNotFound) || (err == nil && user.Disabled) {
		_ = a.svc.Sessions.Revoke(ctx, s.ID)
		return Unauthorized("account disabled")
	}
	if err != nil {
		a.svc.Log.Error("refresh user lookup failed", "err", err)
		return Unavailable("user store unavailable; try again shortly")
	}
	role := domain.RoleViewer
	if s.OrganizationID != nilUUID {
		if r, rerr := a.svc.Memberships.RoleFor(ctx, s.UserID, s.OrganizationID); rerr == nil {
			role = r
		}
	}
	issuer := auth.NewTokenIssuer(a.svc.Cfg.Auth.JWTSecret, a.svc.Cfg.Auth.AccessTokenTTL, a.svc.Cfg.Auth.RefreshTokenTTL)
	access, err := issuer.IssueAccess(user.ID, s.OrganizationID, role, permStrings(auth.PermissionsFor(role)), s.ID)
	if err != nil {
		return Internal("token issuance failed")
	}
	newToken, err := auth.NewRefreshToken()
	if err != nil {
		return Internal("token issuance failed")
	}
	if err := persistRefreshRotation(ctx, a.svc.Sessions, s.ID, hash, newToken); err != nil {
		a.svc.Log.Error("refresh rotation failed", "err", err, "session", s.ID)
		return Unavailable("session store unavailable; try again shortly")
	}
	a.setRefreshCookie(c, newToken)
	return c.JSON(tokenResponse{
		AccessToken: access,
		ExpiresIn:   int(a.svc.Cfg.Auth.AccessTokenTTL.Seconds()),
		User:        &tokenUser{ID: user.ID, Email: user.Email, Name: user.Name},
	})
}

// handleLogout revokes the session family identified by the refresh cookie
// and clears the cookie. Idempotent: without a (valid) cookie it still
// clears the cookie and answers 204, so a stale client can always sign out.
func (a *App) handleLogout(c *fiber.Ctx) error {
	if !requireXHR(c) {
		return Forbidden("missing " + xhrHeaderName + " header")
	}
	ctx := Context(c)
	if token := c.Cookies(a.refreshCookieName()); token != "" {
		if s, err := a.svc.Sessions.ByRefreshHash(ctx, hashRefresh(token)); err == nil {
			_ = a.svc.Sessions.Revoke(ctx, s.ID)
			a.svc.AuditService.Entry(ctx, s.OrganizationID, s.UserID, audit.ActionLogout, "user:"+s.UserID, c.IP(), "", "success", nil)
		}
	}
	a.clearRefreshCookie(c)
	return c.SendStatus(204)
}

// handleMe returns the caller profile + org memberships.
func (a *App) handleMe(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if claims == nil {
		return Unauthorized("authentication required")
	}
	ctx := Context(c)
	user, err := a.svc.Users.ByID(ctx, claims.Subject)
	if err != nil || user == nil {
		return NotFound("user not found")
	}
	orgs, _ := a.svc.Memberships.OrgsFor(ctx, user.ID)
	type orgWithRole struct {
		domain.Organization
		Role domain.Role `json:"role"`
	}
	out := make([]orgWithRole, 0, len(orgs))
	for _, o := range orgs {
		role, _ := a.svc.Memberships.RoleFor(ctx, user.ID, o.ID)
		out = append(out, orgWithRole{Organization: o, Role: role})
	}
	return c.JSON(fiber.Map{
		"user":                    tokenUser{ID: user.ID, Email: user.Email, Name: user.Name},
		"organizations":           out,
		"current_organization_id": claims.OrganizationID,
	})
}

var _ = errors.New
