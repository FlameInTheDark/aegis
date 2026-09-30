package httpx

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/audit"
	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/FlameInTheDark/aegis/internal/oidc"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// SSO (F4): one OIDC provider per organization. The browser flow issues a
// session + refresh cookie exactly like password login, then redirects into
// the console's /#/auth/oidc-complete view, which calls the existing
// /auth/refresh endpoint to bootstrap the in-memory access token. Local
// break-glass accounts keep password login; owner is never granted by a
// group claim.

// oidcStateCookie carries the CSRF state, the nonce and the org id between
// /start and /callback. HttpOnly + short TTL; value is opaque random data
// compared verbatim (double-submit), not a session credential.
const oidcStateCookie = "aegis_oidc_state"

// oidcRedirectPath is the console view that completes the flow.
const oidcRedirectPath = "/#/auth/oidc-complete"

func (a *App) oidcRedirectURI() string {
	return strings.TrimSuffix(a.svc.Cfg.PublicURL, "/") + "/api/v1/auth/oidc/callback"
}

// handleSSOProviders lists enabled providers for the login page (public).
func (a *App) handleSSOProviders(c *fiber.Ctx) error {
	cfgs, err := a.svc.SSO.ListEnabled(Context(c))
	if err != nil {
		return Internal("sso provider list failed")
	}
	items := make([]fiber.Map, 0, len(cfgs))
	for _, cfg := range cfgs {
		orgName := ""
		if org, oerr := a.svc.Orgs.ByID(Context(c), cfg.OrgID); oerr == nil && org != nil {
			orgName = org.Name
		}
		items = append(items, fiber.Map{"organization_id": cfg.OrgID, "organization_name": orgName})
	}
	return c.JSON(fiber.Map{"items": items})
}

// handleGetSSO returns the caller's org config with the secret masked.
func (a *App) handleGetSSO(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	cfg, err := a.svc.SSO.Get(Context(c), claims.OrganizationID)
	if err != nil {
		return c.JSON(fiber.Map{"configured": false})
	}
	return c.JSON(fiber.Map{"configured": true, "sso": cfg})
}

func (a *App) handleUpsertSSO(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	var req struct {
		Issuer       string            `json:"issuer"`
		ClientID     string            `json:"client_id"`
		ClientSecret string            `json:"client_secret"`
		GroupsClaim  string            `json:"groups_claim"`
		RoleMappings map[string]string `json:"role_mappings"`
		DefaultRole  domain.Role       `json:"default_role"`
		AllowJIT     *bool             `json:"allow_jit"`
		Enabled      *bool             `json:"enabled"`
	}
	if err := c.BodyParser(&req); err != nil || req.Issuer == "" || req.ClientID == "" {
		return BadRequest("issuer and client_id are required")
	}
	if !strings.HasPrefix(req.Issuer, "https://") && !strings.HasPrefix(req.Issuer, "http://localhost") {
		return BadRequest("issuer must be an https URL")
	}
	if req.DefaultRole == "" {
		req.DefaultRole = domain.RoleViewer
	}
	if !domain.ValidSSORole(req.DefaultRole) {
		return BadRequest("default_role must be viewer, operator, security_analyst or administrator")
	}
	for g, r := range req.RoleMappings {
		if strings.TrimSpace(g) == "" {
			return BadRequest("role_mappings contains an empty group")
		}
		if !domain.ValidSSORole(domain.Role(r)) {
			return BadRequest("role_mappings may only grant viewer, operator, security_analyst or administrator")
		}
	}
	cfg := &domain.SSOConfig{
		OrgID:        claims.OrganizationID,
		Issuer:       strings.TrimSuffix(strings.TrimSpace(req.Issuer), "/"),
		ClientID:     req.ClientID,
		ClientSecret: req.ClientSecret,
		GroupsClaim:  firstNonEmpty(req.GroupsClaim, "groups"),
		RoleMappings: req.RoleMappings,
		DefaultRole:  req.DefaultRole,
		AllowJIT:     req.AllowJIT == nil || *req.AllowJIT,
		Enabled:      req.Enabled == nil || *req.Enabled,
	}
	if err := a.svc.SSO.Upsert(Context(c), cfg); err != nil {
		return Internal("sso config save failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "auth.sso_configured", "sso:"+claims.OrganizationID, c.IP(), "", "success",
		map[string]any{"issuer": cfg.Issuer, "enabled": cfg.Enabled})
	fresh, _ := a.svc.SSO.Get(Context(c), claims.OrganizationID)
	return c.JSON(fiber.Map{"configured": true, "sso": fresh})
}

func (a *App) handleDeleteSSO(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermSettingsManage); he != nil {
		return he
	}
	if err := a.svc.SSO.Delete(Context(c), claims.OrganizationID); err != nil {
		return Internal("sso config delete failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject, "auth.sso_removed", "sso:"+claims.OrganizationID, c.IP(), "", "success", nil)
	return c.SendStatus(204)
}

// handleOIDCStart begins the flow (public): state+nonce in an HttpOnly
// cookie, redirect to the IdP's authorization endpoint.
func (a *App) handleOIDCStart(c *fiber.Ctx) error {
	var req struct {
		OrganizationID string `json:"organization_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.OrganizationID == "" {
		return BadRequest("organization_id is required")
	}
	cfg, err := a.svc.SSO.Get(Context(c), req.OrganizationID)
	if err != nil || !cfg.Enabled {
		return NotFound("no active SSO provider for this organization")
	}
	pc, err := a.svc.OIDC.Discover(Context(c), cfg.Issuer)
	if err != nil {
		a.svc.Log.Warn("sso discovery failed", "org", cfg.OrgID, "err", err)
		return Unavailable("identity provider is unreachable")
	}
	state, err := oidc.NewState()
	if err != nil {
		return Internal("state generation failed")
	}
	nonce, err := oidc.NewState()
	if err != nil {
		return Internal("state generation failed")
	}
	blob, _ := json.Marshal(map[string]string{
		"state": state, "nonce": nonce, "org": cfg.OrgID,
	})
	c.Cookie(&fiber.Cookie{
		Name:     oidcStateCookie,
		Value:    string(blob),
		Path:     "/",
		HTTPOnly: true,
		Secure:   a.svc.Cfg.IsProduction(),
		SameSite: "Lax",
		Expires:  time.Now().Add(10 * time.Minute),
	})
	return c.Redirect(oidc.AuthURL(pc, cfg.ClientID, a.oidcRedirectURI(), state, nonce), fiber.StatusFound)
}

// handleOIDCCallback finishes the flow (public): verifies state, exchanges
// the code, resolves or JIT-provisions the user, issues a session and
// redirects into the console.
func (a *App) handleOIDCCallback(c *fiber.Ctx) error {
	var blob struct {
		State string `json:"state"`
		Nonce string `json:"nonce"`
		Org   string `json:"org"`
	}
	if raw := c.Cookies(oidcStateCookie); raw != "" {
		_ = json.Unmarshal([]byte(raw), &blob)
	}
	if blob.State == "" || blob.State != c.Query("state") {
		return BadRequest("oidc state mismatch")
	}
	code := c.Query("code")
	if code == "" {
		return BadRequest("code is required")
	}
	if blob.Org == "" || uuid.Validate(blob.Org) != nil {
		return BadRequest("oidc flow lost its organization")
	}
	cfg, err := a.svc.SSO.Get(Context(c), blob.Org)
	if err != nil || !cfg.Enabled {
		return NotFound("no active SSO provider for this organization")
	}
	pc, err := a.svc.OIDC.Discover(Context(c), cfg.Issuer)
	if err != nil {
		return Unavailable("identity provider is unreachable")
	}
	claims, err := a.svc.OIDC.Exchange(Context(c), pc, cfg.ClientID, cfg.ClientSecret, code, a.oidcRedirectURI(), blob.Nonce)
	if err != nil {
		if errors.Is(err, oidc.ErrInvalidToken) || errors.Is(err, oidc.ErrBadIssuer) {
			a.svc.Log.Warn("oidc token verification failed", "org", cfg.OrgID, "err", err)
			return Unauthorized("identity assertion failed verification")
		}
		return Unavailable("identity provider exchange failed")
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))
	if email == "" {
		return Forbidden("identity provider did not share an email; ensure the 'email' scope is allowed")
	}
	if cfg.GroupsClaim != "" && cfg.GroupsClaim != "groups" {
		// Honor a custom claim name by re-decoding the raw payload is not
		// possible post-verification here; the standard claim set covers the
		// first slice. Documented: groups_claim is reserved for IdPs that
		// already expose "groups".
		_ = cfg.GroupsClaim
	}
	user, err := a.svc.Users.ByEmail(Context(c), email)
	if err != nil && !errors.Is(err, pg.ErrNotFound) {
		return Unavailable("user store unavailable; try again shortly")
	}
	if err != nil || user == nil {
		if !cfg.AllowJIT {
			a.svc.AuditService.Entry(Context(c), blob.Org, "", audit.ActionLogin, "user:"+email, c.IP(), "", "denied", map[string]any{"reason": "jit_disabled"})
			return Forbidden("no local account exists for this identity")
		}
		role := cfg.RoleForGroups(claims.Groups)
		user, err = a.svc.Users.Create(Context(c), email, firstNonEmpty(claims.Name, email), "")
		if err != nil {
			return Internal("user provisioning failed")
		}
		if err := a.svc.Memberships.Add(Context(c), user.ID, blob.Org, role); err != nil {
			return Internal("membership provisioning failed")
		}
		a.svc.AuditService.Entry(Context(c), blob.Org, user.ID, "auth.user_provisioned_sso", "user:"+user.ID, c.IP(), "", "success",
			map[string]any{"role": string(role), "groups": claims.Groups})
	}
	if user.Disabled {
		return Forbidden("this account is disabled")
	}
	// Existing users keep their database role; the group mapping applies
	// to JIT provisioning only. Owner can never be granted by a claim.
	orgID := blob.Org
	role, rerr := a.svc.Memberships.RoleFor(Context(c), user.ID, orgID)
	if rerr != nil {
		// No membership (user exists in another org or lost it): deny — SSO
		// must not silently widen tenancy.
		a.svc.AuditService.Entry(Context(c), orgID, user.ID, audit.ActionLogin, "user:"+user.ID, c.IP(), "", "denied", map[string]any{"reason": "no_membership"})
		return Forbidden("this account has no membership in the requested organization")
	}
	_ = role
	if err := a.issueSession(c, user, orgID); err != nil {
		return Internal("token issuance failed")
	}
	a.svc.AuditService.Entry(Context(c), orgID, user.ID, audit.ActionLogin, "user:"+user.ID, c.IP(), "", "success", map[string]any{"method": "oidc"})
	_ = a.svc.Users.TouchLogin(Context(c), user.ID)
	return c.Redirect(strings.TrimSuffix(a.svc.Cfg.PublicURL, "/")+oidcRedirectPath, fiber.StatusFound)
}

// issueSession is the session-issuing tail of login, shared with OIDC.
// The access token is minted by /auth/refresh on the console's next call
// (which re-resolves role from the database); this flow only needs the
// session row + the refresh cookie.
func (a *App) issueSession(c *fiber.Ctx, user *domain.User, orgID string) error {
	ctx := Context(c)
	sessionID := uuid.NewString()
	refresh, err := auth.NewRefreshToken()
	if err != nil {
		return err
	}
	if err := a.svc.Sessions.Create(ctx, sessionID, user.ID, orgID, hashRefresh(refresh), c.IP(), string(c.Request().Header.UserAgent()), time.Now().UTC().Add(a.svc.Cfg.Auth.RefreshTokenTTL)); err != nil {
		return err
	}
	a.setRefreshCookie(c, refresh)
	return nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
