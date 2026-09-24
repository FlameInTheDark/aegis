package httpx

import (
	"context"
	"encoding/json"
	"time"

	"github.com/FlameInTheDark/aegis/internal/connectors"
	"github.com/FlameInTheDark/aegis/internal/domain"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
)

// ---------------------------------------------------------------------------
// External connections (unified connector registry)
//
// Every externally connected component — endpoint agents, remote scanners,
// external collectors — is created here and receives a one-time connect
// command:
//
//      aegis-connector --connect <host>:<port>/<token>
//
// The component enrolls over gRPC (aegis.connector.v1), the token is
// burned, and continued connections use the issued long-lived secret.
// Configuration pushed from here is hot-reloaded by live components.
// A connection performing the agent function additionally binds ONE
// endpoint device (BindDevice); that device is part of these views —
// there is no separate device registry.

type connectorView struct {
	*domain.Connector
	Online bool `json:"online"`
	// ConnState is the heartbeat-derived liveness: online, shutting_down
	// (graceful stop announced, inside the grace window) or offline.
	ConnState string `json:"conn_state"`
	// Device is the endpoint bound to this connection (nil when none —
	// e.g. scanner-only connections).
	Device *deviceView `json:"device,omitempty"`
}

func connectorViewFor(c *domain.Connector) connectorView {
	state := c.ConnState(time.Now().UTC())
	return connectorView{Connector: c, Online: state == domain.ConnStateOnline, ConnState: state}
}

// deviceView is the endpoint-device summary embedded in connector views.
type deviceView struct {
	ID          string `json:"id"`
	AssetID     string `json:"asset_id,omitempty"`
	Hostname    string `json:"hostname"`
	Platform    string `json:"platform,omitempty"`
	PlatformVer string `json:"platform_version,omitempty"`
	Arch        string `json:"arch,omitempty"`
	Version     string `json:"version,omitempty"`
	Status      string `json:"status"`
	LastSeen    string `json:"last_seen,omitempty"`
}

// deviceViewFor projects a bound device record.
func deviceViewFor(d *domain.Agent) *deviceView {
	if d == nil {
		return nil
	}
	v := &deviceView{
		ID:          d.ID,
		Hostname:    d.Hostname,
		Platform:    d.Platform,
		PlatformVer: d.PlatformVer,
		Arch:        d.Arch,
		Version:     d.AgentVersion,
		Status:      d.Status,
		LastSeen:    d.LastSeen.UTC().Format(time.RFC3339),
	}
	if d.AssetID != nil {
		v.AssetID = *d.AssetID
	}
	return v
}

// boundDeviceFor returns the device bound to a connection, nil when the
// connection has none (or the service is unavailable).
func (a *App) boundDeviceFor(ctx context.Context, connectorID string) *deviceView {
	if a.svc.AgentsService == nil {
		return nil
	}
	dev, err := a.svc.AgentsService.Repo.ByConnector(ctx, connectorID)
	if err != nil || dev == nil || dev.Revoked {
		return nil
	}
	return deviceViewFor(dev)
}

// handleListConnectors GET /connectors?kind=
func (a *App) handleListConnectors(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	items, err := a.svc.ConnectorsService.List(ctx, claims.OrganizationID, c.Query("kind"))
	if err != nil {
		return BadRequest(err.Error())
	}
	out := make([]connectorView, 0, len(items))
	for _, it := range items {
		view := connectorViewFor(it)
		view.Device = a.boundDeviceFor(ctx, it.ID)
		out = append(out, view)
	}
	return c.JSON(fiber.Map{"items": out})
}

// handleCreateConnector POST /connectors
func (a *App) handleCreateConnector(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	var req connectors.CreateRequest
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	conn, tok, err := a.svc.ConnectorsService.Create(Context(c), claims.OrganizationID, claims.Subject, req)
	if err != nil {
		return BadRequest(err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"connector.created", "connector:"+conn.ID, c.IP(), "", "success",
		map[string]any{"kind": string(req.Kind), "name": req.Name})
	// The raw token rides in this response exactly once (never stored).
	return c.Status(201).JSON(fiber.Map{
		"connector":       conn,
		"token":           tok.Token,
		"expires_at":      tok.ExpiresAt,
		"connect_command": tok.Command,
	})
}

// handleGetConnector GET /connectors/:id
func (a *App) handleGetConnector(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	ctx := Context(c)
	conn, err := a.svc.ConnectorsService.Get(ctx, claims.OrganizationID, c.Params("id"))
	if err != nil {
		return NotFound("connection not found")
	}
	view := connectorViewFor(conn)
	view.Device = a.boundDeviceFor(ctx, conn.ID)
	return c.JSON(fiber.Map{"connector": view})
}

// handleUpdateConnector PATCH /connectors/:id (rename / re-site)
func (a *App) handleUpdateConnector(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	var req struct {
		Name   *string `json:"name"`
		SiteID *string `json:"site_id"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	fields := map[string]any{}
	if req.Name != nil {
		fields["name"] = *req.Name
	}
	if req.SiteID != nil {
		fields["site_id"] = *req.SiteID
	}
	if len(fields) == 0 {
		return BadRequest("nothing to update")
	}
	conn, err := a.svc.ConnectorsService.Update(Context(c), claims.OrganizationID, c.Params("id"), fields)
	if err != nil {
		if err == pg.ErrNotFound {
			return NotFound("connection not found")
		}
		return BadRequest(err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"connector.updated", "connector:"+conn.ID, c.IP(), "", "success", nil)
	return c.JSON(fiber.Map{"connector": conn})
}

// handleDeleteConnector DELETE /connectors/:id
func (a *App) handleDeleteConnector(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	ctx := Context(c)
	// Retire the bound endpoint device with the connection: the record
	// stays for audit but is marked revoked.
	if err := a.svc.AgentsService.RevokeForConnector(ctx, c.Params("id")); err != nil {
		a.svc.Log.Warn("bound device revoke failed", "connector", c.Params("id"), "err", err)
	}
	if err := a.svc.ConnectorsService.Delete(ctx, claims.OrganizationID, c.Params("id")); err != nil {
		if err == pg.ErrNotFound {
			return NotFound("connection not found")
		}
		return Internal("connection delete failed")
	}
	a.svc.AuditService.Entry(ctx, claims.OrganizationID, claims.Subject,
		"connector.deleted", "connector:"+c.Params("id"), c.IP(), "", "success", nil)
	return c.JSON(fiber.Map{"deleted": true})
}

// handleUpdateConnectorConfig PUT /connectors/:id/config
//
// Stores a new role configuration, bumps the version and pushes the
// update to every live watch stream (hot reload without restart).
func (a *App) handleUpdateConnectorConfig(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	var req struct {
		Config json.RawMessage `json:"config"`
	}
	if err := c.BodyParser(&req); err != nil {
		return BadRequest("invalid request body")
	}
	conn, _, err := a.svc.ConnectorsService.UpdateConfig(Context(c), claims.OrganizationID, c.Params("id"), req.Config)
	if err != nil {
		if err == pg.ErrNotFound {
			return NotFound("connection not found")
		}
		return BadRequest(err.Error())
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"connector.config_updated", "connector:"+conn.ID, c.IP(), "", "success",
		map[string]any{"config_version": conn.ConfigVersion})
	return c.JSON(fiber.Map{"connector": connectorViewFor(conn)})
}

// handleRotateConnectorToken POST /connectors/:id/enroll-token
//
// The UI "reconnect" flow: issues a fresh one-time token and renders the
// new connect command (used when the backend address changes, the secret
// is lost, or the component needs re-onboarding).
func (a *App) handleRotateConnectorToken(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	conn, tok, err := a.svc.ConnectorsService.RotateToken(Context(c), claims.OrganizationID, c.Params("id"), claims.Subject)
	if err != nil {
		if err == pg.ErrNotFound {
			return NotFound("connection not found")
		}
		return Internal("token rotation failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"connector.token_rotated", "connector:"+conn.ID, c.IP(), "", "success", nil)
	return c.Status(201).JSON(fiber.Map{
		"connector":       conn,
		"token":           tok.Token,
		"expires_at":      tok.ExpiresAt,
		"connect_command": tok.Command,
	})
}

// handleRevokeConnector POST /connectors/:id/revoke
func (a *App) handleRevokeConnector(c *fiber.Ctx) error {
	claims := a.claimsFrom(c)
	if he := a.requirePerm(c, domain.PermAgentManage); he != nil {
		return he
	}
	conn, err := a.svc.ConnectorsService.Revoke(Context(c), claims.OrganizationID, c.Params("id"))
	if err != nil {
		if err == pg.ErrNotFound {
			return NotFound("connection not found")
		}
		return Internal("connection revoke failed")
	}
	a.svc.AuditService.Entry(Context(c), claims.OrganizationID, claims.Subject,
		"connector.revoked", "connector:"+conn.ID, c.IP(), "", "success", nil)
	return c.JSON(fiber.Map{"connector": conn})
}
