package httpx

import (
	"context"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/auth"
	pg "github.com/FlameInTheDark/aegis/internal/repository/postgres"
	"github.com/gofiber/fiber/v2"
)

// ingestTokenPrefix is the machine-credential token family (F11): sensors
// authenticate with "Bearer aeg_evt_...". Hash-only storage; shown once.
const ingestTokenPrefix = "aeg_evt"

// ingestTouchTimeout bounds the fire-and-forget liveness write.
const ingestTouchTimeout = 10 * time.Second

// authenticateIngestToken validates a sensor ingest token (F11). Tokens are
// org-scoped machine credentials shown once at creation and stored only as
// SHA-256 hashes; the /ingest group exposes exactly one handler, so there
// are no role checks here — possession of a live token is the authority to
// push events into the token's own organization.
func (a *App) authenticateIngestToken() fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if len(header) < 8 || header[:7] != "Bearer " {
			return Unauthorized("missing or malformed Authorization header")
		}
		raw := strings.TrimSpace(header[7:])
		if !strings.HasPrefix(raw, ingestTokenPrefix+"_") {
			return Unauthorized("invalid ingest token")
		}
		tok, err := a.svc.IngestTokens.GetByHash(Context(c), pg.HashIngestToken(raw))
		if err != nil {
			return Unauthorized("invalid or revoked ingest token")
		}
		claims := &auth.Claims{OrganizationID: tok.OrgID}
		claims.Subject = "ingest-token:" + tok.ID
		c.Locals("claims", claims)
		c.Locals("ingest_token", tok)
		c.Locals("request_id", RequestIDFromCtx(c))
		// Sensor liveness for the setup panel; best-effort and unscoped.
		id := tok.ID
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), ingestTouchTimeout)
			defer cancel()
			a.svc.IngestTokens.TouchLastUsed(ctx, id)
		}()
		return c.Next()
	}
}
