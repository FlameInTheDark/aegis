package httpx

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/gofiber/fiber/v2"
)

// ctxKey identifies request-scoped values.
type ctxKey string

const (
	ctxRequestID ctxKey = "request_id"
	ctxClaims    ctxKey = "claims"
)

// ClaimsFromCtx returns authenticated claims stored by the auth middleware.
func ClaimsFromCtx(c *fiber.Ctx) *auth.Claims {
	if v, ok := c.Locals(string(ctxClaims)).(*auth.Claims); ok {
		return v
	}
	return nil
}

// RequestIDFromCtx returns the middleware-assigned request ID.
func RequestIDFromCtx(c *fiber.Ctx) string {
	if v, ok := c.Locals(string(ctxRequestID)).(string); ok {
		return v
	}
	return ""
}

// Context returns a context.Context carrying tracing scope and request id.
func Context(c *fiber.Ctx) context.Context {
	ctx := c.UserContext()
	if ctx == nil {
		ctx = c.Context()
	}
	if rid := RequestIDFromCtx(c); rid != "" {
		ctx = context.WithValue(ctx, ctxRequestID, rid)
	}
	return ctx
}

// RequestID extracts a request id from a std context (used by workers).
func RequestID(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID).(string); ok {
		return v
	}
	return ""
}

// RateLimitBucket converts client IP + bucket name to a redis key suffix.
func RateLimitBucket(c *fiber.Ctx, bucket string) string {
	return bucket + ":" + c.IP()
}

// RequirePermission is a guard used by handlers after the auth middleware:
// it returns a ready-to-use HTTPError when the role lacks the permission.
func RequirePermission(c *fiber.Ctx, perm domain.Permission) *HTTPError {
	claims := ClaimsFromCtx(c)
	if claims == nil {
		return Unauthorized("authentication required")
	}
	if !auth.HasPermission(claims.Role, perm) {
		return Forbidden("insufficient role for " + string(perm))
	}
	return nil
}

// ParseSince parses common relative windows ("1h","24h","7d","30d").
func ParseSince(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || days <= 0 || days > 365 {
			return time.Time{}, fmt.Errorf("invalid range %q", s)
		}
		return time.Now().UTC().Add(-time.Duration(days) * 24 * time.Hour), nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		// RFC3339 fallback
		return time.Parse(time.RFC3339, s)
	}
	if d <= 0 || d > 365*24*time.Hour {
		return time.Time{}, fmt.Errorf("invalid range %q", s)
	}
	return time.Now().UTC().Add(-d), nil
}
