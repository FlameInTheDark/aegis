// Package auth provides password hashing, JWT issuing/validation,
// role-based access control and session management.
package auth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MiB
	argonThreads = 2
	argonKeyLen  = 32
	argonSaltLen = 16
)

// HashPassword derives an argon2id hash in PHC string format.
func HashPassword(password string) (string, error) {
	if len(password) < 12 {
		return "", errors.New("auth: password must be at least 12 characters")
	}
	salt := make([]byte, argonSaltLen)
	if err := fillRandom(salt); err != nil {
		return "", fmt.Errorf("auth: random salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads, b64(salt), b64(key)), nil
}

// VerifyPassword checks a password against a stored PHC hash.
// Parameters from the stored hash are honored to allow future upgrades.
func VerifyPassword(password, encoded string) bool {
	parts := splitPHC(encoded)
	if parts == nil || parts["algo"] != "argon2id" {
		return false
	}
	salt, err := unb64(parts["salt"])
	if err != nil {
		return false
	}
	want, err := unb64(parts["hash"])
	if err != nil {
		return false
	}
	var m, t, p uint32
	fmt.Sscanf(parts["params"], "m=%d,t=%d,p=%d", &m, &t, &p)
	if m == 0 || t == 0 || p == 0 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, t, m, uint8(p), uint32(len(want)))
	return subtleEqual(got, want)
}

// Claims are the JWT access token claims.
type Claims struct {
	OrganizationID string      `json:"org"`
	Role           domain.Role `json:"role"`
	Permissions    []string    `json:"perms,omitempty"`
	SessionID      string      `json:"sid"`
	jwt.RegisteredClaims
}

// TokenIssuer issues and validates platform JWTs.
//
// Access tokens are short-lived JWTs presented via the Authorization header.
// Refresh tokens are NOT JWTs — they are opaque high-entropy strings
// (NewRefreshToken) delivered in an HttpOnly cookie and stored server-side
// as SHA-256 hashes with per-refresh rotation (see the sessions table and
// handleRefresh). JavaScript never sees a refresh token.
type TokenIssuer struct {
	secret     []byte
	accessTTL  time.Duration
	refreshTTL time.Duration
	now        func() time.Time
}

func NewTokenIssuer(secret string, accessTTL, refreshTTL time.Duration) *TokenIssuer {
	return &TokenIssuer{secret: []byte(secret), accessTTL: accessTTL, refreshTTL: refreshTTL, now: time.Now}
}

// NewRefreshToken returns an opaque 256-bit URL-safe refresh token.
// Opaque-by-construction: no claims to leak, nothing to parse client-side;
// the server stores only its SHA-256 hash and rotates it on every use.
// RawURL base64 keeps the cookie value free of +/ and padding.
func NewRefreshToken() (string, error) {
	raw := make([]byte, 32)
	if err := fillRandom(raw); err != nil {
		return "", err
	}
	return "aeg_rt_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

// IssueAccess mints the short-lived access JWT bound to a user, org, role
// and session. The sid ties the token back to the sessions row so revocation
// (logout, password reset, reuse detection) is traceable in audit trails.
func (t *TokenIssuer) IssueAccess(userID, orgID string, role domain.Role, perms []string, sid string) (string, error) {
	now := t.now()
	access := jwt.NewWithClaims(jwt.SigningMethodHS256, &Claims{
		OrganizationID: orgID,
		Role:           role,
		Permissions:    perms,
		SessionID:      sid,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID,
			Issuer:    "aegis",
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(t.accessTTL)),
			ID:        uuid.NewString(),
		},
	})
	return access.SignedString(t.secret)
}

// ParseAccess validates an access token and returns its claims.
func (t *TokenIssuer) ParseAccess(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(tk *jwt.Token) (any, error) {
		if _, ok := tk.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", tk.Header["alg"])
		}
		return t.secret, nil
	})
	if err != nil || !tok.Valid {
		return nil, fmt.Errorf("auth: invalid token")
	}
	if claims.ExpiresAt != nil && t.now().After(claims.ExpiresAt.Time) {
		return nil, fmt.Errorf("auth: token expired")
	}
	return claims, nil
}

// AccessTTL / RefreshTTL expose lifetimes for cookie handling.
func (t *TokenIssuer) AccessTTL() time.Duration  { return t.accessTTL }
func (t *TokenIssuer) RefreshTTL() time.Duration { return t.refreshTTL }
