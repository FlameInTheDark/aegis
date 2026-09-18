package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/FlameInTheDark/aegis/internal/domain"
	"github.com/google/uuid"
)

func TestPasswordHashRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct-horse-battery", hash) {
		t.Fatal("correct password must verify")
	}
	if VerifyPassword("wrong-password", hash) {
		t.Fatal("wrong password must not verify")
	}
}

func TestPasswordTooShortRejected(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("passwords under 12 chars must be rejected")
	}
}

func TestHashesAreUnique(t *testing.T) {
	h1, _ := HashPassword("same-password-123")
	h2, _ := HashPassword("same-password-123")
	if h1 == h2 {
		t.Fatal("argon2id must produce unique salts (hashes differ)")
	}
}

func TestRBACMatrix(t *testing.T) {
	if !HasPermission(domain.RoleOwner, domain.PermOrgManage) {
		t.Fatal("owner manages org")
	}
	if HasPermission(domain.RoleViewer, domain.PermScanCreate) {
		t.Fatal("viewer cannot create scans")
	}
	if HasPermission(domain.RoleOperator, domain.PermScanElevated) {
		t.Fatal("operator cannot run elevated scans")
	}
	if !HasPermission(domain.RoleSecurityAnalyst, domain.PermFindingWrite) {
		t.Fatal("analyst triages findings")
	}
	if HasPermission(domain.RoleSecurityAnalyst, domain.PermOrgManage) {
		t.Fatal("analyst cannot manage org")
	}
	if !ValidRole(domain.RoleAdministrator) || ValidRole("superadmin") {
		t.Fatal("role validation broken")
	}
}

func TestGenerateToken(t *testing.T) {
	tok, err := GenerateToken("aeg_enroll")
	if err != nil || len(tok) < 20 {
		t.Fatalf("token generation failed: %v %q", err, tok)
	}
}

// NewRefreshToken must be opaque, high-entropy and unique: 256 bits of
// randomness, URL-safe, no structural claims, never repeated.
func TestNewRefreshToken(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		tok, err := NewRefreshToken()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(tok, "aeg_rt_") {
			t.Fatalf("refresh token missing prefix: %q", tok)
		}
		if strings.ContainsAny(tok, "+/=") {
			t.Fatalf("refresh token must be URL-safe: %q", tok)
		}
		if len(tok) < 40 {
			t.Fatalf("refresh token too short (%d): %q", len(tok), tok)
		}
		if seen[tok] {
			t.Fatalf("refresh token repeated: %q", tok)
		}
		seen[tok] = true
	}
}

// The access JWT carries the session id so revocation is traceable; the
// refresh token no longer is a JWT at all (opaque, cookie-only).
func TestIssueAccessSessionID(t *testing.T) {
	iss := NewTokenIssuer("test-secret-at-least-32-bytes-long!!", time.Minute, time.Hour)
	sid := uuid.NewString()
	access, err := iss.IssueAccess("user-1", "org-1", domain.RoleOwner, nil, sid)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := iss.ParseAccess(access)
	if err != nil {
		t.Fatal(err)
	}
	if claims.SessionID != sid {
		t.Fatalf("access sid %q != session id %q", claims.SessionID, sid)
	}
	if claims.Subject != "user-1" || claims.OrganizationID != "org-1" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

// Expired access tokens must fail validation (never resurrect).
func TestParseAccessExpired(t *testing.T) {
	iss := NewTokenIssuer("test-secret-at-least-32-bytes-long!!", -time.Minute, time.Hour)
	access, err := iss.IssueAccess("user-1", "org-1", domain.RoleViewer, nil, uuid.NewString())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.ParseAccess(access); err == nil {
		t.Fatal("expired access token must not validate")
	}
}
