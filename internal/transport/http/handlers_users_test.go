package httpx

import (
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/auth"
	"github.com/gofiber/fiber/v2"
)

// The HTTP password policy and the argon2id hasher are two layers that MUST
// agree on one minimum. Before the unification the policy accepted 10 while
// HashPassword demanded 12, so a 10- or 11-character password passed the
// handler and died inside HashPassword as an opaque hash error. These tests
// pin the shared boundary: reject below 12 at the handler, hash at 12.
func TestPasswordPolicyRejectsBelowTwelve(t *testing.T) {
	for _, pw := range []string{
		strings.Repeat("a", 10),
		strings.Repeat("a", 11),
	} {
		err := passwordPolicy(pw)
		if err == nil {
			t.Fatalf("passwordPolicy(%d chars) = nil, want 400 error", len(pw))
		}
		fe, ok := err.(*fiber.Error)
		if !ok {
			t.Fatalf("passwordPolicy(%d chars) = %T, want *fiber.Error", len(pw), err)
		}
		if fe.Code != fiber.StatusBadRequest {
			t.Fatalf("passwordPolicy(%d chars) code = %d, want %d", len(pw), fe.Code, fiber.StatusBadRequest)
		}
		if !strings.Contains(fe.Message, "12") {
			t.Fatalf("message %q should state the 12-character minimum", fe.Message)
		}
	}
}

func TestPasswordPolicyAcceptsTwelve(t *testing.T) {
	if err := passwordPolicy(strings.Repeat("a", 12)); err != nil {
		t.Fatalf("passwordPolicy(12 chars) = %v, want nil", err)
	}
	if err := passwordPolicy(strings.Repeat("a", 128)); err != nil {
		t.Fatalf("passwordPolicy(128 chars) = %v, want nil", err)
	}
}

// A password accepted by the policy must be accepted by the hasher — the
// contract that was broken when the two layers disagreed.
func TestPolicyAcceptedPasswordHashes(t *testing.T) {
	pw := strings.Repeat("x", 12)
	if err := passwordPolicy(pw); err != nil {
		t.Fatalf("policy rejected a 12-character password: %v", err)
	}
	if _, err := auth.HashPassword(pw); err != nil {
		t.Fatalf("HashPassword rejected a 12-character password: %v", err)
	}
	// And the boundary really is shared: one below fails at BOTH layers.
	short := strings.Repeat("x", 11)
	if passwordPolicy(short) == nil {
		t.Fatal("policy accepted an 11-character password")
	}
	if _, err := auth.HashPassword(short); err == nil {
		t.Fatal("HashPassword accepted an 11-character password")
	}
}
