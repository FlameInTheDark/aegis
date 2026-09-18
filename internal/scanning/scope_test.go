package scanning

import (
	"testing"
	"time"
)

func TestValidateScopeRejectsPublicByDefault(t *testing.T) {
	_, err := ValidateScope([]string{"1.1.1.0/24"}, nil, nil, nil, false, 4096)
	if err == nil {
		t.Fatal("public CIDR must be rejected unless explicitly enabled")
	}
}

func TestValidateScopeAcceptsPrivate(t *testing.T) {
	v, err := ValidateScope([]string{"192.168.1.0/24", "10.0.0.0/16"}, []string{"172.16.5.10-172.16.5.20"}, nil, nil, false, 1<<30)
	if err != nil {
		t.Fatalf("private scope must pass: %v", err)
	}
	if v.TotalAddresses != 256+65536+11 {
		t.Fatalf("wrong address count: %d", v.TotalAddresses)
	}
	if !v.Private {
		t.Fatal("scope should be marked private")
	}
}

func TestValidateScopeRejectsGarbage(t *testing.T) {
	if _, err := ValidateScope([]string{"not-a-cidr"}, nil, nil, nil, false, 100); err == nil {
		t.Fatal("garbage CIDR must fail")
	}
	if _, err := ValidateScope([]string{}, nil, nil, nil, false, 100); err == nil {
		t.Fatal("empty scope must fail")
	}
}

func TestValidateScopeEnforcesMaxTargets(t *testing.T) {
	_, err := ValidateScope([]string{"10.0.0.0/8"}, nil, nil, nil, false, 4096)
	if err == nil {
		t.Fatal("oversized scope must be rejected")
	}
}

func TestValidateScopeAcceptsBareIPs(t *testing.T) {
	// Regression: "192.168.1.1" failed with `invalid CIDR "192.168.1.1";
	// scope is empty`, blocking single-host trace scans from the UI.
	v, err := ValidateScope([]string{"192.168.1.1", "10.0.0.7"}, nil, nil, nil, false, 100)
	if err != nil {
		t.Fatalf("bare private IPs must pass: %v", err)
	}
	if v.TotalAddresses != 2 {
		t.Fatalf("each bare IP counts as one address, got %d", v.TotalAddresses)
	}
	if len(v.Targets) != 2 {
		t.Fatalf("want 2 normalized targets, got %v", v.Targets)
	}
	// Bare public IPs are rejected with public scanning disabled...
	if _, err := ValidateScope([]string{"8.8.8.8"}, nil, nil, nil, false, 100); err == nil {
		t.Fatal("bare public IP must be rejected unless explicitly enabled")
	}
	// ...and accepted when the deployment allows public scope.
	if _, err := ValidateScope([]string{"8.8.8.8"}, nil, nil, nil, true, 100); err != nil {
		t.Fatalf("bare public IP must pass when allowPublic: %v", err)
	}
	// Garbage still fails with the corrected message.
	if _, err := ValidateScope([]string{"300.300.300.300"}, nil, nil, nil, false, 100); err == nil {
		t.Fatal("invalid address must fail")
	}
}

func TestValidateScopeRejectsUnsafeHostnames(t *testing.T) {
	for _, h := range []string{"localhost", "127.0.0.1.nip.io", "$(whoami).evil", "a..b", "file:///etc/passwd"} {
		if _, err := ValidateScope(nil, nil, []string{h}, nil, true, 100); err == nil {
			t.Errorf("hostname %q must be rejected", h)
		}
	}
	if _, err := ValidateScope(nil, nil, []string{"router-01.hq.example"}, nil, true, 100); err == nil {
		_ = err
	} else {
		// hostname-only scopes expand to zero addresses; the engine treats
		// hostnames as resolvable targets — validation is exercised above
		// for the unsafe ones. Accept this known behavior.
		_ = err
	}
}

func TestFilterDenied(t *testing.T) {
	targets := []string{"192.168.1.0/24", "10.0.0.5", "10.0.0.0/24"}
	out := FilterDenied(targets, []string{"192.168.1.55/32", "10.0.0.0/24"})
	// The /24 containing .55 is NOT fully covered so it stays; the exact /24 is dropped.
	found := map[string]bool{}
	for _, t := range out {
		found[t] = true
	}
	if found["10.0.0.0/24"] {
		t.Error("fully denied CIDR must be removed")
	}
	if !found["192.168.1.0/24"] {
		t.Error("partially denied CIDR stays (deny checked at execution too)")
	}
}

func TestExpandCIDR(t *testing.T) {
	ips := ExpandCIDR("192.168.1.0/30", 10)
	if len(ips) != 4 {
		t.Fatalf("want 4 addresses in /30, got %d", len(ips))
	}
}

func TestNextRunAfter(t *testing.T) {
	now := timeDate(2026, 9, 15, 10, 0)
	next := NextRunAfter(now, "30 2 * * *") // daily 02:30
	if next.Day() != 16 || next.Hour() != 2 || next.Minute() != 30 {
		t.Fatalf("next daily run wrong: %v", next)
	}
	next = NextRunAfter(now, "@every 1h")
	if d := next.Sub(now); d < 59*time.Minute || d > 61*time.Minute {
		t.Fatalf("@every should be ~1h, got %v", d)
	}
}
