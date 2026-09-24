// Unit tests for CreateNetwork input validation. The rejection rules run
// before any repository call, so a zero-value Service exercises them without
// a database; exposure normalization is a pure helper tested directly.
package organizations

import (
	"context"
	"strings"
	"testing"
)

func TestNormalizeExposure(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr string
	}{
		{name: "empty defaults to internal_only", in: "", want: "internal_only"},
		{name: "blank defaults to internal_only", in: "   ", want: "internal_only"},
		{name: "internal_only accepted", in: "internal_only", want: "internal_only"},
		{name: "vpn_only accepted", in: "vpn_only", want: "vpn_only"},
		{name: "publicly_reachable accepted", in: "publicly_reachable", want: "publicly_reachable"},
		{name: "unknown accepted", in: "unknown", want: "unknown"},
		{name: "whitespace is trimmed", in: "  vpn_only  ", want: "vpn_only"},
		// The old settings dialog offered these values; the DB CHECK would
		// have rejected them with a 500 had the backend ever forwarded them.
		{name: "legacy dmz value rejected", in: "dmz", wantErr: "exposure must be one of"},
		{name: "legacy internet value rejected", in: "internet", wantErr: "exposure must be one of"},
		{name: "arbitrary value rejected", in: "exposed", wantErr: "exposure must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeExposure(tt.in)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("normalizeExposure(%q): expected error containing %q, got nil", tt.in, tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("normalizeExposure(%q): expected error containing %q, got %q", tt.in, tt.wantErr, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeExposure(%q): unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeExposure(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestCreateNetworkRejections drives the full service entry point with a
// zero-value Service: every rejection path below must fire before the
// (nil) Networks repo is touched, or the test panics — which is exactly
// the regression this guards against.
func TestCreateNetworkRejections(t *testing.T) {
	s := &Service{}
	ctx := context.Background()

	tests := []struct {
		name     string
		cidr     string
		gateway  string
		exposure string
		wantErr  string
	}{
		{name: "invalid cidr rejected", cidr: "192.168.1.1", exposure: "internal_only", wantErr: "valid CIDR"},
		{name: "bad gateway rejected", cidr: "10.0.0.0/24", gateway: "not-an-ip", exposure: "internal_only", wantErr: "valid IP"},
		{name: "invalid exposure rejected", cidr: "10.0.0.0/24", exposure: "dmz", wantErr: "exposure must be one of"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			net, err := s.CreateNetwork(ctx, "org", "site", tt.cidr, "", tt.gateway, tt.exposure, nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil (network %+v)", tt.wantErr, net)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}
