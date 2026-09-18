package scanning

import (
	"net"
	"reflect"
	"testing"
)

// Ranges typed into the scan-form targets field (mixed with CIDRs) must
// validate and expand to CIDR blocks - the previous behavior rejected them
// with `invalid CIDR or IP \"192.168.1.1-192.168.1.27\"; scope is empty`.
func TestValidateScopeAcceptsIPRangesMixedIntoCIDRs(t *testing.T) {
	v, err := ValidateScope([]string{"192.168.1.1-192.168.1.27", "10.0.0.5"}, nil, nil, nil, false, 1<<30)
	if err != nil {
		t.Fatalf("range mixed into CIDR list must pass: %v", err)
	}
	if v.TotalAddresses != 28 {
		t.Fatalf("wrong address count: %d", v.TotalAddresses)
	}
	covered := 0
	for _, tgt := range v.Targets {
		ip, ipnet, err := net.ParseCIDR(tgt)
		if err != nil {
			if net.ParseIP(tgt) != nil {
				continue // bare IP target, added verbatim
			}
			t.Fatalf("target %q must be a CIDR or IP after expansion", tgt)
		}
		if ip.To4() == nil {
			t.Fatalf("unexpected v6 target %q", tgt)
		}
		ones, bits := ipnet.Mask.Size()
		covered += 1 << (bits - ones)
	}
	if covered != 27 {
		t.Fatalf("expanded CIDRs cover %d addresses, want 27", covered)
	}
	if !v.Private {
		t.Fatal("private range must keep scope private")
	}
}

func TestValidateScopeAcceptsShorthandRange(t *testing.T) {
	v, err := ValidateScope([]string{"172.16.5.10-20"}, nil, nil, nil, false, 1<<30)
	if err != nil {
		t.Fatalf("last-octet shorthand range must pass: %v", err)
	}
	if v.TotalAddresses != 11 {
		t.Fatalf("wrong address count: %d", v.TotalAddresses)
	}
}

func TestRangeToCIDRs(t *testing.T) {
	cases := []struct {
		lo, hi string
		want   []string
	}{
		{"192.168.1.5", "192.168.1.5", []string{"192.168.1.5/32"}},
		{"192.168.1.0", "192.168.1.255", []string{"192.168.1.0/24"}},
		{"10.0.0.0", "10.0.1.255", []string{"10.0.0.0/23"}},
		{"192.168.1.1", "192.168.1.27", []string{"192.168.1.1/32", "192.168.1.2/31", "192.168.1.4/30", "192.168.1.8/29", "192.168.1.16/29", "192.168.1.24/30"}},
	}
	for _, c := range cases {
		got := rangeToCIDRs(net.ParseIP(c.lo), net.ParseIP(c.hi))
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("rangeToCIDRs(%s, %s) = %v, want %v", c.lo, c.hi, got, c.want)
		}
	}
	// IPv6 range support.
	if got := rangeToCIDRs(net.ParseIP("fc00::1"), net.ParseIP("fc00::1")); !reflect.DeepEqual(got, []string{"fc00::1/128"}) {
		t.Fatalf("v6 single: %v", got)
	}
	// Reversed ranges are the caller's (parseRange's) problem; expansion of a
	// valid range must never produce blocks outside [lo, hi].
	lo, hi := net.ParseIP("10.9.4.7"), net.ParseIP("10.9.6.130")
	covered := 0
	for _, b := range rangeToCIDRs(lo, hi) {
		_, ipnet, err := net.ParseCIDR(b)
		if err != nil {
			t.Fatalf("bad block %q", b)
		}
		if !ipnet.Contains(lo) && !ipnet.Contains(hi) && !within(lo, hi, ipnet) {
			t.Fatalf("block %q escapes the range", b)
		}
		ones, bits := ipnet.Mask.Size()
		covered += 1 << (bits - ones)
	}
	if covered != 636 { // 0x682 - 0x407 + 1 = 636 addresses (6.130 - 4.7)
		t.Fatalf("coverage %d, want 636", covered)
	}
}

func within(lo, hi net.IP, ipnet *net.IPNet) bool {
	return compare16(lo, ipnet.IP) <= 0 && compare16(ipnetLast(ipnet), hi) <= 0
}

func compare16(a, b net.IP) int {
	x, y := a.To16(), b.To16()
	for i := 0; i < 16; i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func ipnetLast(n *net.IPNet) net.IP {
	l := make(net.IP, 16)
	base := n.IP.To16()
	copy(l, base)
	ones, bits := n.Mask.Size()
	hostBits := bits - ones
	for i := 0; i < hostBits; i++ {
		byteIdx := 15 - i/8
		l[byteIdx] |= byte(1) << uint(i%8)
	}
	return l
}
