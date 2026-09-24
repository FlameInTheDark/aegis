package scanner

import (
	"strings"
	"testing"
)

// English Windows 11 output for `tracert -d -4 -h 8 -w 400 192.168.1.55`.
const tracertEN = "\r\n" +
	"Tracing route to 192.168.1.55 over a maximum of 8 hops\r\n" +
	"\r\n" +
	"  1     1 ms     1 ms     1 ms  192.168.1.1\r\n" +
	"  2     2 ms     1 ms     1 ms  10.0.0.2\r\n" +
	"  3     1 ms     1 ms     1 ms  192.168.1.55\r\n" +
	"\r\n" +
	"Trace complete.\r\n"

// German Windows: localized timeout wording AND localized trace header.
// The parser must still work — hop indices + IPv4 literals are locale-neutral.
const tracertDE = "\r\n" +
	"Route verfolgen zu 192.168.1.55 ueber maximal 8 Hops\r\n" +
	"\r\n" +
	"  1     1 ms     1 ms     1 ms  192.168.1.1\r\n" +
	"  2     *        *        *     Zeitueberschreitung der Anforderung.\r\n" +
	"  3     1 ms     <1 ms     1 ms  192.168.1.55\r\n" +
	"\r\n" +
	"Ablaufverfolgung beendet.\r\n"

func TestParseTracertEnglish(t *testing.T) {
	hops := parseTracert([]byte(tracertEN), "192.168.1.55")
	if len(hops) != 3 {
		t.Fatalf("want 3 hops, got %d: %+v", len(hops), hops)
	}
	if hops[0].TTL != 1 || hops[0].IP != "192.168.1.1" {
		t.Errorf("hop0 = %+v, want TTL 1 @ 192.168.1.1", hops[0])
	}
	if hops[1].IP != "10.0.0.2" || hops[2].IP != "192.168.1.55" {
		t.Errorf("path = %+v", hops)
	}
	if hops[0].RTTms != 1 {
		t.Errorf("hop0 rtt = %v, want 1", hops[0].RTTms)
	}
}

func TestParseTracertLocalizedTimeoutSkipped(t *testing.T) {
	hops := parseTracert([]byte(tracertDE), "192.168.1.55")
	// TTL 2 timed out (localized text, no address): the path keeps the gap.
	if len(hops) != 2 {
		t.Fatalf("want 2 usable hops, got %d: %+v", len(hops), hops)
	}
	if hops[0].IP != "192.168.1.1" || hops[1].IP != "192.168.1.55" {
		t.Errorf("path = %+v", hops)
	}
	if hops[1].TTL != 3 {
		t.Errorf("hop1 TTL = %d, want 3 (real hop index, not compacted)", hops[1].TTL)
	}
}

func TestParseTracertIgnoresHeaderAndSummary(t *testing.T) {
	hops := parseTracert([]byte(tracertEN), "192.168.1.55")
	for _, h := range hops {
		if strings.Contains(h.IP, "over") {
			t.Errorf("header leaked into hops: %+v", hops)
		}
	}
	// All-timeout trace: no route information at all -> empty (caller falls
	// through to the gateway guess).
	dead := "Tracing route to 10.9.9.9 over a maximum of 8 hops\r\n\r\n" +
		"  1     *        *        *     Request timed out.\r\n" +
		"  2     *        *        *     Request timed out.\r\n"
	if hops := parseTracert([]byte(dead), "10.9.9.9"); len(hops) != 0 {
		t.Errorf("want no hops for all-timeout trace, got %+v", hops)
	}
}

func TestParseTracertInvalidAddressSkipped(t *testing.T) {
	bad := "  1     1 ms     1 ms     1 ms  999.999.999.999\r\n" +
		"  2     1 ms     1 ms     1 ms  192.168.1.1\r\n"
	hops := parseTracert([]byte(bad), "192.168.1.1")
	if len(hops) != 1 || hops[0].IP != "192.168.1.1" {
		t.Errorf("want only the valid hop, got %+v", hops)
	}
}
