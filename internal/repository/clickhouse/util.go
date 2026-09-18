package clickhouse

import (
	"encoding/json"
	"net"

	"github.com/google/uuid"
)

// mustUUID parses the standard UUID string form (dashes optional) into the
// google/uuid type. clickhouse-go maps uuid.UUID to ClickHouse's UUID column
// for query parameters and batch appends — a raw [16]byte is NOT recognized
// as a UUID by the driver (it degrades to Array(UInt8) and the server
// rejects comparisons against a UUID column).
func mustUUID(s string) uuid.UUID {
	var b [16]byte
	if s != "" {
		parseUUID(s, &b)
	}
	return uuid.UUID(b)
}

// uuidStr renders a UUID in canonical form; the zero UUID maps to "" (unset).
func uuidStr(b uuid.UUID) string {
	if b == uuid.Nil {
		return ""
	}
	return b.String()
}

// parseUUID parses the standard 8-4-4-4-12 form into dst.
func parseUUID(s string, dst *[16]byte) {
	hexNibble := func(c byte) byte {
		switch {
		case c >= '0' && c <= '9':
			return c - '0'
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10
		}
		return 0
	}
	i := 0
	for k := 0; k < len(s) && i < 32; k++ {
		c := s[k]
		if c == '-' {
			continue
		}
		if i%2 == 0 {
			dst[i/2] = hexNibble(c) << 4
		} else {
			dst[i/2] |= hexNibble(c)
		}
		i++
	}
}

// parseIP converts an IP string into the 16-byte IPv6 representation
// ClickHouse's IPv6 column expects (IPv4 mapped per RFC 4291). The driver
// accepts net.IP for IPv6 columns; empty/invalid maps to the all-zero
// address. A raw [16]byte would not be accepted by the driver.
func parseIP(s string) net.IP {
	if s == "" {
		return net.IPv6zero
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	return net.IPv6zero
}

// formatIP converts the wire format back to a display string. ClickHouse
// native decoding hands us a fixed string; parse defensively.
func formatIP(s string) string {
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	// 16 raw bytes encoded as a Go string
	if len(s) == 16 {
		ip := net.IP(s)
		return ip.String()
	}
	return s
}

func marshalJSON(v map[string]any) string {
	if len(v) == 0 {
		return ""
	}
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	// Cap payload metadata size; oversized raw payloads belong in object storage.
	const maxMeta = 16 * 1024
	if len(b) > maxMeta {
		b = b[:maxMeta]
	}
	return string(b)
}
