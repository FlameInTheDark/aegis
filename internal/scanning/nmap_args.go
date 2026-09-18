package scanning

import (
	"fmt"
	"strconv"
	"strings"
)

// allowNmapValue flags that take one value argument, and the shape that
// value may take. Everything not listed here — most importantly --script,
// -iL, --script-file, --datadir, --excludefile, --resume — is rejected:
// custom presets extend tuning knobs (timing, rate, port selection), never
// pull in external files or NSE script classes beyond the platform's own
// safe-NSE gating.
var allowNmapValue = map[string]func(v string) error{
	"--max-rate": positiveInt,
	"--min-rate": positiveInt,
	"--max-retries": func(v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 || n > 10 {
			return fmt.Errorf("--max-retries wants 0..10, got %q", v)
		}
		return nil
	},
	"--top-ports": positiveInt,
	"-p":          portSpec,
}

// allowNmapBool flags that stand alone (no value).
var allowNmapBool = map[string]bool{
	"-T1": true, "-T2": true, "-T3": true, "-T4": true, "-T5": true,
	"-F": true, "-Pn": true, "-n": true,
	"--system-dns":           true,
	"--defeat-rst-ratelimit": true,
	"--disable-arp-ping":     true,
	"--send-eth":             true,
	"--send-ip":              true,
	"--unprivileged":         true,
}

func positiveInt(v string) error {
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 || n > 1_000_000 {
		return fmt.Errorf("want a positive integer, got %q", v)
	}
	return nil
}

// portSpec accepts nmap port specifications made of digits, '-', ',' and the
// T:/U: protocol prefixes — e.g. "80,443", "1-65535", "T:9100,U:161".
func portSpec(v string) error {
	if v == "" {
		return fmt.Errorf("port spec must not be empty")
	}
	if len(v) > 200 {
		return fmt.Errorf("port spec too long")
	}
	for _, r := range v {
		ok := (r >= '0' && r <= '9') || r == '-' || r == ',' || r == 'T' || r == 'U' || r == ':'
		if !ok {
			return fmt.Errorf("invalid character %q in port spec", string(r))
		}
	}
	return nil
}

// ValidateNmapArgs allowlist-checks the extra arguments of a custom preset.
// Tokens are checked pairwise (flag + value); anything unrecognized is
// rejected with a message naming the offending token. This runs at preset
// create/update time — the engine appends the stored slice verbatim.
func ValidateNmapArgs(args []string) error {
	for i := 0; i < len(args); i++ {
		tok := args[i]
		if tok == "" {
			return fmt.Errorf("empty argument token")
		}
		if checker, ok := allowNmapValue[tok]; ok {
			if i+1 >= len(args) {
				return fmt.Errorf("%s requires a value", tok)
			}
			if err := checker(args[i+1]); err != nil {
				return err
			}
			i++
			continue
		}
		if allowNmapBool[tok] {
			continue
		}
		// -T4 style timing flags are exact tokens; anything else (including
		// every --script* / -iL / --datadir form) falls through to rejection.
		return fmt.Errorf("unsupported nmap argument %q (allowed: %s)",
			tok, strings.Join(append(sortedKeys(allowNmapValue), sortedBoolKeys()...), " "))
	}
	return nil
}

func sortedKeys(m map[string]func(string) error) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// small map: insertion order stability is not required for an error hint
	return out
}

func sortedBoolKeys() []string {
	out := make([]string, 0, len(allowNmapBool))
	for k := range allowNmapBool {
		out = append(out, k)
	}
	return out
}
