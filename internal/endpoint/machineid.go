// machineid.go discovers a stable per-machine identifier sent with the
// enrollment handshake (server-side diagnostics: detecting duplicate
// enrollments from the same box). Best-effort by design: if nothing native
// is available a deterministic hostname hash is used — documented, never a
// secret, never used for auth.
package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"strings"
	"sync"
)

// cachedMachineID computes the identifier once per process.
var cachedMachineID = sync.OnceValue(discoverMachineID)

// machineID returns the stable machine identifier (env override wins).
func machineID() string { return cachedMachineID() }

// discoverMachineID is the testable core: env override, then per-OS native
// identifiers, then a hostname-derived fallback.
func discoverMachineID() string {
	if v := strings.TrimSpace(os.Getenv("AEGIS_MACHINE_ID")); v != "" {
		return v
	}
	for _, p := range machineIDFiles() {
		if b, err := os.ReadFile(p); err == nil {
			if s := strings.TrimSpace(string(b)); s != "" {
				return s
			}
		}
	}
	if id := platformMachineID(); id != "" {
		return id
	}
	// Fallback: deterministic from hostname. Not a hardware identity, but
	// stable per machine and sufficient for duplicate-enrollment detection.
	host, _ := os.Hostname()
	sum := sha256.Sum256([]byte("aegis-machine:" + host))
	return hex.EncodeToString(sum[:16])
}

// machineIDFiles lists flat-file machine ids (first match wins).
func machineIDFiles() []string {
	return []string{
		"/etc/machine-id",
		"/var/lib/dbus/machine-id",
		"/sys/class/dmi/id/product_uuid",
	}
}
