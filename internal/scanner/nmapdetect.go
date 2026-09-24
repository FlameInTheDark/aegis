package scanner

import (
	"os"
	"os/exec"
	"runtime"
)

// DetectNmapPath locates an nmap binary on this host: PATH first (the
// standard case), then the common install locations that fall outside a
// service's default PATH (Linux sbin dirs, macOS Homebrew/MacPorts,
// Windows Program Files). Returns "" when nothing is found — the caller
// decides whether that means a fallback (simulated engine) or an error.
//
// Shared by the embedded scanner (cmd/scanner) and the aegis-connector
// scanner role so both resolve the engine identically.
func DetectNmapPath() string {
	if p, err := exec.LookPath("nmap"); err == nil && p != "" {
		return p
	}
	candidates := []string{
		"/usr/bin/nmap", "/usr/local/bin/nmap", "/sbin/nmap", "/usr/sbin/nmap",
		"/opt/homebrew/bin/nmap", "/opt/local/bin/nmap",
	}
	if runtime.GOOS == "windows" {
		candidates = []string{
			`C:\Program Files\Nmap\nmap.exe`,
			`C:\Program Files (x86)\Nmap\nmap.exe`,
		}
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}
