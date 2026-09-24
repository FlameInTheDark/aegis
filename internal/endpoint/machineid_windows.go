//go:build windows

package endpoint

import (
	"os/exec"
	"strings"
)

// platformMachineID reads the Windows MachineGuid via `reg query`
// (no cgo, no extra dependency; best-effort — errors fall through to the
// hostname fallback in discoverMachineID).
func platformMachineID() string {
	out, err := exec.Command("reg", "query",
		`HKLM\SOFTWARE\Microsoft\Cryptography`, "/v", "MachineGuid").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "MachineGuid") {
			continue
		}
		if i := strings.LastIndex(line, " "); i >= 0 && i+1 < len(line) {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return ""
}
