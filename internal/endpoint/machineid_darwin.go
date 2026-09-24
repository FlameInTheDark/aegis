//go:build darwin

package endpoint

import (
	"os/exec"
	"strings"
)

// platformMachineID parses the IOPlatformUUID from ioreg (best-effort;
// errors fall through to the hostname fallback).
func platformMachineID() string {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if i := strings.Index(line, `"IOPlatformUUID" = "`); i >= 0 {
			v := line[i+len(`"IOPlatformUUID" = "`):]
			if j := strings.Index(v, `"`); j >= 0 {
				return v[:j]
			}
		}
	}
	return ""
}
