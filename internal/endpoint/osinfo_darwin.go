//go:build darwin

package endpoint

import (
	"github.com/shirou/gopsutil/v4/host"
)

// platformOSInfo reports the macOS product version via gopsutil
// (kern.osproductversion, e.g. "14.5"); the display name is the fixed
// "macOS" family label since Apple does not publish a longer product name.
func platformOSInfo() (family, name, version string) {
	family = "darwin"
	info, err := host.Info()
	if err != nil {
		return family, name, version
	}
	if v := info.PlatformVersion; v != "" {
		version = v
	}
	return family, "macOS", version
}
