//go:build windows

package endpoint

import (
	"golang.org/x/sys/windows/registry"
)

// platformOSInfo reads the real Windows edition, release and build from
// HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion: ProductName
// ("Windows 11 Pro"), DisplayVersion ("24H2", falling back to the legacy
// ReleaseId) and CurrentBuildNumber with the UBR update revision
// ("26100.2894"). The connector is a 64-bit binary, so the native registry
// view is read — no WOW64 redirection applies. Values are best-effort: a
// missing key yields an empty field, never an error that would block
// inventory.
func platformOSInfo() (family, name, version string) {
	family = "windows"
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return family, name, version
	}
	defer k.Close()
	product := getStringValue(k, "ProductName")
	display := getStringValue(k, "DisplayVersion")
	if display == "" {
		display = getStringValue(k, "ReleaseId")
	}
	build := getStringValue(k, "CurrentBuildNumber")
	ubr, hasUBR := getIntegerValue(k, "UBR")
	name, version = composeWindowsOS(product, display, build, ubr, hasUBR)
	return family, name, version
}

func getStringValue(k registry.Key, name string) string {
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

func getIntegerValue(k registry.Key, name string) (uint64, bool) {
	v, _, err := k.GetIntegerValue(name)
	return v, err == nil
}
