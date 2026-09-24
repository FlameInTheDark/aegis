//go:build !linux && !windows && !darwin

package endpoint

import "runtime"

// platformOSInfo has no dedicated collector on other platforms; the Go
// target OS stands in for the family and the display fields stay empty so
// the report carries no invented data.
func platformOSInfo() (family, name, version string) {
	return runtime.GOOS, "", ""
}
