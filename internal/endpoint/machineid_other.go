//go:build !windows && !darwin

package endpoint

// platformMachineID on Linux is covered by the flat-file list in
// machineid.go (/etc/machine-id et al.); nothing platform-specific left.
func platformMachineID() string { return "" }
