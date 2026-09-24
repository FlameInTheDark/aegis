package connectorapp

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// serviceUnit is the systemd unit name.
const serviceUnit = "aegis-connector.service"

const unitTemplate = `[Unit]
Description=Aegis Connector (%s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s start --config %s
Restart=always
RestartSec=5
User=%s
# The credential file carries the connector secret.
UMask=0077
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`

// InstallService installs and starts a systemd service running
// `aegis-connector start --config <cfgPath>`. Requires root (or sudo) and
// systemd; other platforms receive manual instructions.
func InstallService(cfgPath string) error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic service installation requires systemd (linux); manual instructions:\n\n"+""+
			"  macOS (launchd): create ~/Library/LaunchAgents/com.aegis.connector.plist with\n"+
			"    ProgramArguments: [<binary>, start, --config, %s]\n"+
			"    RunAtLoad: true, KeepAlive: true\n"+
			"  Windows: schtasks /create /tn AegisConnector /tr \"<binary> start --config %s\" /sc onstart /ru SYSTEM", cfgPath, cfgPath)
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		return fmt.Errorf("systemd not detected; run `aegis-connector start --config %s` under your supervisor of choice", cfgPath)
	}
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve binary path: %w", err)
	}
	exe, err = filepath.Abs(exe)
	if err != nil {
		return err
	}
	user := os.Getenv("SUDO_USER")
	if user == "" {
		user = "root"
	}
	unit := fmt.Sprintf(unitTemplate, cfgPath, exe, cfgPath, user)
	unitPath := filepath.Join("/etc/systemd/system", serviceUnit)
	if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
		return fmt.Errorf("write %s: %w (root required)", unitPath, err)
	}
	for _, args := range [][]string{
		{"daemon-reload"},
		{"enable", serviceUnit},
		{"restart", serviceUnit},
	} {
		cmd := exec.Command("systemctl", args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("systemctl %s: %w", strings.Join(args, " "), err)
		}
	}
	fmt.Printf("service installed and started: %s (unit: %s)\n", unitPath, serviceUnit)
	return nil
}

// UninstallService stops and removes the systemd service.
func UninstallService() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("automatic service uninstallation requires systemd (linux)")
	}
	unitPath := filepath.Join("/etc/systemd/system", serviceUnit)
	for _, args := range [][]string{
		{"disable", "--now", serviceUnit},
	} {
		cmd := exec.Command("systemctl", args...)
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		_ = cmd.Run() // best effort: unit may not exist
	}
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	cmd := exec.Command("systemctl", "daemon-reload")
	_ = cmd.Run()
	fmt.Println("service removed:", unitPath)
	return nil
}
