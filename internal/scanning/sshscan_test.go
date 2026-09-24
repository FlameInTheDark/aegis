package scanning

import (
	"context"
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/fingerprinting"
)

func TestParseDpkgQuery(t *testing.T) {
	out := `libc6:amd64|ii |2.35-0ubuntu3.8
openssh-server|ii |1:9.6p1-2+deb12u4
zlib1g:amd64|iU |1:1.2.11.dfsg-2
broken-line-no-separators
colbert|rc |1.0
libssl3:amd64|ii |3.0.2-0ubuntu1.15
`
	pkgs := ParseDpkgQuery(out)
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3: %+v", len(pkgs), pkgs)
	}
	byName := map[string]string{}
	for _, p := range pkgs {
		byName[p.Name] = p.Version
	}
	if byName["libc6"] != "2.35-0ubuntu3.8" {
		t.Errorf("libc6 wrong: %q", byName["libc6"])
	}
	if byName["openssh-server"] != "1:9.6p1-2+deb12u4" {
		t.Errorf("epoch version wrong: %q", byName["openssh-server"])
	}
	if _, ok := byName["colbert"]; ok {
		t.Error("rc-status package must be excluded")
	}
	if _, ok := byName["zlib1g"]; ok {
		t.Error("iU (partially configured) package must be excluded")
	}
	if _, ok := byName["broken-line-no-separators"]; ok {
		t.Error("malformed line must be skipped")
	}
}

func TestParseRpmQA(t *testing.T) {
	out := `curl|7.76.1-31.el9
bash|5.1.8-6.el9_1
glibc|2.34-60.el9
`
	pkgs := ParseRpmQA(out)
	if len(pkgs) != 3 {
		t.Fatalf("got %d, want 3", len(pkgs))
	}
	if pkgs[0].Name != "curl" || pkgs[0].Version != "7.76.1-31.el9" {
		t.Errorf("curl wrong: %+v", pkgs[0])
	}
}

func TestParseApkList(t *testing.T) {
	out := `zlib-1.2.13-r1 x86_64 {zlib} (Apache-2.0) [installed]
libxml2-2.11.5-r0 x86_64 {libxml2} (MIT) [installed]
alpine-baselayout-3.4.3-r1 x86_64 {alpine-baselayout} (GPL-2.0-only) [installed]
weird-line-without-enough-parts
`
	pkgs := ParseApkList(out)
	if len(pkgs) != 3 {
		t.Fatalf("got %d, want 3: %+v", len(pkgs), pkgs)
	}
	byName := map[string]string{}
	for _, p := range pkgs {
		byName[p.Name] = p.Version
	}
	// Multi-dash names keep their prefix; version = last two components.
	if byName["libxml2"] != "2.11.5-r0" {
		t.Errorf("libxml2 wrong: %q", byName["libxml2"])
	}
	if byName["alpine-baselayout"] != "3.4.3-r1" {
		t.Errorf("alpine-baselayout wrong: %q", byName["alpine-baselayout"])
	}
	if byName["zlib"] != "1.2.13-r1" {
		t.Errorf("zlib wrong: %q", byName["zlib"])
	}
}

func TestParseOSReleaseHost(t *testing.T) {
	family, name, ver, ok := ParseOSReleaseHost("NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n")
	if !ok || family != "ubuntu" || name != "Ubuntu 22.04.3 LTS" || ver != "22.04" {
		t.Fatalf("got %q %q %q ok=%v", family, name, ver, ok)
	}
	if _, _, _, ok := ParseOSReleaseHost("garbage"); ok {
		t.Error("garbage must not resolve")
	}
}

// fakeSSHRunner routes fixed commands to canned outputs and records the
// executed commands (assertion: only read-only probes run).
type fakeSSHRunner struct {
	commands []string
	outputs  map[string]string
}

func (f *fakeSSHRunner) Run(ctx context.Context, host SSHHostConfig, cmd string) (string, error) {
	f.commands = append(f.commands, cmd)
	if out, ok := f.outputs[cmd]; ok {
		return out, nil
	}
	return "", nil
}

func TestSSHCollectorDebianHost(t *testing.T) {
	r := &fakeSSHRunner{outputs: map[string]string{
		osReleaseCmd: "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\n",
		whichDpkgCmd: "/usr/bin/dpkg-query",
		dpkgQueryCmd: "libc6:amd64|ii |2.35-0ubuntu3.8\nopenssl|ii |3.0.2-0ubuntu1.15\n",
	}}
	c := &SSHCollector{Runner: r}
	res := c.Collect(context.Background(), SSHHostConfig{Host: "10.0.0.5", User: "root"})
	if !res.OSOK || res.OSFamily != "ubuntu" || res.OSVersion != "22.04" {
		t.Fatalf("os wrong: %+v", res)
	}
	if len(res.Packages) != 2 || res.Packages[1].Name != "openssl" {
		t.Fatalf("packages wrong: %+v", res.Packages)
	}
	// Only dpkg collected (distro-authoritative), no rpm/apk attempts.
	for _, cmd := range r.commands {
		if cmd == rpmQueryCmd || cmd == apkListCmd {
			t.Errorf("unexpected rpm/apk collection on a debian host: %s", cmd)
		}
	}
}

func TestSSHCollectorAlpineHost(t *testing.T) {
	r := &fakeSSHRunner{outputs: map[string]string{
		osReleaseCmd: "NAME=\"Alpine Linux\"\nID=alpine\nVERSION_ID=3.18.0\n",
		whichApkCmd:  "/sbin/apk",
		apkListCmd:   "zlib-1.2.13-r1 x86_64 {zlib} (Apache-2.0) [installed]\n",
	}}
	c := &SSHCollector{Runner: r}
	res := c.Collect(context.Background(), SSHHostConfig{Host: "10.0.0.9"})
	if !res.OSOK || res.OSFamily != fingerprinting.DistroAlpine {
		t.Fatalf("os wrong: %+v", res)
	}
	if len(res.Packages) != 1 || res.Packages[0].Name != "zlib" {
		t.Fatalf("packages wrong: %+v", res.Packages)
	}
}

func TestSSHCollectorUnreachableHostIsIsolated(t *testing.T) {
	r := &failingSSHRunner{}
	c := &SSHCollector{Runner: r}
	res := c.Collect(context.Background(), SSHHostConfig{Host: "10.255.255.1"})
	if res.OSOK || len(res.Packages) != 0 {
		t.Fatalf("failed host must yield nothing: %+v", res)
	}
	if res.Err == "" {
		t.Error("the failure must be reported honestly")
	}
}

type failingSSHRunner struct{}

func (f *failingSSHRunner) Run(ctx context.Context, host SSHHostConfig, cmd string) (string, error) {
	return "", context.DeadlineExceeded
}

func TestSSHClientRejectsMissingHostKeyPolicy(t *testing.T) {
	c := &SSHClient{User: "root", Password: "x"}
	_, err := c.Run(context.Background(), SSHHostConfig{Host: "127.0.0.1", Port: 1}, "true")
	if err == nil || !strings.Contains(err.Error(), "host key verification refused") {
		t.Fatalf("missing host-key policy must fail loudly, got: %v", err)
	}
}

// errSSHRunner fails every command (unreachable host simulation).
type errSSHRunner struct{ commands []string }

func (e *errSSHRunner) Run(ctx context.Context, host SSHHostConfig, cmd string) (string, error) {
	e.commands = append(e.commands, cmd)
	return "", context.DeadlineExceeded
}

func TestSSHCollectorCommandLog(t *testing.T) {
	r := &fakeSSHRunner{outputs: map[string]string{
		osReleaseCmd: "NAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID=\"22.04\"\n",
		whichDpkgCmd: "/usr/bin/dpkg-query",
		dpkgQueryCmd: "libc6:amd64|ii |2.35-0ubuntu3.8\nopenssl|ii |3.0.2-0ubuntu1.15\n",
	}}
	c := &SSHCollector{Runner: r}
	res := c.Collect(context.Background(), SSHHostConfig{Host: "10.0.0.5", User: "root"})
	if len(res.Commands) != 3 {
		t.Fatalf("expected os-release + dpkg probe + dpkg collect in the log, got %d: %+v", len(res.Commands), res.Commands)
	}
	want := []struct {
		cmd   string
		ok    bool
		lines int
	}{
		{osReleaseCmd, true, 3},
		{whichDpkgCmd, true, 1},
		{dpkgQueryCmd, true, 2},
	}
	for i, w := range want {
		got := res.Commands[i]
		if got.Cmd != w.cmd || got.OK != w.ok || got.Lines != w.lines {
			t.Errorf("command[%d] = %+v, want cmd=%s ok=%v lines=%d", i, got, w.cmd, w.ok, w.lines)
		}
		if got.Err != "" {
			t.Errorf("command[%d]: unexpected err %q", i, got.Err)
		}
	}
	if res.DurationMS < 0 {
		t.Errorf("duration must never be negative: %d", res.DurationMS)
	}
}

func TestSSHCollectorCommandLogRecordsFailures(t *testing.T) {
	r := &errSSHRunner{}
	c := &SSHCollector{Runner: r}
	res := c.Collect(context.Background(), SSHHostConfig{Host: "10.0.0.5", User: "root"})
	if res.OSOK || len(res.Packages) > 0 {
		t.Fatalf("unreachable host must yield nothing: %+v", res)
	}
	if len(res.Commands) == 0 {
		t.Fatal("failed commands must still be logged")
	}
	for _, cmd := range res.Commands {
		if cmd.OK {
			t.Errorf("command %s must be logged as failed", cmd.Cmd)
		}
		if cmd.Err == "" {
			t.Errorf("failed command %s must carry its error", cmd.Cmd)
		}
	}
	if res.Err == "" {
		t.Error("host error must surface")
	}
}
