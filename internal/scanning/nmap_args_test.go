package scanning

import "testing"

func TestValidateNmapArgsAcceptsSafeTuning(t *testing.T) {
	ok := [][]string{
		{"-T4"},
		{"-T3", "--max-rate", "300"},
		{"--max-retries", "2", "--top-ports", "500"},
		{"-p", "22,80,443,8000-8100"},
		{"-p", "T:9100,U:161", "-n", "--system-dns"},
		{},
	}
	for _, args := range ok {
		if err := ValidateNmapArgs(args); err != nil {
			t.Fatalf("args %v must pass: %v", args, err)
		}
	}
}

func TestValidateNmapArgsRejectsDangerous(t *testing.T) {
	bad := [][]string{
		{"--script", "vuln"},        // NSE not allowed via presets
		{"--script-file", "/tmp/x"}, // arbitrary file
		{"-iL", "/etc/passwd"},      // file input
		{"--datadir", "/tmp"},       // data dir override
		{"--excludefile", "/tmp/x"}, // file input
		{"--max-rate"},              // value flag without value
		{"--max-rate", "fast"},      // bad value
		{"-p", "$(whoami)"},         // injection-shaped port spec
		{"--resume", "x"},           // not in allowlist
		{"-oX", "/tmp/out.xml"},     // output redirection
		{"e;$rm"},                   // junk
	}
	for _, args := range bad {
		if err := ValidateNmapArgs(args); err == nil {
			t.Fatalf("args %v must be rejected", args)
		}
	}
}
