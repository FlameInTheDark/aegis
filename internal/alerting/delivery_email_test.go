package alerting

import (
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func TestBuildMailMessageHeaders(t *testing.T) {
	msg := string(buildMailMessage("aegis@example.com", []string{"oncall@example.com"}, "[Aegis][HIGH] Port 22 opened", "Trigger: mgmt-port (high)\n"))
	for _, want := range []string{
		"From: aegis@example.com\r\n",
		"To: oncall@example.com\r\n",
		"Subject: [Aegis][HIGH] Port 22 opened\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
	} {
		if !strings.Contains(msg, want) {
			t.Fatalf("missing header %q in %q", want, msg)
		}
	}
	if strings.Contains(msg, "Subject: [Aegis][HIGH] Port 22 opened\r\nMIME-Version") {
		// subject line properly terminated by CRLF before the next header
	} else {
		t.Fatalf("subject not CRLF-terminated: %q", msg)
	}
}

func TestBuildMailMessageSubjectSanitized(t *testing.T) {
	msg := string(buildMailMessage("a@example.com", []string{"b@example.com"}, "evil\r\nBcc: victim@x.com", "body"))
	if strings.Contains(msg, "\r\nBcc:") || strings.Contains(msg, "\nBcc:") {
		t.Fatalf("subject newline injection survived: %q", msg)
	}
	if !strings.Contains(msg, "Subject: evil  Bcc: victim@x.com\r\n") {
		t.Fatalf("sanitized subject wrong: %q", msg)
	}
}

func TestParseEmailConfigValidation(t *testing.T) {
	valid := []byte(`{"smtp_host":"smtp.example.com","smtp_port":587,"from":"aegis@example.com","to":["oncall@example.com"]}`)
	if _, err := domain.ParseEmailConfig(valid); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	bad := map[string]string{
		"missing":  ``,
		"no host":  `{"from":"a@example.com","to":["b@example.com"]}`,
		"bad port": `{"smtp_host":"h","smtp_port":99999,"from":"a@example.com","to":["b@example.com"]}`,
		"bad from": `{"smtp_host":"h","from":"not-an-email","to":["b@example.com"]}`,
		"no rcpt":  `{"smtp_host":"h","from":"a@example.com","to":[]}`,
		"bad rcpt": `{"smtp_host":"h","from":"a@example.com","to":["b example.com"]}`,
		"not json": `{{{`,
	}
	for name, raw := range bad {
		if _, err := domain.ParseEmailConfig([]byte(raw)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
	// Default port fills in 587.
	cfg, err := domain.ParseEmailConfig([]byte(`{"smtp_host":"h","from":"a@example.com","to":["b@example.com"]}`))
	if err != nil || cfg.SMTPPort != 587 {
		t.Fatalf("default port: %v %v", cfg, err)
	}
}
