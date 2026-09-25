package vulnsearch

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/FlameInTheDark/aegis/internal/domain"
)

func actionWithSelector(t *testing.T, sel string) *domain.VulnSearchAction {
	t.Helper()
	return &domain.VulnSearchAction{
		Name: "test", TargetKind: "software", Mode: domain.VulnActionModeShadow,
		Selector: json.RawMessage(sel), ConfidenceCap: 0.8,
	}
}

func TestValidateActionAcceptsPlanExample(t *testing.T) {
	a := actionWithSelector(t, `{"all":[
		{"field":"name","op":"in","values":["openssh-server","openssh-clients"]},
		{"field":"ecosystem","op":"in","values":["os_debian","os_rpm","os_alpine"]}
	]}`)
	if err := ValidateAction(a); err != nil {
		t.Fatalf("plan example rejected: %v", err)
	}
}

func TestValidateActionRejectsForeignConstructs(t *testing.T) {
	// The DSL is structural: URLs and shell commands are not valid fields
	// or operators. A SQL-looking STRING VALUE is harmless (literal name
	// matching, never executed) and therefore deliberately still accepted.
	cases := []string{
		`{"all":[{"field":"url","op":"eq","values":["https://evil.example"]}]}`,
		`{"all":[{"field":"name","op":"exec","values":["rm -rf /"]}]}`,
		`{"all":[{"field":"name","op":"contains","values":[]}]}`,
		`{"all":[]}`,
	}
	for i, sel := range cases {
		if err := ValidateAction(actionWithSelector(t, sel)); err == nil {
			t.Errorf("case %d: foreign construct accepted", i)
		}
	}
}

func TestValidateActionBounds(t *testing.T) {
	// More than maxConditions conditions must be rejected.
	conds := make([]string, 0, maxConditions+1)
	for i := 0; i <= maxConditions; i++ {
		conds = append(conds, `{"field":"name","op":"in","values":["a`+strings.Repeat("b", i)+`"]}`)
	}
	sel := `{"all":[` + strings.Join(conds, ",") + `]}`
	if err := ValidateAction(actionWithSelector(t, sel)); err == nil {
		t.Fatal("oversized selector accepted")
	}
	// Bad mode.
	a := actionWithSelector(t, `{"all":[{"field":"name","op":"in","values":["x"]}]}`)
	a.Mode = "curl | bash"
	if err := ValidateAction(a); err == nil {
		t.Fatal("foreign mode accepted")
	}
	// Bad target kind.
	a.TargetKind = "kernel"
	if err := ValidateAction(a); err == nil {
		t.Fatal("foreign target kind accepted")
	}
}

func TestSelectorMatching(t *testing.T) {
	sel, err := ParseSelector(json.RawMessage(`{"all":[
		{"field":"name","op":"in","values":["openssh-server"]},
		{"field":"ecosystem","op":"in","values":["os_debian","os_rpm"]}
	]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !sel.Matches(Target{Name: "OpenSSH-Server", Ecosystem: "os_debian"}) {
		t.Fatal("case-insensitive name match failed")
	}
	if sel.Matches(Target{Name: "nginx", Ecosystem: "os_debian"}) {
		t.Fatal("non-matching name accepted")
	}
	if sel.Matches(Target{Name: "openssh-server", Ecosystem: "npm"}) {
		t.Fatal("non-matching ecosystem accepted")
	}
}

func TestQuerySourceAllowlist(t *testing.T) {
	a := actionWithSelector(t, `{"all":[{"field":"name","op":"in","values":["x"]}]}`)
	a.Selector = json.RawMessage(`{"all":[{"field":"name","op":"in","values":["x"]}],"queries":[
		{"source":"https","url":"http://evil"}]}`)
	// The Document's Queries come from the selector JSON; an unknown source
	// must fail validation.
	if err := ValidateAction(a); err == nil {
		t.Fatal("foreign query source accepted")
	}
}
