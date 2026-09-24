package pkgversion

import (
	"errors"
	"strings"
	"testing"
)

// TestParseDebVersion covers the version shapes that flow through the
// scanner: the field-reported Ubuntu/Debian examples plus the structural
// corners (explicit/zero/zero-padded epochs, hyphens inside upstream,
// plus signs, tildes, gigantic numeric components).
func TestParseDebVersion(t *testing.T) {
	cases := []struct {
		name     string
		raw      string
		epoch    uint64
		upstream string
		revision string
	}{
		{name: "plain upstream with revision", raw: "2.0.19-1", upstream: "2.0.19", revision: "1"},
		{name: "ubuntu revision", raw: "2.1.11-1ubuntu3", upstream: "2.1.11", revision: "1ubuntu3"},
		{name: "epoch with ubuntu revision", raw: "2:13.0.0-2ubuntu1", epoch: 2, upstream: "13.0.0", revision: "2ubuntu1"},
		{name: "openssh style with epoch", raw: "1:10.0p1-5ubuntu5.4", epoch: 1, upstream: "10.0p1", revision: "5ubuntu5.4"},
		{name: "multi-part ubuntu revision", raw: "3.5.3-1ubuntu3.4", upstream: "3.5.3", revision: "1ubuntu3.4"},
		{name: "ubuntu suffix stays upstream", raw: "1.83ubuntu2", upstream: "1.83ubuntu2", revision: ""},
		{name: "no revision", raw: "0.49", upstream: "0.49", revision: ""},
		{name: "tilde backport suffix in revision", raw: "1:2.4.62-1ubuntu4.1~24.04.2", epoch: 1, upstream: "2.4.62", revision: "1ubuntu4.1~24.04.2"},
		{name: "plus in upstream", raw: "2.0.0+deb12u1-1", upstream: "2.0.0+deb12u1", revision: "1"},
		{name: "hyphen inside upstream", raw: "1.0-alpha-1", upstream: "1.0-alpha", revision: "1"},
		{name: "explicit zero epoch", raw: "0:1.0", epoch: 0, upstream: "1.0", revision: ""},
		{name: "zero-padded epoch", raw: "007:1.0", epoch: 7, upstream: "1.0", revision: ""},
		{name: "max uint64 epoch", raw: "18446744073709551615:1.0", epoch: 18446744073709551615, upstream: "1.0", revision: ""},
		{name: "bare upstream", raw: "1.0", upstream: "1.0", revision: ""},
		{name: "single digit", raw: "0", upstream: "0", revision: ""},
		{name: "kernel style", raw: "5.15.0-107.114", upstream: "5.15.0", revision: "107.114"},
		{name: "really-rename upstream", raw: "1.2.3+really1.2.4-0ubuntu1", upstream: "1.2.3+really1.2.4", revision: "0ubuntu1"},
		{name: "revision with trailing letter", raw: "1.0-2ubuntu2.1a", upstream: "1.0", revision: "2ubuntu2.1a"},
		{name: "hundred digit numeric component", raw: "1." + strings.Repeat("9", 100), upstream: "1." + strings.Repeat("9", 100), revision: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDebVersion(tc.raw)
			if err != nil {
				t.Fatalf("ParseDebVersion(%q) returned error: %v", tc.raw, err)
			}
			if got.Raw != tc.raw {
				t.Errorf("Raw = %q, want the input preserved verbatim: %q", got.Raw, tc.raw)
			}
			if got.Epoch != tc.epoch {
				t.Errorf("Epoch = %d, want %d", got.Epoch, tc.epoch)
			}
			if got.Upstream != tc.upstream {
				t.Errorf("Upstream = %q, want %q", got.Upstream, tc.upstream)
			}
			if got.Revision != tc.revision {
				t.Errorf("Revision = %q, want %q", got.Revision, tc.revision)
			}
		})
	}
}

// TestParseDebVersionErrors pins every validation rule to its sentinel.
func TestParseDebVersionErrors(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want error
	}{
		{name: "empty", raw: "", want: ErrEmptyVersion},
		{name: "leading whitespace", raw: " 1.0", want: ErrInvalidCharacter},
		{name: "trailing whitespace", raw: "1.0 ", want: ErrInvalidCharacter},
		{name: "internal tab", raw: "1\t.0", want: ErrInvalidCharacter},
		{name: "whitespace only", raw: "   ", want: ErrInvalidCharacter},
		{name: "newline noise", raw: "1.0\n", want: ErrInvalidCharacter},
		{name: "non numeric epoch", raw: "a:1.0", want: ErrInvalidEpoch},
		{name: "dotted epoch", raw: "2.0:1.0", want: ErrInvalidEpoch},
		{name: "empty epoch", raw: ":1.0", want: ErrInvalidEpoch},
		{name: "signed epoch", raw: "+1:1.0", want: ErrInvalidEpoch},
		{name: "negative epoch", raw: "-1:1.0", want: ErrEmptyUpstream}, // hyphen splits revision first: "-1:1.0" -> upstream ""
		{name: "hex epoch", raw: "0x1:1.0", want: ErrInvalidEpoch},
		{name: "underscored epoch", raw: "1_0:1.0", want: ErrInvalidCharacter}, // alphabet check fires before the epoch rule
		{name: "epoch one past uint64", raw: "18446744073709551616:1.0", want: ErrInvalidEpoch},
		{name: "epoch far beyond uint64", raw: "99999999999999999999999999:1.0", want: ErrInvalidEpoch},
		{name: "nothing after epoch", raw: "1:", want: ErrEmptyUpstream},
		{name: "missing upstream before revision", raw: "-1", want: ErrEmptyUpstream},
		{name: "bare hyphen", raw: "-", want: ErrEmptyRevision},
		{name: "empty revision", raw: "1.0-", want: ErrEmptyRevision},
		{name: "second colon in upstream", raw: "1:2:3", want: ErrInvalidCharacter},
		{name: "colon in revision", raw: "1.0-2:3", want: ErrInvalidCharacter},
		{name: "colon without epoch", raw: "1.0:2.0", want: ErrInvalidEpoch},
		{name: "underscore in upstream", raw: "1.0_1", want: ErrInvalidCharacter},
		{name: "at sign", raw: "1.0@1", want: ErrInvalidCharacter},
		{name: "slash", raw: "1.0/1", want: ErrInvalidCharacter},
		{name: "non ascii letter", raw: "1.0é", want: ErrInvalidCharacter},
		{name: "comma", raw: "1,0", want: ErrInvalidCharacter},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseDebVersion(tc.raw)
			if err == nil {
				t.Fatalf("ParseDebVersion(%q) = %+v, want error", tc.raw, got)
			}
			if !errors.Is(err, tc.want) {
				t.Errorf("ParseDebVersion(%q) error = %v, want errors.Is %v", tc.raw, err, tc.want)
			}
		})
	}
}

// TestParseDebVersionErrorMessages checks the errors quote the offending
// input and, where promised, the byte offset — operators feed these
// messages straight into data-quality triage.
func TestParseDebVersionErrorMessages(t *testing.T) {
	_, err := ParseDebVersion("1.0@1")
	if err == nil || !strings.Contains(err.Error(), `"1.0@1"`) || !strings.Contains(err.Error(), "offset 3") {
		t.Errorf("error should quote input and offset, got: %v", err)
	}
	_, err = ParseDebVersion("1.0 ")
	if err == nil || !strings.Contains(err.Error(), "whitespace at offset 3") {
		t.Errorf("whitespace error should name the offset, got: %v", err)
	}
	_, err = ParseDebVersion("1.0-2:3")
	if err == nil || !strings.Contains(err.Error(), "offset 5") {
		t.Errorf("revision colon error should name the absolute offset, got: %v", err)
	}
}

// TestPackageVersionString pins the canonical rendering. Raw keeps the
// input verbatim; String is the normalized display form.
func TestPackageVersionString(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"1:10.0p1-5ubuntu5.4", "1:10.0p1-5ubuntu5.4"},
		{"1.83ubuntu2", "1.83ubuntu2"},
		{"2.0.19-1", "2.0.19-1"},
		{"0.49", "0.49"},
		{"0:1.0", "1.0"}, // zero epoch omitted in canonical form
		{"007:1.0", "7:1.0"},
		{"1:2.4.62-1ubuntu4.1~24.04.2", "1:2.4.62-1ubuntu4.1~24.04.2"},
	}
	for _, tc := range cases {
		v, err := ParseDebVersion(tc.raw)
		if err != nil {
			t.Fatalf("ParseDebVersion(%q): %v", tc.raw, err)
		}
		if got := v.String(); got != tc.want {
			t.Errorf("ParseDebVersion(%q).String() = %q, want %q", tc.raw, got, tc.want)
		}
	}
}
