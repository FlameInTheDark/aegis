package sbom

import (
	"strings"
	"testing"
)

func TestParseValidDocument(t *testing.T) {
	doc := `{
          "bomFormat": "CycloneDX",
          "specVersion": "1.5",
          "components": [
            {"type": "library", "name": "express", "version": "4.18.2", "purl": "pkg:npm/express@4.18.2", "publisher": "OpenJS"},
            {"type": "application", "name": "cli", "version": "2.1.0", "purl": "pkg:golang/github.com/x/cli@v2.1.0"},
            {"type": "library", "name": "django", "version": "5.0.1", "purl": "pkg:pypi/django@5.0.1"},
            {"type": "library", "name": "libc6", "version": "2.36-9", "purl": "pkg:deb/debian/libc6@2.36-9?arch=amd64"},
            {"type": "file", "name": "README.md"},
            {"type": "library", "name": "@angular/core", "version": "17.0.0", "purl": "pkg:npm/%40angular/core@17.0.0"}
          ]
        }`
	pkgs, err := Parse([]byte(doc))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(pkgs) != 5 {
		t.Fatalf("got %d packages, want 5 (file component skipped): %+v", len(pkgs), pkgs)
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if p := byName["express"]; p.Ecosystem != "npm" || p.Vendor != "OpenJS" || p.Version != "4.18.2" {
		t.Fatalf("express: %+v", p)
	}
	if p := byName["github.com/x/cli"]; p.Ecosystem != "Go" || p.Version != "2.1.0" {
		t.Fatalf("golang: %+v", p)
	}
	if p := byName["django"]; p.Ecosystem != "PyPI" {
		t.Fatalf("pypi: %+v", p)
	}
	if p := byName["libc6"]; p.Ecosystem != "os_debian" || p.Version != "2.36-9" {
		t.Fatalf("deb: %+v", p)
	}
	if p := byName["@angular/core"]; p.Ecosystem != "npm" || p.Version != "17.0.0" {
		t.Fatalf("scoped npm: %+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	cases := map[string]string{
		"not json":      `{"bomFormat":`,
		"wrong format":  `{"bomFormat":"SPDX","components":[{"name":"x","version":"1"}]}`,
		"no components": `{"bomFormat":"CycloneDX","components":[]}`,
		"unusable rows": `{"bomFormat":"CycloneDX","components":[{"type":"file","name":"a.txt"}]}`,
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Fatalf("%s: expected error", name)
		}
	}
}

func TestParseComponentCap(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"bomFormat":"CycloneDX","components":[`)
	for i := 0; i < MaxComponents+1; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`{"name":"p","version":"1"}`)
	}
	b.WriteString(`]}`)
	if _, err := Parse([]byte(b.String())); err == nil {
		t.Fatal("expected cap error")
	}
}

func TestSplitPURL(t *testing.T) {
	cases := []struct{ purl, name, version, eco string }{
		{"pkg:npm/express@4.18.2", "express", "4.18.2", "npm"},
		{"pkg:npm/%40angular/core@17.0.0", "@angular/core", "17.0.0", "npm"},
		{"pkg:golang/github.com/x/cli@v2.1.0", "github.com/x/cli", "v2.1.0", "Go"},
		{"pkg:deb/debian/libc6@2.36-9?arch=amd64", "debian/libc6", "2.36-9", "os_debian"},
		{"pkg:pypi/django@5.0.1", "django", "5.0.1", "PyPI"},
		{"pkg:cargo/serde@1.0.0", "serde", "1.0.0", "Cargo"},
		{"not-a-purl", "", "", ""},
		{"pkg:unknown/x@1", "", "", ""},
	}
	for _, c := range cases {
		name, version, eco := splitPURL(c.purl)
		if name != c.name || version != c.version || eco != c.eco {
			t.Fatalf("splitPURL(%q) = (%q,%q,%q), want (%q,%q,%q)", c.purl, name, version, eco, c.name, c.version, c.eco)
		}
	}
}
