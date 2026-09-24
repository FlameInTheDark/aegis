package pkgversion

import (
	"errors"
	"testing"
)

// Compile-time interface conformance.
var (
	_ VersionParser     = DebParser{}
	_ VersionComparator = DebComparator{}
)

// TestRegistryDebBackendIsDefaultWired checks the init() wiring: the deb
// backend is reachable through the generic registry and behaves exactly
// like the direct functions.
func TestRegistryDebBackendIsDefaultWired(t *testing.T) {
	parser, err := ParserFor(EcosystemDeb)
	if err != nil {
		t.Fatalf("ParserFor(deb): %v", err)
	}
	comparator, err := ComparatorFor(EcosystemDeb)
	if err != nil {
		t.Fatalf("ComparatorFor(deb): %v", err)
	}

	got, err := parser.Parse("1:10.0p1-5ubuntu5.4")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want, err := ParseDebVersion("1:10.0p1-5ubuntu5.4")
	if err != nil {
		t.Fatalf("ParseDebVersion: %v", err)
	}
	if got != want {
		t.Errorf("registry parse = %+v, want %+v", got, want)
	}

	cmp, err := comparator.Compare("1.0~rc1", "1.0")
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if cmp != -1 {
		t.Errorf("registry compare = %d, want -1", cmp)
	}
}

// TestRegistryUnsupportedEcosystems documents the current backend
// coverage: rpm/apk/pacman/semver stay with the existing fingerprinting
// implementations until they migrate; requesting them here is an
// explicit, sentinel-wrapped error — never a silent fallback.
func TestRegistryUnsupportedEcosystems(t *testing.T) {
	for _, e := range []Ecosystem{EcosystemRPM, EcosystemAPK, EcosystemPacman, EcosystemSemver} {
		if _, err := ParserFor(e); !errors.Is(err, ErrUnsupportedEcosystem) {
			t.Errorf("ParserFor(%q) error = %v, want ErrUnsupportedEcosystem", e, err)
		}
		if _, err := ComparatorFor(e); !errors.Is(err, ErrUnsupportedEcosystem) {
			t.Errorf("ComparatorFor(%q) error = %v, want ErrUnsupportedEcosystem", e, err)
		}
	}
}

// testBackend is a registry-mechanics probe only — it proves the
// extension point works for future rpm/apk/pacman/semver backends
// without implying any of them exist.
type testBackend struct{}

func (testBackend) Parse(v string) (PackageVersion, error) {
	return PackageVersion{Raw: v, Upstream: v}, nil
}
func (testBackend) Compare(a, b string) (int, error) { return 0, nil }

// TestRegistryExtensionPoint registers a probe backend under a
// test-private ecosystem name and verifies registration and replacement
// (later registration wins).
func TestRegistryExtensionPoint(t *testing.T) {
	const probe = Ecosystem("aegis-test-probe")
	RegisterParser(probe, testBackend{})
	p, err := ParserFor(probe)
	if err != nil {
		t.Fatalf("ParserFor(probe) after RegisterParser: %v", err)
	}
	got, err := p.Parse("9.9")
	if err != nil || got.Upstream != "9.9" {
		t.Errorf("probe parse = %+v, %v; want Upstream 9.9", got, err)
	}
	RegisterParser(probe, DebParser{}) // replacement wins
	p, err = ParserFor(probe)
	if err != nil {
		t.Fatalf("ParserFor(probe) after replacement: %v", err)
	}
	if _, err := p.Parse("1:2-1"); err != nil {
		t.Errorf("replacement backend should parse deb versions, got: %v", err)
	}
}

func BenchmarkParseDebVersion(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := ParseDebVersion("1:10.0p1-5ubuntu5.4"); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompareDebVersions(b *testing.B) {
	b.ReportAllocs()
	for range b.N {
		if _, err := CompareDebVersions("1:10.0p1-5ubuntu5.4", "1:10.0p1-5ubuntu5.5"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCompareDebParsed is the matcher hot path: parse feed bounds
// once, compare against every installed package.
func BenchmarkCompareDebParsed(b *testing.B) {
	a, _ := ParseDebVersion("1:10.0p1-5ubuntu5.4")
	fixed, _ := ParseDebVersion("1:10.0p1-5ubuntu5.5")
	b.ResetTimer()
	b.ReportAllocs()
	for range b.N {
		if CompareDebParsed(a, fixed) != -1 {
			b.Fatal("expected a < fixed")
		}
	}
}
