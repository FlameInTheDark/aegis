package fingerprinting

import "testing"

func TestParseCPE(t *testing.T) {
	cases := []struct {
		in      string
		ok      bool
		vendor  string
		product string
		version string
	}{
		{"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*", true, "nginx", "nginx", "1.24.0"},
		{"cpe:2.3:a:apache:httpd:2.4.49:*:*:*:*:*:*:*", true, "apache", "httpd", "2.4.49"},
		{"cpe:/a:nginx:nginx:1.24.0", true, "nginx", "nginx", "1.24.0"}, // 2.2 form
		{"cpe:2.3:a:*:nginx:*:*:*:*:*:*:*:*", false, "", "", ""},        // wildcard vendor rejected
		{"garbage", false, "", "", ""},
		{"", false, "", "", ""},
	}
	for _, tc := range cases {
		c, ok := ParseCPE(tc.in)
		if ok != tc.ok {
			t.Fatalf("ParseCPE(%q) ok=%v want %v", tc.in, ok, tc.ok)
		}
		if ok && (c.Vendor != tc.vendor || c.Product != tc.product || c.Version != tc.version) {
			t.Fatalf("ParseCPE(%q) = %+v", tc.in, c)
		}
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	in := "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
	c, ok := ParseCPE(in)
	if !ok {
		t.Fatal("parse failed")
	}
	out := FormatCPE(c)
	c2, ok := ParseCPE(out)
	if !ok || c2.Vendor != c.Vendor || c2.Product != c.Product || c2.Version != c.Version {
		t.Fatalf("round trip failed: %s -> %s", in, out)
	}
}

func TestNormalizeProduct(t *testing.T) {
	cases := map[string]string{
		"Apache HTTP Server":            "httpd",
		"apache2":                       "httpd",
		"Internet Information Services": "iis",
		"IIS":                           "iis",
		"PostgreSQL":                    "postgresql",
		"Weird Product":                 "weird product", // never invents
		"":                              "",
	}
	for in, want := range cases {
		if got := NormalizeProduct(in); got != want {
			t.Errorf("NormalizeProduct(%q) = %q want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.24.0", "1.24.0", 0},
		{"1.24.1", "1.24.0", 1},
		{"1.9", "1.10", -1},
		{"2.4.49", "2.4.49", 0},
		{"1", "1.0", 0},
		{"abc", "1.0", 2}, // incomparable
		{"", "1.0", 2},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q,%q) = %d want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestNormalizeVersion(t *testing.T) {
	if v := NormalizeVersion("v1.24.0"); v != "1.24.0" {
		t.Errorf("got %q", v)
	}
	if v := NormalizeVersion("unknown"); v != "" {
		t.Errorf("garbage version must become empty, got %q", v)
	}
	if v := NormalizeVersion("1.24.0-1ubuntu3"); v != "1.24.0-1ubuntu3" {
		t.Errorf("distro suffix kept, got %q", v)
	}
}

func TestServiceToCPE(t *testing.T) {
	cpes := ServiceToCPE("nginx", "nginx", "1.24.0")
	if len(cpes) != 2 {
		t.Fatalf("want versioned + versionless candidates, got %v", cpes)
	}
	cpes = ServiceToCPE("nginx", "", "1.24.0")
	if len(cpes) != 0 {
		t.Fatalf("no product -> no CPE, got %v", cpes)
	}
}

// Escaped separators (\: \. \\) are literal characters, not field breaks —
// a naive strings.Split corrupted vendor/product names carrying them.
func TestParseCPEScapedFields(t *testing.T) {
	c, ok := ParseCPE(`cpe:2.3:a:with\:colon:prod\:uct:1\.0:*:*:*:*:*:*`)
	if !ok {
		t.Fatalf("escaped CPE must parse")
	}
	if c.Vendor != "with:colon" || c.Product != "prod:uct" {
		t.Errorf("vendor/product = %q/%q, want with:colon/prod:uct", c.Vendor, c.Product)
	}
	if c.Version != "1.0" {
		t.Errorf("version = %q, want 1.0", c.Version)
	}
	// Round-trip: FormatCPE escapes, ParseCPE restores.
	again, ok := ParseCPE(FormatCPE(c))
	if !ok || again.Vendor != c.Vendor || again.Product != c.Product || again.Version != c.Version {
		t.Errorf("round-trip mismatch: %+v vs %+v", again, c)
	}
}
