// Package fingerprinting implements product identity normalization:
// raw vendor/product/version strings from scanners, banners
// and agents are canonicalized before vulnerability matching. It never
// guesses aggressively — unknown stays unknown.
package fingerprinting

import (
	"regexp"
	"strconv"
	"strings"
)

// CPE is a parsed CPE 2.3 identity.
type CPE struct {
	Part     string // a | o | h
	Vendor   string
	Product  string
	Version  string
	Update   string
	Edition  string
	Language string
}

// ParseCPE parses a cpe:2.3:<part>:<vendor>:<product>:... string. It is
// tolerant of the 2.2 13-field form. Returns ok=false for garbage input.
func ParseCPE(s string) (CPE, bool) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "cpe:/") // 2.2
	s = strings.TrimPrefix(s, "cpe:2.3:")
	if s == "" {
		return CPE{}, false
	}
	parts := strings.Split(s, ":")
	if len(parts) < 4 {
		return CPE{}, false
	}
	c := CPE{Part: parts[0], Vendor: unescapeCPE(parts[1]), Product: unescapeCPE(parts[2])}
	if len(parts) > 3 {
		c.Version = unescapeCPE(parts[3])
	}
	if c.Version == "*" || c.Version == "-" {
		c.Version = ""
	}
	if len(parts) > 4 {
		c.Update = unescapeCPE(parts[4])
	}
	if len(parts) > 5 {
		c.Edition = unescapeCPE(parts[5])
	}
	if len(parts) > 6 {
		c.Language = unescapeCPE(parts[6])
	}
	if c.Part == "" || c.Part == "*" || c.Part == "-" {
		return CPE{}, false
	}
	if c.Vendor == "" || c.Vendor == "*" {
		return CPE{}, false
	}
	if c.Product == "" || c.Product == "*" {
		return CPE{}, false
	}
	return c, true
}

func unescapeCPE(s string) string {
	s = strings.ReplaceAll(s, "\\:", ":")
	s = strings.ReplaceAll(s, "\\.", ".")
	return s
}

// FormatCPE renders a CPE struct back to the canonical 2.3 string.
func FormatCPE(c CPE) string {
	esc := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, ":", "\\:"), ".", "\\.") }
	f := []string{"cpe:2.3", c.Part, esc(c.Vendor), esc(c.Product)}
	if c.Version != "" {
		f = append(f, esc(c.Version))
	} else {
		f = append(f, "*")
	}
	f = append(f, "*", "*", "*", "*", "*", "*")
	return strings.Join(f, ":")
}

// aliases maps lowercased raw product/vendor strings to canonical pairs.
// The list is intentionally small and evidence-driven; matching falls back
// to the raw identity when no alias exists.
var vendorAliases = map[string]string{
	"microsoft corp": "microsoft", "ms": "microsoft", "internet information services": "microsoft",
	"apache software foundation": "apache", "the apache software foundation": "apache",
	"oracle corp": "oracle", "oracle corporation": "oracle",
	"vmware inc": "vmware", "vmware, inc.": "vmware",
	"red hat inc": "redhat", "red hat": "redhat", "redhat inc": "redhat",
	"canonical ltd": "canonical", "canonical": "canonical",
	"debian": "debian", "suse": "suse", "nginix": "nginx", "f5 inc": "f5",
	"openssh project": "openbsd", "openbsd": "openbsd",
}

var productAliases = map[string]string{
	"httpd": "httpd", "apache http server": "httpd", "apache httpd": "httpd", "apache2": "httpd", "apache": "httpd",
	"internet information services": "iis", "iis": "iis",
	"nginx": "nginx", "openresty": "openresty",
	"openssh": "openssh", "ssh": "openssh",
	"microsoft iis": "iis",
	"postgresql":    "postgresql", "postgres": "postgresql", "psql": "postgresql",
	"mysql": "mysql", "mariadb": "mariadb",
	"exchange": "exchange_server", "microsoft exchange": "exchange_server",
	"exim": "exim", "postfix": "postfix", "sendmail": "sendmail",
	"proftpd": "proftpd", "vsftpd": "vsftpd", "pure-ftpd": "pure-ftpd",
	"lighttpd": "lighttpd", "haproxy": "haproxy", "traefik": "traefik",
	"tomcat": "tomcat", "apache tomcat": "tomcat",
	"jenkins": "jenkins", "gitlab": "gitlab", "jira": "jira", "confluence": "confluence",
	"vmware esxi": "esxi", "esxi": "esxi", "vsphere": "vsphere",
	"linux kernel": "linux_kernel", "linux": "linux_kernel",
	"windows server": "windows_server", "microsoft windows": "windows",
	"dahua": "dahua", "hikvision": "hikvision",
	"openssl": "openssl", "golang http server": "golang", "go http server": "golang",
}

// NormalizeProduct canonicalizes a raw product string ("Apache HTTP Server"
// -> "httpd" style identity used by the CVE index). Returns the input
// lowercased when no alias matches — never invents a product.
func NormalizeProduct(raw string) string {
	if raw == "" {
		return ""
	}
	key := strings.ToLower(strings.TrimSpace(raw))
	if v, ok := productAliases[key]; ok {
		return v
	}
	key = strings.TrimSuffix(key, " server")
	return key
}

// NormalizeVendor canonicalizes a raw vendor string.
func NormalizeVendor(raw string) string {
	if raw == "" {
		return ""
	}
	key := strings.ToLower(strings.TrimSpace(raw))
	if v, ok := vendorAliases[key]; ok {
		return v
	}
	return key
}

// ServiceToCPE builds the best-effort CPE candidate set for an observed
// service (part "a" applications, part "o" when the banner is an OS).
// Multiple candidates are returned; the matcher evaluates each.
func ServiceToCPE(vendor, product, version string) []string {
	canon := NormalizeProduct(product)
	vendor = NormalizeVendor(vendor)
	if canon == "" {
		return nil
	}
	c := CPE{Part: "a", Vendor: vendor, Product: canon, Version: version}
	out := []string{FormatCPE(c)}
	// Version-less candidate helps range matching when version unknown.
	if version != "" {
		c2 := c
		c2.Version = ""
		out = append(out, FormatCPE(c2))
	}
	return out
}

var versionRe = regexp.MustCompile(`^\d+(\.\d+)*([-+_.][0-9A-Za-z]+)*$`)

// NormalizeVersion cleans a detected version string. Returns "" when the
// string does not look like a version at all (no pretending).
func NormalizeVersion(raw string) string {
	v := strings.TrimSpace(raw)
	v = strings.TrimPrefix(v, "v")
	v = strings.Trim(v, "()[] ")
	if v == "" || v == "*" || v == "-" || v == "?" {
		return ""
	}
	if versionRe.MatchString(v) {
		return v
	}
	// Not version-like: return empty — never pretend.
	return ""
}

// VersionParts splits a dotted numeric version into integers for comparison.
func VersionParts(v string) []int {
	var out []int
	for _, seg := range strings.Split(v, ".") {
		n, err := strconv.Atoi(strings.TrimSpace(seg))
		if err != nil {
			return out
		}
		out = append(out, n)
	}
	return out
}

// CompareVersions returns -1/0/1 comparing dotted versions, or +2 when the
// versions are not comparable (caller must not pretend an ordering).
func CompareVersions(a, b string) int {
	pa, pb := VersionParts(a), VersionParts(b)
	if len(pa) == 0 || len(pb) == 0 {
		return 2
	}
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x < y {
			return -1
		}
		if x > y {
			return 1
		}
	}
	return 0
}
