// Package config loads configuration for all Aegis services.
//
// Configuration is environment-first (12-factor) with optional file overrides.
// Secrets are never hardcoded and never logged.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the root configuration shared by all services. Each service uses
// the subset relevant to it; unknown fields are ignored.
type Config struct {
	Env     string // development | staging | production
	Service string // server | worker | scanner | agent | feed-worker

	HTTPAddr     string
	GRPCAddr     string
	MetricsAddr  string
	PublicURL    string
	LogLevel     string
	LogFormat    string // console | json
	WorkerQueues []string

	DatabaseURL   string
	RedisURL      string
	NATSURL       string
	ClickHouseURL string

	S3 struct {
		Endpoint  string
		Bucket    string
		AccessKey string
		SecretKey string
		UseSSL    bool
		Region    string
	}

	Auth struct {
		JWTSecret              string
		AccessTokenTTL         time.Duration
		RefreshTokenTTL        time.Duration
		CookieSecure           bool
		RotationGrace          time.Duration
		BootstrapAdminEmail    string
		BootstrapAdminPassword string
	}

	AgentCA struct {
		CertPath string
		KeyPath  string
	}

	TLS struct {
		CertFile string
		KeyFile  string
	}

	Scanner struct {
		NmapPath         string
		ZgrabPath        string
		NucleiPath       string
		MasscanPath      string
		MaxConcurrency   int
		MaxTargets       int
		MaxPacketRate    int
		MaxRuntime       time.Duration
		AllowPublicScope bool
		SiteID           string // statically bound site for a scanner deployment
		Mode             string
		HubAddr          string
		HubToken         string
		HubCAPath        string
		ScannerName      string
		Capabilities     []string
	}

	SSHScan struct {
		Hosts     []SSHHost
		User      string
		Password  string
		KeyPath   string
		Timeout   time.Duration
		Insecure  bool
		PinnedKey string
	}

	Feeds struct {
		Enabled     []string
		Interval    time.Duration
		CVEListURL  string
		NVDAPIKey   string
		OvalSources []OvalSource
	}

	OTel struct {
		Endpoint    string
		SampleRatio float64
	}

	// Connector configures the unified external-connection plane
	// (aegis.connector.v1): endpoint agents, remote scanners, collectors.
	Connector struct {
		// PublicAddr is the gRPC endpoint components reach from their own
		// networks; it is embedded into UI connect commands and the enroll
		// response (host:port, e.g. "aegis.example.com:9090").
		PublicAddr string
		// EnrollTokenTTL is the validity window of one-time connect tokens.
		EnrollTokenTTL time.Duration
	}

	DemoMode bool
}

// Load reads configuration from the environment (prefixed AEGIS_) and
// validates required fields for the given service.
func Load(service string) (*Config, error) {
	c := &Config{Service: service}
	c.Env = get("AEGIS_ENV", "development")
	c.HTTPAddr = get("AEGIS_HTTP_ADDR", ":8080")
	c.GRPCAddr = get("AEGIS_GRPC_ADDR", ":9090")
	c.MetricsAddr = get("AEGIS_METRICS_ADDR", ":9100")
	c.PublicURL = get("AEGIS_PUBLIC_URL", "http://localhost:5173")
	c.LogLevel = get("AEGIS_LOG_LEVEL", "info")
	c.LogFormat = get("AEGIS_LOG_FORMAT", "console")
	// Infrastructure URLs and S3 settings accept both the canonical
	// AEGIS_-prefixed name (compose/k8s/helm) and the bare name
	// (.env.example / Makefile export for native development).
	c.DatabaseURL = get2("AEGIS_DATABASE_URL", "DATABASE_URL", "")
	c.RedisURL = get2("AEGIS_REDIS_URL", "REDIS_URL", "redis://localhost:6379/0")
	c.NATSURL = get2("AEGIS_NATS_URL", "NATS_URL", "nats://localhost:4222")
	c.ClickHouseURL = get2("AEGIS_CLICKHOUSE_URL", "CLICKHOUSE_URL", "")

	c.S3.Endpoint = get2("AEGIS_S3_ENDPOINT", "S3_ENDPOINT", "")
	c.S3.Bucket = get2("AEGIS_S3_BUCKET", "S3_BUCKET", "aegis")
	c.S3.AccessKey = get2("AEGIS_S3_ACCESS_KEY", "S3_ACCESS_KEY", "")
	c.S3.SecretKey = get2("AEGIS_S3_SECRET_KEY", "S3_SECRET_KEY", "")
	c.S3.UseSSL = get2Bool("AEGIS_S3_USE_SSL", "S3_USE_SSL", false)
	c.S3.Region = get2("AEGIS_S3_REGION", "S3_REGION", "us-east-1")

	c.Auth.JWTSecret = get("AEGIS_JWT_SECRET", "")
	// Access tokens are renewed silently by the SPA well before expiry
	// (single-flight refresh + proactive timer), so 1h gives a smooth UX
	// without weakening the refresh-token lifetime (30d) that actually
	// bounds the session.
	c.Auth.AccessTokenTTL = getDur("AEGIS_ACCESS_TOKEN_TTL", time.Hour)
	c.Auth.RefreshTokenTTL = getDur("AEGIS_REFRESH_TOKEN_TTL", 30*24*time.Hour)
	// Secure flag on the refresh cookie (and the __Host- prefix). Defaults
	// to on in production (HTTPS deployments); explicitly set
	// AEGIS_AUTH_COOKIE_SECURE=false for plain-HTTP demo/dev deployments.
	c.Auth.CookieSecure = getBool("AEGIS_AUTH_COOKIE_SECURE", c.IsProduction())
	// How long a just-rotated-out refresh token still exchanges (multi-tab
	// race window). Beyond it, presenting a retired token is reuse → the
	// session family is revoked. Tests shrink this to run fast.
	c.Auth.RotationGrace = getDur("AEGIS_REFRESH_ROTATION_GRACE", 30*time.Second)
	c.Auth.BootstrapAdminEmail = get("AEGIS_BOOTSTRAP_ADMIN_EMAIL", "")
	c.Auth.BootstrapAdminPassword = get("AEGIS_BOOTSTRAP_ADMIN_PASSWORD", "")

	// Agent device CA. Empty env values fall back to./certs
	// so dev boots auto-generate and persist a CA; production mounts the
	// real pair via secrets and sets both variables explicitly.
	c.AgentCA.CertPath = get("AEGIS_AGENT_CA_CERT", "certs/agent-ca.crt")
	c.AgentCA.KeyPath = get("AEGIS_AGENT_CA_KEY", "certs/agent-ca.key")

	c.TLS.CertFile = get("AEGIS_TLS_CERT", "")
	c.TLS.KeyFile = get("AEGIS_TLS_KEY", "")

	// The compose stack sets AEGIS_SCANNER_NMAP_PATH; bare/native dev uses
	// AEGIS_NMAP_PATH. Both are honored (scanner-prefixed name wins) so an
	// override can never silently degrade the scanner to the simulated
	// engine while nmap is actually installed elsewhere.
	c.Scanner.NmapPath = get2("AEGIS_SCANNER_NMAP_PATH", "AEGIS_NMAP_PATH", "/usr/bin/nmap")
	c.Scanner.ZgrabPath = get("AEGIS_ZGRAB_PATH", "/usr/local/bin/zgrab2")
	c.Scanner.NucleiPath = get("AEGIS_NUCLEI_PATH", "/usr/local/bin/nuclei")
	c.Scanner.MasscanPath = get("AEGIS_MASSCAN_PATH", "")
	c.Scanner.MaxConcurrency = getInt("AEGIS_SCAN_MAX_CONCURRENCY", 4)
	c.Scanner.MaxTargets = getInt("AEGIS_SCAN_MAX_TARGETS", 65536)
	c.Scanner.MaxPacketRate = getInt("AEGIS_SCAN_MAX_PACKET_RATE", 500)
	c.Scanner.MaxRuntime = getDur("AEGIS_SCAN_MAX_RUNTIME", 4*time.Hour)
	c.Scanner.AllowPublicScope = getBool("AEGIS_SCAN_ALLOW_PUBLIC_SCOPES", false)
	c.Scanner.SiteID = get("AEGIS_SCANNER_SITE_ID", "")
	c.Scanner.ScannerName = get("AEGIS_SCANNER_NAME", "")
	c.Scanner.Mode = get("AEGIS_SCANNER_MODE", "embedded")
	c.Scanner.HubAddr = get("AEGIS_SCANNER_HUB_ADDR", "")
	c.Scanner.HubToken = get("AEGIS_SCANNER_HUB_TOKEN", "")
	c.Scanner.HubCAPath = get("AEGIS_SCANNER_HUB_CA", "")
	c.Scanner.Capabilities = getSlice("AEGIS_SCANNER_CAPABILITIES",
		[]string{"ipv4", "ipv6", "tcp_connect", "service_detection", "os_guess"})

	// Agent-less SSH collection. Hosts are
	// "user@host[:port],user@host[:port]" — the collection is read-only.
	c.SSHScan = struct {
		Hosts     []SSHHost
		User      string
		Password  string
		KeyPath   string
		Timeout   time.Duration
		Insecure  bool
		PinnedKey string
	}{
		Hosts:     parseSSHHosts(get("AEGIS_SSH_SCAN_HOSTS", "")),
		User:      get("AEGIS_SSH_SCAN_USER", "root"),
		Password:  get("AEGIS_SSH_SCAN_PASSWORD", ""),
		KeyPath:   get("AEGIS_SSH_SCAN_KEY_PATH", ""),
		Timeout:   getDur("AEGIS_SSH_SCAN_TIMEOUT", 60*time.Second),
		Insecure:  getBool("AEGIS_SSH_SCAN_HOST_KEY_POLICY", false) || get("AEGIS_SSH_SCAN_HOST_KEY_POLICY", "") == "insecure",
		PinnedKey: get("AEGIS_SSH_SCAN_PINNED_KEY", ""),
	}

	c.Feeds.Enabled = getSlice("AEGIS_FEEDS_ENABLED",
		[]string{"nvd", "kev", "epss", "cvelistv5"})
	c.Feeds.Interval = getDur("AEGIS_FEEDS_INTERVAL", 6*time.Hour)
	c.Feeds.CVEListURL = get("AEGIS_FEED_CVELIST_URL", "")
	// Optional but strongly recommended in production: raises NVD from 5
	// requests/30s to 50 and makes the first full sync minutes instead of
	// ~half an hour. Request one at https://data.nist.gov (NVD API key).
	c.Feeds.NVDAPIKey = get("AEGIS_NVD_API_KEY", "")
	// Distro OVAL snapshots. Off by default —
	// full snapshots are large; opt in per distro release:
	//   AEGIS_FEED_OVAL_SOURCES=ubuntu:22.04:https://...bz2:bz2,debian:12:https://...
	c.Feeds.OvalSources = parseOvalSources(get("AEGIS_FEED_OVAL_SOURCES", ""))

	c.OTel.Endpoint = get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	c.OTel.SampleRatio = getFloat("AEGIS_TRACES_SAMPLE_RATIO", 0.05)

	c.Connector.PublicAddr = get("AEGIS_CONNECTOR_PUBLIC_ADDR", deriveGRPCPublicAddr(c.PublicURL, c.GRPCAddr))
	c.Connector.EnrollTokenTTL = getDur("AEGIS_CONNECTOR_TOKEN_TTL", 24*time.Hour)

	c.DemoMode = getBool("AEGIS_DEMO_MODE", false)
	c.WorkerQueues = getSlice("AEGIS_WORKER_QUEUES", nil)

	if err := c.validate(service); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) validate(service string) error {
	// The agent binary runs on customer endpoints and needs no infra URLs.
	if service == "agent" {
		if get("AEGIS_SERVER_URL", "") == "" && c.HTTPAddr == ":8080" {
			// allowed: agent config file may provide the server URL
		}
		return nil
	}
	var missing []string
	if c.DatabaseURL == "" {
		missing = append(missing, "AEGIS_DATABASE_URL")
	}
	if service != "feed-worker" && c.NATSURL == "" {
		missing = append(missing, "AEGIS_NATS_URL")
	}
	if service == "server" {
		if len(c.Auth.JWTSecret) < 32 && c.Env == "production" {
			return fmt.Errorf("config: AEGIS_JWT_SECRET must be at least 32 chars in production")
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: missing required environment variables: %s", strings.Join(missing, ", "))
	}
	return nil
}

// IsProduction reports whether the service runs with production defaults.
func (c *Config) IsProduction() bool { return c.Env == "production" }

func get(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

// get2 returns the first non-empty value among the candidate keys, falling
// back to def. Used where both an AEGIS_-prefixed and a legacy bare name are
// accepted (AEGIS_ takes precedence).
func get2(keyA, keyB, def string) string {
	if v := get(keyA, ""); v != "" {
		return v
	}
	return get(keyB, def)
}

func get2Bool(keyA, keyB string, def bool) bool {
	if v, ok := os.LookupEnv(keyA); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return getBool(keyB, def)
}

func getBool(key string, def bool) bool {
	if v, ok := os.LookupEnv(key); ok {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return def
}

func getInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return n
		}
	}
	return def
}

func getFloat(key string, def float64) float64 {
	if v, ok := os.LookupEnv(key); ok {
		if f, err := strconv.ParseFloat(strings.TrimSpace(v), 64); err == nil {
			return f
		}
	}
	return def
}

func getDur(key string, def time.Duration) time.Duration {
	if v, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err == nil {
			return d
		}
	}
	return def
}

func getSlice(key string, def []string) []string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		parts := strings.Split(v, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return def
}

// OvalSource mirrors feeds.OvalSource without importing the feeds package
// (config must not depend on feed implementations).
type OvalSource struct {
	Family   string
	Release  string
	URL      string
	Compress string
}

// parseOvalSources parses AEGIS_FEED_OVAL_SOURCES:
// family:release:URL[:bz2|gz|zip|none], comma-separated.
func parseOvalSources(raw string) []OvalSource {
	out := []OvalSource{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		head := strings.SplitN(part, ":", 3)
		if len(head) < 3 {
			continue
		}
		src := OvalSource{Family: strings.TrimSpace(head[0]), Release: strings.TrimSpace(head[1]), URL: strings.TrimSpace(head[2])}
		for _, ext := range []string{"bz2", "gz", "gzip", "zip", "none"} {
			if suffix := ":" + ext; strings.HasSuffix(src.URL, suffix) {
				src.URL = strings.TrimSuffix(src.URL, suffix)
				src.Compress = ext
				break
			}
		}
		out = append(out, src)
	}
	return out
}

// SSHHost is one agent-less SSH collection target.
type SSHHost struct {
	User string
	Host string
	Port int
}

// parseSSHHosts parses "user@host[:port],user@host[:port]" lists. The user
// part is optional when AEGIS_SSH_SCAN_USER provides a default.
func parseSSHHosts(raw string) []SSHHost {
	out := []SSHHost{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		user := ""
		if at := strings.IndexByte(part, '@'); at > 0 {
			user = part[:at]
			part = part[at+1:]
		}
		host, port := part, 0
		if h, p, err := net.SplitHostPort(part); err == nil {
			host = h
			if n, err := strconv.Atoi(p); err == nil {
				port = n
			}
		}
		if host == "" {
			continue
		}
		out = append(out, SSHHost{User: user, Host: host, Port: port})
	}
	return out
}

// deriveGRPCPublicAddr guesses the externally reachable gRPC endpoint from
// the public URL's host when AEGIS_CONNECTOR_PUBLIC_ADDR is not set. The
// gRPC listener is a separate port (default :9090), so only the host part
// is reused; operators override via the env var in real deployments.
func deriveGRPCPublicAddr(publicURL, grpcAddr string) string {
	host := ""
	if u, err := url.Parse(publicURL); err == nil && u.Hostname() != "" {
		host = u.Hostname()
	}
	if host == "" {
		if h, _, err := net.SplitHostPort(grpcAddr); err == nil && h != "" && h != "0.0.0.0" && !strings.HasPrefix(h, "[::]") {
			host = h
		}
	}
	if host == "" {
		return ""
	}
	_, port, err := net.SplitHostPort(grpcAddr)
	if err != nil || port == "" {
		port = "9090"
	}
	return net.JoinHostPort(host, port)
}
