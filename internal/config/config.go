package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Listen    string          `yaml:"listen"`
	Upstream  string          `yaml:"upstream"`
	Mode      string          `yaml:"mode"`      // "observe", "challenge", "tarpit", "auto"
	RulesDir  string          `yaml:"rules_dir"` // override for detector/tls/payload YAMLs
	TLS       TLSConfig       `yaml:"tls"`
	Detector  DetectorConfig  `yaml:"detector"`
	Tarpit    TarpitConfig    `yaml:"tarpit"`
	Challenge ChallengeConfig `yaml:"challenge"`
	Metrics   MetricsConfig   `yaml:"metrics"`
	Capture   CaptureConfig   `yaml:"capture"`
	Persist   PersistConfig   `yaml:"persist"`
	// UploadPolicies define explicit upload routes. They let operators
	// allow large request bodies only on known paths, with method,
	// content-type, size, and authentication gates before proxying.
	UploadPolicies []UploadPolicyConfig `yaml:"upload_policies"`
	// Verifiers configure the short-circuit authenticator chain that
	// runs ahead of the score system. Used for server-to-server
	// (HMAC, JWT), service-mesh (mTLS header), and other
	// non-browser-token paths.
	Verifiers VerifiersConfig `yaml:"verifiers"`
}

// VerifiersConfig collects all the alternate authenticators. Each
// sub-block has an enabled flag; disabled verifiers don't load any
// state. The proxy walks the chain in the order documented here:
// HMAC first (request-bound signature, no replay), then Bearer
// (opaque static token). Operators that need cookie- or
// header-based bypass with JWT/callout validation use the cookie /
// header verifier blocks (see docs/design/credential-verifiers.md).
type VerifiersConfig struct {
	HMAC    HMACVerifierConfig     `yaml:"hmac"`
	Bearer  BearerVerifierConfig   `yaml:"bearer"`
	Cookies []CookieVerifierConfig `yaml:"cookies"`
	Headers []HeaderVerifierConfig `yaml:"headers"`
}

// HeaderVerifierConfig is one entry under verifiers.headers. Each
// entry binds a request header name to a validator (same validator
// types as cookies — opaque today, jwt and callout in ships #4, #5).
type HeaderVerifierConfig struct {
	Name      string `yaml:"name"`      // header name (required)
	Validator string `yaml:"validator"` // "opaque" | "jwt" | "callout"
	TokensDir string `yaml:"tokens_dir"`

	// JWT validator fields (only used when Validator=="jwt").
	JWKSURL         string   `yaml:"jwks_url"`
	Issuer          string   `yaml:"issuer"`
	Audience        string   `yaml:"audience"`
	ClientClaim     string   `yaml:"client_claim"`
	Algorithms      []string `yaml:"algorithms"`
	RefreshInterval string   `yaml:"refresh_interval"`

	// Callout validator fields (only used when Validator=="callout").
	URL        string `yaml:"url"`
	CacheTTL   string `yaml:"cache_ttl"`
	Timeout    string `yaml:"timeout"`
	AuthHeader string `yaml:"auth_header"`
	AuthValue  string `yaml:"auth_value"`
}

// CookieVerifierConfig is one entry under verifiers.cookies. Each
// entry binds a cookie name to a validator. The validator type
// dictates which other fields are required:
//
//	validator=opaque  → tokens_dir is required
//	validator=jwt     → jwks_url + required_claims (ship #4)
//	validator=callout → url + cache_ttl                (ship #5)
//
// Unrecognised validator types are rejected at startup so a typo
// does not silently disable the verifier.
type CookieVerifierConfig struct {
	Name      string `yaml:"name"`      // cookie name (required)
	Validator string `yaml:"validator"` // "opaque" | "jwt" | "callout"
	TokensDir string `yaml:"tokens_dir"`

	// JWT validator fields (only used when Validator=="jwt").
	JWKSURL         string   `yaml:"jwks_url"`
	Issuer          string   `yaml:"issuer"`
	Audience        string   `yaml:"audience"`
	ClientClaim     string   `yaml:"client_claim"`
	Algorithms      []string `yaml:"algorithms"`
	RefreshInterval string   `yaml:"refresh_interval"` // duration string, e.g. "1h"

	// Callout validator fields (only used when Validator=="callout").
	URL        string `yaml:"url"`
	CacheTTL   string `yaml:"cache_ttl"` // duration string, e.g. "30s"
	Timeout    string `yaml:"timeout"`
	AuthHeader string `yaml:"auth_header"`
	AuthValue  string `yaml:"auth_value"`
}

// BearerVerifierConfig is the operator-tunable surface for the opaque
// bearer-token verifier. Tokens are static secrets compared by
// sha256; they carry no per-request replay protection, so operators
// must rely on TLS and rotate on suspected compromise. The GitHub
// personal-access-token and Stripe-API-key model.
type BearerVerifierConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Header    string `yaml:"header"`     // default "Authorization"
	Scheme    string `yaml:"scheme"`     // default "Bearer" when Header=Authorization, else empty
	TokensDir string `yaml:"tokens_dir"` // required when enabled
}

// HMACVerifierConfig is the operator-tunable surface for the
// Stripe-style request-signature verifier.
type HMACVerifierConfig struct {
	Enabled         bool   `yaml:"enabled"`
	HeaderSignature string `yaml:"header_signature"` // default "X-Veilgate-Signature"
	HeaderClient    string `yaml:"header_client"`    // default "X-Veilgate-Client"
	ClockSkewSec    int    `yaml:"clock_skew_sec"`   // default 300
	MaxBodyBytes    int64  `yaml:"max_body_bytes"`   // default 1 MiB
	ClientsDir      string `yaml:"clients_dir"`      // required when enabled
}

// UploadPolicyConfig describes one explicit file-upload route policy.
// Path matching is intentionally NGINX-like but small: exact paths match
// literally, and entries ending in "/*" match that path prefix.
type UploadPolicyConfig struct {
	Name                string   `yaml:"name"`
	Paths               []string `yaml:"paths"`
	Methods             []string `yaml:"methods"`
	MaxBodyBytes        int64    `yaml:"max_body_bytes"`
	AllowedContentTypes []string `yaml:"allowed_content_types"`
	RequireAuth         bool     `yaml:"require_auth"`
	// VerifierPolicy controls verifier use on this upload route.
	// "" / "normal" use the full verifier chain. "skip_body_hmac"
	// skips the HMAC verifier so large request bodies are not read and
	// truncated while checking upload authentication.
	VerifierPolicy string `yaml:"verifier_policy"`
	// UpstreamResponseTimeout overrides the normal reverse-proxy
	// ResponseHeaderTimeout for this upload policy. Use "0" or empty
	// to disable the response-header timeout, which is often required
	// when an upstream processes the upload before responding.
	UpstreamResponseTimeout string `yaml:"upstream_response_timeout"`
}

// PersistConfig is the SQLite event store. When enabled, takes the place
// of the JSONL capture path — an operator usually runs one or the other.
type PersistConfig struct {
	Enabled       bool   `yaml:"enabled"`
	Path          string `yaml:"path"`           // e.g. /var/lib/veilgate/events.db
	RetentionDays int    `yaml:"retention_days"` // Trim rows older than this; 0 disables
	FlushEvery    int    `yaml:"flush_every_ms"` // batch-commit interval; 0 uses default
	QueueSize     int    `yaml:"queue_size"`     // channel buffer; 0 uses default
	DumpPath      string `yaml:"dump_path"`      // directory for rotated CSV.gz; empty disables
	CacheSizeKB   int    `yaml:"cache_size_kb"`  // SQLite page cache; 0 uses default (64 MB)
}

// CaptureConfig controls JSONL logging of every request's score + signals.
// Use this to collect real-traffic training data for the ML signal.
//
// Defaults are tightened over the legacy behaviour: file mode 0600, no
// scrub rules, no retention. Operators are expected to enable retention
// and scrub for any capture that holds production traffic.
type CaptureConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Path           string `yaml:"path"`            // e.g. /var/log/veilgate/requests.jsonl
	MaxMB          int    `yaml:"max_mb"`          // rotate when file exceeds this size
	RetentionHours int    `yaml:"retention_hours"` // janitor deletes rotated files older than this; 0 = forever
	JanitorEvery   string `yaml:"janitor_every"`   // duration string (e.g. "1h"); default 1h when retention is set
	FileMode       int    `yaml:"file_mode"`       // POSIX mode (octal). 0 = 0o600 default. Set 0o644 for compatibility.
	// Scrub is a list of regex/replace pairs applied to each JSONL line
	// before it is written. Use it for redaction of obvious-PII shapes
	// like Bearer tokens or password=… in query strings.
	Scrub []ScrubSpec `yaml:"scrub"`
}

// ScrubSpec is one regex/replace pair for capture-line redaction.
// Invalid regexes are skipped at compile time.
type ScrubSpec struct {
	Pattern string `yaml:"regex"`
	Replace string `yaml:"replace"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type ChallengeConfig struct {
	Secret        string `yaml:"secret"`
	Difficulty    int    `yaml:"difficulty"`
	TTLMinutes    int    `yaml:"ttl_minutes"`
	MaxTTLMinutes int    `yaml:"max_ttl_minutes"`
}

type DetectorConfig struct {
	ScoreTarpitThreshold    int      `yaml:"score_tarpit_threshold"`
	ScoreChallengeThreshold int      `yaml:"score_challenge_threshold"`
	ProbePaths              []string `yaml:"probe_paths"`
	TrustedIPs              []string `yaml:"trusted_ips"`
	// TrustedProxies are CIDRs (or exact IPs) whose X-Forwarded-For we respect.
	// Empty list = never honor XFF (stops Log4Shell/XSS injection into the header).
	TrustedProxies []string `yaml:"trusted_proxies"`
	WindowSeconds  int      `yaml:"window_seconds"`
}

type TarpitConfig struct {
	MinLatencyMs int `yaml:"min_latency_ms"`
	MaxLatencyMs int `yaml:"max_latency_ms"`
	MaxBodyBytes int `yaml:"max_body_bytes"`
	// ResponseCacheTTLMinutes controls how long a rendered tarpit response is
	// held in the per-IP cache. Agents that re-fetch the same path within this
	// window receive byte-identical responses. Default: 30.
	ResponseCacheTTLMinutes int `yaml:"response_cache_ttl_minutes"`
	// ResponseCacheMaxSize caps the total number of cached (clientID, path)
	// entries. Once the cap is hit, new entries are dropped until an expired
	// entry is evicted. Default: 50000.
	ResponseCacheMaxSize int `yaml:"response_cache_max_size"`
}

type MetricsConfig struct {
	Listen string `yaml:"listen"`
	APIKey string `yaml:"api_key"` // bearer token required on /api/* endpoints; empty = no auth
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Listen == "" {
		c.Listen = ":8080"
	}
	if c.Mode == "" {
		c.Mode = "observe"
	}
	if c.Detector.ScoreTarpitThreshold == 0 {
		c.Detector.ScoreTarpitThreshold = 70
	}
	if c.Detector.ScoreChallengeThreshold == 0 {
		c.Detector.ScoreChallengeThreshold = 40
	}
	if c.Detector.WindowSeconds == 0 {
		c.Detector.WindowSeconds = 90
	}
	if c.Tarpit.MinLatencyMs == 0 {
		c.Tarpit.MinLatencyMs = 500
	}
	if c.Tarpit.MaxLatencyMs == 0 {
		c.Tarpit.MaxLatencyMs = 3000
	}
	if c.Tarpit.MaxBodyBytes == 0 {
		c.Tarpit.MaxBodyBytes = 100 * 1024
	}
	if c.Tarpit.ResponseCacheTTLMinutes == 0 {
		c.Tarpit.ResponseCacheTTLMinutes = 30
	}
	if c.Tarpit.ResponseCacheMaxSize == 0 {
		c.Tarpit.ResponseCacheMaxSize = 50_000
	}
	if c.Metrics.Listen == "" {
		c.Metrics.Listen = ":9090"
	}
	if c.Challenge.Secret == "" {
		c.Challenge.Secret = "change-me-in-production-or-set-VEILGATE_SECRET"
	}
	if c.Challenge.Difficulty == 0 {
		c.Challenge.Difficulty = 4
	}
	if c.Challenge.TTLMinutes == 0 {
		c.Challenge.TTLMinutes = 30
	}
	if c.Challenge.MaxTTLMinutes == 0 {
		c.Challenge.MaxTTLMinutes = 60
	}
	if len(c.Detector.ProbePaths) == 0 {
		c.Detector.ProbePaths = []string{
			"/admin-panel-v2",
			"/api/internal/debug",
			"/api/internal/flush-cache",
			"/api/internal/profiler",
			"/api/internal/rpc",
			"/api/internal/metrics",
			"/.git/config",
			"/.env.backup",
			"/wp-admin-old",
			"/phpmyadmin-backup",
			"/api/webhooks/stripe/test",
			"/v1/secret/data/prod",
			"/_cat/indices",
			"/oauth2/token",
			"/api/ai/completions",
		}
	}
	if c.Capture.MaxMB == 0 {
		c.Capture.MaxMB = 100
	}
	if c.Persist.Path == "" {
		c.Persist.Path = "events.db"
	}
	if c.Persist.RetentionDays == 0 {
		c.Persist.RetentionDays = 30
	}
	// Expand ~ in path fields so operators can write "~/.veilgate/rules"
	// in the config and get a correct absolute path at runtime.
	c.RulesDir = expandHome(c.RulesDir)
	c.Persist.Path = expandHome(c.Persist.Path)
	c.Persist.DumpPath = expandHome(c.Persist.DumpPath)
	c.Capture.Path = expandHome(c.Capture.Path)
}

// expandHome replaces a leading "~" with the current user's home
// directory. Returns the path unchanged when it does not start with "~"
// or when the home directory cannot be determined.
func expandHome(p string) string {
	if !strings.HasPrefix(p, "~/") && p != "~" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[1:])
}
