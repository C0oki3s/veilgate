package config

import (
	"fmt"
	"os"

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
	// Verifiers configure the short-circuit authenticator chain that
	// runs ahead of the score system. Used for server-to-server
	// (HMAC, JWT), service-mesh (mTLS header), and other
	// non-browser-token paths.
	Verifiers VerifiersConfig `yaml:"verifiers"`
}

// VerifiersConfig collects all the alternate authenticators. Each
// sub-block has an enabled flag; disabled verifiers don't load any
// state. The proxy walks the chain in the order documented here:
// mTLS first (cheapest to verify, lowest false-positive risk), then
// HMAC.
type VerifiersConfig struct {
	HMAC HMACVerifierConfig `yaml:"hmac"`
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
	Secret     string `yaml:"secret"`
	Difficulty int    `yaml:"difficulty"`
	TTLMinutes int    `yaml:"ttl_minutes"`
}

type DetectorConfig struct {
	ScoreTarpitThreshold    int      `yaml:"score_tarpit_threshold"`
	ScoreChallengeThreshold int      `yaml:"score_challenge_threshold"`
	HoneypotPaths           []string `yaml:"honeypot_paths"`
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
}

type MetricsConfig struct {
	Listen string `yaml:"listen"`
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
	if len(c.Detector.HoneypotPaths) == 0 {
		c.Detector.HoneypotPaths = []string{
			"/admin-panel-v2",
			"/api/internal/debug",
			"/.git/config",
			"/.env.backup",
			"/wp-admin-old",
			"/phpmyadmin-backup",
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
}
