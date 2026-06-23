package admin

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SignalDef describes a known VeilGate detection signal.
type SignalDef struct {
	Name    string
	Group   string
	Default int
	Desc    string
}

// KnownSignals is the authoritative list of built-in signals. The order
// within each group matches the evaluation order in scorer.go.
var KnownSignals = []SignalDef{
	// ── Header Shape ─────────────────────────────────────────────────────
	{Name: "suspicious_ua", Group: "Header Shape", Default: 35,
		Desc: "User-Agent matched a known scanner, tool, or LLM client substring"},
	{Name: "empty_ua", Group: "Header Shape", Default: 20,
		Desc: "Request carries no User-Agent header"},
	{Name: "missing_browser_headers", Group: "Header Shape", Default: 15,
		Desc: "Browser-native headers (Accept, Accept-Language, etc.) absent; tiered by count"},

	// ── Browser Consistency ───────────────────────────────────────────────
	{Name: "browser_header_consistency", Group: "Browser Consistency", Default: 20,
		Desc: "Accept/Accept-Language/Accept-Encoding profile doesn't match claimed UA family"},

	// ── Timing ────────────────────────────────────────────────────────────
	{Name: "strict_timing", Group: "Timing", Default: 40,
		Desc: "Inter-request intervals extremely regular (CV < 0.15) — automated loop"},
	{Name: "loose_timing", Group: "Timing", Default: 20,
		Desc: "Intervals regular but less extreme (CV < 0.35)"},

	// ── Toolchain ─────────────────────────────────────────────────────────
	{Name: "toolchain_full", Group: "Toolchain", Default: 60,
		Desc: "Path or header matches multiple toolchain indicators simultaneously"},
	{Name: "toolchain_partial", Group: "Toolchain", Default: 25,
		Desc: "Single toolchain indicator (recon path, exploit marker, or tool UA)"},
	{Name: "wordlist_paths", Group: "Toolchain", Default: 30,
		Desc: "Path substring matches directory-busting wordlist (dirsearch, ffuf, etc.)"},
	{Name: "injection_markers", Group: "Toolchain", Default: 40,
		Desc: "SQLi/XSS/SSRF/LFI/Log4Shell/command-injection payload in path, query, or headers"},
	{Name: "oob_interaction", Group: "Toolchain", Default: 50,
		Desc: "OOB callback host (interactsh, burpcollaborator) detected in request"},
	{Name: "path_bruteforce", Group: "Toolchain", Default: 25,
		Desc: "Many distinct paths probed inside the scoring window (wordlist bruteforcer)"},

	// ── Path / Payload ────────────────────────────────────────────────────
	{Name: "honeypot_hit", Group: "Path / Payload", Default: 50,
		Desc: "Requested a path published only in honeypot bait (route-manifest or well-known)"},
	{Name: "probe_path", Group: "Path / Payload", Default: 35,
		Desc: "Requested a path in detector.probe_paths (admin panels, debug endpoints)"},
	{Name: "api_blueprint_miss", Group: "Path / Payload", Default: 30,
		Desc: "Requested a path absent from the loaded OpenAPI blueprint — agent mapping the surface"},

	// ── IP / Rotation ─────────────────────────────────────────────────────
	{Name: "ip_reputation", Group: "IP / Rotation", Default: 20,
		Desc: "Source IP falls in a known-bad category (cloud egress, VPN, Tor, datacenter proxy)"},
	{Name: "fleet_rotation", Group: "IP / Rotation", Default: 30,
		Desc: "Same TLS/H2/UA fingerprint seen across rotating source IPs — distributed fleet"},
	{Name: "ua_rotation", Group: "IP / Rotation", Default: 25,
		Desc: "User-Agent changed between requests in the same client window"},
	{Name: "public_ip_rotation", Group: "IP / Rotation", Default: 20,
		Desc: "Multiple distinct public IPs with shared behavioral fingerprint"},

	// ── TLS / HTTP2 ───────────────────────────────────────────────────────
	{Name: "tls_fingerprint", Group: "TLS / HTTP2", Default: 40,
		Desc: "JA3 or JA4 fingerprint matches a known scanner or automated tool (requires TLS mode)"},
	{Name: "h2_fingerprint", Group: "TLS / HTTP2", Default: 35,
		Desc: "HTTP/2 SETTINGS + HEADERS frame fingerprint anomaly vs. known browser profiles"},
	{Name: "h2_settings_anomaly", Group: "TLS / HTTP2", Default: 20,
		Desc: "HTTP/2 SETTINGS values atypical for any known browser client"},
	{Name: "h2_header_order", Group: "TLS / HTTP2", Default: 15,
		Desc: "HTTP/2 pseudo-header order deviates from RFC/browser convention"},

	// ── Session / Behavioral ──────────────────────────────────────────────
	{Name: "schema_first", Group: "Session / Behavioral", Default: 25,
		Desc: "First requests in a session targeted schema or docs endpoints — agent recon pattern"},
	{Name: "cache_miss_anomaly", Group: "Session / Behavioral", Default: 20,
		Desc: "Cache-Control: no-cache / Pragma: no-cache used systematically — scraper pattern"},
	{Name: "auth_probe_sequence", Group: "Session / Behavioral", Default: 30,
		Desc: "Auth endpoints probed in a predictable reconnaissance sequence"},
	{Name: "canary_replay", Group: "Session / Behavioral", Default: 80,
		Desc: "Token embedded in a tarpit response was replayed in a subsequent real request"},
	{Name: "failure_recovery", Group: "Session / Behavioral", Default: 15,
		Desc: "Rapid retries after 4xx/5xx responses — automated failure recovery loop"},
	{Name: "request_rate", Group: "Session / Behavioral", Default: 20,
		Desc: "Request rate exceeds the configured threshold within the scoring window"},

	// ── ML ────────────────────────────────────────────────────────────────
	{Name: "ml_score", Group: "ML", Default: 30,
		Desc: "Online Bayesian classifier and pattern miner contribution to the total score"},

	// ── Custom ────────────────────────────────────────────────────────────
	{Name: "custom", Group: "Custom", Default: 0,
		Desc: "Operator-defined custom signal rules (see rules/detector.yaml → custom)"},
}

// SignalGroups returns KnownSignals grouped by Group in declaration order.
func SignalGroups() []struct {
	Name    string
	Signals []SignalDef
} {
	seen := map[string]bool{}
	var order []string
	for _, s := range KnownSignals {
		if !seen[s.Group] {
			seen[s.Group] = true
			order = append(order, s.Group)
		}
	}
	groups := make([]struct {
		Name    string
		Signals []SignalDef
	}, len(order))
	idx := map[string]int{}
	for i, g := range order {
		groups[i].Name = g
		idx[g] = i
	}
	for _, s := range KnownSignals {
		i := idx[s.Group]
		groups[i].Signals = append(groups[i].Signals, s)
	}
	return groups
}

// ── signals.yaml file model ────────────────────────────────────────────────
// Matches the format documented in docs/config/rules/signals.md.

// SignalOverride is one entry under `signals:` in signals.yaml.
// Only list signals you want to change — absent signals use engine defaults.
type SignalOverride struct {
	Enabled     *bool  `yaml:"enabled,omitempty"  json:"enabled,omitempty"`
	Points      *int   `yaml:"points,omitempty"   json:"points,omitempty"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// CustomSignalCondition is one condition inside a custom_signal entry.
type CustomSignalCondition struct {
	Type  string `yaml:"type"  json:"type"`
	Value string `yaml:"value" json:"value"`
	Name  string `yaml:"name,omitempty" json:"name,omitempty"`
}

// CustomSignal is one entry under `custom_signals:` in signals.yaml.
type CustomSignal struct {
	Name        string                  `yaml:"name"                   json:"name"`
	Description string                  `yaml:"description,omitempty"  json:"description,omitempty"`
	Enabled     bool                    `yaml:"enabled"                json:"enabled"`
	Points      int                     `yaml:"points"                 json:"points"`
	Conditions  []CustomSignalCondition `yaml:"conditions"             json:"conditions"`
}

// SignalsFile is the parsed signals.yaml document.
// Both keys are optional per the docs.
type SignalsFile struct {
	Signals       map[string]SignalOverride `yaml:"signals,omitempty"        json:"signals,omitempty"`
	CustomSignals []CustomSignal            `yaml:"custom_signals,omitempty" json:"custom_signals,omitempty"`
}

// loadSignalsFile reads and parses the signals.yaml from rulesDir.
// Returns an empty SignalsFile if the file does not exist.
func loadSignalsFile(rulesDir string) (SignalsFile, error) {
	var sf SignalsFile
	path := filepath.Join(rulesDir, "signals.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sf, nil
		}
		return sf, err
	}
	return sf, yaml.Unmarshal(b, &sf)
}

// marshalSignalsFile serialises a SignalsFile to YAML, emitting only the
// keys that are actually set so the file stays minimal per the docs.
func marshalSignalsFile(sf SignalsFile) (string, error) {
	// Remove zero-value entries from Signals map
	clean := make(map[string]SignalOverride, len(sf.Signals))
	for k, v := range sf.Signals {
		// Only keep if something is actually overridden
		if v.Enabled != nil || (v.Points != nil && *v.Points > 0) || v.Description != "" {
			clean[k] = v
		}
	}
	sf.Signals = clean
	if len(sf.Signals) == 0 {
		sf.Signals = nil
	}

	b, err := yaml.Marshal(sf)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
