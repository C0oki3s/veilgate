// Package rules loads detection rules, TLS fingerprints, and payload
// templates from external YAML files. All rules are read from the rules_dir
// configured in veilgate.yaml — no embedded defaults are shipped.
package rules

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Detector holds scorer rule knobs loaded from detector.yaml.
type Detector struct {
	SuspiciousUserAgents struct {
		Points     int      `yaml:"points"`
		Substrings []string `yaml:"substrings"`
	} `yaml:"suspicious_user_agents"`

	BrowserHeaders struct {
		Hints []string `yaml:"hints"`
		Tiers []struct {
			Missing int `yaml:"missing"`
			Points  int `yaml:"points"`
		} `yaml:"tiers"`
	} `yaml:"browser_headers"`

	EmptyUserAgent struct {
		Points int `yaml:"points"`
	} `yaml:"empty_user_agent"`

	Toolchain struct {
		ReconPaths     []string `yaml:"recon_paths"`
		ProbePaths     []string `yaml:"probe_paths"`
		ExploitMarkers []string `yaml:"exploit_markers"`
		Points         struct {
			Full    int `yaml:"full"`
			Partial int `yaml:"partial"`
		} `yaml:"points"`
	} `yaml:"toolchain"`

	Timing struct {
		MinEvents      int     `yaml:"min_events"`
		MinMeanSeconds float64 `yaml:"min_mean_seconds"`
		MaxMeanSeconds float64 `yaml:"max_mean_seconds"`
		StrictCVMax    float64 `yaml:"strict_cv_max"`
		StrictPoints   int     `yaml:"strict_points"`
		LooseCVMax     float64 `yaml:"loose_cv_max"`
		LoosePoints    int     `yaml:"loose_points"`
	} `yaml:"timing"`

	// PathBruteforce fires when one client hits many distinct paths inside
	// the tracker's window — the fingerprint of dirsearch/ffuf/feroxbuster/nikto
	// wordlist bruteforcers even when they rotate User-Agent pools.
	PathBruteforce struct {
		Tiers []struct {
			DistinctPaths int `yaml:"distinct_paths"`
			Points        int `yaml:"points"`
		} `yaml:"tiers"`
	} `yaml:"path_bruteforce"`

	// WordlistPaths: substring markers that show up in the output of common
	// directory-busting wordlists (SecLists, dirsearch default.yml, nikto
	// db_tests.db). Catches bruteforcers even if UA is rotated.
	WordlistPaths struct {
		Points     int      `yaml:"points"`
		Substrings []string `yaml:"substrings"`
	} `yaml:"wordlist_paths"`

	// InjectionMarkers: strings that indicate an attack payload landed in
	// the path, query string, or any request header. Covers SQLi, XSS,
	// command injection, path traversal, Log4Shell, SSRF OOB.
	InjectionMarkers struct {
		Points     int      `yaml:"points"`
		Substrings []string `yaml:"substrings"`
		// Headers to also scan (beyond path + query). Case-insensitive.
		// Empty = scan all request headers.
		Headers []string `yaml:"headers"`
	} `yaml:"injection_markers"`

	// OOBInteraction: DNS/HTTP callback hosts used by nuclei, burp
	// collaborator, project discovery's interactsh, etc. A request that
	// mentions one is almost certainly part of an OOB exfil/probe template.
	OOBInteraction struct {
		Points     int      `yaml:"points"`
		Substrings []string `yaml:"substrings"`
	} `yaml:"oob_interaction"`

	// BehavioralSignals configures the session-level signals (schema_first,
	// cache_miss_anomaly, auth_probe_sequence). Lists are merged from community
	// YAML files so operators can extend without touching core rules.
	// All numeric thresholds default to sensible values when zero — operators
	// only need to set the fields they want to override.
	BehavioralSignals struct {
		// SchemaPaths holds path substrings that identify API schema endpoints.
		SchemaPaths []string `yaml:"schema_paths"`
		// AuthPathPatterns maps path substrings to category labels. Order matters.
		AuthPathPatterns []AuthPathPattern `yaml:"auth_path_patterns"`

		SchemaFirst struct {
			CheckLimit int `yaml:"check_limit"` // how many early events to inspect; default 3
			Points     int `yaml:"points"`      // default 20
		} `yaml:"schema_first"`

		CacheMissAnomaly struct {
			WindowMinutes int `yaml:"window_minutes"` // rolling window; default 3
			MinEvents     int `yaml:"min_events"`     // minimum events before signal fires; default 5
			LowThreshold  int `yaml:"low_threshold"`  // default 5
			LowPoints     int `yaml:"low_points"`     // default 10
			HighThreshold int `yaml:"high_threshold"` // default 9
			HighPoints    int `yaml:"high_points"`    // default 20
		} `yaml:"cache_miss_anomaly"`

		HeaderMutation struct {
			MinRequests   int `yaml:"min_requests"`   // request count before signal is eligible; default 6
			LowThreshold  int `yaml:"low_threshold"`  // default 5
			LowPoints     int `yaml:"low_points"`     // default 8
			MidThreshold  int `yaml:"mid_threshold"`  // default 10
			MidPoints     int `yaml:"mid_points"`     // default 15
			HighThreshold int `yaml:"high_threshold"` // default 15
			HighPoints    int `yaml:"high_points"`    // default 25
		} `yaml:"header_mutation"`

		AuthProbeSequence struct {
			MinEvents     int `yaml:"min_events"`     // default 10
			WindowMinutes int `yaml:"window_minutes"` // default 5
			LowThreshold  int `yaml:"low_threshold"`  // default 4
			LowPoints     int `yaml:"low_points"`     // default 15
			HighThreshold int `yaml:"high_threshold"` // default 6
			HighPoints    int `yaml:"high_points"`    // default 25
		} `yaml:"auth_probe_sequence"`

		NoCookieReturn struct {
			MinRequests int `yaml:"min_requests"` // default 8
			Points      int `yaml:"points"`       // default 10
		} `yaml:"no_cookie_return"`

		EncodingChain struct {
			SinglePoints int `yaml:"single_points"` // one double-enc occurrence; default 8
			MultiPoints  int `yaml:"multi_points"`  // two+ occurrences; default 15
			TriplePoints int `yaml:"triple_points"` // triple-encoding; default 20
		} `yaml:"encoding_chain"`
	} `yaml:"behavioral_signals"`
}

// AuthPathPattern is one entry in BehavioralSignals.AuthPathPatterns.
type AuthPathPattern struct {
	Pattern string `yaml:"pattern"` // required: path substring to match
	Label   string `yaml:"label"`   // required: category bucket
	Exclude string `yaml:"exclude"` // optional: suppress match if path contains this
}

// TLSFingerprints is the fingerprint database shape.
type TLSFingerprints struct {
	JA4Exact []struct {
		Hash       string `yaml:"hash"`
		Label      string `yaml:"label"`
		Category   string `yaml:"category"`
		Confidence int    `yaml:"confidence"`
	} `yaml:"ja4_exact"`
	JA4Prefix []struct {
		Prefix     string `yaml:"prefix"`
		Label      string `yaml:"label"`
		Category   string `yaml:"category"`
		Confidence int    `yaml:"confidence"`
	} `yaml:"ja4_prefix"`
	JA3Exact []struct {
		Hash       string `yaml:"hash"`
		Label      string `yaml:"label"`
		Category   string `yaml:"category"`
		Confidence int    `yaml:"confidence"`
	} `yaml:"ja3_exact"`
}

// PayloadTemplate is one entry in payloads.yaml.
type PayloadTemplate struct {
	Style     string `yaml:"style"`
	Text      string `yaml:"text"`
	Generator string `yaml:"generator"` // for programmatic renderers (e.g. log_burst)
}

// LogBurstConfig drives the `log_burst` programmatic payload generator.
// All values come from payloads.yaml so operators can tune the decoy
// log-lines without a rebuild.
type LogBurstConfig struct {
	WrapperOpen  string `yaml:"wrapper_open"`
	WrapperClose string `yaml:"wrapper_close"`
	Count        int    `yaml:"count"`
	LineFormat   string `yaml:"line_format"`
	StatusCodes  []int  `yaml:"status_codes"`
	APIVersions  int    `yaml:"api_versions"`
	MaxResource  int    `yaml:"max_resource"`
	MaxDurMs     int    `yaml:"max_dur_ms"`
	DayOfMonth   int    `yaml:"day_of_month"` // upper bound passed to rand.Intn
}

// Payloads groups payload templates by injection category.
type Payloads struct {
	Termination     []PayloadTemplate `yaml:"termination"`
	RabbitHole      []PayloadTemplate `yaml:"rabbit_hole"`
	CostBomb        []PayloadTemplate `yaml:"cost_bomb"`
	Confusion       []PayloadTemplate `yaml:"confusion"`
	MoralAppeal     []PayloadTemplate `yaml:"moral_appeal"`
	PromptInjection []PayloadTemplate `yaml:"prompt_injection"`

	Generators struct {
		LogBurst LogBurstConfig `yaml:"log_burst"`
	} `yaml:"generators"`
}

// LoadDetector reads detector.yaml from dir, then merges any community
// additions from the rules/detector/ subdirectory. Community files may
// extend any list field (substrings, paths, markers); scalar config
// (points, tiers, timing) is authoritative in detector.yaml only.
func LoadDetector(dir string) (*Detector, error) {
	var d Detector
	raw, err := readOptionalFromDir(dir, "detector.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &d); err != nil {
			return nil, fmt.Errorf("parse detector.yaml: %w", err)
		}
	}
	if err := mergeDetectorDir(filepath.Join(dir, "detector"), &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// mergeDetectorDir walks dir and merges all .yaml files into d.
// Scalar fields (points, tiers, timing) are set only when the parsed file
// carries a non-zero value, so base.yaml sets them and community files
// (which omit scalars) never overwrite them.
func mergeDetectorDir(dir string, d *Detector) error {
	return walkYAMLDir(dir, func(path string, raw []byte) error {
		var p Detector
		if err := yaml.Unmarshal(raw, &p); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		// Scalars: only overwrite when the file explicitly sets them.
		if p.SuspiciousUserAgents.Points != 0 {
			d.SuspiciousUserAgents.Points = p.SuspiciousUserAgents.Points
		}
		if p.EmptyUserAgent.Points != 0 {
			d.EmptyUserAgent.Points = p.EmptyUserAgent.Points
		}
		if p.WordlistPaths.Points != 0 {
			d.WordlistPaths.Points = p.WordlistPaths.Points
		}
		if p.InjectionMarkers.Points != 0 {
			d.InjectionMarkers.Points = p.InjectionMarkers.Points
		}
		if p.OOBInteraction.Points != 0 {
			d.OOBInteraction.Points = p.OOBInteraction.Points
		}
		if p.Toolchain.Points.Full != 0 {
			d.Toolchain.Points.Full = p.Toolchain.Points.Full
		}
		if p.Toolchain.Points.Partial != 0 {
			d.Toolchain.Points.Partial = p.Toolchain.Points.Partial
		}
		if len(p.BrowserHeaders.Tiers) > 0 {
			d.BrowserHeaders.Tiers = p.BrowserHeaders.Tiers
		}
		if len(p.PathBruteforce.Tiers) > 0 {
			d.PathBruteforce.Tiers = p.PathBruteforce.Tiers
		}
		if p.Timing.MinEvents > 0 {
			d.Timing = p.Timing
		}
		// Lists: always append.
		d.SuspiciousUserAgents.Substrings = append(d.SuspiciousUserAgents.Substrings, p.SuspiciousUserAgents.Substrings...)
		d.BrowserHeaders.Hints = append(d.BrowserHeaders.Hints, p.BrowserHeaders.Hints...)
		d.Toolchain.ReconPaths = append(d.Toolchain.ReconPaths, p.Toolchain.ReconPaths...)
		d.Toolchain.ProbePaths = append(d.Toolchain.ProbePaths, p.Toolchain.ProbePaths...)
		d.Toolchain.ExploitMarkers = append(d.Toolchain.ExploitMarkers, p.Toolchain.ExploitMarkers...)
		d.WordlistPaths.Substrings = append(d.WordlistPaths.Substrings, p.WordlistPaths.Substrings...)
		d.InjectionMarkers.Substrings = append(d.InjectionMarkers.Substrings, p.InjectionMarkers.Substrings...)
		d.InjectionMarkers.Headers = append(d.InjectionMarkers.Headers, p.InjectionMarkers.Headers...)
		d.OOBInteraction.Substrings = append(d.OOBInteraction.Substrings, p.OOBInteraction.Substrings...)
		d.BehavioralSignals.SchemaPaths = append(d.BehavioralSignals.SchemaPaths, p.BehavioralSignals.SchemaPaths...)
		d.BehavioralSignals.AuthPathPatterns = append(d.BehavioralSignals.AuthPathPatterns, p.BehavioralSignals.AuthPathPatterns...)
		return nil
	})
}

// LoadTLS reads tls_fingerprints.yaml from dir, then merges any community
// additions from rules/tls_fingerprints/.
func LoadTLS(dir string) (*TLSFingerprints, error) {
	var t TLSFingerprints
	raw, err := readOptionalFromDir(dir, "tls_fingerprints.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("parse tls_fingerprints.yaml: %w", err)
		}
	}
	if err := mergeTLSDir(filepath.Join(dir, "tls_fingerprints"), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func mergeTLSDir(dir string, t *TLSFingerprints) error {
	return walkYAMLDir(dir, func(path string, raw []byte) error {
		var patch TLSFingerprints
		if err := yaml.Unmarshal(raw, &patch); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		t.JA4Exact = append(t.JA4Exact, patch.JA4Exact...)
		t.JA4Prefix = append(t.JA4Prefix, patch.JA4Prefix...)
		t.JA3Exact = append(t.JA3Exact, patch.JA3Exact...)
		return nil
	})
}

// LoadPayloads reads payloads.yaml from dir, then merges community
// additions from rules/payloads/.
func LoadPayloads(dir string) (*Payloads, error) {
	var p Payloads
	raw, err := readOptionalFromDir(dir, "payloads.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &p); err != nil {
			return nil, fmt.Errorf("parse payloads.yaml: %w", err)
		}
	}
	if err := mergePayloadsDir(filepath.Join(dir, "payloads"), &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func mergePayloadsDir(dir string, p *Payloads) error {
	return walkYAMLDir(dir, func(path string, raw []byte) error {
		var patch Payloads
		if err := yaml.Unmarshal(raw, &patch); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		p.Termination = append(p.Termination, patch.Termination...)
		p.RabbitHole = append(p.RabbitHole, patch.RabbitHole...)
		p.CostBomb = append(p.CostBomb, patch.CostBomb...)
		p.Confusion = append(p.Confusion, patch.Confusion...)
		p.MoralAppeal = append(p.MoralAppeal, patch.MoralAppeal...)
		p.PromptInjection = append(p.PromptInjection, patch.PromptInjection...)
		// Generators: only set when the file explicitly specifies them.
		if patch.Generators.LogBurst.Count != 0 {
			p.Generators.LogBurst = patch.Generators.LogBurst
		}
		return nil
	})
}

// ── Signal registry ──────────────────────────────────────────────────────────

// SignalEntry configures one built-in detection signal from signals.yaml.
// A missing entry (signal not listed) means "enabled with default points".
type SignalEntry struct {
	// Enabled controls whether this signal contributes to the total score.
	// Set to false to silence the signal completely.
	Enabled bool `yaml:"enabled"`
	// Points overrides the default scoring weight from config.yaml.
	// Leave at 0 to keep the config.yaml default.
	Points      int    `yaml:"points"`
	Description string `yaml:"description"`
}

// CustomSignalCondition is one matching predicate inside a custom signal.
// All conditions in a custom signal must match (AND logic).
type CustomSignalCondition struct {
	// Type selects the matching strategy:
	//   path_prefix    — r.URL.Path starts with Value
	//   path_contains  — r.URL.Path contains Value (substring)
	//   path_suffix    — r.URL.Path ends with Value
	//   path_regex     — r.URL.Path matches Value (Go regex, case-sensitive)
	//   ua_contains    — User-Agent contains Value (case-insensitive)
	//   header_present — header named Name is present
	//   header_value   — header named Name contains Value (case-insensitive)
	//   query_contains — raw query string contains Value (case-insensitive)
	//   method         — HTTP method equals Value (case-insensitive)
	Type  string `yaml:"type"`
	Name  string `yaml:"name"`  // used by header_present, header_value
	Value string `yaml:"value"` // comparison value
}

// CustomSignal is an operator-defined detection rule that fires when every
// listed condition matches. It contributes Points to the request score.
type CustomSignal struct {
	Name        string                  `yaml:"name"`
	Description string                  `yaml:"description"`
	Enabled     bool                    `yaml:"enabled"`
	Points      int                     `yaml:"points"`
	Conditions  []CustomSignalCondition `yaml:"conditions"`
}

// Signals is the full signal registry loaded from signals.yaml. It controls
// which built-in signals are active, overrides their point weights, and
// defines operator-authored custom detection rules.
type Signals struct {
	Signals       map[string]SignalEntry `yaml:"signals"`
	CustomSignals []CustomSignal         `yaml:"custom_signals"`
}

// IsEnabled returns true when the named signal should fire.
// A signal not listed in the registry defaults to enabled.
func (sg *Signals) IsEnabled(name string) bool {
	if sg == nil || sg.Signals == nil {
		return true
	}
	entry, ok := sg.Signals[name]
	if !ok {
		return true
	}
	return entry.Enabled
}

// PointsFor returns the effective points for a signal. If the registry
// specifies a non-zero override, that value is returned; otherwise
// defaultPoints (from config.yaml) is used.
func (sg *Signals) PointsFor(name string, defaultPoints int) int {
	if sg == nil || sg.Signals == nil {
		return defaultPoints
	}
	entry, ok := sg.Signals[name]
	if !ok || entry.Points == 0 {
		return defaultPoints
	}
	return entry.Points
}

// LoadSignals reads signals.yaml from dir. Missing file is not an error —
// it returns an empty registry, which enables all signals with default points.
func LoadSignals(dir string) (*Signals, error) {
	var sg Signals
	raw, err := readOptionalFromDir(dir, "signals.yaml")
	if err != nil {
		return nil, err
	}
	if raw == nil {
		return &Signals{Signals: make(map[string]SignalEntry)}, nil
	}
	if err := yaml.Unmarshal(raw, &sg); err != nil {
		return nil, fmt.Errorf("parse signals.yaml: %w", err)
	}
	if sg.Signals == nil {
		sg.Signals = make(map[string]SignalEntry)
	}
	return &sg, nil
}

func readFromDir(dir, name string) ([]byte, error) {
	if dir == "" {
		return nil, fmt.Errorf("rules_dir must be set: cannot load %s without a rules directory", name)
	}
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}

// readOptionalFromDir is like readFromDir but returns (nil, nil) when the
// file does not exist. Use this for root rule files whose content has been
// moved into the corresponding community subdirectory as base.yaml.
func readOptionalFromDir(dir, name string) ([]byte, error) {
	if dir == "" {
		return nil, fmt.Errorf("rules_dir must be set: cannot load %s without a rules directory", name)
	}
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}
