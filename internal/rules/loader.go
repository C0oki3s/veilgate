// Package rules loads detection rules, TLS fingerprints, and payload
// templates from external YAML files. Defaults ship embedded in the binary;
// operators can override by setting `rules_dir` in veilgate.yaml.
package rules

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

//go:embed defaults/detector.yaml
var embeddedDetector []byte

//go:embed defaults/tls_fingerprints.yaml
var embeddedTLS []byte

//go:embed defaults/payloads.yaml
var embeddedPayloads []byte

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
		MinEvents       int     `yaml:"min_events"`
		MinMeanSeconds  float64 `yaml:"min_mean_seconds"`
		MaxMeanSeconds  float64 `yaml:"max_mean_seconds"`
		StrictCVMax     float64 `yaml:"strict_cv_max"`
		StrictPoints    int     `yaml:"strict_points"`
		LooseCVMax      float64 `yaml:"loose_cv_max"`
		LoosePoints     int     `yaml:"loose_points"`
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
	Termination []PayloadTemplate `yaml:"termination"`
	RabbitHole  []PayloadTemplate `yaml:"rabbit_hole"`
	CostBomb    []PayloadTemplate `yaml:"cost_bomb"`
	Confusion   []PayloadTemplate `yaml:"confusion"`
	MoralAppeal []PayloadTemplate `yaml:"moral_appeal"`

	Generators struct {
		LogBurst LogBurstConfig `yaml:"log_burst"`
	} `yaml:"generators"`
}

// LoadDetector reads detector.yaml from dir, or falls back to the embedded
// defaults when dir is empty or the file is missing.
func LoadDetector(dir string) (*Detector, error) {
	raw, err := readOrEmbed(dir, "detector.yaml", embeddedDetector)
	if err != nil {
		return nil, err
	}
	var d Detector
	if err := yaml.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("parse detector.yaml: %w", err)
	}
	return &d, nil
}

// LoadTLS reads tls_fingerprints.yaml or embedded defaults.
func LoadTLS(dir string) (*TLSFingerprints, error) {
	raw, err := readOrEmbed(dir, "tls_fingerprints.yaml", embeddedTLS)
	if err != nil {
		return nil, err
	}
	var t TLSFingerprints
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("parse tls_fingerprints.yaml: %w", err)
	}
	return &t, nil
}

// LoadPayloads reads payloads.yaml or embedded defaults.
func LoadPayloads(dir string) (*Payloads, error) {
	raw, err := readOrEmbed(dir, "payloads.yaml", embeddedPayloads)
	if err != nil {
		return nil, err
	}
	var p Payloads
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("parse payloads.yaml: %w", err)
	}
	return &p, nil
}

func readOrEmbed(dir, name string, embedded []byte) ([]byte, error) {
	if dir == "" {
		return embedded, nil
	}
	path := filepath.Join(dir, name)
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return embedded, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	return raw, nil
}
