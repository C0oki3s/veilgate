package rules

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// walkYAMLDir calls fn for every .yaml / .yml file under dir in
// lexicographic order, recursing into subdirectories. The directory is
// silently skipped when it does not exist.
func walkYAMLDir(dir string, fn func(path string, raw []byte) error) error {
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		return nil
	}
	return filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		return fn(path, raw)
	})
}

// TemplateResponse is one entry under `templates:` in templates.yaml.
// Body is a text/template string; Headers values are also templated.
type TemplateResponse struct {
	Status      int               `yaml:"status"`
	ContentType string            `yaml:"content_type"`
	Headers     map[string]string `yaml:"headers"`
	Body        string            `yaml:"body"`
}

// Templates is the parsed templates.yaml.
type Templates struct {
	Templates map[string]TemplateResponse `yaml:"templates"`
}

// FakeData is the parsed fake_data.yaml. Empty slices keep the renderer
// safe from panics when an operator pares a pool down to nothing.
type FakeData struct {
	Versions     []string `yaml:"versions"`
	Stacks       []string `yaml:"stacks"`
	Companies    []string `yaml:"companies"`
	AdminUsers   []string `yaml:"admin_users"`
	AdminPasses  []string `yaml:"admin_passes"`
	EmailDomains []string `yaml:"email_domains"`
}

// Vulnerabilities is the parsed vulnerabilities.yaml.
type Vulnerabilities struct {
	HoneypotPaths         []string `yaml:"honeypot_paths"`
	SQLInjectionPatterns  []string `yaml:"sql_injection_patterns"`
	FakeGitPaths          []string `yaml:"fake_git_paths"`
	FakeEnvPaths          []string `yaml:"fake_env_paths"`
}

// Lookup returns a vulnerabilities.yaml list by name.
// Used by `match: list` entries in injection_strategy.yaml.
func (v *Vulnerabilities) Lookup(name string) []string {
	if v == nil {
		return nil
	}
	switch name {
	case "honeypot_paths":
		return v.HoneypotPaths
	case "fake_git_paths":
		return v.FakeGitPaths
	case "fake_env_paths":
		return v.FakeEnvPaths
	}
	return nil
}

// Route is one entry in injection_strategy.yaml -> routes[].
type Route struct {
	Match    string   `yaml:"match"`    // prefix|exact|contains|sqli|regex|list|any
	Values   []string `yaml:"values"`
	Template string   `yaml:"template"`
}

// InjectorConfig is the injector: section of injection_strategy.yaml.
type InjectorConfig struct {
	MaxPayloadsPerResponse int                          `yaml:"max_payloads_per_response"`
	VisitBucketRotation    bool                         `yaml:"visit_bucket_rotation"`
	StyleWeights           map[string]map[string]int    `yaml:"style_weights"`
	CategoryOrder          []string                     `yaml:"category_order"`
}

// InjectionStrategy is the parsed injection_strategy.yaml.
type InjectionStrategy struct {
	Routes   []Route        `yaml:"routes"`
	Injector InjectorConfig `yaml:"injector"`
}

// ChallengeRules is the parsed challenge.yaml.
type ChallengeRules struct {
	Difficulty      int    `yaml:"difficulty"`
	TokenTTLMinutes int    `yaml:"token_ttl_minutes"`
	CookieName      string `yaml:"cookie_name"`
	StatusCode      int    `yaml:"status_code"`
	ContentType     string `yaml:"content_type"`
	VerifyPath      string `yaml:"verify_path"`
	CookiePath      string `yaml:"cookie_path"`
	HTMLTemplate    string `yaml:"html_template"`

	// Cookie scope. Empty CookieDomain leaves the cookie host-only
	// (the historical default — appropriate when veilgate is the
	// single origin). Setting it to ".example.com" issues a
	// parent-domain cookie that travels across subdomains, which is
	// what multi-subdomain deployments (app.example.com +
	// api.example.com) need. SameSite controls cross-site send
	// behaviour; "strict" is the historical default, "lax" is the
	// right pick for cross-subdomain deployments where the SPA
	// originates the request.
	CookieDomain   string `yaml:"cookie_domain"`
	CookieSameSite string `yaml:"cookie_same_site"`

	// Token header transport. When non-empty, the same token value
	// minted into the Set-Cookie is also accepted from this header.
	// Lets cross-origin SPA fetches authenticate without depending
	// on the browser's cookie SameSite/credentials story.
	TokenHeaderName string `yaml:"token_header_name"`

	// SPAAwareResponse, when true, makes the challenge handler
	// inspect the inbound request and return a 401 + JSON body
	// (with WWW-Authenticate hint) for XHR/fetch contexts instead
	// of the 503 HTML page. The HTML page is still served for
	// top-level document navigations.
	SPAAwareResponse bool `yaml:"spa_aware_response"`
}

// ML is the parsed ml.yaml.
type ML struct {
	Enabled        bool    `yaml:"enabled"`
	ScoreMaxPoints int     `yaml:"score_max_points"`
	Alpha          float64 `yaml:"alpha"`
	BurnInEvents   int     `yaml:"burn_in_events"`
	// MinConfidenceToFire: combined (Bayes + anomaly) confidence floor
	// below which the ml_agent_score signal stays silent. Range [0,1];
	// default 0.2 = 8 pts at ScoreMaxPoints=40. Raise to reduce noise
	// contribution from uncertain classifications on legit traffic.
	MinConfidenceToFire float64 `yaml:"min_confidence_to_fire"`

	Bayes struct {
		LaplaceSmoothing     float64   `yaml:"laplace_smoothing"`
		MaxNgramLength       int       `yaml:"max_ngram_length"`
		TimingBucketsSeconds []float64 `yaml:"timing_buckets_seconds"`
	} `yaml:"bayes"`

	IsoForest struct {
		TreeCount           int `yaml:"tree_count"`
		SampleSize          int `yaml:"sample_size"`
		RetrainEveryNEvents int `yaml:"retrain_every_n_events"`
		MaxDepth            int `yaml:"max_depth"`
		// TrainMaxRows caps the buffered rows handed to IsoForest.Fit.
		// 0 means "use all buffered rows". Set e.g. 2000 when ingestion
		// volume makes fits slow — Isolation Forest plateaus quickly.
		TrainMaxRows int `yaml:"train_max_rows"`
	} `yaml:"iso_forest"`

	Miner struct {
		Enabled               bool    `yaml:"enabled"`
		IntervalMinutes       int     `yaml:"interval_minutes"`
		MinSupport            int     `yaml:"min_support"`
		MinPosterior          float64 `yaml:"min_posterior"`
		AutoPromoteConfidence float64 `yaml:"auto_promote_confidence"`
		WritePath             string  `yaml:"write_path"`
	} `yaml:"miner"`

	// PathRedaction governs how high-entropy URL path segments are scrubbed
	// before they become Bayes buckets. The default ruleset (UUIDs, long
	// numeric IDs, hex, base64) is built into the binary and enabled by
	// default. Set Enabled=false to opt out (not recommended outside of
	// ML research environments). Custom rules let an operator add
	// app-specific identifiers — e.g. "MRN-12345".
	PathRedaction struct {
		Enabled bool `yaml:"enabled"`
		Custom  []struct {
			Regex   string `yaml:"regex"`
			Replace string `yaml:"replace"`
		} `yaml:"custom"`
	} `yaml:"path_redaction"`
}

// CandidateInfo holds optional human-readable metadata for a learned candidate.
// All fields are optional and never inspected by the scoring engine — they exist
// purely for operator/community review and tooling (dashboards, LLM template
// generation, rule search). Modelled after the Nuclei template info: block so
// that existing community tooling and LLM prompts transfer easily.
type CandidateInfo struct {
	// Name is a short human-readable label, e.g. "Python-requests UA token".
	Name string `yaml:"name,omitempty"`
	// Author is the GitHub username or email of the rule author.
	Author string `yaml:"author,omitempty"`
	// Severity rates the risk posed by traffic matching this rule.
	// One of: info, low, medium, high, critical.
	Severity string `yaml:"severity,omitempty"`
	// Description explains what traffic pattern this rule detects and why it
	// is agent-indicative. Markdown is accepted; keep it under ~5 lines.
	Description string `yaml:"description,omitempty"`
	// Remediation is an optional note for operators on how to tune or respond.
	Remediation string `yaml:"remediation,omitempty"`
	// Impact describes what a matched client is likely attempting.
	Impact string `yaml:"impact,omitempty"`
	// Tags is a comma-separated or YAML-list set of labels used for filtering
	// and searching rules, e.g. [scanner, python, llm-agent, ja4].
	Tags []string `yaml:"tags,omitempty"`
	// Reference is a list of URLs to threat-intel reports, CVEs, blog posts,
	// or tool documentation that contextualises the rule.
	Reference []string `yaml:"reference,omitempty"`
	// Metadata is a free-form string→string map for quality signals and
	// tooling hints. Recommended keys:
	//   verified: "true"              — tested against known-agent traffic
	//   source: "community"           — "community", "miner", or "operator"
	//   false_positive_rate: "low"    — "low", "medium", "high"
	//   min_veilgate_version: "0.4.0" — earliest compatible release
	//   tool: "nuclei"                — tool or framework that generates this UA
	Metadata map[string]string `yaml:"metadata,omitempty"`
}

// LearnedCandidate is one entry in learned.yaml -> candidates[].
// The core scoring fields (Feature, Bucket, Posterior, Support, Active)
// are required; all others are optional and do not affect scoring.
//
// Minimal (miner output, no metadata):
//
//	- feature: ua_token
//	  bucket: python-requests
//	  posterior: 0.98
//	  support: 47
//	  active: false
//
// Full (community rule with metadata):
//
//	- id: VG-UA-001
//	  feature: ua_token
//	  bucket: python-requests
//	  posterior: 0.98
//	  support: 47
//	  active: true
//	  info:
//	    name: python-requests library default UA
//	    author: community
//	    severity: medium
//	    description: |
//	      Default User-Agent emitted by the Python requests library when no
//	      custom UA is set. Heavily used by automated scanners and LLM agents.
//	    tags: [scanner, python, automation]
//	    metadata:
//	      verified: "true"
//	      source: community
//	      false_positive_rate: low
type LearnedCandidate struct {
	// ID is an optional unique rule identifier, e.g. "VG-UA-001" or
	// "COMMUNITY-JA4-CHROME-BOT". Used for deduplication and referencing.
	// The miner does not set this field; community contributors should.
	ID string `yaml:"id,omitempty"`

	Feature    string  `yaml:"feature"`
	Bucket     string  `yaml:"bucket"`
	Posterior  float64 `yaml:"posterior"`
	Support    int     `yaml:"support"`
	Active     bool    `yaml:"active"`
	ProposedAt string  `yaml:"proposed_at,omitempty"`

	// Info holds optional human-readable metadata. Never inspected by the
	// scoring engine — safe to omit in miner output and minimal rules.
	Info *CandidateInfo `yaml:"info,omitempty"`
}

// Learned is the parsed learned.yaml.
type Learned struct {
	Candidates []LearnedCandidate `yaml:"candidates"`
}

// ActiveByFeature returns the candidates flagged active, grouped by feature name.
func (l *Learned) ActiveByFeature() map[string][]string {
	if l == nil {
		return nil
	}
	out := make(map[string][]string)
	for _, c := range l.Candidates {
		if !c.Active {
			continue
		}
		out[c.Feature] = append(out[c.Feature], c.Bucket)
	}
	return out
}

// Loaders -----------------------------------------------------------

// LoadTemplates reads templates.yaml from dir (optional), then merges
// additions from rules/templates/. All files are equal peers — later files
// (lexicographic order) override earlier ones for the same key.
func LoadTemplates(dir string) (*Templates, error) {
	var t Templates
	raw, err := readOptionalFromDir(dir, "templates.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &t); err != nil {
			return nil, fmt.Errorf("parse templates.yaml: %w", err)
		}
	}
	if err := mergeTemplatesDir(filepath.Join(dir, "templates"), &t); err != nil {
		return nil, err
	}
	return &t, nil
}

func mergeTemplatesDir(dir string, t *Templates) error {
	return walkYAMLDir(dir, func(path string, raw []byte) error {
		var patch Templates
		if err := yaml.Unmarshal(raw, &patch); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		if t.Templates == nil {
			t.Templates = make(map[string]TemplateResponse)
		}
		for k, v := range patch.Templates {
			t.Templates[k] = v
		}
		return nil
	})
}

// LoadFakeData reads fake_data.yaml from dir, then merges community
// additions from rules/fake_data/. All list fields are appended.
func LoadFakeData(dir string) (*FakeData, error) {
	var f FakeData
	raw, err := readOptionalFromDir(dir, "fake_data.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &f); err != nil {
			return nil, fmt.Errorf("parse fake_data.yaml: %w", err)
		}
	}
	if err := mergeFakeDataDir(filepath.Join(dir, "fake_data"), &f); err != nil {
		return nil, err
	}
	return &f, nil
}

func mergeFakeDataDir(dir string, f *FakeData) error {
	return walkYAMLDir(dir, func(path string, raw []byte) error {
		var patch FakeData
		if err := yaml.Unmarshal(raw, &patch); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		f.Versions = append(f.Versions, patch.Versions...)
		f.Stacks = append(f.Stacks, patch.Stacks...)
		f.Companies = append(f.Companies, patch.Companies...)
		f.AdminUsers = append(f.AdminUsers, patch.AdminUsers...)
		f.AdminPasses = append(f.AdminPasses, patch.AdminPasses...)
		f.EmailDomains = append(f.EmailDomains, patch.EmailDomains...)
		return nil
	})
}

// LoadVulnerabilities reads vulnerabilities.yaml from dir, then merges
// community additions from rules/vulnerabilities/.
func LoadVulnerabilities(dir string) (*Vulnerabilities, error) {
	var v Vulnerabilities
	raw, err := readOptionalFromDir(dir, "vulnerabilities.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &v); err != nil {
			return nil, fmt.Errorf("parse vulnerabilities.yaml: %w", err)
		}
	}
	if err := mergeVulnerabilitiesDir(filepath.Join(dir, "vulnerabilities"), &v); err != nil {
		return nil, err
	}
	return &v, nil
}

func mergeVulnerabilitiesDir(dir string, v *Vulnerabilities) error {
	return walkYAMLDir(dir, func(path string, raw []byte) error {
		var patch Vulnerabilities
		if err := yaml.Unmarshal(raw, &patch); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		v.HoneypotPaths = append(v.HoneypotPaths, patch.HoneypotPaths...)
		v.SQLInjectionPatterns = append(v.SQLInjectionPatterns, patch.SQLInjectionPatterns...)
		v.FakeGitPaths = append(v.FakeGitPaths, patch.FakeGitPaths...)
		v.FakeEnvPaths = append(v.FakeEnvPaths, patch.FakeEnvPaths...)
		return nil
	})
}

// LoadInjectionStrategy reads injection_strategy.yaml from dir, then
// prepends community routes from rules/injection_strategy/ before the
// root file's routes. This ensures community-specific routes run before
// the generic catch-all (match: any). The injector config (knobs) is
// authoritative in injection_strategy.yaml only.
func LoadInjectionStrategy(dir string) (*InjectionStrategy, error) {
	var i InjectionStrategy
	raw, err := readOptionalFromDir(dir, "injection_strategy.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		if err := yaml.Unmarshal(raw, &i); err != nil {
			return nil, fmt.Errorf("parse injection_strategy.yaml: %w", err)
		}
	}
	if err := mergeInjectionStrategyDir(filepath.Join(dir, "injection_strategy"), &i); err != nil {
		return nil, err
	}
	return &i, nil
}

func mergeInjectionStrategyDir(dir string, i *InjectionStrategy) error {
	// Collect community routes first so they prepend before root routes;
	// the generic catch-all (match: any) from base.yaml stays last.
	// Injector scalar config is set only when the file specifies non-zero values.
	var extra []Route
	err := walkYAMLDir(dir, func(path string, raw []byte) error {
		var patch InjectionStrategy
		if err := yaml.Unmarshal(raw, &patch); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		extra = append(extra, patch.Routes...)
		if patch.Injector.MaxPayloadsPerResponse != 0 {
			i.Injector.MaxPayloadsPerResponse = patch.Injector.MaxPayloadsPerResponse
		}
		if patch.Injector.VisitBucketRotation {
			i.Injector.VisitBucketRotation = patch.Injector.VisitBucketRotation
		}
		if len(patch.Injector.StyleWeights) > 0 {
			i.Injector.StyleWeights = patch.Injector.StyleWeights
		}
		if len(patch.Injector.CategoryOrder) > 0 {
			i.Injector.CategoryOrder = patch.Injector.CategoryOrder
		}
		return nil
	})
	if err != nil {
		return err
	}
	// Prepend community routes; keep base routes (including any catch-all) after.
	if len(extra) > 0 {
		i.Routes = append(extra, i.Routes...)
	}
	return nil
}

// LoadChallenge reads challenge.yaml from dir.
func LoadChallenge(dir string) (*ChallengeRules, error) {
	raw, err := readFromDir(dir, "challenge.yaml")
	if err != nil {
		return nil, err
	}
	var c ChallengeRules
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse challenge.yaml: %w", err)
	}
	return &c, nil
}

// LoadML reads ml.yaml from dir.
func LoadML(dir string) (*ML, error) {
	raw, err := readFromDir(dir, "ml.yaml")
	if err != nil {
		return nil, err
	}
	var m ML
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse ml.yaml: %w", err)
	}
	return &m, nil
}

// LoadLearned reads learned rules from up to two sources and merges them:
//
//  1. <dir>/learned.yaml — miner output (operator-reviewed candidates). Optional.
//  2. <dir>/learned/ subdirectory — one .yaml file per feature family,
//     shipped via community rules releases or contributed by operators.
//
// Both sources use identical YAML structure (`candidates: []`). Active
// flags from both are honoured; the miner never writes into learned/.
func LoadLearned(dir string) (*Learned, error) {
	var merged Learned

	// Source 1: root learned.yaml (miner output or hand-edited, optional).
	raw, err := readOptionalFromDir(dir, "learned.yaml")
	if err != nil {
		return nil, err
	}
	if raw != nil {
		var root Learned
		if err := yaml.Unmarshal(raw, &root); err != nil {
			return nil, fmt.Errorf("parse learned.yaml: %w", err)
		}
		merged.Candidates = append(merged.Candidates, root.Candidates...)
	}

	// Source 2: learned/ subdirectory (community + contributed rules).
	if dir != "" {
		learnedDir := filepath.Join(dir, "learned")
		if info, err := os.Stat(learnedDir); err == nil && info.IsDir() {
			extra, err := loadLearnedDir(learnedDir)
			if err != nil {
				return nil, err
			}
			merged.Candidates = append(merged.Candidates, extra.Candidates...)
		}
	}

	return &merged, nil
}

// loadLearnedDir reads every .yaml / .yml file under dir (recursively) and
// merges their candidates lists. Files are visited in lexicographic order
// within each directory so results are deterministic across runs.
func loadLearnedDir(dir string) (*Learned, error) {
	var merged Learned
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		var l Learned
		if err := yaml.Unmarshal(raw, &l); err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		merged.Candidates = append(merged.Candidates, l.Candidates...)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk learned dir %s: %w", dir, err)
	}
	return &merged, nil
}

// --- Dashboard config types ---

// DashboardStatCard is one summary stat shown at the top of the console.
type DashboardStatCard struct {
	ID        string            `yaml:"id" json:"id"`
	Title     string            `yaml:"title" json:"title"`
	Metric    string            `yaml:"metric" json:"metric"`
	Filter    map[string]string `yaml:"filter,omitempty" json:"filter,omitempty"`
	Aggregate string            `yaml:"aggregate,omitempty" json:"aggregate,omitempty"`
	Format    string            `yaml:"format,omitempty" json:"format,omitempty"`
	Colour    string            `yaml:"colour,omitempty" json:"colour,omitempty"`
	Label     string            `yaml:"label" json:"label"`
}

// DashboardTierItem is one tier in the IP-rotation or public-IP panel.
type DashboardTierItem struct {
	ID         string `yaml:"id" json:"id"`
	LabelKey   string `yaml:"label_key" json:"label_key"`
	LabelValue string `yaml:"label_value" json:"label_value"`
	Display    string `yaml:"display" json:"display"`
	Colour     string `yaml:"colour,omitempty" json:"colour,omitempty"`
}

// DashboardIPRotation is the IP-rotation panel config.
type DashboardIPRotation struct {
	Title  string              `yaml:"title" json:"title"`
	Metric string              `yaml:"metric" json:"metric"`
	Tiers  []DashboardTierItem `yaml:"tiers" json:"tiers"`
}

// DashboardPublicIPRotation is the public-IP rotation panel config.
type DashboardPublicIPRotation struct {
	Title  string              `yaml:"title" json:"title"`
	Metric string              `yaml:"metric" json:"metric"`
	Items  []DashboardTierItem `yaml:"items" json:"items"`
}

// DashboardCardinality groups the cardinality gauge metrics.
type DashboardCardinality struct {
	ClientsMetric      string `yaml:"clients_metric" json:"clients_metric"`
	FingerprintsMetric string `yaml:"fingerprints_metric" json:"fingerprints_metric"`
}

// DashboardSearchTag is one quick-search tag in the PromQL search bar.
type DashboardSearchTag struct {
	Query string `yaml:"query" json:"query"`
	Label string `yaml:"label" json:"label"`
}

// DashboardGraphSeries is one data series inside a graph.
type DashboardGraphSeries struct {
	Value      string `yaml:"value,omitempty" json:"value,omitempty"`
	Metric     string `yaml:"metric,omitempty" json:"metric,omitempty"`
	Label      string `yaml:"label,omitempty" json:"label,omitempty"`
	Colour     string `yaml:"colour" json:"colour"`
	FillColour string `yaml:"fill_colour,omitempty" json:"fill_colour,omitempty"`
}

// DashboardGraph is one chart panel on the dashboard.
type DashboardGraph struct {
	ID           string                 `yaml:"id" json:"id"`
	Title        string                 `yaml:"title" json:"title"`
	Type         string                 `yaml:"type" json:"type"` // bar, doughnut, horizontal_bar, line
	Metric       string                 `yaml:"metric" json:"metric"`
	LabelKey     string                 `yaml:"label_key,omitempty" json:"label_key,omitempty"`
	BucketLabels []string               `yaml:"bucket_labels,omitempty" json:"bucket_labels,omitempty"`
	Colours      []string               `yaml:"colours,omitempty" json:"colours,omitempty"`
	Colour       string                 `yaml:"colour,omitempty" json:"colour,omitempty"`
	MaxItems     int                    `yaml:"max_items,omitempty" json:"max_items,omitempty"`
	Series       []DashboardGraphSeries `yaml:"series,omitempty" json:"series,omitempty"`
}

// DashboardScoreThresholds defines colouring thresholds for the event table.
type DashboardScoreThresholds struct {
	High   int `yaml:"high" json:"high"`
	Medium int `yaml:"medium" json:"medium"`
}

// DashboardColours holds the CSS colour palette.
type DashboardColours struct {
	BG     string `yaml:"bg" json:"bg"`
	BG2    string `yaml:"bg2" json:"bg2"`
	BG3    string `yaml:"bg3" json:"bg3"`
	FG     string `yaml:"fg" json:"fg"`
	Muted  string `yaml:"muted" json:"muted"`
	Accent string `yaml:"accent" json:"accent"`
	Red    string `yaml:"red" json:"red"`
	Yellow string `yaml:"yellow" json:"yellow"`
	Green  string `yaml:"green" json:"green"`
	Border string `yaml:"border" json:"border"`
}

// Dashboard is the parsed dashboard.yaml.
type Dashboard struct {
	RefreshSeconds    int                        `yaml:"refresh_seconds" json:"refresh_seconds"`
	MaxEvents         int                        `yaml:"max_events" json:"max_events"`
	MaxHistoryPoints  int                        `yaml:"max_history_points" json:"max_history_points"`
	PageReloadSeconds int                        `yaml:"page_reload_seconds" json:"page_reload_seconds"`
	ChartJSCDN       string                     `yaml:"chartjs_cdn" json:"chartjs_cdn"`
	Colours           DashboardColours           `yaml:"colours" json:"colours"`
	StatCards         []DashboardStatCard        `yaml:"stat_cards" json:"stat_cards"`
	IPRotation        DashboardIPRotation        `yaml:"ip_rotation" json:"ip_rotation"`
	PublicIPRotation  DashboardPublicIPRotation  `yaml:"public_ip_rotation" json:"public_ip_rotation"`
	Cardinality       DashboardCardinality       `yaml:"cardinality" json:"cardinality"`
	SearchTags        []DashboardSearchTag       `yaml:"search_tags" json:"search_tags"`
	Graphs            []DashboardGraph           `yaml:"graphs" json:"graphs"`
	ScoreThresholds   DashboardScoreThresholds   `yaml:"score_thresholds" json:"score_thresholds"`
}

// LoadDashboard reads dashboard.yaml from dir.
func LoadDashboard(dir string) (*Dashboard, error) {
	raw, err := readFromDir(dir, "dashboard.yaml")
	if err != nil {
		return nil, err
	}
	var d Dashboard
	if err := yaml.Unmarshal(raw, &d); err != nil {
		return nil, fmt.Errorf("parse dashboard.yaml: %w", err)
	}
	// Sane defaults for zero-value fields.
	if d.RefreshSeconds <= 0 {
		d.RefreshSeconds = 10
	}
	if d.MaxEvents <= 0 {
		d.MaxEvents = 200
	}
	if d.MaxHistoryPoints <= 0 {
		d.MaxHistoryPoints = 60
	}
	if d.PageReloadSeconds <= 0 {
		d.PageReloadSeconds = 60
	}
	if d.ScoreThresholds.High <= 0 {
		d.ScoreThresholds.High = 70
	}
	if d.ScoreThresholds.Medium <= 0 {
		d.ScoreThresholds.Medium = 40
	}
	return &d, nil
}
