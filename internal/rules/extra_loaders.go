package rules

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed defaults/templates.yaml
var embeddedTemplates []byte

//go:embed defaults/fake_data.yaml
var embeddedFakeData []byte

//go:embed defaults/vulnerabilities.yaml
var embeddedVulnerabilities []byte

//go:embed defaults/injection_strategy.yaml
var embeddedInjectionStrategy []byte

//go:embed defaults/challenge.yaml
var embeddedChallenge []byte

//go:embed defaults/ml.yaml
var embeddedML []byte

//go:embed defaults/learned.yaml
var embeddedLearned []byte

//go:embed defaults/dashboard.yaml
var embeddedDashboard []byte

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

// LearnedCandidate is one entry in learned.yaml -> candidates[].
type LearnedCandidate struct {
	Feature   string  `yaml:"feature"`
	Bucket    string  `yaml:"bucket"`
	Posterior float64 `yaml:"posterior"`
	Support   int     `yaml:"support"`
	Active    bool    `yaml:"active"`
	ProposedAt string `yaml:"proposed_at,omitempty"`
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

// LoadTemplates reads templates.yaml or the embedded default.
func LoadTemplates(dir string) (*Templates, error) {
	raw, err := readOrEmbed(dir, "templates.yaml", embeddedTemplates)
	if err != nil {
		return nil, err
	}
	var t Templates
	if err := yaml.Unmarshal(raw, &t); err != nil {
		return nil, fmt.Errorf("parse templates.yaml: %w", err)
	}
	return &t, nil
}

// LoadFakeData reads fake_data.yaml or the embedded default.
func LoadFakeData(dir string) (*FakeData, error) {
	raw, err := readOrEmbed(dir, "fake_data.yaml", embeddedFakeData)
	if err != nil {
		return nil, err
	}
	var f FakeData
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse fake_data.yaml: %w", err)
	}
	return &f, nil
}

// LoadVulnerabilities reads vulnerabilities.yaml or the embedded default.
func LoadVulnerabilities(dir string) (*Vulnerabilities, error) {
	raw, err := readOrEmbed(dir, "vulnerabilities.yaml", embeddedVulnerabilities)
	if err != nil {
		return nil, err
	}
	var v Vulnerabilities
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("parse vulnerabilities.yaml: %w", err)
	}
	return &v, nil
}

// LoadInjectionStrategy reads injection_strategy.yaml or the embedded default.
func LoadInjectionStrategy(dir string) (*InjectionStrategy, error) {
	raw, err := readOrEmbed(dir, "injection_strategy.yaml", embeddedInjectionStrategy)
	if err != nil {
		return nil, err
	}
	var i InjectionStrategy
	if err := yaml.Unmarshal(raw, &i); err != nil {
		return nil, fmt.Errorf("parse injection_strategy.yaml: %w", err)
	}
	return &i, nil
}

// LoadChallenge reads challenge.yaml or the embedded default.
func LoadChallenge(dir string) (*ChallengeRules, error) {
	raw, err := readOrEmbed(dir, "challenge.yaml", embeddedChallenge)
	if err != nil {
		return nil, err
	}
	var c ChallengeRules
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse challenge.yaml: %w", err)
	}
	return &c, nil
}

// LoadML reads ml.yaml or the embedded default.
func LoadML(dir string) (*ML, error) {
	raw, err := readOrEmbed(dir, "ml.yaml", embeddedML)
	if err != nil {
		return nil, err
	}
	var m ML
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse ml.yaml: %w", err)
	}
	return &m, nil
}

// LoadLearned reads learned.yaml or the embedded default (which is an
// empty candidates list — operators never need to edit the file by hand).
func LoadLearned(dir string) (*Learned, error) {
	raw, err := readOrEmbed(dir, "learned.yaml", embeddedLearned)
	if err != nil {
		return nil, err
	}
	var l Learned
	if err := yaml.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("parse learned.yaml: %w", err)
	}
	return &l, nil
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

// LoadDashboard reads dashboard.yaml or the embedded default.
func LoadDashboard(dir string) (*Dashboard, error) {
	raw, err := readOrEmbed(dir, "dashboard.yaml", embeddedDashboard)
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
