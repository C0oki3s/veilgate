// Package recommender analyses live traffic from the persist event store and
// proposes custom_signals entries for signals.yaml. It never writes signals.yaml
// itself — all output goes to signal_suggestions.yaml (or stdout via the CLI flag)
// for operator review. Every suggestion is rendered with enabled:false so an
// accidental copy-paste cannot activate unreviewed rules.
package recommender

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/rules"
)

// SignalRecommendation is one proposed custom signal with full metadata.
type SignalRecommendation struct {
	Name              string             `json:"name"`
	Description       string             `json:"description"`
	Confidence        float64            `json:"confidence"`
	Support           int                `json:"support"`
	FalsePositiveRate float64            `json:"false_positive_rate"`
	Rationale         string             `json:"rationale"`
	Source            string             `json:"source"`
	Signal            rules.CustomSignal `json:"signal"`
}

// AnalysisConfig is the set of filtering/analysis parameters for one pass.
// Built from ml.yaml SignalRecommender at the start of each run.
type AnalysisConfig struct {
	Since                  time.Time
	MinConfidence          float64
	MinSupport             int
	MaxSuggestions         int
	FalsePositiveThreshold float64
	TarpitThreshold        int
}

// Analyzer produces SignalRecommendation candidates from the event store.
type Analyzer interface {
	Name() string
	Analyze(cfg AnalysisConfig, samples []persist.PathSample, totalTarpit, totalClean int) ([]SignalRecommendation, error)
}

// Recommender orchestrates all analyzers, deduplicates results, and delivers
// suggestions via a background goroutine, REST handler, or CLI output.
type Recommender struct {
	store     *persist.Store
	mlCfg     *rules.Holder[rules.ML]
	rulesDir  string
	tarpit    int
	analyzers []Analyzer
}

// New constructs a Recommender. tarpitThreshold must match the detector's
// score_tarpit_threshold so the "tarpitted" classification is consistent.
func New(store *persist.Store, mlCfg *rules.Holder[rules.ML], rulesDir string, tarpitThreshold int) *Recommender {
	r := &Recommender{
		store:    store,
		mlCfg:    mlCfg,
		rulesDir: rulesDir,
		tarpit:   tarpitThreshold,
	}
	r.analyzers = []Analyzer{
		NewPathExtensionAnalyzer(),
		NewPathPrefixAnalyzer(),
		NewUASubstringAnalyzer(store),
		NewMethodComboAnalyzer(),
		NewUAPathComboAnalyzer(),
	}
	return r
}

// Analyze runs all analyzers, deduplicates, filters, and ranks results.
func (r *Recommender) Analyze(ctx context.Context) ([]SignalRecommendation, error) {
	return r.run(ctx, r.buildConfig())
}

// Run blocks until ctx is done, firing one analysis pass per configured interval.
func (r *Recommender) Run(ctx context.Context, onError func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(r.interval()):
		}
		if m := r.loadML(); m != nil && !m.SignalRecommender.Enabled {
			continue
		}
		recs, err := r.Analyze(ctx)
		if err != nil && onError != nil {
			onError(err)
			continue
		}
		if err := r.WriteSuggestions(recs); err != nil && onError != nil {
			onError(err)
		}
	}
}

// Handler returns an http.HandlerFunc for GET /api/signal-suggestions.
// Accepts query params min_confidence (float) and min_support (int) as overrides.
func (r *Recommender) Handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.store == nil {
			http.Error(w, "persist store not enabled", http.StatusServiceUnavailable)
			return
		}
		cfg := r.buildConfig()
		if v := req.URL.Query().Get("min_confidence"); v != "" {
			if f, err := strconv.ParseFloat(v, 64); err == nil {
				cfg.MinConfidence = f
			}
		}
		if v := req.URL.Query().Get("min_support"); v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				cfg.MinSupport = n
			}
		}
		recs, err := r.run(req.Context(), cfg)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if recs == nil {
			recs = []SignalRecommendation{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(recs)
	}
}

// WriteSuggestions writes a human-readable YAML report to the configured path.
// A no-op when recs is empty so the file isn't clobbered on data-sparse runs.
func (r *Recommender) WriteSuggestions(recs []SignalRecommendation) error {
	if len(recs) == 0 {
		return nil
	}
	path := r.writePath()
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("recommender: mkdir: %w", err)
		}
	}
	body, err := RenderReportYAML(recs)
	if err != nil {
		return fmt.Errorf("recommender: render: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ── internal helpers ─────────────────────────────────────────────────────────

func (r *Recommender) run(ctx context.Context, cfg AnalysisConfig) ([]SignalRecommendation, error) {
	totalTarpit, totalClean, err := r.store.CountEventsByDecision(cfg.Since, cfg.TarpitThreshold)
	if err != nil {
		return nil, fmt.Errorf("count events: %w", err)
	}
	if totalTarpit+totalClean < cfg.MinSupport {
		return nil, nil
	}

	// Fetch raw path samples once and share across all analyzers that need them.
	samples, err := r.store.QueryPathSamples(cfg.Since, 20000)
	if err != nil {
		return nil, fmt.Errorf("query path samples: %w", err)
	}

	var all []SignalRecommendation
	for _, az := range r.analyzers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		recs, err := az.Analyze(cfg, samples, totalTarpit, totalClean)
		if err != nil {
			continue // one analyzer failure doesn't abort the pass
		}
		all = append(all, recs...)
	}

	all = deduplicate(all)

	out := all[:0]
	for _, rec := range all {
		if rec.Confidence >= cfg.MinConfidence &&
			rec.Support >= cfg.MinSupport &&
			rec.FalsePositiveRate <= cfg.FalsePositiveThreshold {
			out = append(out, rec)
		}
	}

	sort.Slice(out, func(i, j int) bool {
		si := out[i].Confidence * math.Log1p(float64(out[i].Support))
		sj := out[j].Confidence * math.Log1p(float64(out[j].Support))
		return si > sj
	})

	if len(out) > cfg.MaxSuggestions {
		out = out[:cfg.MaxSuggestions]
	}
	return out, nil
}

func (r *Recommender) buildConfig() AnalysisConfig {
	cfg := AnalysisConfig{
		MinConfidence:          0.85,
		MinSupport:             30,
		MaxSuggestions:         20,
		FalsePositiveThreshold: 0.02,
		TarpitThreshold:        r.tarpit,
	}
	lookback := 168
	if m := r.loadML(); m != nil {
		rc := m.SignalRecommender
		if rc.MinConfidence > 0 {
			cfg.MinConfidence = rc.MinConfidence
		}
		if rc.MinSupport > 0 {
			cfg.MinSupport = rc.MinSupport
		}
		if rc.MaxSuggestions > 0 {
			cfg.MaxSuggestions = rc.MaxSuggestions
		}
		if rc.FalsePositiveThreshold > 0 {
			cfg.FalsePositiveThreshold = rc.FalsePositiveThreshold
		}
		if rc.LookbackHours > 0 {
			lookback = rc.LookbackHours
		}
	}
	cfg.Since = time.Now().Add(-time.Duration(lookback) * time.Hour)
	return cfg
}

func (r *Recommender) loadML() *rules.ML {
	if r.mlCfg == nil {
		return nil
	}
	return r.mlCfg.Load()
}

func (r *Recommender) interval() time.Duration {
	if m := r.loadML(); m != nil && m.SignalRecommender.IntervalHours > 0 {
		return time.Duration(m.SignalRecommender.IntervalHours) * time.Hour
	}
	return 24 * time.Hour
}

func (r *Recommender) writePath() string {
	wpath := "signal_suggestions.yaml"
	if m := r.loadML(); m != nil && m.SignalRecommender.WritePath != "" {
		wpath = m.SignalRecommender.WritePath
	}
	if !filepath.IsAbs(wpath) && r.rulesDir != "" {
		return filepath.Join(r.rulesDir, wpath)
	}
	return wpath
}

// deduplicate removes recommendations with identical condition sets,
// keeping the entry with the higher confidence.
func deduplicate(recs []SignalRecommendation) []SignalRecommendation {
	// Sort by confidence descending so the first occurrence wins.
	sort.Slice(recs, func(i, j int) bool {
		return recs[i].Confidence > recs[j].Confidence
	})
	seen := make(map[string]bool, len(recs))
	out := recs[:0]
	for _, rec := range recs {
		k := conditionKey(rec.Signal.Conditions)
		if !seen[k] {
			seen[k] = true
			out = append(out, rec)
		}
	}
	return out
}

func conditionKey(conds []rules.CustomSignalCondition) string {
	k := ""
	for _, c := range conds {
		k += c.Type + "\x00" + c.Name + "\x00" + c.Value + "\x01"
	}
	return k
}
