package recommender

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/rules"
)

// QueryParamAnalyzer recommends query_contains conditions for URL query
// parameter keys that appear predominantly in tarpitted traffic.
type QueryParamAnalyzer struct{}

// NewQueryParamAnalyzer returns a QueryParamAnalyzer.
func NewQueryParamAnalyzer() *QueryParamAnalyzer { return &QueryParamAnalyzer{} }

func (a *QueryParamAnalyzer) Name() string { return "query_param" }

type paramCount struct{ tarpit, total int }

func (a *QueryParamAnalyzer) Analyze(cfg AnalysisConfig, samples []persist.PathSample, _, _ int) ([]SignalRecommendation, error) {
	byKey := map[string]*paramCount{}

	for _, s := range samples {
		if s.Query == "" {
			continue
		}
		vals, err := url.ParseQuery(s.Query)
		if err != nil {
			continue
		}
		tarpitted := isTarpitted(s, cfg.TarpitThreshold)
		seen := map[string]bool{}
		for k := range vals {
			k = strings.ToLower(k)
			if seen[k] {
				continue
			}
			seen[k] = true
			if _, ok := byKey[k]; !ok {
				byKey[k] = &paramCount{}
			}
			byKey[k].total++
			if tarpitted {
				byKey[k].tarpit++
			}
		}
	}

	// Sort for deterministic output.
	keys := make([]string, 0, len(byKey))
	for k := range byKey {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var out []SignalRecommendation
	for _, k := range keys {
		c := byKey[k]
		if c.tarpit < cfg.MinSupport || c.total == 0 {
			continue
		}
		confidence := float64(c.tarpit) / float64(c.total)
		if confidence < cfg.MinConfidence {
			continue
		}
		// Condition matches "key=" prefix so any value for that key triggers it.
		condVal := k + "="
		name := "auto_qp_" + sanitizeName(k)
		out = append(out, SignalRecommendation{
			Name:              name,
			Description:       fmt.Sprintf("Query param '%s=' appears in %.0f%% tarpitted traffic (%d events)", k, confidence*100, c.tarpit),
			Confidence:        confidence,
			Support:           c.tarpit,
			FalsePositiveRate: 1.0 - confidence,
			Rationale:         fmt.Sprintf("Query key '%s' found in %d of %d requests, %.0f%% tarpitted", k, c.tarpit, c.total, confidence*100),
			Source:            a.Name(),
			Signal: rules.CustomSignal{
				Name:    name,
				Enabled: false,
				Points:  20,
				Conditions: []rules.CustomSignalCondition{
					{Type: "query_contains", Value: condVal},
				},
			},
		})
	}
	return out, nil
}
