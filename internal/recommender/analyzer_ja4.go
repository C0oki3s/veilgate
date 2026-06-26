package recommender

import (
	"fmt"
	"strings"

	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/rules"
)

// JA4FingerprintAnalyzer recommends ja4_prefix conditions for TLS fingerprints
// predominantly associated with tarpitted traffic. JA4 fingerprints are
// injected into X-Veilgate-JA4 by the TLS middleware before the scorer runs.
type JA4FingerprintAnalyzer struct {
	store *persist.Store
}

// NewJA4FingerprintAnalyzer returns a JA4FingerprintAnalyzer backed by store.
func NewJA4FingerprintAnalyzer(store *persist.Store) *JA4FingerprintAnalyzer {
	return &JA4FingerprintAnalyzer{store: store}
}

func (a *JA4FingerprintAnalyzer) Name() string { return "ja4_fingerprint" }

func (a *JA4FingerprintAnalyzer) Analyze(cfg AnalysisConfig, _ []persist.PathSample, totalTarpit, _ int) ([]SignalRecommendation, error) {
	if a.store == nil || totalTarpit < cfg.MinSupport {
		return nil, nil
	}
	rows, err := a.store.TopJA4ByTarpit(cfg.Since, cfg.TarpitThreshold, 20)
	if err != nil {
		return nil, err
	}

	var out []SignalRecommendation
	for _, row := range rows {
		if row.Tarpit < cfg.MinSupport {
			continue
		}
		confidence := float64(row.Tarpit) / float64(row.Count)
		if confidence < cfg.MinConfidence {
			continue
		}
		prefix := ja4Prefix(row.Label)
		name := "auto_ja4_" + sanitizeName(prefix)
		out = append(out, SignalRecommendation{
			Name:              name,
			Description:       fmt.Sprintf("TLS fingerprint %s appears in %.0f%% tarpitted traffic", prefix, confidence*100),
			Confidence:        confidence,
			Support:           row.Tarpit,
			FalsePositiveRate: 1.0 - confidence,
			Rationale:         fmt.Sprintf("JA4 prefix %s seen in %d of %d requests (%.0f%% tarpitted) — likely bot/scanner fingerprint", prefix, row.Tarpit, row.Count, confidence*100),
			Source:            a.Name(),
			Signal: rules.CustomSignal{
				Name:    name,
				Enabled: false,
				Points:  30,
				Conditions: []rules.CustomSignalCondition{
					{Type: "ja4_prefix", Value: prefix},
				},
			},
		})
	}
	return out, nil
}

// ja4Prefix returns the first 12 characters of a JA4 fingerprint — the stable
// prefix encoding TLS version, SNI, and cipher-count that is session-invariant
// for a given tool or library, unlike the cipher-order suffix which varies.
func ja4Prefix(ja4 string) string {
	const n = 12
	if len(ja4) <= n {
		return strings.ToLower(ja4)
	}
	return strings.ToLower(ja4[:n])
}
