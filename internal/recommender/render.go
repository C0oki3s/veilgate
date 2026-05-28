package recommender

import (
	"bytes"
	"fmt"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// RenderReportYAML produces the full signal_suggestions.yaml report body.
// Each recommendation is prefixed with metadata comments and the YAML signal
// block always has enabled:false so accidental paste is safe.
func RenderReportYAML(recs []SignalRecommendation) ([]byte, error) {
	var buf bytes.Buffer
	fmt.Fprintf(&buf,
		"# Auto-generated signal suggestions — do NOT paste into signals.yaml without review.\n"+
			"# Generated: %s\n"+
			"# Each entry is enabled:false. Set to true only after manual review.\n"+
			"# Paste reviewed entries under custom_signals: in your signals.yaml.\n\n",
		time.Now().UTC().Format(time.RFC3339),
	)

	// Wrap all suggestions in a top-level key so the file is valid YAML
	// but clearly NOT a drop-in replacement for signals.yaml.
	type report struct {
		Suggestions []suggestionEntry `yaml:"suggestions"`
	}
	type entry = suggestionEntry

	var entries []entry
	for _, rec := range recs {
		sig := rec.Signal
		sig.Enabled = false // always false in suggestions
		entries = append(entries, suggestionEntry{
			Name:              rec.Name,
			Source:            rec.Source,
			Confidence:        rec.Confidence,
			Support:           rec.Support,
			FalsePositiveRate: rec.FalsePositiveRate,
			Rationale:         rec.Rationale,
			Signal:            sig,
		})
	}

	body, err := yaml.Marshal(report{Suggestions: entries})
	if err != nil {
		return nil, err
	}
	buf.Write(body)
	return buf.Bytes(), nil
}

// RenderSignalYAML produces a standalone copy-pasteable YAML snippet for a
// single recommendation — just the custom_signals list entry, with a short
// comment header. Useful for CLI output.
func RenderSignalYAML(rec SignalRecommendation) (string, error) {
	sig := rec.Signal
	sig.Enabled = false

	type wrapper struct {
		CustomSignals []rules.CustomSignal `yaml:"custom_signals"`
	}
	body, err := yaml.Marshal(wrapper{CustomSignals: []rules.CustomSignal{sig}})
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf,
		"# Source: %s | Confidence: %.0f%% | Support: %d | FP rate: %.2f%%\n"+
			"# Rationale: %s\n",
		rec.Source, rec.Confidence*100, rec.Support, rec.FalsePositiveRate*100,
		rec.Rationale,
	)
	buf.Write(body)
	return buf.String(), nil
}

// suggestionEntry is the YAML shape of one entry in signal_suggestions.yaml.
type suggestionEntry struct {
	Name              string             `yaml:"name"`
	Source            string             `yaml:"source"`
	Confidence        float64            `yaml:"confidence"`
	Support           int                `yaml:"support"`
	FalsePositiveRate float64            `yaml:"false_positive_rate"`
	Rationale         string             `yaml:"rationale"`
	Signal            rules.CustomSignal `yaml:"signal"`
}
