package proxy

import (
	"testing"

	"github.com/C0oki3s/veilgate/internal/config"
)

func TestDecideAutoModeUsesThresholdBands(t *testing.T) {
	s := &Server{cfg: &config.Config{
		Mode: "auto",
		Detector: config.DetectorConfig{
			ScoreChallengeThreshold: 40,
			ScoreTarpitThreshold:    70,
		},
	}}

	tests := []struct {
		name  string
		score int
		want  Decision
	}{
		{name: "below challenge", score: 39, want: DecisionReal},
		{name: "challenge boundary", score: 40, want: DecisionChallenge},
		{name: "middle band", score: 69, want: DecisionChallenge},
		{name: "tarpit boundary", score: 70, want: DecisionTarpit},
		{name: "above tarpit", score: 100, want: DecisionTarpit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := s.decide(tt.score); got != tt.want {
				t.Fatalf("decide(%d) = %s, want %s", tt.score, got, tt.want)
			}
		})
	}
}

func TestDecideObserveModeNeverDiverts(t *testing.T) {
	s := &Server{cfg: &config.Config{
		Mode: "observe",
		Detector: config.DetectorConfig{
			ScoreChallengeThreshold: 40,
			ScoreTarpitThreshold:    70,
		},
	}}

	if got := s.decide(100); got != DecisionObserve {
		t.Fatalf("decide(100) in observe mode = %s, want observe", got)
	}
}
