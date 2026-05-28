package proxy

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/rs/zerolog"
)

func TestRequestLogLevel(t *testing.T) {
	cases := []struct {
		decision Decision
		wantLevel string
	}{
		{DecisionTarpit,   "error"},
		{DecisionChallenge, "warn"},
		{DecisionReal,     "info"},
		{DecisionObserve,  "info"},
	}
	for _, tc := range cases {
		var buf bytes.Buffer
		log := zerolog.New(&buf)
		requestLog(log, tc.decision).Msg("request")

		var fields map[string]interface{}
		if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
			t.Fatalf("decision=%s: invalid JSON: %v", tc.decision, err)
		}
		got, _ := fields["level"].(string)
		if got != tc.wantLevel {
			t.Errorf("decision=%s: got level=%q, want %q", tc.decision, got, tc.wantLevel)
		}
	}
}

func TestScoreToThreatLevel(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0,   "low"},
		{29,  "low"},
		{30,  "medium"},
		{59,  "medium"},
		{60,  "high"},
		{79,  "high"},
		{80,  "critical"},
		{100, "critical"},
	}
	for _, tc := range cases {
		got := scoreToThreatLevel(tc.score)
		if got != tc.want {
			t.Errorf("score=%d: got %q, want %q", tc.score, got, tc.want)
		}
	}
}
