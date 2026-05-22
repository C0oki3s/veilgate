package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// ── protocol detection ────────────────────────────────────────────────────────

func TestIsWebSocketUpgrade(t *testing.T) {
	cases := []struct {
		name    string
		upgrade string
		conn    string
		want    bool
	}{
		{"standard ws", "websocket", "Upgrade", true},
		{"case-insensitive upgrade", "WebSocket", "upgrade", true},
		{"connection has extra values", "websocket", "keep-alive, Upgrade", true},
		{"no upgrade header", "", "Upgrade", false},
		{"no connection header", "websocket", "", false},
		{"different upgrade type", "h2c", "Upgrade", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.upgrade != "" {
				r.Header.Set("Upgrade", tc.upgrade)
			}
			if tc.conn != "" {
				r.Header.Set("Connection", tc.conn)
			}
			if got := isWebSocketUpgrade(r); got != tc.want {
				t.Fatalf("isWebSocketUpgrade = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestIsGRPC(t *testing.T) {
	cases := []struct {
		ct   string
		want bool
	}{
		{"application/grpc", true},
		{"application/grpc+proto", true},
		{"application/grpc+json", true},
		{"application/grpc-web", true},
		{"application/grpc-web+proto", true},
		{"application/json", false},
		{"text/html", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.ct, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/pkg.Svc/Method", nil)
			r.Header.Set("Content-Type", tc.ct)
			if got := isGRPC(r); got != tc.want {
				t.Fatalf("isGRPC(%q) = %v, want %v", tc.ct, got, tc.want)
			}
		})
	}
}

// ── blocked-protocol responses ────────────────────────────────────────────────

func TestServeUpgradeBlockedChallenge(t *testing.T) {
	w := httptest.NewRecorder()
	serveUpgradeBlocked(w, DecisionChallenge)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if body["error"] != "challenge_required" {
		t.Fatalf("error = %q, want challenge_required", body["error"])
	}
}

func TestServeUpgradeBlockedTarpit(t *testing.T) {
	w := httptest.NewRecorder()
	serveUpgradeBlocked(w, DecisionTarpit)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}

func TestServeGRPCBlockedChallenge(t *testing.T) {
	w := httptest.NewRecorder()
	serveGRPCBlocked(w, DecisionChallenge)

	if w.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200 (gRPC uses 200 with grpc-status header)", w.Code)
	}
	if got := w.Header().Get("grpc-status"); got != "16" {
		t.Fatalf("grpc-status = %q, want 16 (UNAUTHENTICATED)", got)
	}
	if got := w.Header().Get("Content-Type"); got != "application/grpc" {
		t.Fatalf("Content-Type = %q, want application/grpc", got)
	}
}

func TestServeGRPCBlockedTarpit(t *testing.T) {
	w := httptest.NewRecorder()
	serveGRPCBlocked(w, DecisionTarpit)

	if w.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", w.Code)
	}
	if got := w.Header().Get("grpc-status"); got != "7" {
		t.Fatalf("grpc-status = %q, want 7 (PERMISSION_DENIED)", got)
	}
}
