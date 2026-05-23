package tests

import (
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/C0oki3s/veilgate/internal/challenge"
	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/payloads"
	"github.com/C0oki3s/veilgate/internal/proxy"
	"github.com/C0oki3s/veilgate/internal/rules"
	"github.com/C0oki3s/veilgate/internal/tarpit"
	"github.com/C0oki3s/veilgate/internal/tlsfp"
)

func repoPath(parts ...string) string {
	if len(parts) > 0 && parts[0] == "rules" {
		parts[0] = "veilgate-rules"
	}
	all := append([]string{".."}, parts...)
	return filepath.Join(all...)
}

func TestRepositoryConfigAndRulesLoad(t *testing.T) {
	cfg, err := config.Load(repoPath("configs", "veilgate.yaml"))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	// configs/veilgate.yaml now defaults to ~/.veilgate/rules which expands
	// to the user home at load time. Accept any non-empty path.
	if cfg.RulesDir == "" {
		t.Fatalf("rules_dir must not be empty, got %q", cfg.RulesDir)
	}

	challengeRules, err := rules.LoadChallenge(repoPath("rules"))
	if err != nil {
		t.Fatalf("load challenge rules: %v", err)
	}
	if challengeRules.VerifyPath != "/__veilgate/verify" {
		t.Fatalf("verify path = %q", challengeRules.VerifyPath)
	}

	detectorRules, err := rules.LoadDetector(repoPath("rules"))
	if err != nil {
		t.Fatalf("load detector rules: %v", err)
	}
	if detectorRules.SuspiciousUserAgents.Points == 0 {
		t.Fatal("detector suspicious UA rule should be populated")
	}
}

func TestChallengeHandlerRejectsUnsignedVerifyPOST(t *testing.T) {
	h, err := challenge.NewHandlerFromDir("integration-secret", repoPath("rules"), 1, time.Minute, 0)
	if err != nil {
		t.Fatalf("NewHandlerFromDir: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/__veilgate/verify", strings.NewReader(`{"challenge":"abc","nonce":1}`))
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("unsigned verify should fail with 400, got %d", w.Code)
	}
}

func TestTLSFingerprintClassifierThroughPublicAPI(t *testing.T) {
	store := tlsfp.NewStore(time.Minute)
	db, err := tlsfp.NewDatabaseFromDir(repoPath("rules"))
	if err != nil {
		t.Fatalf("NewDatabaseFromDir: %v", err)
	}
	classifier := tlsfp.NewClassifier(store, db)

	remote := "203.0.113.10:443"
	store.Put(remote, tlsfp.Fingerprint{JA4: "t13d1715h2_5b57614c22b0_3d5424432f57"})

	label, category, confidence, ok := classifier.Classify(remote)
	if !ok || label != "python-httpx" || category != "agent" || confidence < 80 {
		t.Fatalf("classification mismatch: label=%q category=%q confidence=%d ok=%v", label, category, confidence, ok)
	}
}

func TestDetectorScoresAgentTrafficThroughPublicAPI(t *testing.T) {
	tracker := detector.NewTracker(90)
	scorer := detector.NewScorer(tracker, []string{"/admin-panel-v2"}, nil)
	if d, err := rules.LoadDetector(repoPath("rules")); err == nil {
		scorer.SetRules(d)
	}

	r := httptest.NewRequest(http.MethodGet, "/admin-panel-v2?id=1%27%20UNION%20SELECT%20password", nil)
	r.Header.Set("User-Agent", "sqlmap/1.7")
	score := scorer.Score("203.0.113.20", r)

	if score.Total < 80 {
		t.Fatalf("expected high score for honeypot + sqlmap traffic, got %d signals=%v", score.Total, score.Signals)
	}
}

func TestProxyCanDivertHighScoreRequestToTarpit(t *testing.T) {
	cfg := &config.Config{
		Upstream: "http://127.0.0.1:1",
		Mode:     "tarpit",
		Tarpit: config.TarpitConfig{
			MinLatencyMs: 0,
			MaxLatencyMs: 0,
			MaxBodyBytes: 64 * 1024,
		},
		Detector: config.DetectorConfig{
			ScoreTarpitThreshold:    40,
			ScoreChallengeThreshold: 20,
			HoneypotPaths:           []string{"/admin-panel-v2"},
			WindowSeconds:           90,
		},
	}

	tracker := detector.NewTracker(cfg.Detector.WindowSeconds)
	scorer := detector.NewScorer(tracker, cfg.Detector.HoneypotPaths, nil)
	profileStore := tarpit.NewProfileStore()
	lib := payloads.NewLibrary()
	injector := payloads.NewInjector(lib, 1, false)
	tarpitHandler := tarpit.NewHandler(&cfg.Tarpit, profileStore, injector)

	srv, err := proxy.NewServer(cfg, scorer, tarpitHandler, nil, nil, zerolog.New(io.Discard))
	if err != nil {
		t.Fatalf("new proxy server: %v", err)
	}

	r := httptest.NewRequest(http.MethodGet, "/admin-panel-v2", nil)
	r.RemoteAddr = "203.0.113.30:12345"
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, r)

	if w.Code == http.StatusBadGateway {
		t.Fatal("request reached upstream instead of being diverted to tarpit")
	}
	if w.Code < 200 || w.Code >= 600 {
		t.Fatalf("unexpected tarpit status %d", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Fatal("tarpit response body should not be empty")
	}
}

func TestTrustedProxyParsingPublicAPI(t *testing.T) {
	nets := proxy.ParseTrustedProxies([]string{"127.0.0.1", "10.0.0.0/8", "not-an-ip"})
	if len(nets) != 2 {
		t.Fatalf("expected two parsed trusted proxy entries, got %d", len(nets))
	}
}
