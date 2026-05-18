package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/C0oki3s/veilgate/internal/challenge"
	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/rules"
	"github.com/C0oki3s/veilgate/internal/telemetry"
	"github.com/C0oki3s/veilgate/internal/verifier"
)

const testRulesDir = "../../rules"

// Integration tests for the verifier chain wiring in serve().
//
// These are not pure unit tests — they build a real Server with a
// real Scorer + challenge.Handler + verifier.Chain and exercise the
// HTTP request path end-to-end against a fake upstream. The intent is
// to catch wiring regressions: that an accepted verifier actually
// flips the routing decision, AND that the Tarpit override still wins
// over a valid credential (the load-bearing security invariant).

// upstreamProbe is a tiny test upstream that records every request
// it sees and returns 200. If a request reaches it, the proxy
// decided DecisionReal — that's the assertion shape we use throughout.
func upstreamProbe(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// buildTestServer wires the full proxy stack against a test upstream.
// Returns the *Server and a teardown that removes the temp clients
// dir used by the HMAC verifier.
func buildTestServer(t *testing.T, upstreamURL string, withVerifier bool) (*Server, string) {
	t.Helper()

	cfg := &config.Config{
		Mode:     "auto",
		Upstream: upstreamURL,
		Detector: config.DetectorConfig{
			ScoreChallengeThreshold: 40,
			ScoreTarpitThreshold:    70,
			HoneypotPaths:           []string{"/wp-login.php", "/.env"},
		},
	}
	tracker := detector.NewTracker(60)
	scorer := detector.NewScorer(tracker, cfg.Detector.HoneypotPaths, nil)
	if d, err := rules.LoadDetector(testRulesDir); err == nil {
		scorer.SetRules(d)
	}
	if ip, err := rules.LoadIPReputation(testRulesDir); err == nil {
		scorer.SetIPReputation(ip)
	}

	ch, err := challenge.NewHandlerFromDir("test-secret-not-default", testRulesDir, 0, 0)
	if err != nil {
		t.Fatalf("NewHandlerFromDir: %v", err)
	}
	tarpit := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Tiny stub instead of the real tarpit handler — we only
		// care that THIS handler ran, signalling DecisionTarpit.
		w.Header().Set("X-Test-Tarpit", "1")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tarpit-stub"))
	})

	srv, err := NewServer(cfg, scorer, tarpit, ch, nil, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	srv.SetTracker(tracker)

	clientsDir := ""
	if withVerifier {
		clientsDir = t.TempDir()
		if err := os.WriteFile(
			filepath.Join(clientsDir, "test-client.secret"),
			[]byte("integration-test-secret"),
			0o600,
		); err != nil {
			t.Fatalf("write client secret: %v", err)
		}
		hv, err := verifier.NewHMACVerifier(verifier.HMACConfig{
			ClientsDir: clientsDir,
		})
		if err != nil {
			t.Fatalf("NewHMACVerifier: %v", err)
		}
		srv.SetVerifiers(verifier.NewChain(hv))
	}
	return srv, clientsDir
}

// signForTest produces a valid X-Veilgate-Signature for one request.
// Kept inline so a future shape change to the canonical string
// breaks this test and not silently the consumer.
func signForTest(t *testing.T, secret string, method, path string, body []byte, ts int64) string {
	t.Helper()
	bodySum := sha256.Sum256(body)
	canonical := strconv.FormatInt(ts, 10) + "." + method + "." + path + "." + hex.EncodeToString(bodySum[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

// resetMetrics clears the package-level Prometheus counters between
// subtests so any future assertion that reads them isn't polluted by
// the previous case. We only reset counter-typed metrics; histograms
// don't expose Reset() in the prom client library and we don't assert
// on them anyway.
func resetMetrics() {
	telemetry.RequestsTotal.Reset()
	telemetry.ScoreByDecision.Reset()
	telemetry.SignalHits.Reset()
}

func TestVerifierBypassesChallenge(t *testing.T) {
	resetMetrics()
	upstream, hits := upstreamProbe(t)
	srv, _ := buildTestServer(t, upstream.URL, true)
	handler := srv.Handler()

	// Same request that would otherwise be challenge-band (UA matches
	// suspicious_ua + sparse_headers = ~50 pts). With a valid HMAC
	// signature, the verifier accepts and the request reaches upstream.
	ts := time.Now().Unix()
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "203.0.113.10:12345" // public IP, not loopback
	req.Header.Set("User-Agent", "python-requests/2.32.3")
	req.Header.Set("X-Veilgate-Signature", signForTest(t, "integration-test-secret", "GET", "/api/data", nil, ts))
	req.Header.Set("X-Veilgate-Client", "test-client")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected upstream 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if *hits != 1 {
		t.Fatalf("expected 1 upstream hit, got %d", *hits)
	}
	if rr.Header().Get("X-Test-Tarpit") != "" {
		t.Fatalf("tarpit ran when verifier should have bypassed")
	}
}

func TestVerifierRejectionFallsThroughToScore(t *testing.T) {
	resetMetrics()
	upstream, _ := upstreamProbe(t)
	srv, _ := buildTestServer(t, upstream.URL, true)
	handler := srv.Handler()

	// Bad signature → verifier rejects. Score puts request in the
	// challenge band → 503 HTML challenge (or 401 JSON if XHR-shaped).
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("User-Agent", "python-requests/2.32.3")
	req.Header.Set("X-Veilgate-Signature", "t=1,v1=deadbeef")
	req.Header.Set("X-Veilgate-Client", "test-client")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Should be a challenge (503 HTML or 401 JSON) — not upstream OK.
	if rr.Code == http.StatusOK {
		t.Fatalf("expected challenge response, got 200 (suggests verifier was accepted)")
	}
}

func TestTarpitOverridesVerifierBypass(t *testing.T) {
	// The load-bearing security invariant: even a request the HMAC
	// verifier accepted with a valid signature is STILL tarpitted
	// when the behavioural score reaches the tarpit threshold. A
	// leaked secret can't whitewash attack-shape traffic.
	resetMetrics()
	upstream, hits := upstreamProbe(t)
	srv, _ := buildTestServer(t, upstream.URL, true)
	handler := srv.Handler()

	// /wp-login.php is a honeypot path = 50pts on first hit + suspicious_ua etc.
	// = well above the 70pt tarpit threshold. Valid signature attached.
	ts := time.Now().Unix()
	req := httptest.NewRequest(http.MethodGet, "/wp-login.php", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("User-Agent", "sqlmap/1.8.7#stable")
	req.Header.Set("X-Veilgate-Signature", signForTest(t, "integration-test-secret", "GET", "/wp-login.php", nil, ts))
	req.Header.Set("X-Veilgate-Client", "test-client")

	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if *hits != 0 {
		t.Fatalf("upstream was hit despite tarpit-tier score; Tarpit override failed (%d hits)", *hits)
	}
	if rr.Header().Get("X-Test-Tarpit") != "1" {
		t.Fatalf("tarpit handler did not run; got status=%d body=%q", rr.Code, rr.Body.String())
	}
}

func TestVerifierChainNotConfiguredFallsThroughToPoWCookie(t *testing.T) {
	// When SetVerifiers is never called, the chain is nil and the
	// proxy must fall through to the existing PoW cookie check.
	// Verifies we didn't accidentally make verifier-chain a hard
	// dependency.
	resetMetrics()
	upstream, _ := upstreamProbe(t)
	srv, _ := buildTestServer(t, upstream.URL, false) // no verifier

	// Forge a valid PoW cookie by piggybacking on the challenge
	// handler's signing key. The handler issues cookies of shape
	// "<RFC3339>.<HMAC>" — replicate that here.
	cr := newChallengeRulesForTest(t)
	tsStr := time.Now().Format(time.RFC3339)
	mac := hmacSign(t, "test-secret-not-default", tsStr)
	cookieValue := tsStr + "." + mac

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("User-Agent", "python-requests/2.32.3")
	req.AddCookie(&http.Cookie{Name: cr.CookieName, Value: cookieValue})

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected upstream 200 from valid PoW cookie, got %d (body=%q)",
			rr.Code, rr.Body.String())
	}
}

func TestHeaderTokenAcceptedAsPoWCredential(t *testing.T) {
	// Same as the cookie test but the token travels as the header
	// (Tier 1 transport for cross-origin SPAs).
	resetMetrics()
	upstream, _ := upstreamProbe(t)
	srv, _ := buildTestServer(t, upstream.URL, false)

	cr := newChallengeRulesForTest(t)
	tsStr := time.Now().Format(time.RFC3339)
	mac := hmacSign(t, "test-secret-not-default", tsStr)
	tokenValue := tsStr + "." + mac

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("User-Agent", "python-requests/2.32.3")
	hdr := cr.TokenHeaderName
	if hdr == "" {
		hdr = "X-Veilgate-Token"
	}
	req.Header.Set(hdr, tokenValue)

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected upstream 200 from valid header token, got %d", rr.Code)
	}
}

func TestSPAAwareChallengeReturnsJSONForFetch(t *testing.T) {
	// Tier 2 wiring check from the proxy entrypoint: a fetch-shaped
	// request whose score lands in the challenge band gets 401 JSON,
	// not the 503 HTML page.
	resetMetrics()
	upstream, _ := upstreamProbe(t)
	srv, _ := buildTestServer(t, upstream.URL, false)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	req.Header.Set("User-Agent", "python-requests/2.32.3")
	req.Header.Set("Sec-Fetch-Dest", "empty") // marks this as fetch()
	req.Header.Set("Origin", "https://app.example.com")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for fetch-shaped challenge, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected JSON content-type, got %q", ct)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "https://app.example.com" {
		t.Fatalf("CORS allow-origin should echo Origin, got %q", rr.Header().Get("Access-Control-Allow-Origin"))
	}
}

// --- discovery endpoint tests ---------------------------------------

// buildDiscoveryServer builds a minimal Server with a self-contained
// challenge handler (no rules directory required) so these tests are
// runnable without the external rules/ tree.
func buildDiscoveryServer(t *testing.T, upstreamURL string) *Server {
	t.Helper()
	cfg := &config.Config{
		Mode:     "auto",
		Upstream: upstreamURL,
		Detector: config.DetectorConfig{
			ScoreChallengeThreshold: 40,
			ScoreTarpitThreshold:    70,
		},
	}
	tracker := detector.NewTracker(60)
	scorer := detector.NewScorer(tracker, nil, nil)

	// NewHandler uses embedded-default ChallengeRules (zero value).
	// Override the important descriptor fields via SetRules so the
	// discovery assertions have well-known values to check.
	ch := challenge.NewHandler("disc-test-secret", 0, 0)
	ch.SetRules(rules.NewHolder(&rules.ChallengeRules{
		VerifyPath:      "/__veilgate/verify",
		CookieName:      "veilgate_pow",
		TokenHeaderName: "X-Veilgate-Token",
	}))

	tarpit := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv, err := NewServer(cfg, scorer, tarpit, ch, nil, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestDiscoveryEndpointShape(t *testing.T) {
	// /__veilgate/.well-known returns JSON with challenge + credentials.
	// Verify: Content-Type, Cache-Control, CORS, and field presence.
	resetMetrics()
	upstream, _ := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)

	// Wire a bearer verifier so credentials is non-empty.
	tokensDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tokensDir, "sdk-client.token"), []byte("disc-test-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	bv, err := verifier.NewBearerVerifier(verifier.BearerConfig{TokensDir: tokensDir})
	if err != nil {
		t.Fatalf("NewBearerVerifier: %v", err)
	}
	srv.SetVerifiers(verifier.NewChain(bv))

	req := httptest.NewRequest(http.MethodGet, "/__veilgate/.well-known", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected application/json, got %q", ct)
	}
	if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "max-age=60") {
		t.Fatalf("expected Cache-Control with max-age=60, got %q", cc)
	}
	if cors := rr.Header().Get("Access-Control-Allow-Origin"); cors != "*" {
		t.Fatalf("expected CORS *, got %q", cors)
	}

	var doc discoveryDoc
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Challenge == nil {
		t.Fatal("challenge block absent from discovery doc")
	}
	if doc.Challenge.VerifyPath != "/__veilgate/verify" {
		t.Errorf("challenge.verify_path: got %q, want /__veilgate/verify", doc.Challenge.VerifyPath)
	}
	if doc.Challenge.TokenHeader != "X-Veilgate-Token" {
		t.Errorf("challenge.token_header: got %q, want X-Veilgate-Token", doc.Challenge.TokenHeader)
	}
	if doc.Challenge.CookieName != "veilgate_pow" {
		t.Errorf("challenge.cookie_name: got %q, want veilgate_pow", doc.Challenge.CookieName)
	}
	if len(doc.Credentials) == 0 {
		t.Fatal("credentials block absent from discovery doc")
	}
	if doc.Credentials[0].Type != "bearer" {
		t.Errorf("credentials[0].type: got %q, want bearer", doc.Credentials[0].Type)
	}
}

func TestStartInterstitialRouting(t *testing.T) {
	// /__veilgate/start must be routed to the challenge handler's ServeStart.
	// It should return an HTML page (not be passed to upstream or the scorer).
	resetMetrics()
	upstream, hits := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/__veilgate/start", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body=%q)", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected text/html, got %q", ct)
	}
	if *hits != 0 {
		t.Fatalf("start page reached upstream (%d hits); must never reach upstream", *hits)
	}
	if !strings.Contains(rr.Body.String(), "veilgate-token") {
		t.Error("start page body missing veilgate-token postMessage type")
	}
}

func TestStartInterstitialWithOriginParam(t *testing.T) {
	resetMetrics()
	upstream, _ := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/__veilgate/start?origin=https://spa.example.com", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "https://spa.example.com") {
		t.Error("start page should embed the requested origin")
	}
}

func TestDiscoveryEndpointNoCreds(t *testing.T) {
	// When no verifier chain is configured, discovery returns a valid
	// doc with just the challenge block and no credentials field.
	resetMetrics()
	upstream, _ := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)

	req := httptest.NewRequest(http.MethodGet, "/__veilgate/.well-known", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var doc discoveryDoc
	if err := json.NewDecoder(rr.Body).Decode(&doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc.Challenge == nil {
		t.Fatal("challenge block should still be present when no verifiers configured")
	}
	if doc.Credentials != nil {
		t.Fatalf("credentials should be absent when no verifiers, got %v", doc.Credentials)
	}
}

// --- helpers --------------------------------------------------------

// newChallengeRulesForTest returns the cookie + header names the
// challenge handler uses. We can't reach into the package's private
// rules holder from here, so we rely on the documented defaults.
// If those defaults change in internal/rules/defaults/challenge.yaml,
// the test will fail loudly and tell us to update.
func newChallengeRulesForTest(_ *testing.T) struct {
	CookieName      string
	TokenHeaderName string
} {
	return struct {
		CookieName      string
		TokenHeaderName string
	}{
		CookieName:      "veilgate_pow",
		TokenHeaderName: "X-Veilgate-Token",
	}
}

// hmacSign duplicates challenge.Handler.sign so this test doesn't
// reach into the private surface of another package. The shape
// (HMAC-SHA256 over the timestamp string) must match challenge.go.
func hmacSign(t *testing.T, secret, payload string) string {
	t.Helper()
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

