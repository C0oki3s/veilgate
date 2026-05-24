package proxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── applyCORSHeaders ─────────────────────────────────────────────────────────

func TestApplyCORSHeadersEchoesOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Origin", "https://app.example.com")
	applyCORSHeaders(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO = %q, want https://app.example.com", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Fatalf("ACAC = %q, want true", got)
	}
	if got := w.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}
}

func TestApplyCORSHeadersNoopWithoutOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	// No Origin header.
	applyCORSHeaders(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO should be absent without Origin header, got %q", got)
	}
}

// ── OPTIONS preflight routing ─────────────────────────────────────────────────

// TestCORSPreflightVeilgatePathsSynthesised checks that OPTIONS preflights
// for /_g/* are answered with 204 + CORS headers directly — no
// upstream hit, no scoring, no challenge pipeline.
func TestCORSPreflightVeilgatePathsSynthesised(t *testing.T) {
	upstream, hits := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)
	handler := srv.Handler()

	paths := []string{
		"/_g/verify",
		"/_g/config",
		"/_g/start",
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, path, nil)
			r.Header.Set("Origin", "https://app.example.com")
			r.Header.Set("Access-Control-Request-Method", "POST")
			r.Header.Set("Access-Control-Request-Headers", "Content-Type, X-App-Token")

			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, r)

			if rr.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want 204", rr.Code)
			}
			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
				t.Fatalf("ACAO = %q, want origin", got)
			}
			if got := rr.Header().Get("Access-Control-Allow-Credentials"); got != "true" {
				t.Fatalf("ACAC = %q, want true", got)
			}
			if got := rr.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "Content-Type") {
				t.Fatalf("ACAH = %q, should contain Content-Type", got)
			}
			if rr.Header().Get("Access-Control-Max-Age") == "" {
				t.Fatal("Access-Control-Max-Age must be set on preflight response")
			}
		})
	}
	if *hits != 0 {
		t.Fatalf("preflight for internal paths reached upstream (%d hits)", *hits)
	}
}

// TestCORSPreflightNonVeilgatePathForwardedToUpstream checks that OPTIONS
// preflights for application paths are forwarded to the upstream without
// being scored or challenged.
func TestCORSPreflightNonVeilgatePathForwardedToUpstream(t *testing.T) {
	upstream, hits := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)

	r := httptest.NewRequest(http.MethodOptions, "/api/data", nil)
	r.Header.Set("Origin", "https://app.example.com")
	r.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, r)

	if *hits != 1 {
		t.Fatalf("expected 1 upstream hit for non-internal path preflight, got %d (status=%d)", *hits, rr.Code)
	}
}

// TestCORSPreflightRequiresACRM ensures that OPTIONS requests without
// Access-Control-Request-Method are not treated as preflights (they fall
// through to the normal scoring + routing pipeline instead).
func TestCORSPreflightRequiresACRM(t *testing.T) {
	upstream, _ := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)

	r := httptest.NewRequest(http.MethodOptions, "/page", nil)
	r.Header.Set("Origin", "https://app.example.com")
	// Deliberately no Access-Control-Request-Method.

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, r)

	// Preflight handler returns 204; any other status means it fell through.
	if rr.Code == http.StatusNoContent {
		t.Fatal("got 204 but OPTIONS without ACRM must not trigger the preflight handler")
	}
}

// TestCORSPreflightRequiresOrigin ensures that OPTIONS requests without an
// Origin are not treated as preflights.
func TestCORSPreflightRequiresOrigin(t *testing.T) {
	upstream, _ := upstreamProbe(t)
	srv := buildDiscoveryServer(t, upstream.URL)

	r := httptest.NewRequest(http.MethodOptions, "/page", nil)
	r.Header.Set("Access-Control-Request-Method", "POST")
	// Deliberately no Origin header.

	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, r)

	if rr.Code == http.StatusNoContent {
		t.Fatal("got 204 but OPTIONS without Origin must not trigger the preflight handler")
	}
}

// ── serveUpgradeBlocked extras ────────────────────────────────────────────────

// TestServeUpgradeBlockedContentTypeIsJSON guards against the pre-existing bug
// where http.Error() was called after setting Content-Type: application/json,
// causing http.Error to overwrite it with text/plain.
func TestServeUpgradeBlockedContentTypeIsJSON(t *testing.T) {
	for _, decision := range []Decision{DecisionChallenge, DecisionTarpit} {
		t.Run(decision.String(), func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodGet, "/ws", nil)
			serveUpgradeBlocked(w, r, decision)

			ct := w.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/json") {
				t.Fatalf("Content-Type = %q, want application/json", ct)
			}
			// Body must also be valid JSON.
			var body map[string]string
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatalf("body is not valid JSON: %v (body=%q)", err, w.Body.String())
			}
		})
	}
}

// TestServeUpgradeBlockedNoCORSWithoutOrigin verifies CORS headers are absent
// when the request carries no Origin (same-origin or non-browser caller).
func TestServeUpgradeBlockedNoCORSWithoutOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	serveUpgradeBlocked(w, r, DecisionChallenge)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO should be absent when no Origin header, got %q", got)
	}
}

// TestServeGRPCBlockedNoCORSWithoutOrigin mirrors the above for gRPC.
func TestServeGRPCBlockedNoCORSWithoutOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/svc", nil)
	serveGRPCBlocked(w, r, DecisionChallenge)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO should be absent when no Origin header, got %q", got)
	}
}
