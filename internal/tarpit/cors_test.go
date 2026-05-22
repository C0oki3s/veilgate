package tarpit

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/C0oki3s/veilgate/internal/config"
)

func newCORSTestHandler() *Handler {
	return NewHandler(
		&config.TarpitConfig{
			MinLatencyMs: 0,
			MaxLatencyMs: 0,
			MaxBodyBytes: 10000,
		},
		NewProfileStore(),
		nil,
	)
}

// TestTarpitHandlerSetsCORSOnCrossOriginRequest verifies that the tarpit
// handler sets Access-Control-Allow-Origin (echoing the request Origin),
// Access-Control-Allow-Credentials, and Vary on every cross-origin response.
func TestTarpitHandlerSetsCORSOnCrossOriginRequest(t *testing.T) {
	tp := newCORSTestHandler()

	r := httptest.NewRequest(http.MethodGet, "/page", nil)
	r.Header.Set("Origin", "https://app.example.com")

	w := httptest.NewRecorder()
	tp.ServeHTTP(w, r)

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

// TestTarpitHandlerNoCORSWithoutOrigin verifies that CORS headers are absent
// when the request does not carry an Origin header (same-origin or tool traffic).
func TestTarpitHandlerNoCORSWithoutOrigin(t *testing.T) {
	tp := newCORSTestHandler()

	r := httptest.NewRequest(http.MethodGet, "/page", nil)
	// No Origin header.

	w := httptest.NewRecorder()
	tp.ServeHTTP(w, r)

	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("ACAO should be absent without Origin header, got %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("ACAC should be absent without Origin header, got %q", got)
	}
}

// TestTarpitHandlerCORSAppearsOnNonOKResponses verifies that CORS headers
// are present even when the tarpit returns a non-200 status (e.g. template
// not found returns 500), so the browser can read error details cross-origin.
func TestTarpitHandlerCORSAppearsOnNonOKResponses(t *testing.T) {
	tp := newCORSTestHandler()

	r := httptest.NewRequest(http.MethodGet, "/some-api-endpoint", nil)
	r.Header.Set("Origin", "https://demo.veilgate.dev")

	w := httptest.NewRecorder()
	tp.ServeHTTP(w, r)

	// Regardless of the response status, CORS header must be present.
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "https://demo.veilgate.dev" {
		t.Fatalf("ACAO = %q, want https://demo.veilgate.dev (status was %d)", got, w.Code)
	}
}
