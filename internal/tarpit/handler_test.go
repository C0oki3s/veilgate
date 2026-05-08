package tarpit

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/config"
)

func newTestHandler() *Handler {
	cfg := &config.TarpitConfig{
		MinLatencyMs: 1, // fast for tests
		MaxLatencyMs: 2,
		MaxBodyBytes: 1024 * 1024,
	}
	return NewHandler(cfg, NewProfileStore(), nil)
}

func TestRouteLoginPage(t *testing.T) {
	h := newTestHandler()
	r := httptest.NewRequest("GET", "/login", nil)
	r.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 200 {
		t.Errorf("login page should return 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "<form") {
		t.Error("login page should contain a form")
	}
	if w.Header().Get("Server") == "" {
		t.Error("login page should set fake Server header")
	}
}

func TestRouteSQLErrorOnInjection(t *testing.T) {
	h := newTestHandler()
	r := httptest.NewRequest("GET", "/api/users?id=1'+or+1=1--", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 500 {
		t.Errorf("SQL injection pattern should return 500, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(strings.ToLower(body), "sql") {
		t.Error("SQL error body should mention SQL")
	}
}

func TestRouteGitConfig(t *testing.T) {
	h := newTestHandler()
	r := httptest.NewRequest("GET", "/.git/config", nil)
	r.RemoteAddr = "10.0.0.3:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	body := w.Body.String()
	if !strings.Contains(body, "[remote") {
		t.Error("fake git config should contain [remote] section")
	}
}

func TestRoutePersistenceSameProfile(t *testing.T) {
	h := newTestHandler()
	r1 := httptest.NewRequest("GET", "/login", nil)
	r1.RemoteAddr = "10.0.0.4:1111"
	w1 := httptest.NewRecorder()
	h.ServeHTTP(w1, r1)

	r2 := httptest.NewRequest("GET", "/login", nil)
	r2.RemoteAddr = "10.0.0.4:2222"
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, r2)

	// Same client (IP portion) should see same fake Server string on both visits.
	if w1.Header().Get("Server") != w2.Header().Get("Server") {
		t.Error("same client IP should see consistent fake server across visits")
	}
}

func TestProfileStoreDeterministicSeed(t *testing.T) {
	s := NewProfileStore()
	p1 := s.Get("10.0.0.5")
	p2 := s.Get("10.0.0.5")
	if p1.Seed != p2.Seed {
		t.Error("same client ID must produce same seed")
	}
	if p1.FakeCompany != p2.FakeCompany {
		t.Error("same client ID must produce same fake company")
	}
}

func TestProfileStoreDifferentClientsDifferentProfiles(t *testing.T) {
	s := NewProfileStore()
	p1 := s.Get("10.0.0.6")
	p2 := s.Get("10.0.0.7")
	if p1.Seed == p2.Seed {
		t.Error("different client IDs should produce different seeds")
	}
}

func TestClientIPIgnoresUntrustedXFF(t *testing.T) {
	r := httptest.NewRequest("GET", "/login", nil)
	r.RemoteAddr = "203.0.113.9:4321"
	r.Header.Set("X-Forwarded-For", "198.51.100.123")
	if got := clientIP(r); got != "203.0.113.9" {
		t.Fatalf("expected remote peer ip, got %q", got)
	}
}
