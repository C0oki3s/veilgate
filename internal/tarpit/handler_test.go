package tarpit

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/rules"
)

func testRulesDir(t testing.TB) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Join(filepath.Dir(file), "..", "..")
	if dir := filepath.Join(root, "veilgate-rules"); dirExists(dir) {
		return dir
	}
	return filepath.Join(root, "rules")
}

func newTestHandler(t testing.TB) *Handler {
	t.Helper()
	cfg := &config.TarpitConfig{
		MinLatencyMs: 1, // fast for tests
		MaxLatencyMs: 2,
		MaxBodyBytes: 1024 * 1024,
	}
	h := NewHandler(cfg, NewProfileStore(), nil)
	dir := testRulesDir(t)
	if tpls, err := rules.LoadTemplates(dir); err == nil {
		vuln, _ := rules.LoadVulnerabilities(dir)
		strat, _ := rules.LoadInjectionStrategy(dir)
		var vh *rules.Holder[rules.Vulnerabilities]
		var sh *rules.Holder[rules.InjectionStrategy]
		if vuln != nil {
			vh = rules.NewHolder(vuln)
		}
		if strat != nil {
			sh = rules.NewHolder(strat)
		}
		h.SetRules(rules.NewHolder(tpls), vh, sh)
	}
	return h
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func TestRouteLoginPage(t *testing.T) {
	h := newTestHandler(t)
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
	h := newTestHandler(t)
	r := httptest.NewRequest("GET", "/api/users?id=1%20or%201=1--", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 500 {
		t.Errorf("SQL injection pattern should return 500, got %d", w.Code)
	}
	body := w.Body.String()
	lower := strings.ToLower(body)
	if !strings.Contains(lower, "prisma") && !strings.Contains(lower, "database query error") {
		t.Error("SQL injection should return a realistic database error body")
	}
}

func TestRouteGitConfig(t *testing.T) {
	h := newTestHandler(t)
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
	h := newTestHandler(t)
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
