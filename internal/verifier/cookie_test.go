package verifier

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestOpaqueValidator(t *testing.T, client, token string) (*OpaqueValidator, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, client+".token"), []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	v, err := NewOpaqueValidator(dir)
	if err != nil {
		t.Fatalf("NewOpaqueValidator: %v", err)
	}
	return v, dir
}

func TestCookieVerifierAccepts(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "internal-session", "session-abc-123")
	v, err := NewCookieVerifier("MY_SESSION", val)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "MY_SESSION", Value: "session-abc-123"})

	res := v.Verify(req)
	if !res.Accepted {
		t.Fatalf("expected accept, got reject: %q", res.Reason)
	}
	if res.Client != "internal-session" {
		t.Fatalf("expected client=internal-session, got %q", res.Client)
	}
	if v.Name() != "cookie:MY_SESSION" {
		t.Fatalf("expected name=cookie:MY_SESSION, got %q", v.Name())
	}
}

func TestCookieVerifierReturnsEmptyOnMissingCookie(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "internal-session", "session-abc-123")
	v, _ := NewCookieVerifier("MY_SESSION", val)

	// No cookie at all — verifier should return a zero Result so the
	// chain can continue without polluting the audit log.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject when cookie absent")
	}
	if res.Reason != "" {
		t.Fatalf("expected empty Reason when cookie absent, got %q", res.Reason)
	}
}

func TestCookieVerifierRejectsUnknownValue(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "internal-session", "session-abc-123")
	v, _ := NewCookieVerifier("MY_SESSION", val)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "MY_SESSION", Value: "wrong-value"})

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject on unknown value")
	}
	if !strings.Contains(res.Reason, "unknown") {
		t.Fatalf("expected reason about unknown value, got %q", res.Reason)
	}
}

func TestCookieVerifierRejectsEmptyValue(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "internal-session", "session-abc-123")
	v, _ := NewCookieVerifier("MY_SESSION", val)

	// Browser sends the cookie header with an empty value — treat as
	// absent rather than as a presented credential. Otherwise an
	// attacker could probe whether the validator accepts the empty
	// string.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.AddCookie(&http.Cookie{Name: "MY_SESSION", Value: ""})

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject on empty cookie value")
	}
	// Reason should be empty (treated as absent) so the chain keeps
	// quiet.
	if res.Reason != "" {
		t.Fatalf("expected empty Reason for empty cookie, got %q", res.Reason)
	}
}

func TestCookieVerifierRequiresName(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "x", "y")
	if _, err := NewCookieVerifier("", val); err == nil {
		t.Fatalf("expected error when cookie name is empty")
	}
}

func TestCookieVerifierRequiresValidator(t *testing.T) {
	if _, err := NewCookieVerifier("MY_SESSION", nil); err == nil {
		t.Fatalf("expected error when validator is nil")
	}
}

func TestCookieVerifierHotReload(t *testing.T) {
	val, dir := newTestOpaqueValidator(t, "alpha", "old-value")
	v, _ := NewCookieVerifier("SESSION", val)

	// Rotate the value
	time.Sleep(20 * time.Millisecond)
	path := filepath.Join(dir, "alpha.token")
	now := time.Now()
	if err := os.WriteFile(path, []byte("new-value"), 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := os.Chtimes(dir, now, now.Add(time.Second)); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	reqOld := httptest.NewRequest(http.MethodGet, "/", nil)
	reqOld.AddCookie(&http.Cookie{Name: "SESSION", Value: "old-value"})
	if v.Verify(reqOld).Accepted {
		t.Fatalf("expected reject of rotated-out cookie value")
	}

	reqNew := httptest.NewRequest(http.MethodGet, "/", nil)
	reqNew.AddCookie(&http.Cookie{Name: "SESSION", Value: "new-value"})
	if !v.Verify(reqNew).Accepted {
		t.Fatalf("expected accept after rotation")
	}
}

func TestOpaqueValidatorEmptyValueRejected(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "x", "y")
	if _, ok, _ := val.Validate(""); ok {
		t.Fatalf("empty value must never validate")
	}
}

func TestOpaqueValidatorRequiresDir(t *testing.T) {
	if _, err := NewOpaqueValidator(""); err == nil {
		t.Fatalf("expected error on empty dir")
	}
	if _, err := NewOpaqueValidator("/nonexistent/xyz"); err == nil {
		t.Fatalf("expected error on missing dir")
	}
}
