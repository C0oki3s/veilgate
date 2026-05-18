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

// newTestBearerVerifier writes one token to a tmp dir and returns the
// verifier wired to it. Centralises setup so individual tests stay
// focused on behaviour.
func newTestBearerVerifier(t *testing.T, client, token string) (*BearerVerifier, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, client+".token"), []byte(token), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	v, err := NewBearerVerifier(BearerConfig{TokensDir: dir})
	if err != nil {
		t.Fatalf("NewBearerVerifier: %v", err)
	}
	return v, dir
}

func TestBearerAcceptsValidToken(t *testing.T) {
	v, _ := newTestBearerVerifier(t, "payments", "vg_pat_test_abc123")

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer vg_pat_test_abc123")

	res := v.Verify(req)
	if !res.Accepted {
		t.Fatalf("expected accept, got reject: %q", res.Reason)
	}
	if res.Client != "payments" {
		t.Fatalf("expected client=payments, got %q", res.Client)
	}
	if res.Name != "bearer" {
		t.Fatalf("expected name=bearer, got %q", res.Name)
	}
}

func TestBearerRejectsUnknownToken(t *testing.T) {
	v, _ := newTestBearerVerifier(t, "payments", "vg_pat_test_abc123")

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer vg_pat_test_DIFFERENT")

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject on unknown token")
	}
	if !strings.Contains(res.Reason, "unknown") {
		t.Fatalf("expected reason about unknown token, got %q", res.Reason)
	}
}

func TestBearerReturnsEmptyOnMissingHeader(t *testing.T) {
	v, _ := newTestBearerVerifier(t, "payments", "vg_pat_test_abc123")

	// No Authorization header — verifier should return zero-value
	// Result so the chain can keep walking without an audit-log entry.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject when no Authorization header")
	}
	if res.Reason != "" {
		t.Fatalf("expected empty Reason when header absent, got %q", res.Reason)
	}
}

func TestBearerRejectsWrongScheme(t *testing.T) {
	v, _ := newTestBearerVerifier(t, "payments", "vg_pat_test_abc123")

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Basic vg_pat_test_abc123")

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject on wrong scheme")
	}
	if !strings.Contains(res.Reason, "scheme") {
		t.Fatalf("expected reason about scheme, got %q", res.Reason)
	}
}

func TestBearerSchemeIsCaseInsensitive(t *testing.T) {
	// RFC 7235 §2.1: scheme is case-insensitive. "bearer" must work.
	v, _ := newTestBearerVerifier(t, "payments", "vg_pat_test_abc123")

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "bearer vg_pat_test_abc123")

	if res := v.Verify(req); !res.Accepted {
		t.Fatalf("expected accept on lowercase scheme: %q", res.Reason)
	}
}

func TestBearerCustomHeaderRawToken(t *testing.T) {
	// Custom header without a scheme prefix: the entire header value
	// is the token. Use case: Cloudflare Access service tokens, where
	// CF-Access-Client-Secret carries the raw secret.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "internal.token"), []byte("raw-secret-xyz"), 0o600); err != nil {
		t.Fatalf("write token: %v", err)
	}
	v, err := NewBearerVerifier(BearerConfig{
		Header:    "X-Internal-Service-Token",
		Scheme:    "", // raw-token mode
		TokensDir: dir,
	})
	if err != nil {
		t.Fatalf("NewBearerVerifier: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Internal-Service-Token", "raw-secret-xyz")

	if res := v.Verify(req); !res.Accepted {
		t.Fatalf("expected accept in raw-token mode: %q", res.Reason)
	}
}

func TestBearerHotReloadOnNewToken(t *testing.T) {
	v, dir := newTestBearerVerifier(t, "alpha", "token-alpha")

	// Drop in a second client's token after startup. Verifier must
	// pick it up without restart.
	time.Sleep(20 * time.Millisecond)
	path := filepath.Join(dir, "beta.token")
	now := time.Now()
	if err := os.WriteFile(path, []byte("token-beta"), 0o600); err != nil {
		t.Fatalf("write beta token: %v", err)
	}
	// Bump the directory mtime — on some filesystems creating a file
	// updates the parent dir mtime, but force it to be sure.
	if err := os.Chtimes(dir, now, now.Add(time.Second)); err != nil {
		t.Fatalf("chtimes dir: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Authorization", "Bearer token-beta")

	res := v.Verify(req)
	if !res.Accepted {
		t.Fatalf("expected accept of newly-added token, got %q", res.Reason)
	}
	if res.Client != "beta" {
		t.Fatalf("expected client=beta, got %q", res.Client)
	}
}

func TestBearerHotReloadOnRotation(t *testing.T) {
	v, dir := newTestBearerVerifier(t, "alpha", "old-token")

	// Rotate: overwrite the alpha token. Old value must stop working,
	// new value must start working — without restart.
	time.Sleep(20 * time.Millisecond)
	path := filepath.Join(dir, "alpha.token")
	now := time.Now()
	if err := os.WriteFile(path, []byte("new-token"), 0o600); err != nil {
		t.Fatalf("rewrite token: %v", err)
	}
	if err := os.Chtimes(dir, now, now.Add(time.Second)); err != nil {
		t.Fatalf("chtimes dir: %v", err)
	}

	reqOld := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	reqOld.Header.Set("Authorization", "Bearer old-token")
	if v.Verify(reqOld).Accepted {
		t.Fatalf("expected reject of rotated-out token")
	}

	reqNew := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	reqNew.Header.Set("Authorization", "Bearer new-token")
	if !v.Verify(reqNew).Accepted {
		t.Fatalf("expected accept of new token after rotation")
	}
}

func TestBearerRequiresTokensDir(t *testing.T) {
	if _, err := NewBearerVerifier(BearerConfig{TokensDir: ""}); err == nil {
		t.Fatalf("expected error when tokens_dir is empty")
	}
	if _, err := NewBearerVerifier(BearerConfig{TokensDir: "/nonexistent/path/xyz"}); err == nil {
		t.Fatalf("expected error when tokens_dir does not exist")
	}
}

func TestBearerSkipsHiddenFiles(t *testing.T) {
	// Editor swap / hidden files in the tokens dir must not produce a
	// usable token. Otherwise a stray ".alpha.token.swp" with VIM
	// contents could grant access.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".alpha.token.swp"), []byte("garbage-vim-buffer"), 0o600); err != nil {
		t.Fatalf("write hidden: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "alpha.token"), []byte("real-token"), 0o600); err != nil {
		t.Fatalf("write real: %v", err)
	}
	v, err := NewBearerVerifier(BearerConfig{TokensDir: dir})
	if err != nil {
		t.Fatalf("NewBearerVerifier: %v", err)
	}

	// Hidden contents must not match
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer garbage-vim-buffer")
	if v.Verify(req).Accepted {
		t.Fatalf("hidden swap file must not produce a usable token")
	}

	// Real token still works
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Authorization", "Bearer real-token")
	if !v.Verify(req2).Accepted {
		t.Fatalf("real token must still work")
	}
}
