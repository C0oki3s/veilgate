package verifier

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// newTestHMACVerifier writes one client secret to a tmp dir and
// returns the verifier wired to it. Centralises setup so individual
// tests stay focused on behaviour.
func newTestHMACVerifier(t *testing.T, clientName, secret string) (*HMACVerifier, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, clientName+".secret")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	v, err := NewHMACVerifier(HMACConfig{ClientsDir: dir})
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}
	return v, dir
}

// signRequest produces a valid X-Veilgate-Signature for the given
// (method, path, body, ts) tuple. Mirror of what the operator's
// client code does — kept in the test so a mismatch with the
// production verifier surfaces as a test failure.
func signRequest(secret, method, path, body string, ts int64) string {
	bodySum := sha256.Sum256([]byte(body))
	canonical := strconv.FormatInt(ts, 10) + "." + method + "." + path + "." + hex.EncodeToString(bodySum[:])
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(canonical))
	return "t=" + strconv.FormatInt(ts, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestHMACVerifyAcceptsValidSignature(t *testing.T) {
	v, _ := newTestHMACVerifier(t, "payment-service", "shared-secret-1234")
	ts := time.Now().Unix()
	sig := signRequest("shared-secret-1234", http.MethodGet, "/api/data", "", ts)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Veilgate-Signature", sig)
	req.Header.Set("X-Veilgate-Client", "payment-service")

	res := v.Verify(req)
	if !res.Accepted {
		t.Fatalf("expected accept, got reject: %q", res.Reason)
	}
	if res.Client != "payment-service" {
		t.Fatalf("expected client=payment-service, got %q", res.Client)
	}
}

func TestHMACVerifyRejectsTamperedSignature(t *testing.T) {
	v, _ := newTestHMACVerifier(t, "client-a", "secret-a")
	ts := time.Now().Unix()
	sig := signRequest("secret-a", http.MethodPost, "/api/transfer", `{"amount":10}`, ts)

	// Same headers, but body changed in flight — body-hash differs,
	// so the signature must not validate.
	req := httptest.NewRequest(http.MethodPost, "/api/transfer", bytes.NewReader([]byte(`{"amount":100000}`)))
	req.Header.Set("X-Veilgate-Signature", sig)
	req.Header.Set("X-Veilgate-Client", "client-a")

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject on tampered body, got accept")
	}
}

func TestHMACVerifyRejectsExpiredTimestamp(t *testing.T) {
	v, _ := newTestHMACVerifier(t, "client-a", "secret-a")
	// 10 minutes in the past — well beyond the 5min default skew.
	ts := time.Now().Add(-10 * time.Minute).Unix()
	sig := signRequest("secret-a", http.MethodGet, "/api/data", "", ts)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Veilgate-Signature", sig)
	req.Header.Set("X-Veilgate-Client", "client-a")

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject on expired timestamp")
	}
	if !strings.Contains(res.Reason, "timestamp") {
		t.Fatalf("expected reason mentioning timestamp, got %q", res.Reason)
	}
}

func TestHMACVerifyRejectsUnknownClient(t *testing.T) {
	v, _ := newTestHMACVerifier(t, "client-a", "secret-a")
	ts := time.Now().Unix()
	sig := signRequest("secret-a", http.MethodGet, "/api/data", "", ts)

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Veilgate-Signature", sig)
	req.Header.Set("X-Veilgate-Client", "client-b") // no client-b.secret on disk

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject for unknown client")
	}
}

func TestHMACVerifyRejectsPathTraversalClientName(t *testing.T) {
	v, _ := newTestHMACVerifier(t, "client-a", "secret-a")
	ts := time.Now().Unix()
	sig := signRequest("secret-a", http.MethodGet, "/api/data", "", ts)

	// Try to load ../something via the client name. The verifier must
	// reject this BEFORE touching the filesystem.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Veilgate-Signature", sig)
	req.Header.Set("X-Veilgate-Client", "../etc/passwd")

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject for path-traversal client name")
	}
	if !strings.Contains(res.Reason, "invalid") {
		t.Fatalf("expected reason mentioning invalid characters, got %q", res.Reason)
	}
}

func TestHMACVerifyReturnsEmptyOnMissingHeader(t *testing.T) {
	v, _ := newTestHMACVerifier(t, "client-a", "secret-a")

	// No signature header at all — verifier should return a
	// non-accepted, empty Result (not log noise about a malformed
	// header), so the chain can move on to the next verifier.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject when no signature header")
	}
	if res.Reason != "" {
		t.Fatalf("expected empty Reason when header absent, got %q", res.Reason)
	}
}

func TestHMACSecretHotReloadOnFileChange(t *testing.T) {
	v, dir := newTestHMACVerifier(t, "client-a", "old-secret")

	// Touching the file with the same secret should still hit the
	// cache after the initial load; mtime change triggers a re-read.
	ts := time.Now().Unix()
	sig := signRequest("old-secret", http.MethodGet, "/api/data", "", ts)
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Veilgate-Signature", sig)
	req.Header.Set("X-Veilgate-Client", "client-a")
	if !v.Verify(req).Accepted {
		t.Fatalf("expected accept on initial secret")
	}

	// Rewrite the secret. mtime must advance enough for the cache
	// check to notice — on some filesystems mtime resolution is 1s.
	time.Sleep(20 * time.Millisecond)
	path := filepath.Join(dir, "client-a.secret")
	now := time.Now()
	if err := os.WriteFile(path, []byte("new-secret"), 0o600); err != nil {
		t.Fatalf("rewrite secret: %v", err)
	}
	if err := os.Chtimes(path, now, now.Add(time.Second)); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	// Old signature with old secret should now fail.
	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected old-secret signature to be rejected after rotation")
	}

	// New signature with new secret should pass.
	ts2 := time.Now().Unix()
	sig2 := signRequest("new-secret", http.MethodGet, "/api/data", "", ts2)
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req2.Header.Set("X-Veilgate-Signature", sig2)
	req2.Header.Set("X-Veilgate-Client", "client-a")
	if !v.Verify(req2).Accepted {
		t.Fatalf("expected accept under new secret")
	}
}

func TestChainShortCircuits(t *testing.T) {
	v1 := &stubVerifier{name: "v1", accept: false}
	v2 := &stubVerifier{name: "v2", accept: true}
	v3 := &stubVerifier{name: "v3", accept: true} // should never be called

	chain := NewChain(v1, v2, v3)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := chain.Verify(req)
	if res.Name != "v2" {
		t.Fatalf("expected v2 to win, got %q", res.Name)
	}
	if v3.calls != 0 {
		t.Fatalf("expected v3 to be skipped after v2 accepted, got %d calls", v3.calls)
	}
}

func TestChainNilSafe(t *testing.T) {
	var chain *Chain // nil
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := chain.Verify(req)
	if res.Accepted {
		t.Fatalf("nil chain should never accept")
	}
}

type stubVerifier struct {
	name   string
	accept bool
	calls  int
}

func (s *stubVerifier) Name() string { return s.name }
func (s *stubVerifier) Verify(_ *http.Request) Result {
	s.calls++
	if s.accept {
		return Result{Accepted: true, Name: s.name, Reason: "stub accept"}
	}
	return Result{Name: s.name, Reason: "stub reject"}
}
