package verifier

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// calloutFixture spins up an in-process HTTP server that plays the
// role of the operator's validation endpoint. Behaviour is
// configurable per test via the handler field.
type calloutFixture struct {
	server  *httptest.Server
	hits    int64
	handler func(value string) (status int, client string, ttlSec int)
}

func newCalloutFixture(t *testing.T) *calloutFixture {
	t.Helper()
	f := &calloutFixture{}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.hits, 1)
		var body calloutRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		status, client, ttl := f.handler(body.Value)
		w.WriteHeader(status)
		if status >= 200 && status < 300 {
			_ = json.NewEncoder(w).Encode(calloutResponse{Client: client, CacheTTL: ttl})
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func TestCalloutAcceptsValid(t *testing.T) {
	f := newCalloutFixture(t)
	f.handler = func(v string) (int, string, int) {
		if v == "good-token" {
			return 200, "alice", 0
		}
		return 401, "", 0
	}
	v, err := NewCalloutValidator(CalloutConfig{URL: f.server.URL})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}

	client, ok, reason := v.Validate("good-token")
	if !ok {
		t.Fatalf("expected accept, got reject: %s", reason)
	}
	if client != "alice" {
		t.Fatalf("expected client=alice, got %q", client)
	}
}

func TestCalloutRejectsNon2xx(t *testing.T) {
	f := newCalloutFixture(t)
	f.handler = func(_ string) (int, string, int) { return 401, "", 0 }
	v, err := NewCalloutValidator(CalloutConfig{URL: f.server.URL})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}

	_, ok, reason := v.Validate("any-token")
	if ok {
		t.Fatalf("expected reject on 401")
	}
	if !strings.Contains(reason, "rejected") {
		t.Fatalf("expected reason to mention rejection, got %q", reason)
	}
}

func TestCalloutCachesAffirmative(t *testing.T) {
	f := newCalloutFixture(t)
	f.handler = func(_ string) (int, string, int) { return 200, "alice", 0 }
	v, err := NewCalloutValidator(CalloutConfig{URL: f.server.URL, CacheTTL: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}

	// First call → network
	if _, ok, _ := v.Validate("tok-1"); !ok {
		t.Fatalf("first validate should succeed")
	}
	// Second call → cache; hits should not increment
	if _, ok, _ := v.Validate("tok-1"); !ok {
		t.Fatalf("second validate should succeed from cache")
	}
	if got := atomic.LoadInt64(&f.hits); got != 1 {
		t.Fatalf("expected exactly 1 callout (rest served from cache), got %d", got)
	}
}

func TestCalloutDoesNotCacheNegative(t *testing.T) {
	// Negative responses must NOT be cached — a transient 401 from
	// the upstream must not lock out a credential for the full cache
	// window.
	f := newCalloutFixture(t)
	f.handler = func(_ string) (int, string, int) { return 401, "", 0 }
	v, err := NewCalloutValidator(CalloutConfig{URL: f.server.URL, CacheTTL: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, ok, _ := v.Validate("tok"); ok {
			t.Fatalf("call %d should be rejected", i)
		}
	}
	if got := atomic.LoadInt64(&f.hits); got != 3 {
		t.Fatalf("expected 3 callouts (no negative caching), got %d", got)
	}
}

func TestCalloutPerResultTTLCapsGlobal(t *testing.T) {
	// Per-result TTL of 1s must shorten the cache window even when
	// global default is 1h. Otherwise short-lived tokens would
	// outlive their server-side validity.
	f := newCalloutFixture(t)
	f.handler = func(_ string) (int, string, int) { return 200, "alice", 1 }
	v, err := NewCalloutValidator(CalloutConfig{URL: f.server.URL, CacheTTL: time.Hour})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}

	if _, ok, _ := v.Validate("tok"); !ok {
		t.Fatalf("first validate should succeed")
	}
	if v.CacheSize() != 1 {
		t.Fatalf("expected 1 cache entry")
	}

	// Wait for the per-result TTL to elapse, then purge — the entry
	// must be expired.
	time.Sleep(1100 * time.Millisecond)
	v.purgeExpired()
	if v.CacheSize() != 0 {
		t.Fatalf("expected entry to expire after per-result TTL")
	}
}

func TestCalloutSendsAuthHeader(t *testing.T) {
	// The operator's introspection endpoint may require authn from
	// veilgate itself. AuthHeader/AuthValue plumb that through.
	var seenAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenAuth = r.Header.Get("X-Veilgate-Secret")
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"client":"x"}`))
	}))
	t.Cleanup(srv.Close)

	v, err := NewCalloutValidator(CalloutConfig{
		URL:        srv.URL,
		AuthHeader: "X-Veilgate-Secret",
		AuthValue:  "shhh",
	})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}
	if _, ok, _ := v.Validate("tok"); !ok {
		t.Fatalf("expected accept")
	}
	if seenAuth != "shhh" {
		t.Fatalf("expected upstream to see auth header value, got %q", seenAuth)
	}
}

func TestCalloutEmptyBodyIsAccept(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	t.Cleanup(srv.Close)

	v, err := NewCalloutValidator(CalloutConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}
	client, ok, reason := v.Validate("tok")
	if !ok {
		t.Fatalf("expected accept on 200 with empty body: %s", reason)
	}
	if client != "" {
		t.Fatalf("expected empty client on no-body response, got %q", client)
	}
}

func TestCalloutTransportErrorRejects(t *testing.T) {
	// Server that closes the connection immediately — simulates a
	// network failure to the validator.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "no hijack", 500)
			return
		}
		conn, _, _ := hj.Hijack()
		_ = conn.Close()
	}))
	t.Cleanup(srv.Close)

	v, err := NewCalloutValidator(CalloutConfig{URL: srv.URL, Timeout: 500 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}
	_, ok, reason := v.Validate("tok")
	if ok {
		t.Fatalf("expected reject on transport error")
	}
	if !strings.Contains(reason, "transport") && !strings.Contains(reason, "rejected") {
		t.Fatalf("expected reason about transport error, got %q", reason)
	}
}

func TestCalloutRequiresURL(t *testing.T) {
	if _, err := NewCalloutValidator(CalloutConfig{}); err == nil {
		t.Fatalf("expected error when URL empty")
	}
	if _, err := NewCalloutValidator(CalloutConfig{URL: "not-a-url"}); err == nil {
		t.Fatalf("expected error when URL not http(s)")
	}
}

func TestCalloutCookieIntegration(t *testing.T) {
	f := newCalloutFixture(t)
	f.handler = func(v string) (int, string, int) {
		if v == "good" {
			return 200, "alice", 0
		}
		return 401, "", 0
	}
	cv, err := NewCalloutValidator(CalloutConfig{URL: f.server.URL})
	if err != nil {
		t.Fatalf("NewCalloutValidator: %v", err)
	}
	v, err := NewCookieVerifier("SESSION", cv)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "SESSION", Value: "good"})

	res := v.Verify(req)
	if !res.Accepted {
		t.Fatalf("expected accept: %s", res.Reason)
	}
	if res.Client != "alice" {
		t.Fatalf("expected client=alice, got %q", res.Client)
	}
}
