package verifier

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHeaderVerifierAccepts(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "cf-access", "jwt-style-token")
	v, err := NewHeaderVerifier("X-Internal-Service-Token", val)
	if err != nil {
		t.Fatalf("NewHeaderVerifier: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Internal-Service-Token", "jwt-style-token")

	res := v.Verify(req)
	if !res.Accepted {
		t.Fatalf("expected accept, got reject: %q", res.Reason)
	}
	if res.Client != "cf-access" {
		t.Fatalf("expected client=cf-access, got %q", res.Client)
	}
	if v.Name() != "header:X-Internal-Service-Token" {
		t.Fatalf("name mismatch: %q", v.Name())
	}
}

func TestHeaderVerifierCanonicalisesName(t *testing.T) {
	// Operator wrote the header in any casing; the verifier must
	// match regardless of the casing the client sends.
	val, _ := newTestOpaqueValidator(t, "cf-access", "tok")
	v, _ := NewHeaderVerifier("x-internal-service-token", val)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-INTERNAL-SERVICE-TOKEN", "tok")
	if !v.Verify(req).Accepted {
		t.Fatalf("expected case-insensitive header match")
	}
}

func TestHeaderVerifierReturnsEmptyOnMissingHeader(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "x", "y")
	v, _ := NewHeaderVerifier("X-Foo", val)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject when header absent")
	}
	if res.Reason != "" {
		t.Fatalf("expected empty reason when header absent, got %q", res.Reason)
	}
}

func TestHeaderVerifierRejectsUnknownValue(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "x", "good")
	v, _ := NewHeaderVerifier("X-Foo", val)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Foo", "bad")

	res := v.Verify(req)
	if res.Accepted {
		t.Fatalf("expected reject on unknown value")
	}
	if !strings.Contains(res.Reason, "unknown") {
		t.Fatalf("expected reason about unknown value, got %q", res.Reason)
	}
}

func TestHeaderVerifierTrimsWhitespace(t *testing.T) {
	// Some proxies prepend or append space; treat trimmed value as
	// the credential so a stray space doesn't break verification.
	val, _ := newTestOpaqueValidator(t, "x", "good")
	v, _ := NewHeaderVerifier("X-Foo", val)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Foo", "  good  ")
	if !v.Verify(req).Accepted {
		t.Fatalf("expected accept of whitespace-padded header")
	}
}

func TestHeaderVerifierRequiresName(t *testing.T) {
	val, _ := newTestOpaqueValidator(t, "x", "y")
	if _, err := NewHeaderVerifier("", val); err == nil {
		t.Fatalf("expected error when header name empty")
	}
}

func TestHeaderVerifierRequiresValidator(t *testing.T) {
	if _, err := NewHeaderVerifier("X-Foo", nil); err == nil {
		t.Fatalf("expected error when validator nil")
	}
}
