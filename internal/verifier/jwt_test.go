package verifier

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// jwksFixture spins up an in-process JWKS server backed by RSA keys
// generated in the test. Returns the URL, a helper to sign JWTs, and
// a function to rotate the signing key (drops a new kid into the
// JWKS without changing the URL).
type jwksFixture struct {
	url     string
	server  *httptest.Server
	keys    map[string]*rsa.PrivateKey // kid → private key
	primary string                     // kid used by default for signing
	hits    int64
}

func newJWKSFixture(t *testing.T) *jwksFixture {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	f := &jwksFixture{
		keys:    map[string]*rsa.PrivateKey{"key-1": priv},
		primary: "key-1",
	}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.hits, 1)
		doc := jwksDoc{Keys: make([]jwk, 0, len(f.keys))}
		for kid, k := range f.keys {
			doc.Keys = append(doc.Keys, jwk{
				Kty: "RSA",
				Kid: kid,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
			})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	f.url = f.server.URL
	t.Cleanup(f.server.Close)
	return f
}

// signWith builds and signs a JWT with the requested kid.
func (f *jwksFixture) signWith(t *testing.T, kid string, claims jwt.MapClaims) string {
	t.Helper()
	key, ok := f.keys[kid]
	if !ok {
		t.Fatalf("unknown kid %q", kid)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// addKey rotates the signing key: a new kid appears in the JWKS,
// and signing now uses it by default.
func (f *jwksFixture) addKey(t *testing.T, kid string) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	f.keys[kid] = priv
	f.primary = kid
}

func TestJWTValidatorAcceptsValidToken(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{
		JWKSURL:     f.url,
		Issuer:      "https://idp.example.com",
		Audience:    "veilgate",
		ClientClaim: "sub",
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}
	if v.LoadedKeys() != 1 {
		t.Fatalf("expected 1 loaded key, got %d", v.LoadedKeys())
	}

	tok := f.signWith(t, "key-1", jwt.MapClaims{
		"iss": "https://idp.example.com",
		"aud": "veilgate",
		"sub": "alice@example.com",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	client, ok, reason := v.Validate(tok)
	if !ok {
		t.Fatalf("expected accept, got reject: %s", reason)
	}
	if client != "alice@example.com" {
		t.Fatalf("expected client=alice@example.com, got %q", client)
	}
}

func TestJWTValidatorRejectsExpiredToken(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{JWKSURL: f.url, Audience: "veilgate"})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	tok := f.signWith(t, "key-1", jwt.MapClaims{
		"aud": "veilgate",
		"sub": "alice",
		"exp": time.Now().Add(-1 * time.Minute).Unix(),
	})
	_, ok, reason := v.Validate(tok)
	if ok {
		t.Fatalf("expected reject of expired token")
	}
	if !strings.Contains(reason, "signature") {
		// jwt/v5 surfaces expiry through Parse() error; the validator
		// maps any verify failure to "signature invalid" to avoid
		// leaking which check failed to a caller-controlled audit
		// surface.
		t.Fatalf("expected reason about signature, got %q", reason)
	}
}

func TestJWTValidatorRejectsWrongIssuer(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{
		JWKSURL: f.url,
		Issuer:  "https://idp.example.com",
	})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	tok := f.signWith(t, "key-1", jwt.MapClaims{
		"iss": "https://malicious.example.com",
		"sub": "alice",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	_, ok, reason := v.Validate(tok)
	if ok {
		t.Fatalf("expected reject on wrong issuer")
	}
	if !strings.Contains(reason, "iss") {
		t.Fatalf("expected reason about iss, got %q", reason)
	}
}

func TestJWTValidatorRejectsWrongAudience(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{JWKSURL: f.url, Audience: "veilgate"})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	tok := f.signWith(t, "key-1", jwt.MapClaims{
		"aud": "other-service",
		"sub": "alice",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	_, ok, reason := v.Validate(tok)
	if ok {
		t.Fatalf("expected reject on wrong audience")
	}
	if !strings.Contains(reason, "aud") {
		t.Fatalf("expected reason about aud, got %q", reason)
	}
}

func TestJWTValidatorAcceptsAudienceArray(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{JWKSURL: f.url, Audience: "veilgate"})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	// aud as []string is RFC-compliant; validator must accept it
	// when the target audience appears anywhere in the array.
	tok := f.signWith(t, "key-1", jwt.MapClaims{
		"aud": []string{"other-service", "veilgate", "third"},
		"sub": "alice",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	if _, ok, reason := v.Validate(tok); !ok {
		t.Fatalf("expected accept of audience-array token: %s", reason)
	}
}

func TestJWTValidatorRejectsTamperedSignature(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{JWKSURL: f.url})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	tok := f.signWith(t, "key-1", jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	// Flip a byte in the signature section
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}
	tampered := parts[0] + "." + parts[1] + "." + flipFirstRune(parts[2])

	if _, ok, _ := v.Validate(tampered); ok {
		t.Fatalf("expected reject of tampered signature")
	}
}

func TestJWTValidatorPicksUpRotatedKey(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{JWKSURL: f.url})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	// Rotate: add key-2 to the JWKS and sign with it. The validator's
	// in-process JWKS cache only knows about key-1, so the first
	// validate must trigger a synchronous refresh and then succeed.
	f.addKey(t, "key-2")
	tok := f.signWith(t, "key-2", jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})

	if _, ok, reason := v.Validate(tok); !ok {
		t.Fatalf("expected accept after on-demand JWKS refresh: %s", reason)
	}
	if v.LoadedKeys() != 2 {
		t.Fatalf("expected 2 keys after rotation, got %d", v.LoadedKeys())
	}
}

func TestJWTValidatorRejectsHS256Config(t *testing.T) {
	f := newJWKSFixture(t)
	_, err := NewJWTValidator(JWTConfig{
		JWKSURL:    f.url,
		Algorithms: []string{"HS256"},
	})
	if err == nil {
		t.Fatalf("expected error when only HS256 is configured")
	}
}

func TestJWTValidatorRejectsMissingKid(t *testing.T) {
	f := newJWKSFixture(t)
	v, err := NewJWTValidator(JWTConfig{JWKSURL: f.url})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "alice",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	// Deliberately no kid in header.
	signed, err := tok.SignedString(f.keys["key-1"])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, ok, _ := v.Validate(signed); ok {
		t.Fatalf("expected reject when kid header missing")
	}
}

func TestJWTValidatorRequiresJWKSURL(t *testing.T) {
	if _, err := NewJWTValidator(JWTConfig{}); err == nil {
		t.Fatalf("expected error when jwks_url empty")
	}
	if _, err := NewJWTValidator(JWTConfig{JWKSURL: "not-a-url"}); err == nil {
		t.Fatalf("expected error when jwks_url not http(s)")
	}
}

func TestJWTValidatorCookieIntegration(t *testing.T) {
	// End-to-end: cookie verifier with a JWT validator. Proves the
	// validator surface plugs into CookieVerifier exactly like the
	// opaque validator does.
	f := newJWKSFixture(t)
	jv, err := NewJWTValidator(JWTConfig{JWKSURL: f.url, Audience: "veilgate"})
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}
	v, err := NewCookieVerifier("SESSION_JWT", jv)
	if err != nil {
		t.Fatalf("NewCookieVerifier: %v", err)
	}

	tok := f.signWith(t, "key-1", jwt.MapClaims{
		"aud": "veilgate",
		"sub": "alice",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	})
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "SESSION_JWT", Value: tok})

	res := v.Verify(req)
	if !res.Accepted {
		t.Fatalf("expected accept: %s", res.Reason)
	}
	if res.Client != "alice" {
		t.Fatalf("expected client=alice, got %q", res.Client)
	}
}

func flipFirstRune(s string) string {
	if s == "" {
		return s
	}
	// Change a single character — works for the base64url signature
	// section regardless of which character we pick.
	first := byte('A')
	if s[0] == 'A' {
		first = 'B'
	}
	return string(first) + s[1:]
}

// fmt kept reachable so go vet doesn't complain if helpers grow.
var _ = fmt.Sprintf
