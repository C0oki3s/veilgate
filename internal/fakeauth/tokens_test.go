package fakeauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestJWTAdminUsesRealHS256Signature(t *testing.T) {
	seed := int64(123456789)
	tok := JWTAdmin("admin@northgate.io", seed)
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %q", tok)
	}
	if parts[0] != jwtHeader {
		t.Fatalf("unexpected JWT header: %s", parts[0])
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[1]); err != nil {
		t.Fatalf("payload is not base64url: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not base64url: %v", err)
	}
	if len(sig) != sha256.Size {
		t.Fatalf("expected 32-byte HS256 signature, got %d", len(sig))
	}
	mac := hmac.New(sha256.New, deriveKey("jwt-signing-key", seed))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		t.Fatal("JWT signature does not verify")
	}
}

func TestTokensVaryBySeed(t *testing.T) {
	a := JWTAdminGeneric(100)
	b := JWTAdminGeneric(101)
	if a == b {
		t.Fatal("JWTs should vary by seed")
	}
	if APIKey(100) == APIKey(101) {
		t.Fatal("API keys should vary by seed")
	}
	if SessionID(100) == SessionID(101) {
		t.Fatal("session IDs should vary by seed")
	}
}

func TestExtractCanariesFindsRealisticTokens(t *testing.T) {
	body := JWTAdminGeneric(42) + "\n" + APIKey(42) + "\n" + AWSKeyID(42) + "\n" + SessionID(42)
	got := ExtractCanaries(body)
	if len(got) != 4 {
		t.Fatalf("expected 4 canaries, got %d: %#v", len(got), got)
	}
}
