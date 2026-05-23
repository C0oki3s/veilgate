// Package fakeauth generates realistic-looking auth tokens (JWTs, API keys,
// session IDs, AWS credentials) that are cryptographically valid in structure
// but bound to a per-client seed.
//
// Every function is deterministic on seed — the same seed always produces the
// same token, preserving the coherent fake identity across requests. Tokens
// from different seeds are independent.
//
// The HMAC-SHA256 signatures in JWTs are genuine — a validator with the
// matching key would accept them. The key is derived from the seed, so the
// tokens are non-transferable between VeilGate instances.
package fakeauth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// jwtBase is an anchor Unix timestamp (~late April 2026).
// iat is varied within ±30 days so tokens from different clients look
// independently issued rather than all sharing the same timestamp.
const jwtBase = int64(1777000000)

// jwtHeader is the standard HS256 header, base64url-encoded.
// Always the same for HS256 JWTs — a recognisable constant is fine
// because the payload + signature provide uniqueness.
const jwtHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"

// b62Chars is the base-62 alphabet used for Stripe-style opaque tokens.
const b62Chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

// awsChars is the Base32 alphabet AWS uses for key IDs (A–Z, 2–7).
const awsChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

// adminDomains mirrors the email_domains in core-identities.yaml.
// JWTs in payload files (no profile context) pick a domain from this list.
var adminDomains = []string{
	"northgate.io", "meridian.io", "crestline.io", "cascade.io",
	"lumina.io", "axion.io", "archway.io", "veritas.io",
}

// ─── Public API ──────────────────────────────────────────────────────────────

// JWTAdmin returns a real HS256 JWT with admin claims for the given email.
// Use .AdminUser from the ShadowProfile as email in templates.
func JWTAdmin(email string, seed int64) string {
	iat := jwtIAT(seed)
	return makeJWT(map[string]any{
		"sub":   "usr_" + b62String(deriveKey("admin-sub", seed), 14),
		"role":  "admin",
		"email": email,
		"iat":   iat,
		"exp":   iat + 86400,
		"jti":   fmt.Sprintf("%016x", uint64(seed^0xdecafbad)),
	}, seed)
}

// JWTAdminGeneric returns an admin JWT using a seed-derived admin email.
// Used in payload YAML files where the ShadowProfile is unavailable.
func JWTAdminGeneric(seed int64) string {
	idx := int((seed & 0x7fffffff) % int64(len(adminDomains)))
	email := "admin@" + adminDomains[idx]
	return JWTAdmin(email, seed)
}

// JWTUser returns a real HS256 JWT with customer claims.
func JWTUser(seed int64) string {
	iat := jwtIAT(seed)
	sub := "usr_" + b62String(deriveKey("user-sub", seed), 14)
	email := fmt.Sprintf("user%d@example.com", (seed&0x7fffffff)%9000+1000)
	return makeJWT(map[string]any{
		"sub":   sub,
		"role":  "customer",
		"email": email,
		"iat":   iat,
		"exp":   iat + 86400,
		"jti":   fmt.Sprintf("%016x", uint64(seed^0xfeedface)),
	}, seed)
}

// JWTSvc returns a real HS256 JWT for a named service account.
// Suitable for canary tokens injected as "stale internal credentials".
func JWTSvc(name string, seed int64) string {
	iat := jwtBase + (seed&0x7fffffff)%(7*86400) // within last week
	return makeJWT(map[string]any{
		"sub":   "svc_" + name,
		"role":  "service",
		"scope": "read:all",
		"iat":   iat,
		"exp":   iat + 30*86400,
		"jti":   fmt.Sprintf("%016x", uint64(seed^0xbeefc0de)),
	}, seed)
}

// APIKey returns a Stripe-style secret key: sk_live_<24 b62 chars>.
func APIKey(seed int64) string {
	return "sk_live_" + b62String(deriveKey("apikey", seed), 24)
}

// AWSKeyID returns a realistic AWS access key ID: AKIA + 16 Base32 chars.
func AWSKeyID(seed int64) string {
	k := deriveKey("awskeyid", seed)
	var b strings.Builder
	b.WriteString("AKIA")
	for i := 0; i < 16; i++ {
		b.WriteByte(awsChars[k[i]%32])
	}
	return b.String()
}

// AWSSecret returns a realistic AWS secret access key (40-char base64).
// Real AWS secrets are 40 chars of base64 (standard alphabet with padding).
func AWSSecret(seed int64) string {
	k := deriveKey("awssecret", seed)
	return base64.StdEncoding.EncodeToString(k)[:40]
}

// JWTSecret returns a 64-char base64url string for a JWT_SECRET env var.
// Represents a cryptographically-sized random secret, not a human password.
func JWTSecret(seed int64) string {
	k1 := deriveKey("jwtsecret-a", seed)
	k2 := deriveKey("jwtsecret-b", seed)
	raw := append(k1, k2...)
	// URLEncoding with padding; trim to 64 chars (covers 48 raw bytes).
	return base64.URLEncoding.EncodeToString(raw)[:64]
}

// RedisPass returns a realistic Redis AUTH password (32 hex chars).
func RedisPass(seed int64) string {
	k := deriveKey("redispass", seed)
	return fmt.Sprintf("%x", k[:16])
}

// SendGridKey returns a realistic SendGrid API key: SG.<22>.<43>.
func SendGridKey(seed int64) string {
	k1 := deriveKey("sgkey-prefix", seed)
	k2 := deriveKey("sgkey-suffix", seed)
	prefix := base64.RawURLEncoding.EncodeToString(k1)[:22]
	suffix := base64.RawURLEncoding.EncodeToString(k2)[:43]
	return "SG." + prefix + "." + suffix
}

// SessionID returns a realistic Express.js connect.sid-style session token.
func SessionID(seed int64) string {
	k := deriveKey("session-data", seed)
	mac := hmac.New(sha256.New, deriveKey("session-sig", seed))
	mac.Write(k)
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "s%3A" + fmt.Sprintf("%x", k[:16]) + "." + sig[:27]
}

// RequestID returns a UUID v4-formatted request ID for X-Request-Id headers.
func RequestID(seed int64) string {
	k := deriveKey("reqid", seed)
	// Version 4 UUID format: xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx
	// We force version (4) and variant (10xx) bits.
	k[6] = (k[6] & 0x0f) | 0x40 // version 4
	k[8] = (k[8] & 0x3f) | 0x80 // variant bits
	return fmt.Sprintf("%x-%x-%x-%x-%x", k[0:4], k[4:6], k[6:8], k[8:10], k[10:16])
}

// UserID returns a Stripe-style user ID: usr_<14 b62 chars>.
func UserID(seed int64) string {
	return "usr_" + b62String(deriveKey("userid", seed), 14)
}

// SlugID returns prefix + "_" + 12 b62 chars — for order/ticket IDs.
func SlugID(prefix string, seed int64) string {
	return prefix + "_" + b62String(deriveKey("slugid-"+prefix, seed), 12)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// deriveKey returns a 32-byte SHA-256 hash of (salt + seed).
// The salt isolates different token types — api keys, JWT keys, session IDs —
// so they can't be trivially correlated even if the seed leaks.
func deriveKey(salt string, seed int64) []byte {
	h := sha256.New()
	fmt.Fprintf(h, "vg:%s:%d", salt, seed)
	return h.Sum(nil)
}

// makeJWT builds a real HS256 JWT: header.payload.signature.
// The signature is a genuine HMAC-SHA256 over header + "." + payload.
func makeJWT(claims map[string]any, seed int64) string {
	claimsJSON, _ := json.Marshal(sortedClaims(claims))
	payload := base64.RawURLEncoding.EncodeToString(claimsJSON)
	sigInput := jwtHeader + "." + payload
	mac := hmac.New(sha256.New, deriveKey("jwt-signing-key", seed))
	mac.Write([]byte(sigInput))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return sigInput + "." + sig
}

// jwtIAT derives an `iat` timestamp that varies per seed within the last
// 30 days. Different clients appear to have authenticated at different times.
func jwtIAT(seed int64) int64 {
	offset := (seed & 0x7fffffff) % (30 * 86400)
	return jwtBase + offset
}

// b62String encodes key bytes as a base-62 string of the requested length.
func b62String(key []byte, length int) string {
	var b strings.Builder
	for i := 0; i < length && i < len(key); i++ {
		b.WriteByte(b62Chars[int(key[i])%62])
	}
	return b.String()
}

// sortedClaims returns claims in a stable order so JSON marshalling is
// deterministic (Go maps randomise iteration order).
func sortedClaims(m map[string]any) map[string]any {
	// json.Marshal on a map produces alphabetical key order in Go 1.12+,
	// so no extra sorting is needed — this function is a no-op pass-through
	// that documents the invariant.
	return m
}
