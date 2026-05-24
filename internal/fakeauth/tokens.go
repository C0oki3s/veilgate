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

// AWSSTSKeyID returns a temporary AWS STS credential key ID: ASIA + 16 Base32 chars.
// Temporary credentials (from AssumeRole / instance profiles) always use the ASIA prefix.
func AWSSTSKeyID(seed int64) string {
	k := deriveKey("awsstsid", seed)
	var b strings.Builder
	b.WriteString("ASIA")
	for i := 0; i < 16; i++ {
		b.WriteByte(awsChars[k[i]%32])
	}
	return b.String()
}

// AWSSTSToken returns a realistic AWS STS session token.
// Real STS tokens are 400–1000 char base64 strings starting with AQo.
func AWSSTSToken(seed int64) string {
	var raw []byte
	for _, salt := range []string{"sts-a", "sts-b", "sts-c", "sts-d", "sts-e", "sts-f"} {
		raw = append(raw, deriveKey(salt, seed)...)
	}
	return "AQoXnyc2LvQ" + base64.StdEncoding.EncodeToString(raw)
}

// AzureAccessToken returns a realistic Azure AD access token.
// Claims match what Microsoft's identity platform emits: tid, oid, appid, upn, iss, aud.
// Signature is genuine HS256 — same structure as a real token, different signing key.
func AzureAccessToken(tenantID, email string, seed int64) string {
	iat := jwtIAT(seed)
	oid := requestIDFrom("az-oid", seed)
	appid := requestIDFrom("az-appid", seed)
	return makeJWT(map[string]any{
		"aud":                "https://management.azure.com/",
		"iss":                "https://login.microsoftonline.com/" + tenantID + "/v2.0",
		"tid":                tenantID,
		"oid":                oid,
		"sub":                oid,
		"appid":              appid,
		"upn":                email,
		"unique_name":        email,
		"scp":                "user_impersonation",
		"roles":              []string{"Contributor"},
		"iat":                iat,
		"nbf":                iat,
		"exp":                iat + 3599,
		"aio":                b62String(deriveKey("az-aio", seed), 40),
	}, seed)
}

// AzureTenantID returns a UUID v4 formatted as an Azure tenant ID.
// Tenants are UUIDs — this reuses the UUID derivation with a distinct salt.
func AzureTenantID(seed int64) string { return requestIDFrom("az-tenant", seed) }

// AzureSubscriptionID returns a UUID v4 formatted as an Azure subscription ID.
func AzureSubscriptionID(seed int64) string { return requestIDFrom("az-subid", seed) }

// GCPAccessToken returns a realistic GCP OAuth2 access token.
// Real tokens are ya29. followed by ~200 chars of base64url.
func GCPAccessToken(seed int64) string {
	var raw []byte
	for _, salt := range []string{"gcp-a", "gcp-b", "gcp-c", "gcp-d", "gcp-e", "gcp-f", "gcp-g"} {
		raw = append(raw, deriveKey(salt, seed)...)
	}
	return "ya29." + base64.RawURLEncoding.EncodeToString(raw)
}

// GCPServiceAccountEmail returns a format-accurate GCP service account email.
// Real format: <name>@<project>.iam.gserviceaccount.com
func GCPServiceAccountEmail(name, project string) string {
	return name + "@" + project + ".iam.gserviceaccount.com"
}

// OCIDSuffix returns a realistic 60-char OCI ID unique suffix.
// Real OCIDs end with a long base32-like string of lowercase letters and digits.
func OCIDSuffix(seed int64) string {
	const ociAlpha = "abcdefghijklmnopqrstuvwxyz234567"
	var raw []byte
	for _, salt := range []string{"oci-a", "oci-b", "oci-c", "oci-d"} {
		raw = append(raw, deriveKey(salt, seed)...)
	}
	var b strings.Builder
	b.WriteString("aaaa")
	for i := 4; i < 60; i++ {
		b.WriteByte(ociAlpha[raw[i%len(raw)]%32])
	}
	return b.String()
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
func RequestID(seed int64) string { return requestIDFrom("reqid", seed) }

// requestIDFrom derives a UUID v4 from a named salt + seed.
func requestIDFrom(salt string, seed int64) string {
	k := deriveKey(salt, seed)
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

// ─── Third-party service tokens ──────────────────────────────────────────────

// VaultToken returns a HashiCorp Vault 1.10+ service token: hvs.<40 base64url chars>.
func VaultToken(seed int64) string {
	var raw []byte
	raw = append(raw, deriveKey("vaulttok-a", seed)...)
	raw = append(raw, deriveKey("vaulttok-b", seed)...)
	return "hvs." + base64.RawURLEncoding.EncodeToString(raw)[:40]
}

// CsrfToken returns a 64-char lowercase hex CSRF token (Django / Rails / Jenkins style).
func CsrfToken(seed int64) string {
	k1 := deriveKey("csrf-a", seed)
	k2 := deriveKey("csrf-b", seed)
	return fmt.Sprintf("%x%x", k1, k2)
}

// OAuthRefreshToken returns a 64-char base64url opaque OAuth2 refresh token.
func OAuthRefreshToken(seed int64) string {
	k1 := deriveKey("oarefresh-a", seed)
	k2 := deriveKey("oarefresh-b", seed)
	raw := append(k1, k2...)
	return base64.RawURLEncoding.EncodeToString(raw)[:64]
}

// StripeWebhookSecret returns a Stripe webhook secret: whsec_<43 base64url chars>.
// Real secrets are 32 random bytes → 43 base64url chars.
func StripeWebhookSecret(seed int64) string {
	k := deriveKey("stripewhsec", seed)
	return "whsec_" + base64.RawURLEncoding.EncodeToString(k)[:43]
}

// GithubToken returns a GitHub token with the given prefix (ghp_, gho_, ghs_, github_pat_).
// Real GitHub tokens are prefix + 36 alphanumeric chars.
func GithubToken(prefix string, seed int64) string {
	return prefix + b62String(deriveKey("ghtoken-"+prefix, seed), 36)
}

// NPMToken returns a realistic npm access token: npm_<32 b62 chars>.
func NPMToken(seed int64) string {
	return "npm_" + b62String(deriveKey("npmtoken", seed), 32)
}

// DatadogKey returns a Datadog API or application key: 32 hex chars.
func DatadogKey(seed int64) string {
	k := deriveKey("ddkey", seed)
	return fmt.Sprintf("%x", k[:16])
}

// CloudflareToken returns a Cloudflare API token: 40 b62 chars.
func CloudflareToken(seed int64) string {
	return b62String(deriveKey("cftoken", seed), 40)
}

// TwilioSID returns a Twilio Account SID: AC + 32 hex chars.
func TwilioSID(seed int64) string {
	k := deriveKey("twiliosid", seed)
	return "AC" + fmt.Sprintf("%x", k[:16])
}

// TwilioToken returns a Twilio Auth Token: 32 hex chars.
func TwilioToken(seed int64) string {
	k := deriveKey("twiliotok", seed)
	return fmt.Sprintf("%x", k[:16])
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
