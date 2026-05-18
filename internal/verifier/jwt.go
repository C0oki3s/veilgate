package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig is the operator-supplied configuration for a JWT
// validator. Used by cookie and header verifiers when the cookie /
// header carries a signed token (Cloudflare Access JWT, an IdP
// session token, an OAuth2 access token, …).
//
// JWT validation rests on three things:
//   - the signature verifies against a key fetched from JWKSURL,
//   - the standard claims (exp, nbf) are within their windows,
//   - the operator-asserted claims (iss, aud) match exactly.
//
// Symmetric algorithms (HS256 / HS384 / HS512) are deliberately
// rejected: shipping a shared secret in veilgate.yaml that the IdP
// also holds is a footgun, and any deployment that has a JWKS URL
// is already using asymmetric keys.
type JWTConfig struct {
	// JWKSURL is the HTTPS URL the validator GETs to discover public
	// keys. Required. The endpoint must return a standard RFC 7517
	// JSON Web Key Set.
	JWKSURL string

	// Issuer, when non-empty, is required to equal the JWT's `iss`
	// claim. Strongly recommended in production — without it a token
	// from any IdP signing under the same JWKS key would be accepted.
	Issuer string

	// Audience, when non-empty, is required to appear in the JWT's
	// `aud` claim (string or array). Strongly recommended.
	Audience string

	// ClientClaim names the claim whose value becomes the audit
	// "client" identifier. Defaults to "sub".
	ClientClaim string

	// Algorithms is the allow-list of `alg` header values. Defaults
	// to RS256 + ES256. HS* is rejected unconditionally even if
	// listed (see above).
	Algorithms []string

	// RefreshInterval is how often the JWKS is re-fetched in the
	// background. Defaults to 1h. Operators rotating keys faster
	// should lower this; for an IdP that rarely rotates, 1h is fine.
	RefreshInterval time.Duration

	// HTTPClient is used for JWKS fetches. Defaults to a client with
	// a 10s timeout — JWKS endpoints are tiny, anything slower is a
	// network problem the operator should surface, not silently wait
	// on.
	HTTPClient *http.Client
}

// JWTValidator implements Validator for signed JWTs.
type JWTValidator struct {
	cfg JWTConfig

	mu          sync.RWMutex
	keys        map[string]crypto.PublicKey
	lastRefresh time.Time
	parser      *jwt.Parser
}

// NewJWTValidator constructs the validator. It performs an initial
// blocking JWKS fetch so a misconfigured JWKSURL fails loudly at
// startup; subsequent refreshes happen on a background timer.
func NewJWTValidator(cfg JWTConfig) (*JWTValidator, error) {
	if cfg.JWKSURL == "" {
		return nil, &configError{"jwt validator: jwks_url is required"}
	}
	if !strings.HasPrefix(cfg.JWKSURL, "https://") && !strings.HasPrefix(cfg.JWKSURL, "http://") {
		return nil, &configError{"jwt validator: jwks_url must be http(s)"}
	}
	if cfg.ClientClaim == "" {
		cfg.ClientClaim = "sub"
	}
	if len(cfg.Algorithms) == 0 {
		cfg.Algorithms = []string{"RS256", "ES256"}
	}
	cfg.Algorithms = sanitizeAlgs(cfg.Algorithms)
	if len(cfg.Algorithms) == 0 {
		return nil, &configError{"jwt validator: no acceptable algorithms after filtering HS*"}
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = time.Hour
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	v := &JWTValidator{
		cfg:    cfg,
		parser: jwt.NewParser(jwt.WithValidMethods(cfg.Algorithms)),
	}
	if err := v.refreshKeys(); err != nil {
		return nil, fmt.Errorf("jwt validator: initial JWKS fetch: %w", err)
	}
	go v.refreshLoop()
	return v, nil
}

// Type implements Validator.
func (v *JWTValidator) Type() string { return "jwt" }

// Validate implements Validator.
//
// On any verification failure returns ok=false with a short reason
// suitable for audit ("signature invalid", "iss mismatch", …). The
// reason never includes claim values or token bytes — those are
// caller-controlled and would pollute the audit log.
func (v *JWTValidator) Validate(token string) (string, bool, string) {
	if token == "" {
		return "", false, "value empty"
	}
	parsed, err := v.parser.Parse(token, v.keyFunc)
	if err != nil || !parsed.Valid {
		return "", false, "signature invalid"
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return "", false, "claims unreadable"
	}
	if v.cfg.Issuer != "" {
		got, _ := claims["iss"].(string)
		if got != v.cfg.Issuer {
			return "", false, "iss mismatch"
		}
	}
	if v.cfg.Audience != "" && !audienceContains(claims["aud"], v.cfg.Audience) {
		return "", false, "aud mismatch"
	}
	client, _ := claims[v.cfg.ClientClaim].(string)
	if client == "" {
		// Accept the token but record an empty client — audit logs
		// stay honest about which token validated without a client id.
		return "", true, ""
	}
	return client, true, ""
}

// LoadedKeys returns the count of currently-cached signing keys —
// for startup audit.
func (v *JWTValidator) LoadedKeys() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.keys)
}

// keyFunc is passed to the jwt parser. It looks up the kid header
// in our cached JWKS. Tokens without a kid header are rejected: a
// JWKS-based deployment always names its keys.
func (v *JWTValidator) keyFunc(t *jwt.Token) (any, error) {
	kid, _ := t.Header["kid"].(string)
	if kid == "" {
		return nil, fmt.Errorf("kid header missing")
	}
	v.mu.RLock()
	key, ok := v.keys[kid]
	v.mu.RUnlock()
	if !ok {
		// The signer may have rotated mid-refresh-window. Try one
		// synchronous refresh before giving up — the cost is a single
		// JWKS GET in the unhappy path, the benefit is graceful
		// failover across rotations.
		if err := v.refreshKeys(); err == nil {
			v.mu.RLock()
			key, ok = v.keys[kid]
			v.mu.RUnlock()
		}
		if !ok {
			return nil, fmt.Errorf("kid %q not found in JWKS", kid)
		}
	}
	return key, nil
}

// refreshLoop pulls the JWKS on the configured interval. Errors are
// swallowed — a transient JWKS failure must not crash the validator;
// the cached keys remain valid until they verify a token signed by a
// retired key, at which point keyFunc triggers a synchronous retry.
func (v *JWTValidator) refreshLoop() {
	t := time.NewTicker(v.cfg.RefreshInterval)
	defer t.Stop()
	for range t.C {
		_ = v.refreshKeys()
	}
}

// refreshKeys fetches the JWKS and atomically swaps the cached map.
// A partial parse (one bad key) does not invalidate the rest — bad
// entries are skipped, good ones are taken.
func (v *JWTValidator) refreshKeys() error {
	req, err := http.NewRequest(http.MethodGet, v.cfg.JWKSURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("JWKS HTTP %d", resp.StatusCode)
	}
	// Cap JWKS body at 1 MiB — a malicious or misconfigured endpoint
	// returning gigabytes would otherwise blow up the validator.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var doc jwksDoc
	if err := json.Unmarshal(body, &doc); err != nil {
		return err
	}
	next := make(map[string]crypto.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kid == "" {
			continue
		}
		key, err := k.publicKey()
		if err != nil {
			continue
		}
		next[k.Kid] = key
	}
	if len(next) == 0 {
		return fmt.Errorf("JWKS contained no usable keys")
	}
	v.mu.Lock()
	v.keys = next
	v.lastRefresh = time.Now()
	v.mu.Unlock()
	return nil
}

// jwksDoc is the minimal subset of RFC 7517 we parse. Unknown fields
// are ignored; an IdP shipping extra metadata won't break us.
type jwksDoc struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`           // "RSA" or "EC"
	Kid string `json:"kid"`           // key id
	Alg string `json:"alg,omitempty"` // optional; we trust the JWT header's alg

	// RSA fields
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`

	// EC fields
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
}

// publicKey decodes a JWK into the matching Go public-key type.
// Returns an error for unsupported curves / kty values; the loader
// skips those quietly.
func (k *jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		if e < 3 {
			return nil, fmt.Errorf("RSA exponent too small")
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
	case "EC":
		var curve elliptic.Curve
		switch k.Crv {
		case "P-256":
			curve = elliptic.P256()
		case "P-384":
			curve = elliptic.P384()
		case "P-521":
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported curve %q", k.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(xBytes),
			Y:     new(big.Int).SetBytes(yBytes),
		}, nil
	default:
		return nil, fmt.Errorf("unsupported kty %q", k.Kty)
	}
}

// audienceContains checks whether want appears in the aud claim,
// which may be a string or an array of strings per RFC 7519 §4.1.3.
func audienceContains(aud any, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []any:
		for _, v := range a {
			if s, ok := v.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}

// sanitizeAlgs filters out symmetric algorithms unconditionally. We
// only accept asymmetric algorithms in JWKS-based deployments —
// putting a shared HMAC secret in veilgate.yaml that the IdP also
// holds is a configuration footgun, not a feature.
func sanitizeAlgs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		switch strings.ToUpper(a) {
		case "HS256", "HS384", "HS512", "NONE", "":
			continue
		default:
			out = append(out, strings.ToUpper(a))
		}
	}
	return out
}
