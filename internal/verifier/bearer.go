package verifier

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BearerConfig is the operator-supplied configuration for the opaque
// bearer-token verifier. Maps 1:1 to the verifiers.bearer block in
// configs/veilgate.yaml.
//
// Unlike HMAC, bearer tokens carry no per-request signature: a bearer
// is just a static secret presented in a header. Replay protection is
// the operator's responsibility — rely on TLS for confidentiality and
// rotate tokens on suspected compromise. This matches the GitHub
// personal-access-token and Stripe-API-key model.
type BearerConfig struct {
	// Header is the request header the token rides on. Defaults to
	// "Authorization" so curl -H "Authorization: Bearer …" works
	// out-of-the-box.
	Header string

	// Scheme is the leading prefix to strip from the header value. The
	// canonical case is "Bearer" (RFC 6750). Set to empty string to
	// treat the entire header value as the token (useful when a custom
	// header carries the raw token without a scheme prefix).
	Scheme string

	// TokensDir contains one file per registered token. Filename
	// (without extension) is the client identifier; file contents is
	// the raw token. The verifier maintains a sha256(token) → client
	// map; lookup is O(1) and constant-time relative to the token
	// value. The map is rebuilt when the directory's contents change
	// (mtime-based), so operators can rotate without restarting.
	TokensDir string
}

// BearerVerifier accepts requests carrying a recognised opaque token
// in the configured header.
//
//	Authorization: Bearer vg_pat_a1b2c3d4…
//
// Tokens are stored on disk as one file per token. Filename = client
// id (e.g. "payment-service"), contents = the raw token. Operators
// rotate by overwriting or by dropping a new file alongside the old
// one (multiple files per client are fine — a client can hold two
// active tokens during rotation).
type BearerVerifier struct {
	cfg BearerConfig

	mu      sync.RWMutex
	dirMod  time.Time
	tokens  map[[32]byte]string // sha256(token) → client id
	scheme  string              // cached "Bearer " (with trailing space) for fast prefix-strip
	hdrName string              // cached canonical header name
}

// NewBearerVerifier constructs the verifier. Returns a non-nil error
// when config is incomplete in a way that would make every Verify call
// fail silently — operators get a clear startup error instead of a
// mysterious "every request goes to the challenge tier."
func NewBearerVerifier(cfg BearerConfig) (*BearerVerifier, error) {
	if cfg.Header == "" {
		cfg.Header = "Authorization"
	}
	// Empty scheme is valid (raw-token mode); only default when
	// caller left the field zero-valued AND used the default header.
	if cfg.Scheme == "" && cfg.Header == "Authorization" {
		cfg.Scheme = "Bearer"
	}
	if cfg.TokensDir == "" {
		return nil, &configError{"tokens_dir is required"}
	}
	if _, err := os.Stat(cfg.TokensDir); err != nil {
		return nil, err
	}
	v := &BearerVerifier{
		cfg:     cfg,
		hdrName: http.CanonicalHeaderKey(cfg.Header),
	}
	if cfg.Scheme != "" {
		v.scheme = cfg.Scheme + " "
	}
	if err := v.reload(); err != nil {
		return nil, err
	}
	return v, nil
}

// Name implements Verifier.
func (v *BearerVerifier) Name() string { return "bearer" }

// Describe implements Discoverable.
func (v *BearerVerifier) Describe() CredentialDescriptor {
	scheme := strings.TrimSpace(v.scheme)
	return CredentialDescriptor{
		Type:   "bearer",
		Header: v.hdrDisplay(),
		Scheme: scheme,
	}
}

// hdrDisplay returns the configured header in its original casing.
// http.CanonicalHeaderKey lowercases and re-cases unevenly, so we
// prefer the value the operator wrote when emitting it on the
// discovery surface.
func (v *BearerVerifier) hdrDisplay() string {
	if v.cfg.Header != "" {
		return v.cfg.Header
	}
	return v.hdrName
}

// Verify implements Verifier.
//
// Returns a zero Result (Accepted=false, empty Reason) when the
// configured header is absent so the chain can move on quietly. Only
// emits a non-empty Reason when the header is present but the token
// is wrong — that is the case worth auditing.
func (v *BearerVerifier) Verify(r *http.Request) Result {
	raw := r.Header.Get(v.hdrName)
	if raw == "" {
		return Result{}
	}
	token := raw
	if v.scheme != "" {
		// Compare scheme case-insensitively per RFC 7235 §2.1. The
		// token portion is opaque, so trim any single space after the
		// scheme but preserve the remainder verbatim.
		if len(raw) < len(v.scheme) || !strings.EqualFold(raw[:len(v.scheme)], v.scheme) {
			return rejected("bearer", "scheme mismatch")
		}
		token = strings.TrimLeft(raw[len(v.scheme):], " ")
	}
	if token == "" {
		return rejected("bearer", "token empty")
	}

	v.maybeReload()

	sum := sha256.Sum256([]byte(token))
	v.mu.RLock()
	client, ok := v.tokens[sum]
	v.mu.RUnlock()
	if !ok {
		return rejected("bearer", "token unknown")
	}
	return Result{
		Accepted: true,
		Name:     "bearer",
		Client:   client,
		Reason:   "valid bearer token",
	}
}

// LoadedTokens returns the count of currently-loaded tokens, exposed
// for the startup audit log. Not for the hot path.
func (v *BearerVerifier) LoadedTokens() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.tokens)
}

// maybeReload re-reads the tokens directory if its mtime has advanced
// since the last load. A miss on the read lock is cheap; a hit on the
// write lock only happens when files have actually changed.
func (v *BearerVerifier) maybeReload() {
	st, err := os.Stat(v.cfg.TokensDir)
	if err != nil {
		// Directory removed under us — keep serving the last-known
		// token set rather than failing every request. Operators will
		// see the error in the startup-style audit on next restart.
		return
	}
	v.mu.RLock()
	current := v.dirMod
	v.mu.RUnlock()
	if st.ModTime().Equal(current) {
		return
	}
	_ = v.reload()
}

// reload scans the tokens directory and rebuilds the sha256 → client
// map. Files whose names start with "." are skipped so editor swap
// files don't poison the map.
func (v *BearerVerifier) reload() error {
	entries, err := os.ReadDir(v.cfg.TokensDir)
	if err != nil {
		return err
	}
	st, err := os.Stat(v.cfg.TokensDir)
	if err != nil {
		return err
	}
	next := make(map[[32]byte]string, len(entries))
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		client := strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
		if !validClientName(client) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(v.cfg.TokensDir, e.Name()))
		if err != nil {
			continue
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			continue
		}
		// One client can hold multiple active tokens during rotation:
		// each file produces a distinct sha256 entry. The map value
		// records which client this token belongs to for audit.
		sum := sha256.Sum256([]byte(token))
		next[sum] = client
	}
	v.mu.Lock()
	v.tokens = next
	v.dirMod = st.ModTime()
	v.mu.Unlock()
	return nil
}

// HashTokenForFilename is exported so the future `veilgate add-token`
// CLI subcommand can name files by token-hash if an operator later
// prefers that layout. Today the loader uses filename = client id;
// this helper is here for tooling and tests.
func HashTokenForFilename(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
