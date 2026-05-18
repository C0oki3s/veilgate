package verifier

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Validator inspects a single credential string (a cookie value, a
// header value, etc.) and decides whether it is valid. Unlike a
// Verifier — which knows where to find the credential on a request —
// a Validator only sees the raw value and answers "is this good?"
//
// Implementations: OpaqueValidator (dir of pre-shared secrets),
// JWTValidator (JWKS), CalloutValidator (HTTP delegate). The latter
// two land in their own ships; this file defines the interface they
// share with the cookie and header verifiers.
type Validator interface {
	// Type is a stable string for config / audit ("opaque", "jwt", …).
	Type() string

	// Validate returns the client id the credential belongs to, plus
	// a non-empty reason on rejection (for audit). An empty client id
	// with ok=true is allowed when a validator cannot attribute a
	// specific identity (e.g. a shared cookie with no claim).
	Validate(value string) (client string, ok bool, reason string)
}

// OpaqueValidator matches a credential value against a directory of
// pre-shared secrets, exactly like the bearer verifier's token store
// but reusable from cookie and header verifiers. Lookup is sha256
// keyed for constant-time comparison; the directory is reloaded on
// mtime change.
//
// The file layout matches the bearer verifier's convention so an
// operator who already understands `tokens_dir` does not have to
// learn a new format:
//
//	dir/
//	├── client-a.token   contents: <raw-token>
//	├── client-b.token
//	└── client-a-2.token (second active token during rotation)
//
// Filename without extension = client id; file contents = raw value.
// Hidden files and subdirectories are skipped.
type OpaqueValidator struct {
	dir string

	mu     sync.RWMutex
	dirMod time.Time
	tokens map[[32]byte]string // sha256(value) → client id
}

// NewOpaqueValidator constructs the validator. Returns an error when
// the directory cannot be statted at startup — operators get a clear
// failure rather than every request quietly rejecting.
func NewOpaqueValidator(dir string) (*OpaqueValidator, error) {
	if dir == "" {
		return nil, &configError{"opaque validator: dir is required"}
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, err
	}
	v := &OpaqueValidator{dir: dir}
	if err := v.reload(); err != nil {
		return nil, err
	}
	return v, nil
}

// Type implements Validator.
func (v *OpaqueValidator) Type() string { return "opaque" }

// Validate implements Validator.
func (v *OpaqueValidator) Validate(value string) (string, bool, string) {
	if value == "" {
		return "", false, "value empty"
	}
	v.maybeReload()
	sum := sha256.Sum256([]byte(value))
	v.mu.RLock()
	client, ok := v.tokens[sum]
	v.mu.RUnlock()
	if !ok {
		return "", false, "value unknown"
	}
	return client, true, ""
}

// Loaded returns the count of currently-cached tokens — for startup
// audit, not the hot path.
func (v *OpaqueValidator) Loaded() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.tokens)
}

func (v *OpaqueValidator) maybeReload() {
	st, err := os.Stat(v.dir)
	if err != nil {
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

func (v *OpaqueValidator) reload() error {
	entries, err := os.ReadDir(v.dir)
	if err != nil {
		return err
	}
	st, err := os.Stat(v.dir)
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
		raw, err := os.ReadFile(filepath.Join(v.dir, e.Name()))
		if err != nil {
			continue
		}
		token := strings.TrimSpace(string(raw))
		if token == "" {
			continue
		}
		sum := sha256.Sum256([]byte(token))
		next[sum] = client
	}
	v.mu.Lock()
	v.tokens = next
	v.dirMod = st.ModTime()
	v.mu.Unlock()
	return nil
}
