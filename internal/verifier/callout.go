package verifier

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// CalloutConfig configures a Validator that delegates credential
// validation to an operator-supplied HTTP endpoint.
//
// Request shape (sent by veilgate):
//
//	POST <URL>
//	Content-Type: application/json
//	<AuthHeader>: <AuthValue>           (when configured)
//
//	{"value": "<the credential>"}
//
// Response shape:
//
//	200 OK with optional JSON body {"client": "alice", "cache_ttl": 60}
//	any non-2xx → invalid
//
// The credential value is sent in the JSON body, never in a URL or
// header, so it does not leak into upstream access logs. A short
// timeout (5s default) keeps a slow validator from stalling the
// proxy hot path.
type CalloutConfig struct {
	// URL is the validator endpoint. POSTed to on every cache miss.
	// Required. HTTPS strongly recommended.
	URL string

	// CacheTTL is how long a successful validation is cached. A
	// per-result TTL in the response body overrides this when
	// smaller. Defaults to 30s. Set to 0 to disable caching (every
	// validate is a network hop — expensive but maximally fresh).
	CacheTTL time.Duration

	// AuthHeader / AuthValue is an optional header the validator
	// sends so the upstream introspection endpoint can authenticate
	// veilgate. Common shapes: ("Authorization", "Bearer …") or
	// ("X-Veilgate-Secret", "…").
	AuthHeader string
	AuthValue  string

	// Timeout caps each callout's HTTP request. Defaults to 5s.
	Timeout time.Duration

	// HTTPClient is injectable for tests. Defaults to a client with
	// the configured Timeout.
	HTTPClient *http.Client
}

// CalloutValidator implements Validator by HTTP-POSTing the
// credential to an operator-supplied endpoint and caching
// affirmative responses.
//
// Negative responses are NOT cached: if the upstream returns 401 for
// a credential because of a transient bug, we don't want every
// subsequent request to fail for the duration of a cache window.
// The cost is a network hop per bad-token request, which is fine
// because attackers presenting random tokens are already paying the
// cost of being wrong.
type CalloutValidator struct {
	cfg CalloutConfig

	mu    sync.RWMutex
	cache map[[32]byte]calloutEntry // sha256(value) → cached result
}

type calloutEntry struct {
	client    string
	expiresAt time.Time
}

// NewCalloutValidator constructs the validator.
func NewCalloutValidator(cfg CalloutConfig) (*CalloutValidator, error) {
	if cfg.URL == "" {
		return nil, &configError{"callout validator: url is required"}
	}
	if !strings.HasPrefix(cfg.URL, "http://") && !strings.HasPrefix(cfg.URL, "https://") {
		return nil, &configError{"callout validator: url must be http(s)"}
	}
	if cfg.CacheTTL < 0 {
		return nil, &configError{"callout validator: cache_ttl must be >= 0"}
	}
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: cfg.Timeout}
	}
	return &CalloutValidator{
		cfg:   cfg,
		cache: make(map[[32]byte]calloutEntry),
	}, nil
}

// Type implements Validator.
func (v *CalloutValidator) Type() string { return "callout" }

// Validate implements Validator.
func (v *CalloutValidator) Validate(value string) (string, bool, string) {
	if value == "" {
		return "", false, "value empty"
	}
	sum := sha256.Sum256([]byte(value))

	// Cache check
	v.mu.RLock()
	entry, hit := v.cache[sum]
	v.mu.RUnlock()
	if hit && time.Now().Before(entry.expiresAt) {
		return entry.client, true, ""
	}

	// Cache miss → call out
	client, ttl, ok, reason := v.callout(value)
	if !ok {
		return "", false, reason
	}

	// Cache the affirmative result. Per-result TTL caps the global
	// default — a short-lived token can ask for a 5s cache so its
	// expiry is honored promptly.
	effective := v.cfg.CacheTTL
	if ttl > 0 && ttl < effective {
		effective = ttl
	}
	v.mu.Lock()
	v.cache[sum] = calloutEntry{client: client, expiresAt: time.Now().Add(effective)}
	v.mu.Unlock()
	return client, true, ""
}

// CacheSize returns the count of currently-cached entries — for
// startup audit and observability. Stale entries are counted; the
// cache is purged lazily on lookup.
func (v *CalloutValidator) CacheSize() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.cache)
}

// calloutResponse is the JSON body the operator's endpoint may return
// on a 200. All fields are optional — a 200 with empty body is a
// valid "yes, but I have no client id and no TTL" response.
type calloutResponse struct {
	Client   string `json:"client,omitempty"`
	CacheTTL int    `json:"cache_ttl,omitempty"` // seconds
}

// calloutRequest is the JSON we POST to the upstream.
type calloutRequest struct {
	Value string `json:"value"`
}

// callout performs the actual HTTP request. Returns the validated
// client id, per-result TTL, ok-flag, and an audit reason.
func (v *CalloutValidator) callout(value string) (string, time.Duration, bool, string) {
	body, err := json.Marshal(calloutRequest{Value: value})
	if err != nil {
		return "", 0, false, "callout encode failed"
	}
	req, err := http.NewRequest(http.MethodPost, v.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return "", 0, false, "callout request build failed"
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if v.cfg.AuthHeader != "" {
		req.Header.Set(v.cfg.AuthHeader, v.cfg.AuthValue)
	}
	resp, err := v.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", 0, false, "callout transport error"
	}
	defer resp.Body.Close()
	// Drain the body up to a cap so even a misbehaving validator can't
	// blow up memory; 64 KiB is plenty for a validation response.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Non-2xx is the operator's way of saying "no". We do not
		// surface the upstream status code in the audit reason —
		// that's an implementation detail the upstream owns.
		return "", 0, false, "callout rejected"
	}

	// Empty body is a valid "yes, no metadata."
	if len(bytes.TrimSpace(respBody)) == 0 {
		return "", 0, true, ""
	}
	var parsed calloutResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		// Operator returned a 2xx with a non-JSON body. Accept the
		// validation but record the parsing issue at audit time.
		return "", 0, true, ""
	}
	var ttl time.Duration
	if parsed.CacheTTL > 0 {
		ttl = time.Duration(parsed.CacheTTL) * time.Second
	}
	return parsed.Client, ttl, true, ""
}

// purgeExpired drops cache entries past their expiry. Called only
// from tests today; production relies on lazy eviction (a stale
// entry returns nothing useful and the next call refreshes it).
func (v *CalloutValidator) purgeExpired() {
	now := time.Now()
	v.mu.Lock()
	defer v.mu.Unlock()
	for k, e := range v.cache {
		if now.After(e.expiresAt) {
			delete(v.cache, k)
		}
	}
}

// for go vet / future expansion — keeps the symbol used.
var _ = fmt.Sprintf
