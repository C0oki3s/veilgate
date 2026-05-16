package verifier

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// HMACConfig is the operator-supplied configuration for the HMAC
// verifier. It maps 1:1 to the verifiers.hmac block in
// configs/veilgate.yaml.
type HMACConfig struct {
	// HeaderSignature is the request header carrying the timestamp
	// and signature, formatted as "t=<unix>,v1=<hex>". Stripe
	// webhooks use "Stripe-Signature" and the same shape; we default
	// to "X-Veilgate-Signature" to avoid colliding with any
	// operator-internal headers.
	HeaderSignature string

	// HeaderClient is the request header naming which client secret
	// to look up. Required because veilgate supports many clients
	// with distinct secrets — single-secret deployments still
	// configure one named client.
	HeaderClient string

	// ClockSkewSec is the ± window (in seconds) around now within
	// which the request timestamp must fall. Defaults to 300 (5 min)
	// when zero, matching Stripe's window. Replay protection.
	ClockSkewSec int

	// MaxBodyBytes caps how much of the body we hash. Without a cap a
	// malicious client could ship a 10 GB body and exhaust memory.
	// Defaults to 1 MiB.
	MaxBodyBytes int64

	// ClientsDir contains one file per registered client. Filename
	// (without extension) is the client name; file contents is the
	// raw secret. Files are loaded lazily and cached; the cache is
	// invalidated on file mtime change so operators can rotate by
	// overwriting and don't have to restart veilgate.
	ClientsDir string
}

// HMACVerifier validates a request against operator-issued HMAC
// secrets, in the Stripe-webhook style:
//
//	X-Veilgate-Signature: t=<unix-ts>,v1=<hex-sha256>
//	X-Veilgate-Client:    payment-service
//
// where v1 = HMAC_SHA256(secret, "<t>.<method>.<path>.<sha256(body)>")
//
// The canonical-string includes method and path so a stolen signature
// can't be replayed against a different endpoint, and body-hash so the
// body itself can't be modified in flight.
type HMACVerifier struct {
	cfg HMACConfig

	mu    sync.RWMutex
	cache map[string]secretEntry // clientName → {secret, mtime}
}

type secretEntry struct {
	secret []byte
	mtime  time.Time
}

// NewHMACVerifier constructs the verifier. Returns nil if the config
// is incomplete in a way that would make every call to Verify fail
// silently — better to fail loud at startup.
func NewHMACVerifier(cfg HMACConfig) (*HMACVerifier, error) {
	if cfg.HeaderSignature == "" {
		cfg.HeaderSignature = "X-Veilgate-Signature"
	}
	if cfg.HeaderClient == "" {
		cfg.HeaderClient = "X-Veilgate-Client"
	}
	if cfg.ClockSkewSec <= 0 {
		cfg.ClockSkewSec = 300
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.ClientsDir == "" {
		return nil, errClientsDirRequired
	}
	if _, err := os.Stat(cfg.ClientsDir); err != nil {
		return nil, err
	}
	return &HMACVerifier{
		cfg:   cfg,
		cache: make(map[string]secretEntry),
	}, nil
}

// Name implements Verifier.
func (v *HMACVerifier) Name() string { return "hmac" }

// Verify implements Verifier.
func (v *HMACVerifier) Verify(r *http.Request) Result {
	sigHdr := r.Header.Get(v.cfg.HeaderSignature)
	if sigHdr == "" {
		return Result{}
	}
	clientName := strings.TrimSpace(r.Header.Get(v.cfg.HeaderClient))
	if clientName == "" {
		return rejected("hmac", "client header missing")
	}
	if !validClientName(clientName) {
		return rejected("hmac", "client header invalid characters")
	}

	ts, providedSig, ok := parseSigHeader(sigHdr)
	if !ok {
		return rejected("hmac", "signature header malformed")
	}

	now := time.Now().Unix()
	skew := int64(v.cfg.ClockSkewSec)
	if ts < now-skew || ts > now+skew {
		return rejected("hmac", "timestamp outside skew window")
	}

	secret, err := v.loadSecret(clientName)
	if err != nil {
		return rejected("hmac", "unknown client")
	}

	body, err := readCappedBody(r, v.cfg.MaxBodyBytes)
	if err != nil {
		return rejected("hmac", "body read failed")
	}
	bodySum := sha256.Sum256(body)
	canonical := strconv.FormatInt(ts, 10) + "." +
		r.Method + "." + r.URL.Path + "." +
		hex.EncodeToString(bodySum[:])

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(canonical))
	expected := mac.Sum(nil)
	provided, decodeErr := hex.DecodeString(providedSig)
	if decodeErr != nil {
		return rejected("hmac", "signature not hex")
	}
	if !hmac.Equal(expected, provided) {
		return rejected("hmac", "signature mismatch")
	}

	return Result{
		Accepted: true,
		Name:     "hmac",
		Client:   clientName,
		Reason:   "valid HMAC signature",
	}
}

// loadSecret returns the cached secret for clientName, re-reading
// from disk when the file's mtime has advanced since the last cache
// entry. Cache hits avoid filesystem syscalls on the hot path.
func (v *HMACVerifier) loadSecret(clientName string) ([]byte, error) {
	path := filepath.Join(v.cfg.ClientsDir, clientName+".secret")
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	v.mu.RLock()
	entry, ok := v.cache[clientName]
	v.mu.RUnlock()
	if ok && entry.mtime.Equal(st.ModTime()) {
		return entry.secret, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	secret := bytes.TrimSpace(b)
	v.mu.Lock()
	v.cache[clientName] = secretEntry{secret: secret, mtime: st.ModTime()}
	v.mu.Unlock()
	return secret, nil
}

// LoadedClients returns the count of currently-cached client secrets,
// exposed for the audit log's startup summary. Not for the hot path.
func (v *HMACVerifier) LoadedClients() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.cache)
}

// rejectCount lets a future caller emit a metric without breaking the
// abstraction. Atomic so the counter is safe across concurrent calls.
var hmacRejectCount uint64

func rejected(name, reason string) Result {
	atomic.AddUint64(&hmacRejectCount, 1)
	return Result{Name: name, Reason: reason}
}

// parseSigHeader splits "t=<unix>,v1=<hex>" into its parts. Returns
// (timestamp, signature, ok). Extra keys are ignored — operators can
// add v2, v3 etc. for future signature versions without breaking the
// parser.
func parseSigHeader(h string) (int64, string, bool) {
	var ts int64 = -1
	var sig string
	for _, part := range strings.Split(h, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			n, err := strconv.ParseInt(kv[1], 10, 64)
			if err != nil {
				return 0, "", false
			}
			ts = n
		case "v1":
			sig = kv[1]
		}
	}
	if ts < 0 || sig == "" {
		return 0, "", false
	}
	return ts, sig, true
}

// validClientName guards against filesystem traversal. Client names
// must be filename-safe — alphanumerics, dash, underscore, dot — and
// not contain "..".
func validClientName(s string) bool {
	if s == "" || strings.Contains(s, "..") {
		return false
	}
	for _, c := range s {
		ok := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.'
		if !ok {
			return false
		}
	}
	return true
}

// readCappedBody reads at most maxBytes of the body and replaces
// r.Body with a fresh reader so the downstream handler can still
// consume the body in full. The cap protects against
// memory-exhaustion attacks via huge bodies; a request whose body
// exceeds the cap will fail the HMAC check (because the body-hash
// won't match) but won't OOM the proxy.
func readCappedBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, maxBytes)
	b, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	// Restore body so downstream handlers can still read it. The
	// truncated tail isn't observable by them in practice because
	// HMAC failure short-circuits before we'd forward upstream.
	r.Body = io.NopCloser(bytes.NewReader(b))
	return b, nil
}

// Sentinel errors. Kept unexported — callers branch on nil/non-nil
// rather than on specific values; we don't want operators to gain a
// dependency on these symbols.
var errClientsDirRequired = &configError{"clients_dir is required"}

type configError struct{ msg string }

func (e *configError) Error() string { return "hmac verifier: " + e.msg }
