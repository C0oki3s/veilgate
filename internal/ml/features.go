// Package ml is the online classifier + Isolation Forest that produces
// the detector's `ml_agent_score` signal. Everything here is pure Go,
// CGO-free, and tunable from rules/ml.yaml.
package ml

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// PathRedactor scrubs high-entropy URL path segments to keep things like
// UUIDs, opaque IDs, and tokens from landing in Bayes buckets and the
// learned.yaml file. Built once at startup; the proxy hot path only calls
// Apply, which is read-only.
//
// The default ruleset (NewDefaultPathRedactor) covers UUIDs, long numeric
// IDs, hex strings, and base64-ish tokens. Operators can extend it via
// rules/ml.yaml -> path_redaction.custom.
type PathRedactor struct {
	rules []redactRule
}

type redactRule struct {
	re      *regexp.Regexp
	replace string
}

var defaultRedactRules = []struct {
	pattern string
	replace string
}{
	// RFC 4122 UUID (any case).
	{`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`, "<uuid>"},
	// Long numeric IDs (4+ digits) — covers /users/12345/orders.
	{`^\d{4,}$`, "<id>"},
	// Long hex strings (object IDs, sha1/sha256 fragments).
	{`(?i)^[0-9a-f]{16,}$`, "<hex>"},
	// Base64 / URL-safe base64 tokens.
	{`^[A-Za-z0-9_\-]{20,}={0,2}$`, "<token>"},
}

// NewDefaultPathRedactor returns a redactor with the built-in rule set
// enabled. Suitable for almost every deployment; operators only need to
// extend it when their app has app-specific identifier shapes (medical
// record numbers, account codes, etc.).
func NewDefaultPathRedactor() *PathRedactor {
	out := &PathRedactor{}
	for _, r := range defaultRedactRules {
		out.rules = append(out.rules, redactRule{
			re:      regexp.MustCompile(r.pattern),
			replace: r.replace,
		})
	}
	return out
}

// AddCustom appends an operator-supplied (regex, replacement) pair. Used
// when ml.yaml ships a path_redaction.custom block. Invalid regexes are
// silently dropped — the caller has no good way to surface a YAML error
// from inside the hot path.
func (p *PathRedactor) AddCustom(pattern, replace string) {
	if p == nil || pattern == "" || replace == "" {
		return
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return
	}
	p.rules = append(p.rules, redactRule{re: re, replace: replace})
}

// Apply returns segment unchanged when no rule matches; otherwise it
// returns the first matching rule's replacement. Cheap and allocation-free
// in the common no-match case.
func (p *PathRedactor) Apply(segment string) string {
	if p == nil || segment == "" {
		return segment
	}
	for _, r := range p.rules {
		if r.re.MatchString(segment) {
			return r.replace
		}
	}
	return segment
}

// activeRedactor is the process-wide redactor used by Extract. Set via
// SetActiveRedactor at boot from rules/ml.yaml. Nil means "no redaction"
// — the hot path checks for that explicitly so unit tests and the
// embedded-defaults flow keep their existing behaviour.
var (
	redactorMu      sync.RWMutex
	activeRedactor  *PathRedactor
)

// SetActiveRedactor installs the process-wide path redactor. Safe to call
// from a hot-reload watcher; reads on the request path use a read-lock.
func SetActiveRedactor(p *PathRedactor) {
	redactorMu.Lock()
	activeRedactor = p
	redactorMu.Unlock()
}

func currentRedactor() *PathRedactor {
	redactorMu.RLock()
	defer redactorMu.RUnlock()
	return activeRedactor
}

// Feature is one (name, bucket) pair. Buckets are strings so they can be
// stored verbatim in the features_rollup table and mentioned in
// rules/learned.yaml without post-processing.
type Feature struct {
	Name   string
	Bucket string
}

// Vec is what the detector hands to the classifier every request.
// Categorical holds the discrete features used by Naive Bayes. Numeric
// is the float vector the Isolation Forest sees.
type Vec struct {
	Categorical []Feature
	Numeric     []float64
}

// JSON returns a compact serialization used for the events.features_json
// column. Callers are expected to treat it as opaque.
func (v Vec) JSON() string {
	type out struct {
		Cat [][]string `json:"c"`
		Num []float64  `json:"n"`
	}
	cat := make([][]string, 0, len(v.Categorical))
	for _, f := range v.Categorical {
		cat = append(cat, []string{f.Name, f.Bucket})
	}
	b, _ := json.Marshal(out{Cat: cat, Num: v.Numeric})
	return string(b)
}

// ParseVec is the inverse of Vec.JSON.
func ParseVec(s string) (Vec, error) {
	var out struct {
		Cat [][]string `json:"c"`
		Num []float64  `json:"n"`
	}
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return Vec{}, err
	}
	v := Vec{Numeric: out.Num}
	for _, p := range out.Cat {
		if len(p) == 2 {
			v.Categorical = append(v.Categorical, Feature{Name: p[0], Bucket: p[1]})
		}
	}
	return v, nil
}

// Extractor computes Vec from an HTTP request + inter-request timing.
// It is stateless; everything it needs is passed in.
type Extractor struct {
	TimingBuckets  []float64 // upper bounds in seconds
	MaxNgramLength int
}

// NewExtractor returns an Extractor with sane defaults. Override fields
// from rules/ml.yaml after construction.
func NewExtractor() *Extractor {
	return &Extractor{
		TimingBuckets:  []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 300},
		MaxNgramLength: 3,
	}
}

// Extract builds a Vec from the live request. gapSeconds is the time
// since the client's previous request, or 0 for the first request.
func (e *Extractor) Extract(r *http.Request, gapSeconds float64, ja4 string) Vec {
	var feats []Feature
	nums := make([]float64, 0, 12)

	// Method — low-cardinality, so keep as-is.
	method := strings.ToUpper(r.Method)
	feats = append(feats, Feature{Name: "method", Bucket: method})

	// Header set — a stable hash of the sorted set of present header
	// names. Captures structural fingerprints like "curl sends only
	// User-Agent + Accept".
	headerSet := headerSetID(r)
	feats = append(feats, Feature{Name: "header_set_id", Bucket: headerSet})
	nums = append(nums, float64(countHeaders(r)))

	// User-Agent tokens — the single biggest signal for tool identification.
	// Split by /, whitespace, and dots; keep each token.
	for _, tok := range uaTokens(r.UserAgent()) {
		feats = append(feats, Feature{Name: "ua_token", Bucket: tok})
	}

	// Path n-grams of 1..MaxNgramLength words (split by `/`).
	for _, ng := range pathNgrams(r.URL.Path, e.MaxNgramLength) {
		feats = append(feats, Feature{Name: "path_ngram", Bucket: ng})
	}

	// JA4 prefix (10 chars). Empty when TLS fingerprinting is disabled.
	if len(ja4) >= 10 {
		feats = append(feats, Feature{Name: "ja4_prefix", Bucket: ja4[:10]})
	}

	// Timing bucket — "which log-spaced bin does the gap land in".
	feats = append(feats, Feature{Name: "timing_bucket", Bucket: e.timingBucket(gapSeconds)})
	nums = append(nums, gapSeconds)

	// Reasoning-pause bucket. Same gap, but inside a finer set of bins
	// tuned to typical LLM token-generation pauses (~3-8s). Lets Bayes
	// learn "this client always pauses ~5s ± 0.5" without that signal
	// being smeared across the much wider log-spaced timing_bucket.
	feats = append(feats, Feature{Name: "pause_bucket", Bucket: pauseBucket(gapSeconds)})

	// Query-present bit — agents often hit `/path?param=value` shapes.
	if r.URL.RawQuery != "" {
		nums = append(nums, 1)
	} else {
		nums = append(nums, 0)
	}

	// Body presence via Content-Length (cheap proxy — we don't read the body).
	if cl := r.Header.Get("Content-Length"); cl != "" && cl != "0" {
		nums = append(nums, 1)
	} else {
		nums = append(nums, 0)
	}

	// UA length — agents with short or empty UAs push this low.
	nums = append(nums, float64(len(r.UserAgent())))

	// Sec-Fetch-* coherence. Real browsers emit a coherent (Dest, Mode,
	// Site) triple that matches the request shape; libs either omit it
	// entirely or send incoherent combinations.
	feats = append(feats, Feature{Name: "sec_fetch_coh", Bucket: secFetchCoherence(r)})

	// Accept-Encoding algorithm posture. Browsers always advertise a
	// rich set (gzip, deflate, br; Chromium also zstd). Many libs
	// advertise just "gzip" or omit it.
	feats = append(feats, Feature{Name: "accept_enc", Bucket: acceptEncodingPosture(r)})

	// Header value canonicalization fingerprint. Hashes the *normalized
	// values* of a small set of high-signal headers (Accept, Sec-Ch-Ua,
	// Accept-Language). Catches libs that match the browser's *names*
	// but botch the values (a common mistake in spoofed agents).
	feats = append(feats, Feature{Name: "header_canon_fp", Bucket: headerCanonFingerprint(r)})

	// HTTP/3 capability mismatch. Today H3 hint is computed by the proxy
	// and stored on a request header — see h3_hint_header below. The
	// numeric is 0 when the client honored H3, 1 when it ignored an
	// Alt-Svc hint, -1 when no hint applies.
	nums = append(nums, h3MismatchScore(r))

	return Vec{Categorical: feats, Numeric: nums}
}

// pauseBucket is a fine-grained bucketing of inter-request gaps tuned
// for LLM token-generation cadence. The boundaries are deliberately
// narrower than the configurable timing_buckets so this signal can
// learn LLM-specific pauses even when an operator has widened the main
// timing buckets to suppress regular-timing false positives on legit
// background polling clients.
func pauseBucket(gap float64) string {
	switch {
	case gap <= 0:
		return "first"
	case gap < 1:
		return "lt1"
	case gap < 2:
		return "1_2"
	case gap < 3:
		return "2_3"
	case gap < 5:
		return "3_5" // canonical LLM "thinking" pause
	case gap < 8:
		return "5_8" // larger model / chain-of-thought pause
	case gap < 15:
		return "8_15"
	case gap < 30:
		return "15_30"
	case gap < 90:
		return "30_90"
	}
	return "gt90"
}

// secFetchCoherence labels the (Sec-Fetch-Site, Sec-Fetch-Mode,
// Sec-Fetch-Dest) triple. Five outcomes:
//
//   - "absent": none of the three present (libs).
//   - "partial": one or two present.
//   - "navigate": classic top-level navigation triple.
//   - "subresource": subresource fetch triple from a page.
//   - "cors_xhr": cross-origin XHR/fetch from JS.
//   - "incoherent": all three present but not a recognised combination.
func secFetchCoherence(r *http.Request) string {
	site := r.Header.Get("Sec-Fetch-Site")
	mode := r.Header.Get("Sec-Fetch-Mode")
	dest := r.Header.Get("Sec-Fetch-Dest")
	present := 0
	for _, v := range []string{site, mode, dest} {
		if v != "" {
			present++
		}
	}
	if present == 0 {
		return "absent"
	}
	if present < 3 {
		return "partial"
	}
	switch {
	case dest == "document" && mode == "navigate":
		return "navigate"
	case mode == "no-cors" && (dest == "script" || dest == "image" || dest == "style" || dest == "font"):
		return "subresource"
	case mode == "cors" && (dest == "empty" || dest == "json"):
		return "cors_xhr"
	}
	return "incoherent"
}

// acceptEncodingPosture labels the Accept-Encoding header by what
// algorithms the client claims to support. Real browsers always
// advertise gzip + deflate + br (Chromium 2023+ adds zstd); libs vary
// from "" through "gzip" to a permissive identity-only list.
func acceptEncodingPosture(r *http.Request) string {
	v := strings.ToLower(r.Header.Get("Accept-Encoding"))
	if v == "" {
		return "empty"
	}
	has := func(alg string) bool { return strings.Contains(v, alg) }
	g, d, b, z := has("gzip"), has("deflate"), has("br"), has("zstd")
	switch {
	case g && d && b && z:
		return "chromium_full"
	case g && d && b:
		return "browser_full"
	case g && d && !b:
		return "gzip_deflate"
	case g && !d && !b:
		return "gzip_only"
	case has("identity") || has("*"):
		return "permissive"
	}
	return "other"
}

// headerCanonFingerprint hashes the *values* of a fixed set of
// high-signal headers, after light normalization. Catches a lib that
// learned the browser header *names* but emitted them with the wrong
// casing or spacing. We pick four headers because that's the sweet
// spot: enough collision space, low enough that benign minor-version
// drift doesn't shatter the bucket into uniqueness.
func headerCanonFingerprint(r *http.Request) string {
	pick := func(name string) string {
		v := r.Header.Get(name)
		// Normalize light whitespace; keep casing because *that's the
		// signal* — Chrome emits "gzip, deflate, br" with that exact
		// spacing; libs reorder or compact it.
		return strings.TrimSpace(v)
	}
	parts := []string{
		pick("Accept"),
		pick("Accept-Language"),
		pick("Sec-Ch-Ua"),
		pick("Sec-Ch-Ua-Platform"),
	}
	h := sha1.Sum([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:4])
}

// h3MismatchScore returns 1 when the request carries the proxy-set
// X-Veilgate-H3-Hint flag indicating the upstream advertised H3 via
// Alt-Svc but this connection still came in over H1/H2. Returns 0
// when the flag is absent. Header is set by the proxy — keeping it as
// a request-header lookup means Extract stays stateless.
func h3MismatchScore(r *http.Request) float64 {
	if r.Header.Get("X-Veilgate-H3-Mismatch") == "1" {
		return 1
	}
	return 0
}

// ExtractFromEvent rebuilds a Vec from stored event fields (used by the
// miner when replaying rollups). It duplicates the core of Extract
// because http.Request.URL is a concrete *url.URL and we don't want to
// allocate one just to read two fields.
func (e *Extractor) ExtractFromEvent(method, path, query, ua, ja4 string, gapSeconds float64) Vec {
	// Synthesize a request-like struct inline. Because Extract reads
	// only a small surface, we inline the same logic here rather than
	// fight the url.URL type.
	var feats []Feature
	nums := make([]float64, 0, 8)

	feats = append(feats, Feature{Name: "method", Bucket: strings.ToUpper(method)})
	feats = append(feats, Feature{Name: "header_set_id", Bucket: "replay"})
	nums = append(nums, 0)

	for _, tok := range uaTokens(ua) {
		feats = append(feats, Feature{Name: "ua_token", Bucket: tok})
	}
	for _, ng := range pathNgrams(path, e.MaxNgramLength) {
		feats = append(feats, Feature{Name: "path_ngram", Bucket: ng})
	}
	if len(ja4) >= 10 {
		feats = append(feats, Feature{Name: "ja4_prefix", Bucket: ja4[:10]})
	}
	feats = append(feats, Feature{Name: "timing_bucket", Bucket: e.timingBucket(gapSeconds)})
	nums = append(nums, gapSeconds)
	feats = append(feats, Feature{Name: "pause_bucket", Bucket: pauseBucket(gapSeconds)})
	if query != "" {
		nums = append(nums, 1)
	} else {
		nums = append(nums, 0)
	}
	nums = append(nums, 0) // Content-Length unknown in replay
	nums = append(nums, float64(len(ua)))
	// Replay can't observe the live header set, so the canonicalization /
	// Sec-Fetch / Accept-Encoding features come back as their "absent"
	// bucket. This is fine for IF training — the absence is itself a
	// signal — but the operator should know the replay path is lossy.
	feats = append(feats, Feature{Name: "sec_fetch_coh", Bucket: "absent"})
	feats = append(feats, Feature{Name: "accept_enc", Bucket: "empty"})
	feats = append(feats, Feature{Name: "header_canon_fp", Bucket: "replay"})
	nums = append(nums, 0) // h3 mismatch unknown in replay
	return Vec{Categorical: feats, Numeric: nums}
}

// headerSetID hashes the sorted set of header names a request carries.
// Stable across Go map iteration, so equivalent clients always bucket
// identically.
func headerSetID(r *http.Request) string {
	names := make([]string, 0, len(r.Header))
	for k := range r.Header {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	h := sha1.Sum([]byte(strings.Join(names, ",")))
	return hex.EncodeToString(h[:4]) // 8 hex chars — good enough
}

func countHeaders(r *http.Request) int {
	return len(r.Header)
}

// uaTokens returns lowercased tokens from a User-Agent. Empty input yields
// a single "<empty>" token so Bayes sees empty-UA as a distinct feature.
func uaTokens(ua string) []string {
	ua = strings.ToLower(ua)
	if ua == "" {
		return []string{"<empty>"}
	}
	seps := func(r rune) bool {
		switch r {
		case ' ', '/', '(', ')', ',', ';':
			return true
		}
		return false
	}
	fields := strings.FieldsFunc(ua, seps)
	// Drop raw versions ("1.2.3") — they explode the feature space and rarely
	// carry stable signal.
	out := fields[:0]
	for _, f := range fields {
		if len(f) < 2 || looksLikeVersion(f) {
			continue
		}
		out = append(out, f)
	}
	return out
}

func looksLikeVersion(s string) bool {
	for _, r := range s {
		if r >= '0' && r <= '9' {
			continue
		}
		if r == '.' || r == '-' || r == '+' {
			continue
		}
		return false
	}
	return true
}

// pathNgrams returns 1..n-grams of the path split by `/`. Trailing and
// leading slashes are dropped. When a process-wide PathRedactor is
// installed via SetActiveRedactor, each segment is passed through it
// BEFORE n-gram joining — so /users/12345/orders becomes
// users/<id>/orders, and the high-entropy bucket never makes it into
// learned.yaml.
func pathNgrams(path string, n int) []string {
	if n < 1 {
		n = 1
	}
	parts := strings.Split(strings.Trim(strings.ToLower(path), "/"), "/")
	if len(parts) == 0 || (len(parts) == 1 && parts[0] == "") {
		return []string{"/"}
	}
	if r := currentRedactor(); r != nil {
		for i, seg := range parts {
			parts[i] = r.Apply(seg)
		}
	}
	var out []string
	for size := 1; size <= n && size <= len(parts); size++ {
		for i := 0; i+size <= len(parts); i++ {
			out = append(out, strings.Join(parts[i:i+size], "/"))
		}
	}
	return out
}

// timingBucket returns a string label for the bucket gapSeconds lands in.
// "gt_<last>" for anything above the last bucket; "lt_<first>" for below.
func (e *Extractor) timingBucket(gap float64) string {
	if len(e.TimingBuckets) == 0 {
		return "none"
	}
	if gap <= 0 {
		return "first"
	}
	for _, ub := range e.TimingBuckets {
		if gap <= ub {
			return fmt.Sprintf("le_%g", ub)
		}
	}
	return fmt.Sprintf("gt_%g", e.TimingBuckets[len(e.TimingBuckets)-1])
}

// GapSince returns the seconds since prev, clamped to [0, max] to keep
// the Isolation Forest from seeing outliers that dominate its scale.
func GapSince(prev, now time.Time, max float64) float64 {
	if prev.IsZero() {
		return 0
	}
	d := now.Sub(prev).Seconds()
	if d < 0 {
		return 0
	}
	if max > 0 && d > max {
		return max
	}
	return d
}
