package recommender

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/C0oki3s/veilgate/internal/persist"
)

// ── JA4FingerprintAnalyzer ───────────────────────────────────────────────────

func TestJA4AnalyzerHighTarpitRate(t *testing.T) {
	s := openMemStore(t)

	// 50 tarpitted events with a distinctive JA4 fingerprint.
	const suspiciousJA4 = "t13d1516h2_abc123def456_abcdef012345"
	evs := make([]persist.Event, 60)
	for i := 0; i < 50; i++ {
		evs[i] = persist.Event{Path: "/", Method: "GET", Score: 80, Decision: "tarpit", JA4: suspiciousJA4}
	}
	// 10 clean events with a different JA4.
	for i := 50; i < 60; i++ {
		evs[i] = persist.Event{Path: "/", Method: "GET", Score: 0, Decision: "real", JA4: "t13d1516h2_ffffffff_111111111111"}
	}
	seedEvents(t, s, evs)

	cfg := AnalysisConfig{
		Since:                  since7d(),
		MinConfidence:          0.85,
		MinSupport:             10,
		MaxSuggestions:         20,
		FalsePositiveThreshold: 0.15,
		TarpitThreshold:        70,
	}
	az := NewJA4FingerprintAnalyzer(s)
	recs, err := az.Analyze(cfg, nil, 50, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("expected at least one JA4 recommendation")
	}
	r := recs[0]
	if r.Signal.Conditions[0].Type != "ja4_prefix" {
		t.Fatalf("expected ja4_prefix condition, got %q", r.Signal.Conditions[0].Type)
	}
	wantPrefix := ja4Prefix(suspiciousJA4)
	if r.Signal.Conditions[0].Value != wantPrefix {
		t.Fatalf("expected prefix %q, got %q", wantPrefix, r.Signal.Conditions[0].Value)
	}
	if r.Confidence < 0.85 {
		t.Fatalf("confidence too low: %.2f", r.Confidence)
	}
	if r.Signal.Enabled {
		t.Fatal("suggestion must have enabled:false")
	}
	if r.Signal.Points != 30 {
		t.Fatalf("expected 30 points, got %d", r.Signal.Points)
	}
}

func TestJA4AnalyzerLowTarpitRateSkipped(t *testing.T) {
	s := openMemStore(t)

	// JA4 fingerprint with only 50% tarpit rate — below MinConfidence.
	const mixedJA4 = "t13d1516h2_mixed_fingerprint12"
	evs := make([]persist.Event, 40)
	for i := 0; i < 20; i++ {
		evs[i] = persist.Event{Path: "/", Score: 80, Decision: "tarpit", JA4: mixedJA4}
	}
	for i := 20; i < 40; i++ {
		evs[i] = persist.Event{Path: "/", Score: 0, Decision: "real", JA4: mixedJA4}
	}
	seedEvents(t, s, evs)

	cfg := AnalysisConfig{
		Since:                  since7d(),
		MinConfidence:          0.85,
		MinSupport:             10,
		MaxSuggestions:         20,
		FalsePositiveThreshold: 0.15,
		TarpitThreshold:        70,
	}
	az := NewJA4FingerprintAnalyzer(s)
	recs, err := az.Analyze(cfg, nil, 20, 20)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		for _, c := range r.Signal.Conditions {
			if c.Type == "ja4_prefix" {
				t.Fatal("low-tarpit-rate JA4 should not be recommended")
			}
		}
	}
}

func TestJA4AnalyzerNilStoreReturnsNil(t *testing.T) {
	az := NewJA4FingerprintAnalyzer(nil)
	recs, err := az.Analyze(AnalysisConfig{MinSupport: 1}, nil, 50, 50)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatal("nil store should return no recs")
	}
}

func TestJA4AnalyzerLowTotalTarpitSkipped(t *testing.T) {
	s := openMemStore(t)
	az := NewJA4FingerprintAnalyzer(s)
	cfg := AnalysisConfig{MinSupport: 100, TarpitThreshold: 70, Since: since7d()}
	// totalTarpit (5) < MinSupport (100) — analyzer should return nothing.
	recs, err := az.Analyze(cfg, nil, 5, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no recs with low totalTarpit, got %d", len(recs))
	}
}

// ── ja4Prefix helper ─────────────────────────────────────────────────────────

func TestJA4Prefix(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"t13d1516h2_abc123", "t13d1516h2_a"}, // exactly 12 chars
		{"short", "short"},                      // shorter than 12
		{"T13D1516H2_XYZ", "t13d1516h2_x"},     // lowercase normalised
		{"", ""},
	}
	for _, tc := range cases {
		got := ja4Prefix(tc.in)
		if got != tc.want {
			t.Errorf("ja4Prefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ── QueryParamAnalyzer ───────────────────────────────────────────────────────

func TestQueryParamAnalyzerHighTarpitKey(t *testing.T) {
	s := openMemStore(t)

	// 35 tarpitted events with ?cmd=id query string.
	evs := make([]persist.Event, 45)
	for i := 0; i < 35; i++ {
		evs[i] = persist.Event{Path: "/api", Query: "cmd=id", Method: "GET", Score: 80, Decision: "tarpit"}
	}
	// 10 clean events with a different query string.
	for i := 35; i < 45; i++ {
		evs[i] = persist.Event{Path: "/api", Query: "page=1", Method: "GET", Score: 0, Decision: "real"}
	}
	seedEvents(t, s, evs)

	samples, err := s.QueryPathSamples(since7d(), 200)
	if err != nil {
		t.Fatal(err)
	}

	cfg := AnalysisConfig{
		Since:                  since7d(),
		MinConfidence:          0.85,
		MinSupport:             30,
		MaxSuggestions:         20,
		FalsePositiveThreshold: 0.15,
		TarpitThreshold:        70,
	}
	az := NewQueryParamAnalyzer()
	recs, err := az.Analyze(cfg, samples, 35, 10)
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, r := range recs {
		for _, c := range r.Signal.Conditions {
			if c.Type == "query_contains" && c.Value == "cmd=" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("expected query_contains cmd= recommendation, got: %v", recs)
	}
}

func TestQueryParamAnalyzerNoQuerySkipped(t *testing.T) {
	samples := []persist.PathSample{
		{Path: "/admin.php", Score: 80, Decision: "tarpit"},
		{Path: "/login", Score: 80, Decision: "tarpit"},
	}
	cfg := AnalysisConfig{MinConfidence: 0.85, MinSupport: 1, TarpitThreshold: 70, Since: since7d()}
	az := NewQueryParamAnalyzer()
	recs, err := az.Analyze(cfg, samples, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("no query strings in samples should produce no recs, got %d", len(recs))
	}
}

func TestQueryParamAnalyzerEnabledFalse(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 35)
	for i := range evs {
		evs[i] = persist.Event{Path: "/x", Query: "debug=true", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	samples, err := s.QueryPathSamples(since7d(), 200)
	if err != nil {
		t.Fatal(err)
	}

	cfg := AnalysisConfig{
		Since: since7d(), MinConfidence: 0.85, MinSupport: 30, TarpitThreshold: 70,
		MaxSuggestions: 20, FalsePositiveThreshold: 0.15,
	}
	az := NewQueryParamAnalyzer()
	recs, err := az.Analyze(cfg, samples, 35, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Signal.Enabled {
			t.Fatalf("suggestion %q has enabled:true — must always be false", r.Name)
		}
	}
}

// ── RunOnce ──────────────────────────────────────────────────────────────────

func TestRunOncePopulatesCache(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 50)
	for i := range evs {
		evs[i] = persist.Event{Path: "/exploit.php", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, "", 70)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := rec.RunOnce(ctx); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	cached, err := s.ListSuggestions()
	if err != nil {
		t.Fatal(err)
	}
	if len(cached) == 0 {
		t.Fatal("cache should be populated after RunOnce")
	}
}

func TestRunOnceThenHandlerServesCache(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 50)
	for i := range evs {
		evs[i] = persist.Event{Path: "/shell.php", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, "", 70)
	ctx := context.Background()
	if err := rec.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}

	// Handler should now serve from cache (X-Suggestions-Source: cache).
	req, _ := http.NewRequest("GET", "/api/signal-suggestions", nil)
	// Use the existing TestHandlerReturnsJSON helper indirectly by running
	// through Handler() and checking the source header.
	rr := &headerCapture{}
	rec.Handler()(rr, req)
	if rr.source != "cache" {
		t.Fatalf("expected X-Suggestions-Source=cache after RunOnce, got %q", rr.source)
	}
}

// headerCapture is a minimal http.ResponseWriter that records the
// X-Suggestions-Source header written by the recommender handler.
type headerCapture struct {
	source  string
	headers http.Header
	body    []byte
	code    int
}

func (h *headerCapture) Header() http.Header {
	if h.headers == nil {
		h.headers = http.Header{}
	}
	return h.headers
}

func (h *headerCapture) Write(b []byte) (int, error) {
	h.body = append(h.body, b...)
	if h.source == "" {
		h.source = h.headers.Get("X-Suggestions-Source")
	}
	return len(b), nil
}

func (h *headerCapture) WriteHeader(code int) {
	h.code = code
	h.source = h.headers.Get("X-Suggestions-Source")
}

// ── Integration: new analyzers registered in New() ───────────────────────────

func TestNewAnalyzersRegistered(t *testing.T) {
	s := openMemStore(t)
	rec := New(s, nil, "", 70)

	names := map[string]bool{}
	for _, az := range rec.analyzers {
		names[az.Name()] = true
	}
	for _, want := range []string{"ja4_fingerprint", "query_param"} {
		if !names[want] {
			t.Errorf("analyzer %q not registered in New()", want)
		}
	}
}
