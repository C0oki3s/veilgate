package recommender

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	goyaml "gopkg.in/yaml.v3"

	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/rules"
)

// openMemStore returns an in-memory persist.Store for testing.
// FlushInterval is set to 5ms so seedEvents only needs a short sleep.
func openMemStore(t *testing.T) *persist.Store {
	t.Helper()
	s, err := persist.Open(persist.Config{Path: ":memory:", FlushInterval: 5 * time.Millisecond})
	if err != nil {
		t.Fatalf("open mem store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// seedEvents inserts synthetic events into the store and waits for them to flush.
func seedEvents(t *testing.T, s *persist.Store, events []persist.Event) {
	t.Helper()
	for _, e := range events {
		if e.Time.IsZero() {
			e.Time = time.Now()
		}
		s.Record(e)
	}
	time.Sleep(50 * time.Millisecond) // let the flusher commit
}

func since7d() time.Time { return time.Now().Add(-7 * 24 * time.Hour) }

// ── CountEventsByDecision ────────────────────────────────────────────────────

func TestCountEventsByDecisionBasic(t *testing.T) {
	s := openMemStore(t)
	seedEvents(t, s, []persist.Event{
		{Path: "/a", Score: 80, Decision: "tarpit"},
		{Path: "/b", Score: 80, Decision: "tarpit"},
		{Path: "/c", Score: 0, Decision: "real"},
	})

	tarpit, clean, err := s.CountEventsByDecision(since7d(), 70)
	if err != nil {
		t.Fatal(err)
	}
	if tarpit != 2 {
		t.Fatalf("tarpit count: got %d, want 2", tarpit)
	}
	if clean != 1 {
		t.Fatalf("clean count: got %d, want 1", clean)
	}
}

func TestCountEventsByDecisionEmpty(t *testing.T) {
	s := openMemStore(t)
	tp, cl, err := s.CountEventsByDecision(since7d(), 70)
	if err != nil {
		t.Fatal(err)
	}
	if tp != 0 || cl != 0 {
		t.Fatalf("empty store: got tp=%d cl=%d", tp, cl)
	}
}

// ── QueryPathSamples ─────────────────────────────────────────────────────────

func TestQueryPathSamples(t *testing.T) {
	s := openMemStore(t)
	seedEvents(t, s, []persist.Event{
		{Path: "/admin.php", Method: "GET", Score: 80, Decision: "tarpit", UserAgent: "sqlmap"},
		{Path: "/index.html", Method: "GET", Score: 0, Decision: "real", UserAgent: "Mozilla/5.0"},
	})

	samples, err := s.QueryPathSamples(since7d(), 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 2 {
		t.Fatalf("want 2 samples, got %d", len(samples))
	}
}

func TestQueryPathSamplesLimit(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 20)
	for i := range evs {
		evs[i] = persist.Event{Path: "/x", Method: "GET", Score: 50, Decision: "observe"}
	}
	seedEvents(t, s, evs)

	samples, err := s.QueryPathSamples(since7d(), 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 5 {
		t.Fatalf("limit not applied: got %d want 5", len(samples))
	}
}

// ── PathExtensionAnalyzer ────────────────────────────────────────────────────

func TestPathExtensionAnalyzer(t *testing.T) {
	s := openMemStore(t)
	// 50 tarpitted .php — no clean .php requests.
	evs := make([]persist.Event, 50)
	for i := range evs {
		evs[i] = persist.Event{Path: "/wp-login.php", Method: "GET", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)
	// 100 clean .html events so totalClean is large enough that FP rate stays low.
	htmlEvs := make([]persist.Event, 100)
	for i := range htmlEvs {
		htmlEvs[i] = persist.Event{Path: "/index.html", Score: 0, Decision: "real"}
	}
	seedEvents(t, s, htmlEvs)

	rec := New(s, nil, "", 70)
	recs, err := rec.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found *SignalRecommendation
	for i := range recs {
		for _, c := range recs[i].Signal.Conditions {
			if c.Type == "path_suffix" && c.Value == ".php" {
				found = &recs[i]
			}
		}
	}
	if found == nil {
		t.Fatalf("expected path_suffix .php recommendation, got: %v", recs)
	}
	if found.Confidence < 0.85 {
		t.Fatalf("confidence too low: %.2f", found.Confidence)
	}
	if found.Signal.Enabled {
		t.Fatal("suggested signal must have enabled:false")
	}
}

func TestPathExtensionAnalyzerBenignSkipped(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 40)
	for i := range evs {
		evs[i] = persist.Event{Path: "/page.html", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, "", 70)
	recs, err := rec.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		for _, c := range r.Signal.Conditions {
			if c.Type == "path_suffix" && c.Value == ".html" {
				t.Fatal("benign extension .html should not be suggested")
			}
		}
	}
}

// ── UASubstringAnalyzer ──────────────────────────────────────────────────────

func TestUASubstringAnalyzer(t *testing.T) {
	s := openMemStore(t)
	for i := 0; i < 80; i++ {
		s.RollupUpdate(persist.RollupDelta{Feature: "ua_token", Bucket: "python-requests", Label: "agent"})
	}
	for i := 0; i < 2; i++ {
		s.RollupUpdate(persist.RollupDelta{Feature: "ua_token", Bucket: "python-requests", Label: "human"})
	}
	evs := make([]persist.Event, 40)
	for i := range evs {
		evs[i] = persist.Event{Path: "/api/test", Score: 80, Decision: "tarpit", UserAgent: "python-requests/2.31.0"}
	}
	seedEvents(t, s, evs)
	time.Sleep(100 * time.Millisecond)

	rec := New(s, nil, "", 70)
	recs, err := rec.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, r := range recs {
		for _, c := range r.Signal.Conditions {
			if c.Type == "ua_contains" && c.Value == "python-requests" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected ua_contains python-requests recommendation")
	}
}

// ── MethodComboAnalyzer ──────────────────────────────────────────────────────

func TestMethodComboAnalyzer(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 35)
	for i := range evs {
		evs[i] = persist.Event{Path: "/api/v1/users", Method: "DELETE", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)
	cleanEvs := make([]persist.Event, 10)
	for i := range cleanEvs {
		cleanEvs[i] = persist.Event{Path: "/api/v1/users", Method: "GET", Score: 0, Decision: "real"}
	}
	seedEvents(t, s, cleanEvs)

	rec := New(s, nil, "", 70)
	recs, err := rec.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, r := range recs {
		if r.Source != "method_combo" {
			continue
		}
		hasMethod, hasPrefix := false, false
		for _, c := range r.Signal.Conditions {
			if c.Type == "method" && c.Value == "DELETE" {
				hasMethod = true
			}
			if c.Type == "path_prefix" {
				hasPrefix = true
			}
		}
		if hasMethod && hasPrefix {
			found = true
		}
	}
	if !found {
		t.Fatal("expected DELETE + path_prefix combo recommendation")
	}
}

// ── Deduplication ────────────────────────────────────────────────────────────

func TestDeduplicateKeepsHigherConfidence(t *testing.T) {
	cond := rules.CustomSignalCondition{Type: "path_suffix", Value: ".php"}
	recs := []SignalRecommendation{
		{Confidence: 0.80, Source: "a", Signal: rules.CustomSignal{Conditions: []rules.CustomSignalCondition{cond}}},
		{Confidence: 0.95, Source: "b", Signal: rules.CustomSignal{Conditions: []rules.CustomSignalCondition{cond}}},
	}
	out := deduplicate(recs)
	if len(out) != 1 {
		t.Fatalf("expected 1 after dedup, got %d", len(out))
	}
	if out[0].Confidence != 0.95 {
		t.Fatalf("kept lower confidence: %.2f", out[0].Confidence)
	}
}

func TestDeduplicateDifferentConditionsKeptSeparate(t *testing.T) {
	recs := []SignalRecommendation{
		{Confidence: 0.90, Signal: rules.CustomSignal{Conditions: []rules.CustomSignalCondition{{Type: "path_suffix", Value: ".php"}}}},
		{Confidence: 0.90, Signal: rules.CustomSignal{Conditions: []rules.CustomSignalCondition{{Type: "path_suffix", Value: ".env"}}}},
	}
	out := deduplicate(recs)
	if len(out) != 2 {
		t.Fatalf("expected 2 distinct recommendations, got %d", len(out))
	}
}

// ── MinConfidence filter ─────────────────────────────────────────────────────

func TestMinConfidenceFiltersResults(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 40)
	for i := 0; i < 20; i++ {
		evs[i] = persist.Event{Path: "/a.php", Score: 80, Decision: "tarpit"}
		evs[20+i] = persist.Event{Path: "/b.php", Score: 0, Decision: "real"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, "", 70)
	recs, err := rec.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Confidence < 0.85 {
			t.Fatalf("result below MinConfidence threshold: %.2f", r.Confidence)
		}
	}
}

// ── enabled:false guarantee ──────────────────────────────────────────────────

func TestAllSuggestionsHaveEnabledFalse(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 40)
	for i := range evs {
		evs[i] = persist.Event{Path: "/hack.php", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, "", 70)
	recs, err := rec.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
		if r.Signal.Enabled {
			t.Fatalf("suggestion %q has enabled:true — must always be false", r.Name)
		}
	}
}

// ── RenderReportYAML round-trip ──────────────────────────────────────────────

func TestRenderReportYAMLIsValidYAML(t *testing.T) {
	recs := []SignalRecommendation{
		{
			Name:       "test_sig",
			Source:     "path_extension",
			Confidence: 0.92,
			Support:    40,
			Rationale:  "test",
			Signal: rules.CustomSignal{
				Name:    "test_sig",
				Enabled: false,
				Points:  15,
				Conditions: []rules.CustomSignalCondition{
					{Type: "path_suffix", Value: ".php"},
				},
			},
		},
	}
	body, err := RenderReportYAML(recs)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) == 0 {
		t.Fatal("empty YAML output")
	}
	var parsed interface{}
	if err := goyaml.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("output is not valid YAML: %v\n%s", err, body)
	}
}

// ── REST handler ─────────────────────────────────────────────────────────────

func TestHandlerReturnsJSON(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 40)
	for i := range evs {
		evs[i] = persist.Event{Path: "/test.php", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, "", 70)
	req := httptest.NewRequest("GET", "/api/signal-suggestions", nil)
	w := httptest.NewRecorder()
	rec.Handler()(w, req)

	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q", ct)
	}
	var result []SignalRecommendation
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("parse JSON: %v\n%s", err, w.Body.String())
	}
}

func TestHandlerNilStoreReturns503(t *testing.T) {
	rec := New(nil, nil, "", 70)
	req := httptest.NewRequest("GET", "/api/signal-suggestions", nil)
	w := httptest.NewRecorder()
	rec.Handler()(w, req)
	if w.Code != 503 {
		t.Fatalf("expected 503 for nil store, got %d", w.Code)
	}
}

func TestHandlerQueryParamOverrides(t *testing.T) {
	s := openMemStore(t)
	evs := make([]persist.Event, 40)
	for i := range evs {
		evs[i] = persist.Event{Path: "/test.php", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, "", 70)
	req := httptest.NewRequest("GET", "/api/signal-suggestions?min_confidence=0.99&min_support=1000", nil)
	w := httptest.NewRecorder()
	rec.Handler()(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d", w.Code)
	}
	var result []SignalRecommendation
	_ = json.Unmarshal(w.Body.Bytes(), &result)
	for _, r := range result {
		if r.Confidence < 0.99 {
			t.Fatalf("result below overridden min_confidence: %.2f", r.Confidence)
		}
	}
}

// ── WriteSuggestions ─────────────────────────────────────────────────────────

func TestWriteSuggestionsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s := openMemStore(t)
	evs := make([]persist.Event, 40)
	for i := range evs {
		evs[i] = persist.Event{Path: "/probe.php", Score: 80, Decision: "tarpit"}
	}
	seedEvents(t, s, evs)

	rec := New(s, nil, dir, 70)
	recs, err := rec.Analyze(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.WriteSuggestions(recs); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(dir + "/signal_suggestions.yaml")
	if err != nil {
		t.Fatalf("suggestions file not written: %v", err)
	}
	var parsed interface{}
	if err := goyaml.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("suggestions file is invalid YAML: %v", err)
	}
}

func TestWriteSuggestionsNoopOnEmpty(t *testing.T) {
	dir := t.TempDir()
	rec := New(nil, nil, dir, 70)
	if err := rec.WriteSuggestions(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + "/signal_suggestions.yaml"); err == nil {
		t.Fatal("file should not be created for empty recommendations")
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func mustReadAll(t *testing.T, path string) []byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
