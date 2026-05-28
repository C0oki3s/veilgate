package detector

// Tests for the six behavioral signals added in the session-signal pass:
//   header_mutation, schema_first, cache_miss_anomaly,
//   no_cookie_return, encoding_chain, auth_probe_sequence.
//
// Each signal block contains:
//   • positive cases (fires at the expected threshold/tier)
//   • false-positive prevention cases (must NOT fire on legitimate traffic)
//
// Additional coverage:
//   • mutationBitmap isolation (only 5 stable headers tracked)
//   • ML tarpit-threshold gate (observe suppressed for tarpitted clients)
//   • Dynamic schema/auth patterns loaded from rules

import (
	"net/http/httptest"
	"testing"
	"time"

	"github.com/C0oki3s/veilgate/internal/ml"
	"github.com/C0oki3s/veilgate/internal/rules"
)

// ── header_mutation ──────────────────────────────────────────────────────────

func TestHeaderMutationSignal(t *testing.T) {
	s, _ := newScorer()

	t.Run("fires at 5 mutations when total >= 6", func(t *testing.T) {
		state := &ClientState{HeaderMutations: 5, RequestsTotal: 10}
		if sig := s.scoreHeaderMutation(state); sig.Name != "header_mutation" || sig.Points != 8 {
			t.Fatalf("expected header_mutation 8pts, got %+v", sig)
		}
	})

	t.Run("fires at 10 mutations with medium tier", func(t *testing.T) {
		state := &ClientState{HeaderMutations: 10, RequestsTotal: 15}
		if sig := s.scoreHeaderMutation(state); sig.Name != "header_mutation" || sig.Points != 15 {
			t.Fatalf("expected header_mutation 15pts, got %+v", sig)
		}
	})

	t.Run("fires at 15+ mutations with high tier", func(t *testing.T) {
		state := &ClientState{HeaderMutations: 20, RequestsTotal: 30}
		if sig := s.scoreHeaderMutation(state); sig.Name != "header_mutation" || sig.Points != 25 {
			t.Fatalf("expected header_mutation 25pts, got %+v", sig)
		}
	})

	t.Run("no fire when total requests below minimum of 6", func(t *testing.T) {
		state := &ClientState{HeaderMutations: 8, RequestsTotal: 4}
		if sig := s.scoreHeaderMutation(state); sig.Points != 0 {
			t.Fatalf("should not fire with <6 total requests, got %+v", sig)
		}
	})

	t.Run("no fire when mutations below threshold of 5", func(t *testing.T) {
		state := &ClientState{HeaderMutations: 3, RequestsTotal: 20}
		if sig := s.scoreHeaderMutation(state); sig.Points != 0 {
			t.Fatalf("should not fire with <5 mutations, got %+v", sig)
		}
	})
}

// ── mutationBitmap isolation ──────────────────────────────────────────────────

func TestMutationBitmapIsolation(t *testing.T) {
	t.Run("changes when Accept-Language is dropped (absent → present transition)", func(t *testing.T) {
		// The bitmap tracks presence/absence, not values. A library that adds
		// Accept-Language mid-session (absent on first request, present later)
		// registers as a mutation. Test: one request with it, one without.
		r1 := httptest.NewRequest("GET", "/", nil)
		r1.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r2 := httptest.NewRequest("GET", "/", nil)
		// r2 has no Accept-Language at all — simulates an agent that drops it
		if mutationBitmap(r1) == mutationBitmap(r2) {
			t.Fatal("Accept-Language present vs absent should produce different mutation bitmaps")
		}
	})

	t.Run("unchanged when Referer is added mid-session (volatile header)", func(t *testing.T) {
		r1 := httptest.NewRequest("GET", "/page1", nil)
		r1.Header.Set("Accept-Language", "en-US")
		r2 := httptest.NewRequest("GET", "/page2", nil)
		r2.Header.Set("Accept-Language", "en-US")
		r2.Header.Set("Referer", "https://example.com/page1")
		if mutationBitmap(r1) != mutationBitmap(r2) {
			t.Fatal("adding Referer should not change mutation bitmap — real browsers add it on navigation")
		}
	})

	t.Run("unchanged when Cookie appears after Set-Cookie", func(t *testing.T) {
		r1 := httptest.NewRequest("GET", "/", nil)
		r1.Header.Set("Accept-Language", "en-US")
		r2 := httptest.NewRequest("GET", "/", nil)
		r2.Header.Set("Accept-Language", "en-US")
		r2.Header.Set("Cookie", "session=abc123")
		if mutationBitmap(r1) != mutationBitmap(r2) {
			t.Fatal("adding Cookie should not change mutation bitmap — real browsers add it after first Set-Cookie")
		}
	})

	t.Run("unchanged when Sec-Fetch changes between doc and cors request", func(t *testing.T) {
		r1 := httptest.NewRequest("GET", "/docs", nil)
		r1.Header.Set("Accept-Language", "en-US")
		r1.Header.Set("Sec-Fetch-Site", "none")
		r1.Header.Set("Sec-Fetch-Mode", "navigate")
		r2 := httptest.NewRequest("GET", "/api/data", nil)
		r2.Header.Set("Accept-Language", "en-US")
		r2.Header.Set("Sec-Fetch-Site", "same-origin")
		r2.Header.Set("Sec-Fetch-Mode", "cors")
		if mutationBitmap(r1) != mutationBitmap(r2) {
			t.Fatal("Sec-Fetch changes should not affect mutation bitmap — they vary by request type")
		}
	})

	t.Run("Sec-Ch-Ua presence is tracked (stable header)", func(t *testing.T) {
		r1 := httptest.NewRequest("GET", "/", nil)
		r1.Header.Set("Accept-Language", "en-US")
		r1.Header.Set("Sec-Ch-Ua", `"Chromium";v="124"`)
		r2 := httptest.NewRequest("GET", "/", nil)
		r2.Header.Set("Accept-Language", "en-US")
		// r2 does not have Sec-Ch-Ua — simulates agent that drops it mid-session
		if mutationBitmap(r1) == mutationBitmap(r2) {
			t.Fatal("dropping Sec-Ch-Ua should change mutation bitmap")
		}
	})
}

// ── schema_first ─────────────────────────────────────────────────────────────

func TestSchemaFirstSignal(t *testing.T) {
	s, _ := newScorer()
	now := time.Now()

	t.Run("fires when non-browser first request hits openapi path", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now, Path: "/openapi.json", UserAgent: "python-requests/2.28.0"},
		}
		if sig := s.scoreSchemaFirst(events); sig.Name != "schema_first" || sig.Points != 20 {
			t.Fatalf("expected schema_first 20pts, got %+v", sig)
		}
	})

	t.Run("fires on swagger path in second request", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now.Add(-5 * time.Second), Path: "/", UserAgent: "go-http-client/1.1"},
			{Timestamp: now, Path: "/swagger-ui/index.html", UserAgent: "go-http-client/1.1"},
		}
		if sig := s.scoreSchemaFirst(events); sig.Name != "schema_first" {
			t.Fatalf("swagger in second request should fire schema_first, got %+v", sig)
		}
	})

	t.Run("no fire when browser UA visits Swagger UI (legitimate developer)", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now, Path: "/swagger-ui/", UserAgent: "Mozilla/5.0 Chrome/124"},
		}
		if sig := s.scoreSchemaFirst(events); sig.Points != 0 {
			t.Fatalf("browser UA on Swagger UI should not fire schema_first, got %+v", sig)
		}
	})

	t.Run("no fire when schema path is 4th or later request", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now.Add(-30 * time.Second), Path: "/api/users", UserAgent: "curl/7.84"},
			{Timestamp: now.Add(-20 * time.Second), Path: "/api/items", UserAgent: "curl/7.84"},
			{Timestamp: now.Add(-10 * time.Second), Path: "/api/orders", UserAgent: "curl/7.84"},
			{Timestamp: now, Path: "/openapi.json", UserAgent: "curl/7.84"}, // 4th
		}
		if sig := s.scoreSchemaFirst(events); sig.Points != 0 {
			t.Fatalf("schema path as 4th+ request should not fire, got %+v", sig)
		}
	})
}

// ── cache_miss_anomaly ────────────────────────────────────────────────────────

func TestCacheMissAnomalySignal(t *testing.T) {
	s, _ := newScorer()
	now := time.Now()

	t.Run("fires when same path repeated 5 times without conditional headers", func(t *testing.T) {
		events := make([]ClientEvent, 5)
		for i := range events {
			events[i] = ClientEvent{
				Timestamp:      now.Add(-time.Duration(i*10) * time.Second),
				Path:           "/api/users",
				HasConditional: false,
			}
		}
		if sig := s.scoreCacheMissAnomaly(events); sig.Name != "cache_miss_anomaly" || sig.Points != 10 {
			t.Fatalf("5 unconditional repeats should fire cache_miss_anomaly(10), got %+v", sig)
		}
	})

	t.Run("fires at 9+ repeats with higher tier", func(t *testing.T) {
		events := make([]ClientEvent, 9)
		for i := range events {
			events[i] = ClientEvent{
				Timestamp: now.Add(-time.Duration(i*5) * time.Second),
				Path:      "/api/status",
			}
		}
		if sig := s.scoreCacheMissAnomaly(events); sig.Name != "cache_miss_anomaly" || sig.Points != 20 {
			t.Fatalf("9 repeats should fire cache_miss_anomaly(20), got %+v", sig)
		}
	})

	t.Run("no fire when requests carry conditional headers (proper SPA caching)", func(t *testing.T) {
		events := make([]ClientEvent, 8)
		for i := range events {
			events[i] = ClientEvent{
				Timestamp:      now.Add(-time.Duration(i*10) * time.Second),
				Path:           "/api/feed",
				HasConditional: true, // If-None-Match set — correct cache discipline
			}
		}
		if sig := s.scoreCacheMissAnomaly(events); sig.Points != 0 {
			t.Fatalf("conditional requests should not trigger cache_miss_anomaly, got %+v", sig)
		}
	})

	t.Run("no fire when 5 repeats spread outside 3-minute burst window", func(t *testing.T) {
		// All repeated events are > 3 min before the most recent event.
		// cutoff = events[last].Timestamp - 3min = now - 3min
		// events at now - 4..8 min are before the cutoff, so not counted.
		events := []ClientEvent{
			{Timestamp: now.Add(-8 * time.Minute), Path: "/api/hot"},
			{Timestamp: now.Add(-7 * time.Minute), Path: "/api/hot"},
			{Timestamp: now.Add(-6 * time.Minute), Path: "/api/hot"},
			{Timestamp: now.Add(-5 * time.Minute), Path: "/api/hot"},
			{Timestamp: now.Add(-4 * time.Minute), Path: "/api/hot"},
			{Timestamp: now, Path: "/api/other"}, // recent, unique path
		}
		if sig := s.scoreCacheMissAnomaly(events); sig.Points != 0 {
			t.Fatalf("repeats outside 3-min window should not fire, got %+v", sig)
		}
	})

	t.Run("no fire when fewer than 5 total events", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now, Path: "/api/x"},
			{Timestamp: now.Add(-1 * time.Second), Path: "/api/x"},
			{Timestamp: now.Add(-2 * time.Second), Path: "/api/x"},
		}
		if sig := s.scoreCacheMissAnomaly(events); sig.Points != 0 {
			t.Fatalf("fewer than 5 events should skip signal, got %+v", sig)
		}
	})
}

// ── no_cookie_return ──────────────────────────────────────────────────────────

func TestNoCookieReturnSignal(t *testing.T) {
	s, _ := newScorer()

	t.Run("fires when SetCookie was served and no cookies ever returned", func(t *testing.T) {
		state := &ClientState{
			SetCookieReceived: true,
			CookiesSent:       0,
			RequestsTotal:     10,
		}
		if sig := s.scoreNoCookieReturn(state); sig.Name != "no_cookie_return" || sig.Points != 10 {
			t.Fatalf("expected no_cookie_return 10pts, got %+v", sig)
		}
	})

	t.Run("no fire when cookies are being returned", func(t *testing.T) {
		state := &ClientState{
			SetCookieReceived: true,
			CookiesSent:       3,
			RequestsTotal:     10,
		}
		if sig := s.scoreNoCookieReturn(state); sig.Points != 0 {
			t.Fatalf("client sending cookies should not fire, got %+v", sig)
		}
	})

	t.Run("no fire when fewer than 8 requests (too early to judge)", func(t *testing.T) {
		state := &ClientState{
			SetCookieReceived: true,
			CookiesSent:       0,
			RequestsTotal:     6,
		}
		if sig := s.scoreNoCookieReturn(state); sig.Points != 0 {
			t.Fatalf("should not fire with <8 total requests, got %+v", sig)
		}
	})

	t.Run("no fire when SetCookie was never served", func(t *testing.T) {
		state := &ClientState{
			SetCookieReceived: false,
			CookiesSent:       0,
			RequestsTotal:     20,
		}
		if sig := s.scoreNoCookieReturn(state); sig.Points != 0 {
			t.Fatalf("should not fire without prior Set-Cookie, got %+v", sig)
		}
	})

	t.Run("CORS guard: no fire for cross-origin SPA without credentials include", func(t *testing.T) {
		// React/Vue/Angular SPA calling a different-domain API without
		// credentials:include cannot return cookies, and the browser is correct
		// not to send them. Firing here would false-positive every SPA.
		state := &ClientState{
			SetCookieReceived:      true,
			CookiesSent:            0,
			RequestsTotal:          15,
			HasCrossOriginRequests: true, // Origin header seen
		}
		if sig := s.scoreNoCookieReturn(state); sig.Points != 0 {
			t.Fatalf("cross-origin requests should suppress no_cookie_return CORS guard failed, got %+v", sig)
		}
	})
}

// ── encoding_chain ────────────────────────────────────────────────────────────

func TestEncodingChainSignal(t *testing.T) {
	s, _ := newScorer()

	t.Run("fires for single double-encoding %2520", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/search?q=test%2520abc", nil)
		if sig := s.scoreEncodingChain(r); sig.Name != "encoding_chain" || sig.Points != 8 {
			t.Fatalf("single double-enc should give encoding_chain(8), got %+v", sig)
		}
	})

	t.Run("fires at 2+ double-encodings with higher tier", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api?a=%2520&b=%2527", nil)
		if sig := s.scoreEncodingChain(r); sig.Name != "encoding_chain" || sig.Points != 15 {
			t.Fatalf("two double-enc occurrences should give encoding_chain(15), got %+v", sig)
		}
	})

	t.Run("fires for triple URL-encoding %2525 with top tier", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/path/%2525xx", nil)
		if sig := s.scoreEncodingChain(r); sig.Name != "encoding_chain" || sig.Points != 20 {
			t.Fatalf("triple encoding should give encoding_chain(20), got %+v", sig)
		}
	})

	t.Run("no false positive for literal percent sign %25 alone", func(t *testing.T) {
		// A user searching for '50% off' legitimately produces ?q=50%25+off.
		// %25 followed by '+' is NOT double-encoding; the + is not a hex digit.
		r := httptest.NewRequest("GET", "/search?q=50%25+off", nil)
		if sig := s.scoreEncodingChain(r); sig.Points != 0 {
			t.Fatalf("literal percent sign %%25 should not fire encoding_chain, got %+v", sig)
		}
	})

	t.Run("no false positive for normal URL with no encoding", func(t *testing.T) {
		r := httptest.NewRequest("GET", "/api/v1/users?page=1&limit=20", nil)
		if sig := s.scoreEncodingChain(r); sig.Points != 0 {
			t.Fatalf("normal URL should not fire encoding_chain, got %+v", sig)
		}
	})
}

// countDoubleEnc helper unit tests

func TestCountDoubleEnc(t *testing.T) {
	cases := []struct {
		input string
		want  int
	}{
		{"/normal/path", 0},
		{"/q=%2520abc", 1},
		{"/q=%2520&r=%2527", 2},
		{"/q=50%25+off", 0},    // %25 not followed by 2 hex chars
		{"/q=50%25zz", 0},      // z is not a hex digit
		{"/q=%25201", 1},       // %2520 then 1 — only 1 match
		{"/%2525xx", 1},        // %2525 contains %25 followed by "25" (hex), so countDoubleEnc returns 1;
		// triple-encoding is caught at the scoreEncodingChain level (strings.Contains "%2525"), not here
	}
	for _, tc := range cases {
		if got := countDoubleEnc(tc.input); got != tc.want {
			t.Errorf("countDoubleEnc(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// ── auth_probe_sequence ───────────────────────────────────────────────────────

func TestAuthProbeSequenceSignal(t *testing.T) {
	s, _ := newScorer()
	now := time.Now()

	makeEvents := func(paths []string) []ClientEvent {
		evts := make([]ClientEvent, len(paths))
		for i, p := range paths {
			evts[i] = ClientEvent{
				Timestamp: now.Add(-time.Duration(len(paths)-i) * time.Second),
				Path:      p,
			}
		}
		return evts
	}

	t.Run("fires at 4+ distinct auth categories", func(t *testing.T) {
		// 10 events needed; first 4 are distinct auth categories, rest are filler
		paths := []string{
			"/login",       // label: login
			"/oauth/token", // label: oauth_token
			"/sso/saml",    // label: sso
			"/jwt/verify",  // label: jwt
			// filler to reach 10 total
			"/api/users", "/api/items", "/api/cart", "/api/orders", "/api/search", "/api/home",
		}
		if sig := s.scoreAuthProbeSequence(makeEvents(paths)); sig.Name != "auth_probe_sequence" || sig.Points != 15 {
			t.Fatalf("4 distinct auth cats should give auth_probe_sequence(15), got %+v", sig)
		}
	})

	t.Run("fires at 6+ distinct auth categories with high tier", func(t *testing.T) {
		paths := []string{
			"/login",          // login
			"/oauth/token",    // oauth_token
			"/sso/callback",   // sso
			"/jwt/token",      // jwt
			"/password/reset", // password
			"/api/session",    // api_session
			// filler
			"/api/users", "/api/items", "/api/cart", "/api/orders",
		}
		if sig := s.scoreAuthProbeSequence(makeEvents(paths)); sig.Name != "auth_probe_sequence" || sig.Points != 25 {
			t.Fatalf("6 distinct auth cats should give auth_probe_sequence(25), got %+v", sig)
		}
	})

	t.Run("no fire when fewer than 10 total requests (OAuth flow exclusion)", func(t *testing.T) {
		// Standard OAuth: /login + /auth/callback + /api/auth/token = 3 paths, 3 requests
		// Even with 4 distinct labels, we require 10+ total events to avoid FPs
		paths := []string{"/login", "/oauth/token", "/sso/cb", "/jwt/x"}
		if sig := s.scoreAuthProbeSequence(makeEvents(paths)); sig.Points != 0 {
			t.Fatalf("fewer than 10 events should not fire, got %+v", sig)
		}
	})

	t.Run("no fire when fewer than 4 distinct auth categories", func(t *testing.T) {
		paths := []string{
			"/login", "/signin", // both → "login" (same label)
			"/api/users", "/api/items", "/api/cart",
			"/api/orders", "/api/search", "/api/home", "/api/feed", "/api/profile",
		}
		if sig := s.scoreAuthProbeSequence(makeEvents(paths)); sig.Points != 0 {
			t.Fatalf("3 or fewer distinct categories should not fire, got %+v", sig)
		}
	})

	t.Run("logout path suppressed by exclude rule (not counted as auth category)", func(t *testing.T) {
		// /auth/logout should NOT match the /auth/ pattern due to Exclude:/logout
		// so it doesn't count as a distinct auth category
		paths := []string{
			"/login",        // login
			"/oauth/token",  // oauth_token
			"/auth/logout",  // EXCLUDED — should not count
			"/sso/saml",     // sso
			// filler
			"/api/a", "/api/b", "/api/c", "/api/d", "/api/e", "/api/f",
		}
		events := makeEvents(paths)
		// With the exclude rule: login, oauth_token, sso = 3 labels (not 4)
		if sig := s.scoreAuthProbeSequence(events); sig.Points != 0 {
			t.Fatalf("logout exclude rule should prevent 4th label, got %+v", sig)
		}
	})
}

// ── dynamic rules-based patterns ─────────────────────────────────────────────

func TestSchemaPathsFromRules(t *testing.T) {
	s, _ := newScorer() // loads real rules from testRulesDir

	paths := s.schemaPaths()
	if len(paths) == 0 {
		t.Fatal("schemaPaths should not be empty after rules load")
	}
	found := false
	for _, p := range paths {
		if p == "openapi" {
			found = true
		}
	}
	if !found {
		t.Fatalf("schemaPaths from rules should include 'openapi', got %v", paths)
	}
}

func TestSchemaPathsFallbackWhenNoRules(t *testing.T) {
	tr := NewTracker(90)
	sc := NewScorer(tr, nil, nil)
	// sc.rules is new(rules.Detector) — BehavioralSignals.SchemaPaths is empty
	// so schemaPaths() should fall back to defaultSchemaPaths
	paths := sc.schemaPaths()
	if len(paths) == 0 {
		t.Fatal("schemaPaths should fall back to defaults when rules not loaded")
	}
}

func TestAuthLabelFromRules(t *testing.T) {
	s, _ := newScorer() // loads real rules

	cases := []struct {
		path  string
		want  string
	}{
		{"/oauth/token", "oauth_token"},   // specific before generic
		{"/sso/saml-idp", "sso"},          // /saml/ match
		{"/auth/logout", ""},              // excluded by /logout
		{"/auth/profile", "auth_generic"}, // /auth/ without /logout
		{"/api/users", ""},                // not an auth path
		{"/login", "login"},
		{"/password/forgot", "password"},
		{"/api/session/current", "api_session"},
	}
	for _, tc := range cases {
		if got := s.authLabel(tc.path); got != tc.want {
			t.Errorf("authLabel(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// ── ML training data purity gate ─────────────────────────────────────────────

func TestMLTarpitThresholdGateObserve(t *testing.T) {
	mlCfg := &rules.ML{
		Enabled:        true,
		ScoreMaxPoints: 40,
		Alpha:          0.7,
	}
	mlCfg.Bayes.LaplaceSmoothing = 1.0

	t.Run("clean request below threshold is observed", func(t *testing.T) {
		s, _ := newScorer()
		mlS := ml.NewScorer(rules.NewHolder(mlCfg))
		s.SetML(mlS, ml.NewExtractor(), 40)
		s.SetMLTarpitThreshold(70)

		// Full browser headers → score = 0, which is below 70
		r := httptest.NewRequest("GET", "/about", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
		r.Header.Set("Sec-Fetch-Site", "none")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		s.Score("203.0.113.50", r)

		if mlS.Observed() == 0 {
			t.Fatal("clean request (score=0) should be observed for ML training")
		}
	})

	t.Run("high-scoring request at or above threshold is NOT observed", func(t *testing.T) {
		s, _ := newScorer()
		mlS := ml.NewScorer(rules.NewHolder(mlCfg))
		s.SetML(mlS, ml.NewExtractor(), 40)
		s.SetMLTarpitThreshold(70)

		// Honeypot hit (50 pts) + sqlmap UA (35 pts) = 85 pts → above threshold
		r := httptest.NewRequest("GET", "/admin-panel-v2", nil)
		r.Header.Set("User-Agent", "sqlmap/1.7.2#stable")
		s.Score("203.0.113.51", r)

		if mlS.Observed() != 0 {
			t.Fatalf("tarpitted client (score>=70) should not be observed, got Observed=%d", mlS.Observed())
		}
	})

	t.Run("threshold=0 disables gate and observes all requests", func(t *testing.T) {
		s, _ := newScorer()
		mlS := ml.NewScorer(rules.NewHolder(mlCfg))
		s.SetML(mlS, ml.NewExtractor(), 40)
		s.SetMLTarpitThreshold(0) // gate disabled

		r := httptest.NewRequest("GET", "/admin-panel-v2", nil)
		r.Header.Set("User-Agent", "sqlmap/1.7.2#stable")
		s.Score("203.0.113.52", r)

		// With no gate, high-scoring request IS observed (labeled "agent" by agentThreshold)
		if mlS.Observed() == 0 {
			t.Fatal("with threshold=0 all requests including high-scoring ones should be observed")
		}
	})
}

// ── helper unit tests ─────────────────────────────────────────────────────────

func TestMaxRepeatFetchCount(t *testing.T) {
	now := time.Now()

	t.Run("counts max same-path repeats within 3-min window", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now.Add(-30 * time.Second), Path: "/api/x"},
			{Timestamp: now.Add(-20 * time.Second), Path: "/api/x"},
			{Timestamp: now.Add(-10 * time.Second), Path: "/api/x"},
			{Timestamp: now, Path: "/api/y"},
		}
		if got := maxRepeatFetchCount(events); got != 3 {
			t.Fatalf("expected 3 repeats of /api/x, got %d", got)
		}
	})

	t.Run("excludes paths where any request carried conditional headers", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now.Add(-20 * time.Second), Path: "/api/feed", HasConditional: true},
			{Timestamp: now.Add(-10 * time.Second), Path: "/api/feed", HasConditional: false},
			{Timestamp: now.Add(-5 * time.Second), Path: "/api/feed", HasConditional: false},
			{Timestamp: now, Path: "/api/feed"},
		}
		// /api/feed has a conditional, so cond["/api/feed"] = true → excluded
		if got := maxRepeatFetchCount(events); got != 0 {
			t.Fatalf("path with conditional headers should be excluded, got %d", got)
		}
	})

	t.Run("returns 0 for empty event list", func(t *testing.T) {
		if got := maxRepeatFetchCount(nil); got != 0 {
			t.Fatalf("empty events should return 0, got %d", got)
		}
	})
}

func TestSchemaFirstScoreHelper(t *testing.T) {
	now := time.Now()
	paths := []string{"openapi", "swagger", "graphiql"}

	t.Run("returns 1.0 for non-browser hitting schema in first 3", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now, Path: "/swagger/v2", UserAgent: "curl/7.84"},
		}
		if got := schemaFirstScore(events, paths, 3); got != 1.0 {
			t.Fatalf("expected 1.0, got %v", got)
		}
	})

	t.Run("returns 0.0 for browser UA", func(t *testing.T) {
		events := []ClientEvent{
			{Timestamp: now, Path: "/openapi.json", UserAgent: "Mozilla/5.0 Chrome/124"},
		}
		if got := schemaFirstScore(events, paths, 3); got != 0.0 {
			t.Fatalf("browser UA should return 0.0, got %v", got)
		}
	})

	t.Run("returns 0.0 for empty events", func(t *testing.T) {
		if got := schemaFirstScore(nil, paths, 3); got != 0.0 {
			t.Fatalf("empty events should return 0.0, got %v", got)
		}
	})
}
