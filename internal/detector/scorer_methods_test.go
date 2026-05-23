package detector

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/C0oki3s/veilgate/internal/fakeauth"
	"github.com/C0oki3s/veilgate/internal/rules"
)

type staticLookup struct {
	label      string
	category   string
	confidence int
	ok         bool
}

func (l staticLookup) Classify(string) (string, string, int, bool) {
	return l.label, l.category, l.confidence, l.ok
}

type canaryLookup map[string]string

func (c canaryLookup) HitCanary(token, clientID string) (string, bool) {
	orig, ok := c[token]
	return orig, ok
}

func TestTLSAndH2Signals(t *testing.T) {
	cases := []struct {
		name     string
		lookup   staticLookup
		tlsName  string
		h2Name   string
		tlsPoint int
		h2Point  int
	}{
		{
			name:     "known agent high confidence",
			lookup:   staticLookup{label: "python-httpx", category: "agent", confidence: 95, ok: true},
			tlsName:  "tls_agent",
			h2Name:   "h2_agent",
			tlsPoint: 45,
			h2Point:  35,
		},
		{
			name:     "known scanner low confidence",
			lookup:   staticLookup{label: "sqlmap", category: "scanner", confidence: 70, ok: true},
			tlsName:  "tls_agent",
			h2Name:   "h2_agent",
			tlsPoint: 30,
			h2Point:  22,
		},
		{
			name:     "known bot",
			lookup:   staticLookup{label: "crawler", category: "bot", confidence: 90, ok: true},
			tlsName:  "tls_bot",
			h2Name:   "h2_bot",
			tlsPoint: 25,
			h2Point:  18,
		},
		{
			name:     "unknown non browser",
			lookup:   staticLookup{label: "unknown", category: "unknown", confidence: 50, ok: true},
			tlsName:  "tls_non_browser",
			h2Name:   "h2_non_browser",
			tlsPoint: 20,
			h2Point:  15,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newScorer()
			s.SetTLSLookup(tc.lookup)
			s.SetH2Lookup(tc.lookup)
			if sig := s.scoreTLS("1.2.3.4:443"); sig.Name != tc.tlsName || sig.Points != tc.tlsPoint {
				t.Fatalf("scoreTLS = %+v", sig)
			}
			if sig := s.scoreH2("1.2.3.4:443"); sig.Name != tc.h2Name || sig.Points != tc.h2Point {
				t.Fatalf("scoreH2 = %+v", sig)
			}
		})
	}
}

func TestTLSAndH2NoSignalWhenLookupMisses(t *testing.T) {
	s, _ := newScorer()
	s.SetTLSLookup(staticLookup{})
	s.SetH2Lookup(staticLookup{})
	if sig := s.scoreTLS("missing"); sig.Points != 0 {
		t.Fatalf("expected empty TLS signal, got %+v", sig)
	}
	if sig := s.scoreH2("missing"); sig.Points != 0 {
		t.Fatalf("expected empty H2 signal, got %+v", sig)
	}
}

func TestBrowserCoherenceSignals(t *testing.T) {
	s, _ := newScorer()
	browserUA := "Mozilla/5.0 AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"

	t.Run("sec fetch absent", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("User-Agent", browserUA)
		if sig := s.scoreSecFetch(r); sig.Name != "sec_fetch_absent" {
			t.Fatalf("expected sec_fetch_absent, got %+v", sig)
		}
	})

	t.Run("sec fetch partial", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("User-Agent", browserUA)
		r.Header.Set("Sec-Fetch-Site", "none")
		if sig := s.scoreSecFetch(r); sig.Name != "sec_fetch_partial" {
			t.Fatalf("expected sec_fetch_partial, got %+v", sig)
		}
	})

	t.Run("subresource partial allowed", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/app.js", nil)
		r.Header.Set("User-Agent", browserUA)
		r.Header.Set("Referer", "https://example.test/")
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		if sig := s.scoreSecFetch(r); sig.Points != 0 {
			t.Fatalf("subresource fetch should not score, got %+v", sig)
		}
	})

	t.Run("accept encoding empty and no br", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("User-Agent", browserUA)
		if sig := s.scoreAcceptEncoding(r); sig.Name != "ae_browser_empty" {
			t.Fatalf("expected ae_browser_empty, got %+v", sig)
		}
		r.Header.Set("Accept-Encoding", "gzip, deflate")
		if sig := s.scoreAcceptEncoding(r); sig.Name != "ae_browser_no_br" {
			t.Fatalf("expected ae_browser_no_br, got %+v", sig)
		}
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
		if sig := s.scoreAcceptEncoding(r); sig.Points != 0 {
			t.Fatalf("complete browser encoding should not score, got %+v", sig)
		}
	})

	t.Run("h3 mismatch only for browser UA", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Veilgate-H3-Mismatch", "1")
		r.Header.Set("User-Agent", browserUA)
		if sig := s.scoreH3Mismatch(r); sig.Name != "h3_mismatch" {
			t.Fatalf("expected h3_mismatch, got %+v", sig)
		}
		r.Header.Set("User-Agent", "python-requests/2.31")
		if sig := s.scoreH3Mismatch(r); sig.Points != 0 {
			t.Fatalf("library UA should not get h3 mismatch, got %+v", sig)
		}
	})
}

func TestStatefulBehaviorSignals(t *testing.T) {
	s, tr := newScorer()

	t.Run("request graph flat", func(t *testing.T) {
		state := &ClientState{RequestsTotal: 9, DocumentFetches: 9}
		if sig := s.scoreRequestGraph(state); sig.Name != "graph_flat" {
			t.Fatalf("expected graph_flat, got %+v", sig)
		}
	})

	t.Run("request graph document heavy", func(t *testing.T) {
		state := &ClientState{RequestsTotal: 12, DocumentFetches: 9, SubresourceFetches: 2}
		if sig := s.scoreRequestGraph(state); sig.Name != "graph_doc_heavy" {
			t.Fatalf("expected graph_doc_heavy, got %+v", sig)
		}
	})

	t.Run("cookie ecology stateless", func(t *testing.T) {
		state := &ClientState{RequestsTotal: 10}
		if sig := s.scoreCookieEcology(state); sig.Name != "cookie_stateless" {
			t.Fatalf("expected cookie_stateless, got %+v", sig)
		}
		state.CookiesSent = 1
		if sig := s.scoreCookieEcology(state); sig.Points != 0 {
			t.Fatalf("cookie sender should not score, got %+v", sig)
		}
	})

	t.Run("fanout high and extreme", func(t *testing.T) {
		state := &ClientState{}
		for i := 0; i < 65; i++ {
			state.Events = append(state.Events, ClientEvent{
				Timestamp: time.Now(),
				Path:      "/p/" + itoaInt(i),
			})
		}
		if sig := s.scoreFanout(state); sig.Name != "fanout_high" {
			t.Fatalf("expected fanout_high, got %+v", sig)
		}
		state.Events = state.Events[:0]
		for i := 0; i < 205; i++ {
			state.Events = append(state.Events, ClientEvent{
				Timestamp: time.Now(),
				Path:      "/x/" + itoaInt(i),
			})
		}
		if sig := s.scoreFanout(state); sig.Name != "fanout_extreme" {
			t.Fatalf("expected fanout_extreme, got %+v", sig)
		}
	})

	t.Run("failure recovery pivot", func(t *testing.T) {
		state := &ClientState{LastStatus: 404, LastNon200Path: "/missing", LastNon200Method: http.MethodGet}
		same := httptest.NewRequest(http.MethodGet, "/missing", nil)
		if sig := s.scoreFailureRecovery(state, same); sig.Points != 0 {
			t.Fatalf("same-shape retry should not score, got %+v", sig)
		}
		pivot := httptest.NewRequest(http.MethodPost, "/login", nil)
		if sig := s.scoreFailureRecovery(state, pivot); sig.Name != "recovery_pivot" {
			t.Fatalf("expected recovery_pivot, got %+v", sig)
		}
	})

	t.Run("score observes graph and cookie state", func(t *testing.T) {
		client := "198.51.100.77"
		for i := 0; i < 10; i++ {
			r := httptest.NewRequest(http.MethodGet, "/doc/"+itoaInt(i), nil)
			r.Header.Set("User-Agent", "Mozilla/5.0 Chrome/124")
			r.Header.Set("Accept-Encoding", "gzip, deflate, br")
			r.Header.Set("Sec-Fetch-Site", "none")
			r.Header.Set("Sec-Fetch-Mode", "navigate")
			r.Header.Set("Sec-Fetch-Dest", "document")
			_ = s.Score(client, r)
		}
		state := tr.Get(client)
		if state == nil || state.RequestsTotal != 10 || state.DocumentFetches != 10 {
			t.Fatalf("tracker state not updated as expected: %+v", state)
		}
	})
}

func TestToolchainHMMAndStageClassification(t *testing.T) {
	s, _ := newScorer()
	events := []ClientEvent{
		{ToolStage: "recon"},
		{ToolStage: "recon"},
		{ToolStage: "probe"},
		{ToolStage: "probe"},
		{ToolStage: "exploit"},
	}
	if sig := s.scoreToolchainHMM(events); sig.Name != "toolchain_hmm" {
		t.Fatalf("expected full HMM signal, got %+v", sig)
	}
	if sig := s.scoreToolchainHMM([]ClientEvent{
		{ToolStage: "probe"}, {ToolStage: "probe"}, {ToolStage: "exploit"}, {ToolStage: ""}, {ToolStage: ""},
	}); sig.Name != "toolchain_hmm_partial" || sig.Points != 12 {
		t.Fatalf("expected probe->exploit partial, got %+v", sig)
	}

	recon := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
	probe := httptest.NewRequest(http.MethodGet, "/admin", nil)
	exploit := httptest.NewRequest(http.MethodGet, "/search?q=union%20select", nil)
	if got := classifyToolStage(recon, s.rules); got != "recon" {
		t.Fatalf("recon stage = %q", got)
	}
	if got := classifyToolStage(probe, s.rules); got != "probe" {
		t.Fatalf("probe stage = %q", got)
	}
	if got := classifyToolStage(exploit, s.rules); got != "exploit" {
		t.Fatalf("exploit stage = %q", got)
	}
}

func TestCanaryReplaySignalsAndCandidates(t *testing.T) {
	s, _ := newScorer()
	s.SetCanaryLookup(canaryLookup{
		"same-token":  "10.0.0.1",
		"cross-token": "10.0.0.9",
	})

	r := httptest.NewRequest(http.MethodGet, "/anything?token=same-token", nil)
	if sig := s.scoreCanaryReplay("10.0.0.1", r); sig.Name != "canary_replay" || sig.Points != 50 {
		t.Fatalf("expected same-client replay, got %+v", sig)
	}

	r = httptest.NewRequest(http.MethodGet, "/anything", nil)
	r.Header.Set("Authorization", "Bearer cross-token")
	if sig := s.scoreCanaryReplay("10.0.0.2", r); sig.Name != "canary_replay" || sig.Points != 60 {
		t.Fatalf("expected cross-client replay, got %+v", sig)
	}

	r = httptest.NewRequest(http.MethodGet, "/last/path-token?api_key=query-token", nil)
	r.Header.Set("X-Api-Key", "header-key")
	r.AddCookie(&http.Cookie{Name: "session", Value: "cookie-token"})
	candidates := strings.Join(canaryCandidates(r), "|")
	for _, want := range []string{"header-key", "cookie-token", "path-token", "query-token"} {
		if !strings.Contains(candidates, want) {
			t.Fatalf("candidate %q missing from %q", want, candidates)
		}
	}

	bodyToken := fakeauth.JWTAdminGeneric(42)
	r = httptest.NewRequest(http.MethodPost, "/api/auth/login", strings.NewReader(`{"token":"`+bodyToken+`"}`))
	r.Header.Set("Content-Type", "application/json")
	candidates = strings.Join(canaryCandidates(r), "|")
	if !strings.Contains(candidates, bodyToken) {
		t.Fatalf("body token candidate missing from %q", candidates)
	}
	if r.Body == nil {
		t.Fatal("request body was not restored")
	}
}

func TestIPHelpersFleetAndHeaderIdentity(t *testing.T) {
	s, _ := newScorer()
	ir := &rules.IPReputation{}
	_, cloudNet, _ := net.ParseCIDR("203.0.113.0/24")
	_, privateNet, _ := net.ParseCIDR("10.0.0.0/8")
	ir.Categories = []rules.IPReputationCategory{{
		Name:   "test_cloud",
		Points: 17,
		Parsed: []*net.IPNet{cloudNet},
	}}
	ir.ParsedPrivate = []*net.IPNet{privateNet}
	ir.FleetRotation.Enabled = true
	ir.FleetRotation.WindowSeconds = 60
	ir.FleetRotation.MaxFingerprints = 100
	ir.FleetRotation.Tiers = []rules.IPReputationRotationTier{{DistinctIPs: 2, Points: 11}}
	s.SetIPReputation(ir)

	if cat, pts, ok := s.ClassifyIP("203.0.113.7"); !ok || cat != "test_cloud" || pts != 17 {
		t.Fatalf("ClassifyIP mismatch: %q %d %v", cat, pts, ok)
	}
	if s.IsPublicIP("10.1.2.3") {
		t.Fatal("private IP should not be public")
	}
	if !s.IsPublicIP("198.51.100.10") {
		t.Fatal("non-private IP should be public under configured private CIDRs")
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("User-Agent", "python-requests/2.31")
	r.Header.Set("Accept", "*/*")
	sig, fp, distinct := s.scoreFleetRotation("203.0.113.1", r, "t13d1517h2_aaaaaaaaaaaa")
	if sig.Points != 0 || fp == "" || distinct != 1 {
		t.Fatalf("first fleet member should not fire: sig=%+v fp=%q distinct=%d", sig, fp, distinct)
	}
	sig, _, distinct = s.scoreFleetRotation("203.0.113.2", r, "t13d1517h2_aaaaaaaaaaaa")
	if sig.Name != "ip_rotation_fleet" || sig.Points != 11 || distinct != 2 {
		t.Fatalf("second fleet member should fire: sig=%+v distinct=%d", sig, distinct)
	}

	if headerBitmap(r) == headerBitmap(httptest.NewRequest(http.MethodGet, "/", nil)) {
		t.Fatal("header bitmap should differ when interesting headers are present")
	}
	if got := UAFamilyFromUA("MyTool/1.0 Custom-Agent"); got != "custom_mytool" {
		t.Fatalf("fallback UA family = %q", got)
	}
}

func TestLooksLikeBrowserUAAndJA4Extraction(t *testing.T) {
	if looksLikeBrowserUA("HeadlessChrome/124") {
		t.Fatal("headless chrome should be excluded from browser-like UA")
	}
	if !looksLikeBrowserUA("Mozilla/5.0 Firefox/125") {
		t.Fatal("Firefox token should look browser-like")
	}
	if extractJA4(nil) != "" {
		t.Fatal("nil request should not produce JA4")
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Veilgate-JA4", "t13d1517h2_abc_def")
	if got := extractJA4(r); got != "t13d1517h2_abc_def" {
		t.Fatalf("extractJA4 = %q", got)
	}
}
