package detector

import (
	"fmt"
	"net/http"
	"strings"
)

func (s *Scorer) scoreHeaders(r *http.Request) Signal {
	hints := s.rules.BrowserHeaders.Hints
	present := 0
	for _, h := range hints {
		if r.Header.Get(h) != "" {
			present++
		}
	}
	missing := len(hints) - present

	if present > 0 && looksLikeBrowserUA(r.UserAgent()) {
		return Signal{}
	}

	for _, tier := range s.rules.BrowserHeaders.Tiers {
		if missing >= tier.Missing {
			reason := "client missing some browser headers"
			if tier.Missing >= 3 {
				reason = "client sent few browser-typical headers"
			}
			return Signal{Name: "sparse_headers", Points: tier.Points, Reason: reason}
		}
	}
	return Signal{}
}

// looksLikeBrowserUA returns true when the User-Agent contains the
// canonical token of a real browser. Case-insensitive. HeadlessChrome is
// explicitly excluded — puppeteer/playwright ship with it and it is
// strongly agent-leaning.
func looksLikeBrowserUA(ua string) bool {
	ua = strings.ToLower(ua)
	if ua == "" {
		return false
	}
	if strings.Contains(ua, "headlesschrome") {
		return false
	}
	for _, tok := range []string{"chrome/", "firefox/", "safari/", "edg/", "edge/", "opera/", "opr/"} {
		if strings.Contains(ua, tok) {
			return true
		}
	}
	return false
}

func (s *Scorer) scoreUserAgent(r *http.Request) Signal {
	ua := strings.ToLower(r.UserAgent())
	if ua == "" {
		return Signal{Name: "empty_ua", Points: s.rules.EmptyUserAgent.Points, Reason: "no User-Agent"}
	}
	for _, sub := range s.rules.SuspiciousUserAgents.Substrings {
		if strings.Contains(ua, strings.ToLower(sub)) {
			return Signal{
				Name:   "suspicious_ua",
				Points: s.rules.SuspiciousUserAgents.Points,
				Reason: "user-agent matches known tool/library: " + sub,
			}
		}
	}
	return Signal{}
}

// scoreSecFetch fires when a client claims to be a browser but sends an
// absent or incoherent Sec-Fetch-* triple.
func (s *Scorer) scoreSecFetch(r *http.Request) Signal {
	site := r.Header.Get("Sec-Fetch-Site")
	mode := r.Header.Get("Sec-Fetch-Mode")
	dest := r.Header.Get("Sec-Fetch-Dest")
	present := 0
	for _, v := range []string{site, mode, dest} {
		if v != "" {
			present++
		}
	}
	if present == 3 {
		return Signal{}
	}
	if r.Method == http.MethodGet && r.Header.Get("Referer") != "" && present > 0 {
		return Signal{}
	}
	if !looksLikeBrowserUA(r.UserAgent()) {
		return Signal{}
	}
	if present == 0 {
		return Signal{Name: "sec_fetch_absent", Points: 12,
			Reason: "claimed browser UA but no Sec-Fetch-* headers present"}
	}
	return Signal{Name: "sec_fetch_partial", Points: 6,
		Reason: "claimed browser UA but Sec-Fetch-* headers are incomplete"}
}

// scoreAcceptEncoding fires when a browser-shaped UA advertises a
// lib-shaped Accept-Encoding.
func (s *Scorer) scoreAcceptEncoding(r *http.Request) Signal {
	if !looksLikeBrowserUA(r.UserAgent()) {
		return Signal{}
	}
	v := strings.ToLower(r.Header.Get("Accept-Encoding"))
	if v == "" {
		return Signal{Name: "ae_browser_empty", Points: 12,
			Reason: "browser-shaped UA but Accept-Encoding is empty"}
	}
	if !strings.Contains(v, "br") {
		return Signal{Name: "ae_browser_no_br", Points: 8,
			Reason: "browser-shaped UA but Accept-Encoding is missing brotli"}
	}
	return Signal{}
}

// scoreH3Mismatch reads the proxy-set header for an Alt-Svc/H3 mismatch.
func (s *Scorer) scoreH3Mismatch(r *http.Request) Signal {
	if r.Header.Get("X-Veilgate-H3-Mismatch") != "1" {
		return Signal{}
	}
	if !looksLikeBrowserUA(r.UserAgent()) {
		return Signal{}
	}
	return Signal{Name: "h3_mismatch", Points: 8,
		Reason: "claimed browser UA but stayed on H1/H2 across multiple Alt-Svc hints"}
}

// scoreH2 consults the HTTP/2 SETTINGS fingerprint database.
func (s *Scorer) scoreH2(remoteAddr string) Signal {
	if s.h2 == nil {
		return Signal{}
	}
	label, category, conf, ok := s.h2.Classify(remoteAddr)
	if !ok {
		return Signal{}
	}
	switch category {
	case "agent", "scanner":
		points := 35
		if conf < 80 {
			points = 22
		}
		return Signal{Name: "h2_agent", Points: points,
			Reason: "HTTP/2 SETTINGS match known agent library: " + label}
	case "bot":
		return Signal{Name: "h2_bot", Points: 18,
			Reason: "HTTP/2 SETTINGS match known bot: " + label}
	case "unknown":
		return Signal{Name: "h2_non_browser", Points: 15,
			Reason: "HTTP/2 SETTINGS look library-shaped (no browser match)"}
	}
	return Signal{}
}

// headerBitmap builds a short identifier of which non-trivial headers a request
// carries. Lets the FleetTracker group a proxy-rotating attacker whose IP
// changes but whose client library stays the same.
func headerBitmap(r *http.Request) string {
	interesting := []string{
		"Accept", "Accept-Language", "Accept-Encoding",
		"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest",
		"Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
		"Upgrade-Insecure-Requests", "Referer", "Cookie",
		"Cache-Control", "Connection", "Pragma",
	}
	var mask uint32
	for i, h := range interesting {
		if r.Header.Get(h) != "" {
			mask |= 1 << i
		}
	}
	return fmt.Sprintf("%08x", mask)
}

// mutationBitmap tracks only headers whose presence should be constant for the
// entire session — UA hints and encoding preferences set by the browser at
// startup. Excludes headers that legitimately change during normal browsing.
func mutationBitmap(r *http.Request) string {
	stable := []string{
		"Accept-Language",
		"Accept-Encoding",
		"Sec-Ch-Ua",
		"Sec-Ch-Ua-Mobile",
		"Sec-Ch-Ua-Platform",
	}
	var mask uint32
	for i, h := range stable {
		if r.Header.Get(h) != "" {
			mask |= 1 << uint(i)
		}
	}
	return fmt.Sprintf("%02x", mask)
}
