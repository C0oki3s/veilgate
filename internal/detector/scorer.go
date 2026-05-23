package detector

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/C0oki3s/veilgate/internal/fakeauth"
	"github.com/C0oki3s/veilgate/internal/ml"
	"github.com/C0oki3s/veilgate/internal/rules"
)

// Signal represents one detection signal's contribution to the total score.
type Signal struct {
	Name   string
	Points int
	Reason string
}

// Score is the full scoring result for a request.
type Score struct {
	Total   int
	Signals []Signal
}

// Scorer combines signals into a total 0-100 score.
type Scorer struct {
	tracker       *Tracker
	fleet         *FleetTracker
	honeypotPaths map[string]struct{}
	trustedIPs    map[string]struct{}
	tls           TLSLookup // optional, nil disables TLS signal
	h2            TLSLookup // optional, h2fp.Classifier satisfies the same shape
	canary        CanaryLookup
	rules         *rules.Detector
	ipRep         *rules.IPReputation

	// Optional ML signal. Nil disables; everything downstream treats the
	// ml_agent_score signal as just another additive input.
	mlScorer    *ml.Scorer
	mlExtractor *ml.Extractor
	// agentThreshold is used for weak-label training in Observe. Mirrors
	// cfg.Detector.ScoreChallengeThreshold so the label boundary matches
	// the operator's "enough evidence to challenge" line.
	agentThreshold int
}

// CanaryLookup is what the cross-request canary signal calls on every
// request. Implemented by persist.Store; nil disables the signal.
type CanaryLookup interface {
	// HitCanary reports whether token is one of our previously-served
	// tarpit canaries. When true, the second return value is the
	// client originally served the canary — same client = replay,
	// different client = leaked credential reuse.
	HitCanary(token, clientID string) (origClientID string, hit bool)
}

// SetH2Lookup wires an HTTP/2 SETTINGS-fingerprint classifier. The
// concrete type is internal/h2fp.Classifier, but we accept the same
// TLSLookup interface to keep the wiring symmetric and avoid an import
// cycle.
func (s *Scorer) SetH2Lookup(l TLSLookup) { s.h2 = l }

// SetCanaryLookup wires a canary table (typically backed by the
// persist.Store). Safe to leave nil.
func (s *Scorer) SetCanaryLookup(l CanaryLookup) { s.canary = l }

// NewScorer builds a scorer with the embedded default rule set.
// Call SetRules to override with a user-supplied rule file.
func NewScorer(t *Tracker, honeypots, trusted []string) *Scorer {
	hp := make(map[string]struct{}, len(honeypots))
	for _, p := range honeypots {
		hp[p] = struct{}{}
	}
	tr := make(map[string]struct{}, len(trusted))
	for _, ip := range trusted {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue // ignore blank entries so an accidental `- ""` in YAML doesn't allowlist empty clientIDs
		}
		tr[ip] = struct{}{}
	}
	d := new(rules.Detector)
	ip := new(rules.IPReputation)
	window := 600
	maxFP := 20000
	if ip != nil {
		if ip.FleetRotation.WindowSeconds > 0 {
			window = ip.FleetRotation.WindowSeconds
		}
		if ip.FleetRotation.MaxFingerprints > 0 {
			maxFP = ip.FleetRotation.MaxFingerprints
		}
	}
	return &Scorer{
		tracker:       t,
		fleet:         NewFleetTracker(window, maxFP),
		honeypotPaths: hp,
		trustedIPs:    tr,
		rules:         d,
		ipRep:         ip,
	}
}

// SetRules swaps in a rule set loaded from an external file.
func (s *Scorer) SetRules(r *rules.Detector) {
	if r != nil {
		s.rules = r
	}
}

// SetIPReputation swaps in a new IP-reputation / rotation rule set.
// Safe to call at any time; passing nil is a no-op.
func (s *Scorer) SetIPReputation(r *rules.IPReputation) {
	if r == nil {
		return
	}
	s.ipRep = r
	// If the operator resized the fleet window on reload, rebuild the
	// tracker. We accept losing in-flight fingerprint state in exchange
	// for the new window taking effect immediately.
	if s.fleet != nil && r.FleetRotation.WindowSeconds > 0 {
		newWindow := time.Duration(r.FleetRotation.WindowSeconds) * time.Second
		if newWindow != s.fleet.window {
			s.fleet = NewFleetTracker(r.FleetRotation.WindowSeconds, r.FleetRotation.MaxFingerprints)
		}
	}
}

// FleetSnapshot exposes the current fingerprint → distinct-IP map so
// a metrics exporter goroutine can publish summary gauges.
func (s *Scorer) FleetSnapshot() map[string]int {
	if s.fleet == nil {
		return nil
	}
	return s.fleet.Snapshot()
}

// FleetGC prunes fingerprints idle beyond maxIdle. Call from the
// existing GC goroutine alongside tracker.GC.
func (s *Scorer) FleetGC(maxIdle time.Duration) {
	if s.fleet != nil {
		s.fleet.GC(maxIdle)
	}
}

// ClassifyIP returns the IP reputation category for a client IP, or
// ("", 0, false) if the IP doesn't match any known category.
func (s *Scorer) ClassifyIP(clientID string) (string, int, bool) {
	if s.ipRep == nil {
		return "", 0, false
	}
	return s.ipRep.Classify(clientID)
}

// IsPublicIP returns true when the client IP is routable (not in any
// private_cidrs range from ip_reputation.yaml).
func (s *Scorer) IsPublicIP(clientID string) bool {
	if s.ipRep == nil {
		return false
	}
	return s.ipRep.IsPublicIP(clientID)
}

// SetML installs the online ML signal. Safe to call at any time; passing
// nil disables the signal. agentThreshold is the rule-based score at or
// above which a sample is weak-labeled "agent" for online training.
func (s *Scorer) SetML(m *ml.Scorer, e *ml.Extractor, agentThreshold int) {
	s.mlScorer = m
	s.mlExtractor = e
	s.agentThreshold = agentThreshold
}

// Score evaluates the given request in the context of the client's history.
func (s *Scorer) Score(clientID string, r *http.Request) Score {
	if _, ok := s.trustedIPs[clientID]; ok {
		return Score{Total: 0, Signals: []Signal{{Name: "trusted_ip", Points: 0, Reason: "allowlisted"}}}
	}

	evt := ClientEvent{
		Timestamp:    time.Now(),
		Path:         r.URL.Path,
		Query:        r.URL.RawQuery,
		Method:       r.Method,
		UserAgent:    r.UserAgent(),
		SecFetchDest: r.Header.Get("Sec-Fetch-Dest"),
		HasCookie:    r.Header.Get("Cookie") != "",
		ToolStage:    classifyToolStage(r, s.rules),
	}
	state := s.tracker.Record(clientID, evt)

	var result Score

	// Honeypot hit — highest-confidence single signal.
	if _, hit := s.honeypotPaths[r.URL.Path]; hit {
		state.mu.Lock()
		state.HoneypotHits++
		hits := state.HoneypotHits
		state.mu.Unlock()
		points := 50
		if hits > 1 {
			points = 80
		}
		result.Signals = append(result.Signals, Signal{
			Name: "honeypot_hit", Points: points,
			Reason: "requested path in honeypot list",
		})
	}

	// Header-based signals
	if sig := s.scoreHeaders(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreUserAgent(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// History-based signals (need multiple requests)
	state.mu.Lock()
	events := append([]ClientEvent(nil), state.Events...)
	state.mu.Unlock()

	if sig := s.scoreTiming(events); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreToolchain(events); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scorePathBruteforce(events); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreWordlistPath(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreInjection(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreOOB(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// IP-reputation: is the client IP inside a known bad CIDR
	// (Tor/cloud/VPN/anonymizer)? Stateless, so no tracker dependency.
	if sig, cat := s.scoreIPReputation(clientID); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
		_ = cat // exported to proxy-level metrics via sig.Reason parsing — kept here for future labelled metrics
	}

	// IP-rotation fleet detector: does this request share a behavioural
	// fingerprint with N distinct client IPs inside the window?
	if sig, fp, distinct := s.scoreFleetRotation(clientID, r, extractJA4(r)); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
		_, _ = fp, distinct // available to callers/metrics if they want them later
	}

	// UA-rotation: one client IP cycled through too many User-Agents.
	if sig := s.scoreUARotation(state); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// TLS fingerprint signal (if wired)
	if s.tls != nil {
		if sig := s.scoreTLS(r.RemoteAddr); sig.Points > 0 {
			result.Signals = append(result.Signals, sig)
		}
	}

	// HTTP/2 SETTINGS fingerprint — same wiring as TLS.
	if s.h2 != nil {
		if sig := s.scoreH2(r.RemoteAddr); sig.Points > 0 {
			result.Signals = append(result.Signals, sig)
		}
	}

	// Sec-Fetch-* coherence: a client claiming to be a browser but
	// emitting an "absent"/"incoherent" Sec-Fetch triple is library-shaped.
	if sig := s.scoreSecFetch(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// Accept-Encoding posture: browsers always advertise gzip+deflate+br.
	if sig := s.scoreAcceptEncoding(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// HTTP/3 capability mismatch (set by the proxy when applicable).
	if sig := s.scoreH3Mismatch(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// Cross-request behavioural signals derived from per-client state.
	if sig := s.scoreRequestGraph(state); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreCookieEcology(state); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreFanout(state); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreFailureRecovery(state, r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreToolchainHMM(events); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// Bundle-mining: JS asset fetch followed by rapid /api/* probing.
	if sig := s.scoreBundleMining(state); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// Canary replay — strongest cross-request signal we have.
	if s.canary != nil {
		if sig := s.scoreCanaryReplay(clientID, r); sig.Points > 0 {
			result.Signals = append(result.Signals, sig)
		}
	}

	// ML signal — computed over the per-request feature vector. Added
	// before summing so the total includes the learned score.
	var mlVec ml.Vec
	if s.mlScorer != nil && s.mlExtractor != nil {
		mlVec = s.mlExtractor.Extract(r, gapSeconds(events), extractJA4(r))
		if res := s.mlScorer.Score(mlVec); res.Fired {
			result.Signals = append(result.Signals, Signal{
				Name:   "ml_agent_score",
				Points: res.Points,
				Reason: res.Reason,
			})
		}
	}

	total := 0
	for _, sig := range result.Signals {
		total += sig.Points
	}
	if total > 100 {
		total = 100
	}
	result.Total = total

	state.mu.Lock()
	state.Score = total
	state.mu.Unlock()

	// Weak-label training: feed this observation into the online learner.
	// Done after the final total is computed so the label reflects every
	// rule-based signal that fired.
	if s.mlScorer != nil && len(mlVec.Categorical) > 0 {
		s.mlScorer.Observe(mlVec, total, s.agentThreshold)
	}

	return result
}

// gapSeconds returns seconds between the last two events in the history,
// clamped to [0, 300] to keep the isolation forest's numeric feature
// scale sane.
func gapSeconds(events []ClientEvent) float64 {
	if len(events) < 2 {
		return 0
	}
	return ml.GapSince(events[len(events)-2].Timestamp, events[len(events)-1].Timestamp, 300)
}

// extractJA4 pulls a JA4 value from the request if an upstream component
// stored one on the context. We keep it opt-in to avoid depending on a
// specific context key type.
func extractJA4(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Header.Get("X-Veilgate-JA4"); v != "" {
		return v
	}
	return ""
}

func (s *Scorer) scoreHeaders(r *http.Request) Signal {
	hints := s.rules.BrowserHeaders.Hints
	present := 0
	for _, h := range hints {
		if r.Header.Get(h) != "" {
			present++
		}
	}
	missing := len(hints) - present

	// A real browser asset fetch (CSS / JS / image) can legitimately
	// omit Sec-Fetch-* — the spec lets UAs skip the headers on
	// no-cors subresource loads. So if the UA *looks like* a real
	// browser (Chrome / Firefox / Safari / Edge) AND at least one
	// browser-ish hint is present, we don't flag sparse headers. This
	// kills the "legit page load scores 14-20 pts just from subresource
	// fetches" false positive.
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
// canonical token of a real browser. Case-insensitive. We keep the
// list tight — only tokens a scanner would have to actively spoof to
// hit this path, and in that case suspicious_ua / TLS signals take over.
func looksLikeBrowserUA(ua string) bool {
	ua = strings.ToLower(ua)
	if ua == "" {
		return false
	}
	// HeadlessChrome is explicitly excluded — puppeteer / playwright
	// ship with it and it is strongly agent-leaning.
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

// scoreTiming detects suspiciously regular inter-request intervals.
// LLM agents tend to produce 2-8 second gaps with low variance.
func (s *Scorer) scoreTiming(events []ClientEvent) Signal {
	t := s.rules.Timing
	if len(events) < t.MinEvents {
		return Signal{}
	}
	gaps := make([]float64, 0, len(events)-1)
	for i := 1; i < len(events); i++ {
		d := events[i].Timestamp.Sub(events[i-1].Timestamp).Seconds()
		if d > 0 && d < 60 {
			gaps = append(gaps, d)
		}
	}
	if len(gaps) < t.MinEvents-1 {
		return Signal{}
	}

	mean := 0.0
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))

	variance := 0.0
	for _, g := range gaps {
		variance += (g - mean) * (g - mean)
	}
	variance /= float64(len(gaps))
	cv := math.Sqrt(variance) / mean

	if mean >= t.MinMeanSeconds && mean <= t.MaxMeanSeconds && cv < t.StrictCVMax {
		return Signal{Name: "regular_timing", Points: t.StrictPoints,
			Reason: "request gaps are suspiciously regular (LLM-paced)"}
	}
	if mean >= t.MinMeanSeconds && mean <= t.MaxMeanSeconds && cv < t.LooseCVMax {
		return Signal{Name: "regular_timing", Points: t.LoosePoints,
			Reason: "request gaps show moderate regularity"}
	}
	return Signal{}
}

// scoreTLS consults the TLS fingerprint database.
// Known-agent hashes are the single strongest signal in the system (45 points).
// A "non-browser-looking" JA4 prefix with no match is moderate (20 points).
func (s *Scorer) scoreTLS(remoteAddr string) Signal {
	if s.tls == nil {
		return Signal{}
	}
	label, category, conf, ok := s.tls.Classify(remoteAddr)
	if !ok {
		return Signal{}
	}
	switch category {
	case "agent", "scanner":
		points := 45
		if conf < 80 {
			points = 30
		}
		return Signal{Name: "tls_agent", Points: points,
			Reason: "TLS fingerprint matches known agent library: " + label}
	case "bot":
		return Signal{Name: "tls_bot", Points: 25,
			Reason: "TLS fingerprint matches known bot: " + label}
	case "unknown":
		return Signal{Name: "tls_non_browser", Points: 20,
			Reason: "TLS fingerprint does not match any known browser"}
	}
	return Signal{}
}

// scoreToolchain flags classic scanner sequences: recon → probe → exploit.
func (s *Scorer) scoreToolchain(events []ClientEvent) Signal {
	tc := s.rules.Toolchain
	if len(events) < 4 {
		return Signal{}
	}
	sawRecon, sawProbe, sawExploit := false, false, false
	for _, e := range events {
		// Scan both the path and the raw query: exploit markers almost always
		// land in the query string (e.g. `/search?q=' or 1=1--`), not the path.
		p := strings.ToLower(e.Path + "?" + e.Query)
		for _, r := range tc.ReconPaths {
			if strings.Contains(p, r) {
				sawRecon = true
			}
		}
		for _, pr := range tc.ProbePaths {
			if strings.Contains(p, pr) {
				sawProbe = true
			}
		}
		for _, ex := range tc.ExploitMarkers {
			if strings.Contains(p, ex) {
				sawExploit = true
			}
		}
	}
	stages := 0
	for _, b := range []bool{sawRecon, sawProbe, sawExploit} {
		if b {
			stages++
		}
	}
	switch stages {
	case 3:
		return Signal{Name: "toolchain_full", Points: tc.Points.Full,
			Reason: "observed recon + probe + exploit sequence"}
	case 2:
		return Signal{Name: "toolchain_partial", Points: tc.Points.Partial,
			Reason: "observed two pentest stages"}
	}
	return Signal{}
}

// scorePathBruteforce detects one client rapidly walking a wordlist.
// Counts distinct paths in the tracker's window; dirsearch/ffuf/feroxbuster
// look like nothing else when they rotate UAs but keep hitting the wordlist.
// Tiers are defined descending in rules/detector.yaml; first match wins.
func (s *Scorer) scorePathBruteforce(events []ClientEvent) Signal {
	tiers := s.rules.PathBruteforce.Tiers
	if len(tiers) == 0 || len(events) < 2 {
		return Signal{}
	}
	seen := make(map[string]struct{}, len(events))
	for _, e := range events {
		seen[e.Path] = struct{}{}
	}
	distinct := len(seen)
	for _, tier := range tiers {
		if distinct >= tier.DistinctPaths {
			return Signal{
				Name:   "path_bruteforce",
				Points: tier.Points,
				Reason: fmt.Sprintf("client hit %d distinct paths inside the window (wordlist bruteforce)", distinct),
			}
		}
	}
	return Signal{}
}

// scoreWordlistPath matches the request path against known dirsearch / nikto
// wordlist markers. Case-insensitive substring match; one hit scores once.
func (s *Scorer) scoreWordlistPath(r *http.Request) Signal {
	cfg := s.rules.WordlistPaths
	if cfg.Points == 0 || len(cfg.Substrings) == 0 {
		return Signal{}
	}
	path := strings.ToLower(r.URL.Path)
	for _, sub := range cfg.Substrings {
		if strings.Contains(path, strings.ToLower(sub)) {
			return Signal{
				Name:   "wordlist_path",
				Points: cfg.Points,
				Reason: "path matches known scanner wordlist entry: " + sub,
			}
		}
	}
	return Signal{}
}

// scoreInjection looks for attack payload markers in the URL (path + query)
// and in request headers listed under injection_markers.headers in the YAML.
// One hit scores once; the first hit wins so we report the most specific
// reason rather than a long laundry list.
func (s *Scorer) scoreInjection(r *http.Request) Signal {
	cfg := s.rules.InjectionMarkers
	if cfg.Points == 0 || len(cfg.Substrings) == 0 {
		return Signal{}
	}
	haystacks := []string{
		strings.ToLower(r.URL.Path),
		strings.ToLower(r.URL.RawQuery),
	}
	if r.Body != nil && (r.ContentLength >= 0 && r.ContentLength <= 64*1024) {
		body, err := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err == nil && len(body) > 0 {
			haystacks = append(haystacks, strings.ToLower(string(body)))
		}
	}
	if len(cfg.Headers) == 0 {
		for _, vs := range r.Header {
			for _, v := range vs {
				haystacks = append(haystacks, strings.ToLower(v))
			}
		}
	} else {
		for _, h := range cfg.Headers {
			if v := r.Header.Get(h); v != "" {
				haystacks = append(haystacks, strings.ToLower(v))
			}
		}
		// Host isn't in r.Header — fetch it explicitly if requested.
		for _, h := range cfg.Headers {
			if strings.EqualFold(h, "Host") && r.Host != "" {
				haystacks = append(haystacks, strings.ToLower(r.Host))
			}
		}
	}
	for _, sub := range cfg.Substrings {
		needle := strings.ToLower(sub)
		for _, h := range haystacks {
			if strings.Contains(h, needle) {
				return Signal{
					Name:   "injection_marker",
					Points: cfg.Points,
					Reason: "request contains attack payload marker: " + sub,
				}
			}
		}
	}
	return Signal{}
}

// scoreIPReputation tags the client IP against the operator-editable
// CIDR list in rules/ip_reputation.yaml. Returns the category name as
// the second return value so the proxy layer can emit a labelled
// Prometheus counter without re-classifying.
func (s *Scorer) scoreIPReputation(clientID string) (Signal, string) {
	if s.ipRep == nil {
		return Signal{}, ""
	}
	cat, pts, ok := s.ipRep.Classify(clientID)
	if !ok || pts <= 0 {
		return Signal{}, ""
	}
	return Signal{
		Name:   "ip_reputation",
		Points: pts,
		Reason: "client IP matches " + cat + " CIDR list",
	}, cat
}

// scoreFleetRotation observes the current request's behavioural
// fingerprint and returns a signal when N distinct IPs have shared that
// fingerprint inside the rolling window. The fingerprint deliberately
// excludes the client IP so a rotating attacker collapses to one entry.
func (s *Scorer) scoreFleetRotation(clientID string, r *http.Request, ja4 string) (Signal, string, int) {
	if s.fleet == nil || s.ipRep == nil || !s.ipRep.FleetRotation.Enabled {
		return Signal{}, "", 0
	}
	tiers := s.ipRep.FleetRotation.Tiers
	if len(tiers) == 0 {
		return Signal{}, "", 0
	}
	uaFam := UAFamilyFromUA(r.UserAgent())
	ja4p := ja4
	if len(ja4p) > 10 {
		ja4p = ja4p[:10]
	}
	hdr := headerBitmap(r)
	fp, distinct := s.fleet.Observe(clientID, uaFam, ja4p, hdr, r.Method, time.Now())
	// Tiers are listed descending (highest threshold first) in YAML; first match wins.
	for _, tier := range tiers {
		if distinct >= tier.DistinctIPs {
			return Signal{
				Name:   "ip_rotation_fleet",
				Points: tier.Points,
				Reason: fmt.Sprintf("%d distinct client IPs share fingerprint %s (ua=%s ja4=%s) — proxy/VPN rotation", distinct, fp, uaFam, ja4p),
			}, fp, distinct
		}
	}
	return Signal{}, fp, distinct
}

// scoreUARotation fires when one client IP has sent requests under N+
// distinct User-Agent strings inside the tracker's window. That's the
// canonical dirsearch / ffuf-with-UA-pool signature; a real browser
// never changes its UA inside a single session.
func (s *Scorer) scoreUARotation(state *ClientState) Signal {
	if s.ipRep == nil || !s.ipRep.UARotation.Enabled {
		return Signal{}
	}
	threshold := s.ipRep.UARotation.DistinctUAsForFire
	if threshold < 2 {
		return Signal{}
	}
	state.mu.Lock()
	distinct := len(state.UniqueUAs)
	state.mu.Unlock()
	if distinct < threshold {
		return Signal{}
	}
	return Signal{
		Name:   "ua_rotation",
		Points: s.ipRep.UARotation.Points,
		Reason: fmt.Sprintf("client sent %d distinct User-Agents inside the window — UA pool rotation", distinct),
	}
}

// headerBitmap builds a short, stable identifier of "which non-trivial
// headers did this request carry". Two requests with the same header
// set return the same bitmap, which lets the FleetTracker group a
// proxy-rotating attacker whose IP changes but whose client library
// stays the same.
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
	// 8 hex chars is plenty for a 32-bit mask and keeps the fingerprint short.
	return fmt.Sprintf("%08x", mask)
}

// classifyToolStage tags one request as belonging to the recon / probe
// / exploit phase of a typical pentest pipeline, or "" when no marker
// matches. Reuses the same path lists the toolchain signal already
// consumes — the difference is that classifyToolStage emits a label
// per request so downstream signals can reason about the *sequence*
// (HMM-lite over the visit), not just the set.
func classifyToolStage(r *http.Request, d *rules.Detector) string {
	if d == nil {
		return ""
	}
	hay := strings.ToLower(r.URL.Path + "?" + r.URL.RawQuery)
	for _, ex := range d.Toolchain.ExploitMarkers {
		if strings.Contains(hay, strings.ToLower(ex)) {
			return "exploit"
		}
	}
	for _, p := range d.Toolchain.ProbePaths {
		if strings.Contains(hay, strings.ToLower(p)) {
			return "probe"
		}
	}
	for _, p := range d.Toolchain.ReconPaths {
		if strings.Contains(hay, strings.ToLower(p)) {
			return "recon"
		}
	}
	return ""
}

// scoreH2 consults the HTTP/2 SETTINGS fingerprint database. Same shape
// as scoreTLS — agent/scanner is the strongest match, "minimal_h2" is
// the catch-all unknown-but-non-browser bucket.
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

// scoreSecFetch fires when a client claims to be a browser
// (UA-token-wise) but sends an absent or incoherent Sec-Fetch-* triple.
// Browsers since 2020 emit the triple consistently on top-level
// navigation and main-document fetches; libraries don't.
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
	// All three present + browser-shaped UA → consistent. No signal.
	if present == 3 {
		return Signal{}
	}
	// A subresource fetch (same-origin) can legitimately omit some
	// Sec-Fetch headers depending on the destination; don't flag those.
	if r.Method == http.MethodGet && r.Header.Get("Referer") != "" && present > 0 {
		return Signal{}
	}
	if !looksLikeBrowserUA(r.UserAgent()) {
		// Library UA won't have Sec-Fetch — that's caught by sparse_headers,
		// not here. Avoid double-charging.
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
// libshaped Accept-Encoding (empty, identity-only, or gzip-only). Real
// Chromium/Firefox/Safari always advertise gzip + deflate + br at
// minimum; Chrome 113+ adds zstd.
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

// scoreH3Mismatch reads the proxy-set header for an Alt-Svc/H3 mismatch
// — a client that claims to be a full browser but never upgraded to H3
// despite repeated hints. The proxy decides when to set the header;
// this scorer just attaches points if it's there.
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

// scoreRequestGraph compares the ratio of subresource fetches (image,
// script, style, font, …) to document fetches per client. Real browsers
// produce a tree-shaped traffic pattern — one document fetch followed
// by O(10) subresource fetches; agents tend toward a flat list of
// independent document-shaped fetches.
func (s *Scorer) scoreRequestGraph(state *ClientState) Signal {
	state.mu.Lock()
	docs := state.DocumentFetches
	subs := state.SubresourceFetches
	total := state.RequestsTotal
	state.mu.Unlock()
	// Need enough samples and at least one document fetch to reason
	// about the ratio at all.
	if total < 8 || docs < 1 {
		return Signal{}
	}
	if subs == 0 {
		return Signal{Name: "graph_flat", Points: 10,
			Reason: "many requests but zero subresource fetches (agent topology)"}
	}
	if subs*4 < docs {
		return Signal{Name: "graph_doc_heavy", Points: 6,
			Reason: "document fetches dominate subresource fetches (crawler topology)"}
	}
	return Signal{}
}

// scoreCookieEcology fires when a client makes many requests without
// ever sending a Cookie. Real browsers accumulate cookies over a
// session; stateless agents and many libs don't.
func (s *Scorer) scoreCookieEcology(state *ClientState) Signal {
	state.mu.Lock()
	total := state.RequestsTotal
	sent := state.CookiesSent
	state.mu.Unlock()
	if total < 10 {
		return Signal{}
	}
	if sent == 0 {
		return Signal{Name: "cookie_stateless", Points: 8,
			Reason: "many requests with no Cookie header (agent / lib pattern)"}
	}
	return Signal{}
}

// scoreFanout flags clients whose distinct-path-per-minute rate looks
// scanner-shaped. Distinct from scorePathBruteforce, which counts
// distinct paths in the *whole* tracker window — fan-out is a finer
// rate signal that fires before bruteforce thresholds saturate.
func (s *Scorer) scoreFanout(state *ClientState) Signal {
	state.mu.Lock()
	defer state.mu.Unlock()
	if len(state.Events) < 30 {
		return Signal{}
	}
	cutoff := time.Now().Add(-1 * time.Minute)
	seen := make(map[string]struct{}, len(state.Events))
	for i := len(state.Events) - 1; i >= 0; i-- {
		if state.Events[i].Timestamp.Before(cutoff) {
			break
		}
		seen[state.Events[i].Path] = struct{}{}
	}
	distinct := len(seen)
	switch {
	case distinct >= 200:
		return Signal{Name: "fanout_extreme", Points: 30,
			Reason: fmt.Sprintf("%d distinct paths in last 60s (scanner)", distinct)}
	case distinct >= 60:
		return Signal{Name: "fanout_high", Points: 15,
			Reason: fmt.Sprintf("%d distinct paths in last 60s", distinct)}
	}
	return Signal{}
}

// scoreFailureRecovery fires when the immediately-preceding request
// returned 4xx and the *next* request from the same client is a
// shape-change retry — different path or different method — rather
// than a same-shape retry-with-credentials. LLM agents often pivot
// after a 401/403 in a way real users don't.
func (s *Scorer) scoreFailureRecovery(state *ClientState, r *http.Request) Signal {
	state.mu.Lock()
	last := state.LastStatus
	lastPath := state.LastNon200Path
	lastMethod := state.LastNon200Method
	state.mu.Unlock()
	if last < 400 || lastPath == "" {
		return Signal{}
	}
	// Same shape — that's the human pattern; ignore.
	if r.URL.Path == lastPath && strings.EqualFold(r.Method, lastMethod) {
		return Signal{}
	}
	// Different shape after a 4xx. Worth a small bump; pairs with the
	// stronger toolchain HMM signal that catches the wider sequence.
	return Signal{Name: "recovery_pivot", Points: 6,
		Reason: "request shape changed after a 4xx — agent-style failure pivot"}
}

// scoreToolchainHMM scores the ordered sequence of (recon, probe,
// exploit) labels across the rolling event history. The original
// scoreToolchain signal looks at the *set* of stages; this one rewards
// the canonical *order*, which is the strongest per-client tell.
func (s *Scorer) scoreToolchainHMM(events []ClientEvent) Signal {
	if len(events) < 5 {
		return Signal{}
	}
	// Build the compressed stage sequence: collapse consecutive duplicates.
	var seq []string
	for _, e := range events {
		if e.ToolStage == "" {
			continue
		}
		if len(seq) > 0 && seq[len(seq)-1] == e.ToolStage {
			continue
		}
		seq = append(seq, e.ToolStage)
	}
	if len(seq) < 2 {
		return Signal{}
	}
	// Look for the canonical "recon → probe → exploit" subsequence.
	idx := 0
	want := []string{"recon", "probe", "exploit"}
	for _, st := range seq {
		if st == want[idx] {
			idx++
			if idx == len(want) {
				return Signal{Name: "toolchain_hmm", Points: 20,
					Reason: "observed ordered recon→probe→exploit pattern across visits"}
			}
		}
	}
	// Two-stage ordered subsequence — weaker but still informative.
	for i := 0; i+1 < len(seq); i++ {
		if seq[i] == "recon" && seq[i+1] == "probe" {
			return Signal{Name: "toolchain_hmm_partial", Points: 8,
				Reason: "observed ordered recon→probe pattern"}
		}
		if seq[i] == "probe" && seq[i+1] == "exploit" {
			return Signal{Name: "toolchain_hmm_partial", Points: 12,
				Reason: "observed ordered probe→exploit pattern"}
		}
	}
	return Signal{}
}

// scoreCanaryReplay scans the request for any token previously served
// from the tarpit. A hit is near-perfect proof of agent: a real user
// would never see the canary, let alone reuse it.
//
// Tokens may live in the path, the query string, the Authorization
// header, or any cookie — agents that scrape "credentials" out of a
// tarpit response typically try them in one of those locations next.
func (s *Scorer) scoreCanaryReplay(clientID string, r *http.Request) Signal {
	if s.canary == nil {
		return Signal{}
	}
	candidates := canaryCandidates(r)
	for _, tok := range candidates {
		if tok == "" {
			continue
		}
		if orig, hit := s.canary.HitCanary(tok, clientID); hit {
			points := 50
			reason := "request reused a tarpit canary token (LLM-leaked credential)"
			if orig != "" && orig != clientID {
				points = 60
				reason = "canary served to a different client was replayed here (cross-client leak)"
			}
			return Signal{Name: "canary_replay", Points: points, Reason: reason}
		}
	}
	return Signal{}
}

// scoreBundleMining fires when a client fetched a JavaScript asset and
// then issued several /api/* requests within 60 seconds without any
// intervening HTML document navigation. This is the canonical
// "LLM agent downloaded the SPA bundle, ran js-beautify + grep to
// extract API routes, then began probing them" pattern observed in
// automated pentesting runs (e.g. demo-veilgate-dev_2b03).
// Real users open the SPA which makes the API calls for them; they
// never independently probe the API surface immediately after fetching
// the bundle with a raw HTTP client.
func (s *Scorer) scoreBundleMining(state *ClientState) Signal {
	state.mu.Lock()
	defer state.mu.Unlock()
	if state.LastJSAssetAt.IsZero() {
		return Signal{}
	}
	since := time.Since(state.LastJSAssetAt)
	if since > 60*time.Second {
		return Signal{}
	}
	// Count distinct /api/* paths hit since the JS bundle was fetched,
	// excluding subresource fetches the SPA itself would generate.
	apiHits := 0
	seen := make(map[string]struct{}, 8)
	for _, e := range state.Events {
		if e.Timestamp.Before(state.LastJSAssetAt) {
			continue
		}
		if !strings.HasPrefix(e.Path, "/api/") {
			continue
		}
		if _, dup := seen[e.Path]; dup {
			continue
		}
		seen[e.Path] = struct{}{}
		apiHits++
	}
	switch {
	case apiHits >= 12:
		return Signal{Name: "bundle_mining", Points: 30,
			Reason: fmt.Sprintf("%d distinct /api/ paths probed within %ds of JS bundle fetch (agent recon)", apiHits, int(since.Seconds()))}
	case apiHits >= 6:
		return Signal{Name: "bundle_mining", Points: 20,
			Reason: fmt.Sprintf("%d distinct /api/ paths probed within %ds of JS bundle fetch", apiHits, int(since.Seconds()))}
	case apiHits >= 3:
		return Signal{Name: "bundle_mining", Points: 10,
			Reason: fmt.Sprintf("%d /api/ requests within %ds of JS bundle fetch", apiHits, int(since.Seconds()))}
	}
	return Signal{}
}

// canaryCandidates extracts the strings we want to test against the
// canary table. Conservative — we don't want to fire on legitimate
// short tokens that collide with canary values.
func canaryCandidates(r *http.Request) []string {
	out := make([]string, 0, 8)
	// Authorization: Bearer <token>
	if a := r.Header.Get("Authorization"); a != "" {
		if i := strings.IndexByte(a, ' '); i > 0 && i+1 < len(a) {
			out = append(out, strings.TrimSpace(a[i+1:]))
		} else {
			out = append(out, strings.TrimSpace(a))
		}
	}
	// X-API-Key style headers commonly used by tarpit decoys.
	for _, h := range []string{"X-Api-Key", "X-Api-Token", "X-Auth-Token"} {
		if v := r.Header.Get(h); v != "" {
			out = append(out, strings.TrimSpace(v))
		}
	}
	// Cookies — try each value individually.
	for _, c := range r.Cookies() {
		if c.Value != "" {
			out = append(out, c.Value)
		}
	}
	// Last segment of path and any "token=" / "key=" query value.
	if p := r.URL.Path; p != "" {
		if i := strings.LastIndexByte(p, '/'); i >= 0 && i+1 < len(p) {
			out = append(out, p[i+1:])
		}
	}
	if q := r.URL.Query(); q != nil {
		for _, name := range []string{"token", "api_key", "apikey", "key", "auth", "session"} {
			if v := q.Get(name); v != "" {
				out = append(out, v)
			}
		}
	}
	// JSON/form bodies are where auth scanners often replay leaked JWTs:
	// {"token":"..."}, {"apiKey":"..."}, {"password":"..."}.
	// Only inspect small bodies and always restore r.Body so upstream proxying
	// and ML extraction still see the original bytes.
	if r.Body != nil && (r.ContentLength >= 0 && r.ContentLength <= 64*1024) {
		body, err := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err == nil && len(body) > 0 {
			out = append(out, fakeauth.ExtractCanaries(string(body))...)
		}
	}
	return out
}

// scoreOOB flags out-of-band callback hosts used by Burp Collaborator,
// interactsh, webhook.site, etc. These almost never appear in legit traffic.
func (s *Scorer) scoreOOB(r *http.Request) Signal {
	cfg := s.rules.OOBInteraction
	if cfg.Points == 0 || len(cfg.Substrings) == 0 {
		return Signal{}
	}
	candidates := []string{
		strings.ToLower(r.URL.Path),
		strings.ToLower(r.URL.RawQuery),
		strings.ToLower(r.Host),
	}
	for _, vs := range r.Header {
		for _, v := range vs {
			candidates = append(candidates, strings.ToLower(v))
		}
	}
	for _, sub := range cfg.Substrings {
		needle := strings.ToLower(sub)
		for _, h := range candidates {
			if strings.Contains(h, needle) {
				return Signal{
					Name:   "oob_interaction",
					Points: cfg.Points,
					Reason: "request references OOB callback host: " + sub,
				}
			}
		}
	}
	return Signal{}
}
