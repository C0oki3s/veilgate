package detector

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/C0oki3s/veilgate/internal/blueprint"
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
	// mlTarpitThreshold gates which requests contribute to ML training.
	// Requests scoring at or above this value were served tarpit responses
	// (synthetic fake content). Their subsequent interactions should NOT
	// train the "human" class — the agent is reacting to deception, not
	// behaving normally. Set to cfg.Detector.ScoreTarpitThreshold at boot.
	mlTarpitThreshold int

	// signals is the operator-loaded signal registry from signals.yaml.
	// nil means all built-in signals are enabled with their config.yaml default
	// points, and no custom signals are defined.
	signals *rules.Signals
	// customRegexes caches compiled path_regex conditions keyed by the raw
	// regex string so we don't recompile on every request.
	customRegexes map[string]*regexp.Regexp

	// blueprint is the operator-supplied API route map. nil disables the
	// api_blueprint_miss signal. Set via SetBlueprint; safe to update at runtime.
	bp *blueprint.Matcher
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

// SetMLTarpitThreshold sets the minimum rule-based score at which ML training
// is suppressed. Requests at or above this score were served tarpit responses;
// their subsequent traffic is reacting to deception, not behaving naturally,
// so including it in training would contaminate the human class.
// Call at boot with cfg.Detector.ScoreTarpitThreshold.
func (s *Scorer) SetMLTarpitThreshold(threshold int) {
	s.mlTarpitThreshold = threshold
}

// SetSignals installs a signal registry loaded from signals.yaml. It controls
// which built-in signals are enabled, overrides their point weights, and
// adds operator-defined custom signals. Safe to call at any time; passing nil
// is a no-op. Precompiles path_regex conditions for zero-alloc hot-path use.
func (s *Scorer) SetSignals(sg *rules.Signals) {
	if sg == nil {
		return
	}
	s.signals = sg
	regs := make(map[string]*regexp.Regexp)
	for _, cs := range sg.CustomSignals {
		for _, cond := range cs.Conditions {
			if cond.Type == "path_regex" && cond.Value != "" {
				if _, already := regs[cond.Value]; !already {
					if re, err := regexp.Compile(cond.Value); err == nil {
						regs[cond.Value] = re
					}
				}
			}
		}
	}
	s.customRegexes = regs
}

// SetBlueprint wires an operator-supplied API route map. Passing nil disables
// the api_blueprint_miss signal. Safe to call at any time (hot-reload).
func (s *Scorer) SetBlueprint(m *blueprint.Matcher) {
	s.bp = m
}

// Score evaluates the given request in the context of the client's history.
func (s *Scorer) Score(clientID string, r *http.Request) Score {
	if _, ok := s.trustedIPs[clientID]; ok {
		return Score{Total: 0, Signals: []Signal{{Name: "trusted_ip", Points: 0, Reason: "allowlisted"}}}
	}

	evt := ClientEvent{
		Timestamp:      time.Now(),
		Path:           r.URL.Path,
		Query:          r.URL.RawQuery,
		Method:         r.Method,
		UserAgent:      r.UserAgent(),
		SecFetchDest:   r.Header.Get("Sec-Fetch-Dest"),
		HasCookie:      r.Header.Get("Cookie") != "",
		ToolStage:      classifyToolStage(r, s.rules),
		HeaderBitmap:   mutationBitmap(r),
		HasConditional: r.Header.Get("If-None-Match") != "" || r.Header.Get("If-Modified-Since") != "",
		HasOriginHeader: r.Header.Get("Origin") != "",
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

	// Behavioural signals validated against real agent logs.
	if sig := s.scoreHeaderMutation(state); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreSchemaFirst(events); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreCacheMissAnomaly(events); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreNoCookieReturn(state); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreEncodingChain(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}
	if sig := s.scoreAuthProbeSequence(events); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// Operator-defined custom signals from signals.yaml.
	result.Signals = append(result.Signals, s.scoreCustomSignals(r)...)

	// Blueprint miss — request is in the API namespace but not a known route.
	if sig := s.scoreAPIBlueprintMiss(r); sig.Points > 0 {
		result.Signals = append(result.Signals, sig)
	}

	// Canary replay — strongest cross-request signal we have.
	if s.canary != nil {
		if sig := s.scoreCanaryReplay(clientID, r); sig.Points > 0 {
			result.Signals = append(result.Signals, sig)
		}
	}

	// ML signal — computed over the per-request + session feature vector.
	// Session stats are derived from the same events + state the rule-based
	// signals already inspected, so there is no additional tracker access here.
	var mlVec ml.Vec
	if s.mlScorer != nil && s.mlExtractor != nil {
		sess := s.buildSessionStats(r, state, events)
		mlVec = s.mlExtractor.ExtractWithSession(r, gapSeconds(events), extractJA4(r), sess)
		if res := s.mlScorer.Score(mlVec); res.Fired {
			result.Signals = append(result.Signals, Signal{
				Name:   "ml_agent_score",
				Points: res.Points,
				Reason: res.Reason,
			})
		}
	}

	// Apply signal registry: disable signals the operator turned off and
	// substitute any point overrides from signals.yaml.
	if s.signals != nil {
		result.Signals = s.applySignalConfig(result.Signals)
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

	// Weak-label training: feed this observation into the online learner ONLY
	// when the client's score is below the tarpit threshold. Tarpitted clients
	// receive synthetic fake responses; their subsequent requests are reacting
	// to deception and must not train the "human" class. Observe-mode and
	// real-traffic (score == 0) remain clean training signal.
	if s.mlScorer != nil && len(mlVec.Categorical) > 0 {
		if s.mlTarpitThreshold <= 0 || total < s.mlTarpitThreshold {
			s.mlScorer.Observe(mlVec, total, s.agentThreshold)
		}
	}

	return result
}
