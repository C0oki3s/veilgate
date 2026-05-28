package detector

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/C0oki3s/veilgate/internal/ml"
)

func (s *Scorer) buildSessionStats(r *http.Request, state *ClientState, events []ClientEvent) ml.SessionStats {
	state.mu.Lock()
	mutations := float64(state.HeaderMutations)
	state.mu.Unlock()

	checkLimit := orDefault(s.rules.BehavioralSignals.SchemaFirst.CheckLimit, 3)
	return ml.SessionStats{
		HeaderMutations:  mutations,
		MaxRepeatFetches: float64(maxRepeatFetchCount(events)),
		DistinctAuthCats: float64(s.distinctAuthCatCount(events)),
		SchemaFirstHit:   schemaFirstScore(events, s.schemaPaths(), checkLimit),
		DoubleEncCount:   float64(doubleEncCountFromRequest(r)),
	}
}

func (s *Scorer) schemaPaths() []string {
	if s.rules != nil && len(s.rules.BehavioralSignals.SchemaPaths) > 0 {
		return s.rules.BehavioralSignals.SchemaPaths
	}
	return defaultSchemaPaths
}

var defaultSchemaPaths = []string{
	"openapi", "swagger", "api-docs", "api/docs",
	"schema.json", "graphql/schema", "graphiql",
}

// orDefault returns v if v > 0, otherwise returns def.
// Used throughout behavioral signals to apply YAML overrides with hardcoded fallbacks.
func orDefault(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func maxRepeatFetchCount(events []ClientEvent) int {
	if len(events) == 0 {
		return 0
	}
	// Window matches CacheMissAnomaly default; shared so ML session stats
	// and the scoring signal agree on the same window.
	cutoff := events[len(events)-1].Timestamp.Add(-3 * time.Minute)
	counts := make(map[string]int, len(events))
	cond := make(map[string]bool, len(events))
	for i := range events {
		if events[i].Timestamp.Before(cutoff) {
			continue
		}
		p := strings.ToLower(events[i].Path)
		counts[p]++
		if events[i].HasConditional {
			cond[p] = true
		}
	}
	max := 0
	for p, n := range counts {
		if !cond[p] && n > max {
			max = n
		}
	}
	return max
}

func (s *Scorer) distinctAuthCatCount(events []ClientEvent) int {
	if len(events) == 0 {
		return 0
	}
	// Window matches AuthProbeSequence default; shared so ML session stats
	// and the scoring signal agree on the same window.
	winMin := orDefault(s.rules.BehavioralSignals.AuthProbeSequence.WindowMinutes, 5)
	cutoff := events[len(events)-1].Timestamp.Add(-time.Duration(winMin) * time.Minute)
	seen := make(map[string]struct{}, 8)
	for i := range events {
		if events[i].Timestamp.Before(cutoff) {
			continue
		}
		if label := s.authLabel(strings.ToLower(events[i].Path)); label != "" {
			seen[label] = struct{}{}
		}
	}
	return len(seen)
}

func schemaFirstScore(events []ClientEvent, schemaPaths []string, checkLimit int) float64 {
	limit := checkLimit
	if len(events) < limit {
		limit = len(events)
	}
	for i := 0; i < limit; i++ {
		if looksLikeBrowserUA(events[i].UserAgent) {
			continue
		}
		p := strings.ToLower(events[i].Path)
		for _, pat := range schemaPaths {
			if strings.Contains(p, pat) {
				return 1.0
			}
		}
	}
	return 0.0
}

func doubleEncCountFromRequest(r *http.Request) int {
	raw := r.RequestURI
	if raw == "" {
		raw = r.URL.RequestURI()
	}
	return countDoubleEnc(strings.ToLower(raw))
}

func (s *Scorer) authLabel(p string) string {
	if s.rules != nil && len(s.rules.BehavioralSignals.AuthPathPatterns) > 0 {
		for _, ap := range s.rules.BehavioralSignals.AuthPathPatterns {
			if strings.Contains(p, strings.ToLower(ap.Pattern)) {
				if ap.Exclude != "" && strings.Contains(p, strings.ToLower(ap.Exclude)) {
					continue
				}
				return ap.Label
			}
		}
		return ""
	}
	return authPathLabel(p)
}

func gapSeconds(events []ClientEvent) float64 {
	if len(events) < 2 {
		return 0
	}
	return ml.GapSince(events[len(events)-2].Timestamp, events[len(events)-1].Timestamp, 300)
}

func extractJA4(r *http.Request) string {
	if r == nil {
		return ""
	}
	if v := r.Header.Get("X-Veilgate-JA4"); v != "" {
		return v
	}
	return ""
}

// scoreHeaderMutation fires when a client's stable-header presence bitmap
// has changed multiple times mid-session.
func (s *Scorer) scoreHeaderMutation(state *ClientState) Signal {
	cfg := s.rules.BehavioralSignals.HeaderMutation
	minReq := orDefault(cfg.MinRequests, 6)
	lowT, lowP := orDefault(cfg.LowThreshold, 5), orDefault(cfg.LowPoints, 8)
	midT, midP := orDefault(cfg.MidThreshold, 10), orDefault(cfg.MidPoints, 15)
	highT, highP := orDefault(cfg.HighThreshold, 15), orDefault(cfg.HighPoints, 25)

	state.mu.Lock()
	n := state.HeaderMutations
	total := state.RequestsTotal
	state.mu.Unlock()
	if total < minReq {
		return Signal{}
	}
	switch {
	case n >= highT:
		return Signal{Name: "header_mutation", Points: highP,
			Reason: fmt.Sprintf("stable-header set changed %d times mid-session (agent tool-call boundary)", n)}
	case n >= midT:
		return Signal{Name: "header_mutation", Points: midP,
			Reason: fmt.Sprintf("stable-header set changed %d times mid-session", n)}
	case n >= lowT:
		return Signal{Name: "header_mutation", Points: lowP,
			Reason: fmt.Sprintf("stable-header set changed %d times mid-session", n)}
	}
	return Signal{}
}

// scoreSchemaFirst fires when a non-browser client's earliest requests
// targeted API schema endpoints.
func (s *Scorer) scoreSchemaFirst(events []ClientEvent) Signal {
	if len(events) < 1 {
		return Signal{}
	}
	cfg := s.rules.BehavioralSignals.SchemaFirst
	checkLimit := orDefault(cfg.CheckLimit, 3)
	points := orDefault(cfg.Points, 20)

	limit := checkLimit
	if len(events) < limit {
		limit = len(events)
	}
	for i := 0; i < limit; i++ {
		if looksLikeBrowserUA(events[i].UserAgent) {
			continue
		}
		p := strings.ToLower(events[i].Path)
		for _, pat := range s.schemaPaths() {
			if strings.Contains(p, pat) {
				return Signal{Name: "schema_first", Points: points,
					Reason: "non-browser client's first requests targeted API schema — agent recon"}
			}
		}
	}
	return Signal{}
}

// scoreCacheMissAnomaly fires when the same path is requested many times
// within a short burst and none of those requests carried conditional headers.
func (s *Scorer) scoreCacheMissAnomaly(events []ClientEvent) Signal {
	cfg := s.rules.BehavioralSignals.CacheMissAnomaly
	minEvt := orDefault(cfg.MinEvents, 5)
	winMin := orDefault(cfg.WindowMinutes, 3)
	lowT, lowP := orDefault(cfg.LowThreshold, 5), orDefault(cfg.LowPoints, 10)
	highT, highP := orDefault(cfg.HighThreshold, 9), orDefault(cfg.HighPoints, 20)

	if len(events) < minEvt {
		return Signal{}
	}
	cutoff := events[len(events)-1].Timestamp.Add(-time.Duration(winMin) * time.Minute)
	type pathStat struct {
		count       int
		conditional int
	}
	stats := make(map[string]*pathStat, len(events))
	for i := range events {
		if events[i].Timestamp.Before(cutoff) {
			continue
		}
		p := strings.ToLower(events[i].Path)
		ps := stats[p]
		if ps == nil {
			ps = &pathStat{}
			stats[p] = ps
		}
		ps.count++
		if events[i].HasConditional {
			ps.conditional++
		}
	}
	maxCount := 0
	var hotPath string
	for p, ps := range stats {
		if ps.conditional == 0 && ps.count > maxCount {
			maxCount = ps.count
			hotPath = p
		}
	}
	switch {
	case maxCount >= highT:
		return Signal{Name: "cache_miss_anomaly", Points: highP,
			Reason: fmt.Sprintf("path %s fetched %d times in %d min with no conditional headers — agent burst re-poll", hotPath, maxCount, winMin)}
	case maxCount >= lowT:
		return Signal{Name: "cache_miss_anomaly", Points: lowP,
			Reason: fmt.Sprintf("path %s fetched %d times in %d min with no conditional headers", hotPath, maxCount, winMin)}
	}
	return Signal{}
}

// scoreNoCookieReturn fires when the tarpit has served a Set-Cookie but the
// client never sent it back.
func (s *Scorer) scoreNoCookieReturn(state *ClientState) Signal {
	cfg := s.rules.BehavioralSignals.NoCookieReturn
	minReq := orDefault(cfg.MinRequests, 8)
	points := orDefault(cfg.Points, 10)

	state.mu.Lock()
	setCookie := state.SetCookieReceived
	cookiesSent := state.CookiesSent
	total := state.RequestsTotal
	crossOrigin := state.HasCrossOriginRequests
	state.mu.Unlock()
	if !setCookie || total < minReq {
		return Signal{}
	}
	if crossOrigin {
		return Signal{}
	}
	if cookiesSent == 0 {
		return Signal{Name: "no_cookie_return", Points: points,
			Reason: "tarpit served Set-Cookie but client never returned any Cookie header — stateless agent"}
	}
	return Signal{}
}

// scoreEncodingChain detects double or triple URL-encoding.
func (s *Scorer) scoreEncodingChain(r *http.Request) Signal {
	cfg := s.rules.BehavioralSignals.EncodingChain
	singleP := orDefault(cfg.SinglePoints, 8)
	multiP := orDefault(cfg.MultiPoints, 15)
	tripleP := orDefault(cfg.TriplePoints, 20)

	raw := r.RequestURI
	if raw == "" {
		raw = r.URL.RequestURI()
	}
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "%2525") {
		return Signal{Name: "encoding_chain", Points: tripleP,
			Reason: "request uses triple URL-encoding — WAF evasion attempt"}
	}
	n := countDoubleEnc(lower)
	switch {
	case n >= 2:
		return Signal{Name: "encoding_chain", Points: multiP,
			Reason: fmt.Sprintf("request uses double URL-encoding (%d occurrences) — payload obfuscation", n)}
	case n == 1:
		return Signal{Name: "encoding_chain", Points: singleP,
			Reason: "request uses double URL-encoding — possible WAF bypass attempt"}
	}
	return Signal{}
}

func countDoubleEnc(s string) int {
	n := 0
	for i := 0; i+4 < len(s); i++ {
		if s[i] == '%' && s[i+1] == '2' && s[i+2] == '5' && isHexByte(s[i+3]) && isHexByte(s[i+4]) {
			n++
			i += 4
		}
	}
	return n
}

func isHexByte(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

// scoreAuthProbeSequence fires when a client hits many distinct auth endpoint
// categories within the configured window.
func (s *Scorer) scoreAuthProbeSequence(events []ClientEvent) Signal {
	cfg := s.rules.BehavioralSignals.AuthProbeSequence
	minEvt := orDefault(cfg.MinEvents, 10)
	winMin := orDefault(cfg.WindowMinutes, 5)
	lowT, lowP := orDefault(cfg.LowThreshold, 4), orDefault(cfg.LowPoints, 15)
	highT, highP := orDefault(cfg.HighThreshold, 6), orDefault(cfg.HighPoints, 25)

	if len(events) < minEvt {
		return Signal{}
	}
	cutoff := events[len(events)-1].Timestamp.Add(-time.Duration(winMin) * time.Minute)
	seen := make(map[string]struct{}, 8)
	for i := range events {
		if events[i].Timestamp.Before(cutoff) {
			continue
		}
		p := strings.ToLower(events[i].Path)
		if label := s.authLabel(p); label != "" {
			seen[label] = struct{}{}
		}
	}
	distinct := len(seen)
	switch {
	case distinct >= highT:
		return Signal{Name: "auth_probe_sequence", Points: highP,
			Reason: fmt.Sprintf("probed %d distinct auth endpoint categories in %d min — agent auth scanning", distinct, winMin)}
	case distinct >= lowT:
		return Signal{Name: "auth_probe_sequence", Points: lowP,
			Reason: fmt.Sprintf("probed %d distinct auth endpoint categories in %d min", distinct, winMin)}
	}
	return Signal{}
}

// authPathLabel returns a short category label for known auth paths.
func authPathLabel(p string) string {
	switch {
	case strings.Contains(p, "/login") || strings.Contains(p, "/signin"):
		return "login"
	case strings.Contains(p, "/oauth/token") || strings.Contains(p, "/oauth2/token"):
		return "oauth_token"
	case strings.Contains(p, "/auth/token") || strings.Contains(p, "/api/token"):
		return "auth_token"
	case strings.Contains(p, "/auth/") && !strings.Contains(p, "/logout"):
		return "auth_generic"
	case strings.Contains(p, "/jwt/") || strings.Contains(p, "/jwt"):
		return "jwt"
	case strings.Contains(p, "/sso/") || strings.Contains(p, "/saml/"):
		return "sso"
	case strings.Contains(p, "/password") || strings.Contains(p, "/credentials"):
		return "password"
	case strings.Contains(p, "/session") && strings.Contains(p, "/api/"):
		return "api_session"
	}
	return ""
}
