package detector

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/C0oki3s/veilgate/internal/fakeauth"
)

// scoreRequestGraph compares the ratio of subresource fetches to document
// fetches per client.
func (s *Scorer) scoreRequestGraph(state *ClientState) Signal {
	state.mu.Lock()
	docs := state.DocumentFetches
	subs := state.SubresourceFetches
	total := state.RequestsTotal
	state.mu.Unlock()
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

// scoreCookieEcology fires when a client makes many requests without ever
// sending a Cookie.
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
// scanner-shaped.
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

// scoreFailureRecovery fires when the preceding request returned 4xx and the
// next request is a shape-change retry.
func (s *Scorer) scoreFailureRecovery(state *ClientState, r *http.Request) Signal {
	state.mu.Lock()
	last := state.LastStatus
	lastPath := state.LastNon200Path
	lastMethod := state.LastNon200Method
	state.mu.Unlock()
	if last < 400 || lastPath == "" {
		return Signal{}
	}
	if r.URL.Path == lastPath && strings.EqualFold(r.Method, lastMethod) {
		return Signal{}
	}
	return Signal{Name: "recovery_pivot", Points: 6,
		Reason: "request shape changed after a 4xx — agent-style failure pivot"}
}

// scoreBundleMining fires when a client fetched a JavaScript asset and then
// issued several /api/* requests within 60 seconds.
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

// scoreCanaryReplay scans the request for any token previously served from
// the tarpit.
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

// canaryCandidates extracts strings to test against the canary table.
func canaryCandidates(r *http.Request) []string {
	out := make([]string, 0, 8)
	if a := r.Header.Get("Authorization"); a != "" {
		if i := strings.IndexByte(a, ' '); i > 0 && i+1 < len(a) {
			out = append(out, strings.TrimSpace(a[i+1:]))
		} else {
			out = append(out, strings.TrimSpace(a))
		}
	}
	for _, h := range []string{"X-Api-Key", "X-Api-Token", "X-Auth-Token"} {
		if v := r.Header.Get(h); v != "" {
			out = append(out, strings.TrimSpace(v))
		}
	}
	for _, c := range r.Cookies() {
		if c.Value != "" {
			out = append(out, c.Value)
		}
	}
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
	if r.Body != nil && (r.ContentLength >= 0 && r.ContentLength <= 64*1024) {
		body, err := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if err == nil && len(body) > 0 {
			out = append(out, fakeauth.ExtractCanaries(string(body))...)
		}
	}
	return out
}
