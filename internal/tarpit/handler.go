package tarpit

import (
	"bytes"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/fakeauth"
	"github.com/C0oki3s/veilgate/internal/rules"
	"github.com/C0oki3s/veilgate/internal/telemetry"
)

// CanaryRegistrar is implemented by persist.Store. After serving a tarpit
// response the handler extracts any token-shaped strings from the body and
// registers each one so that scoreCanaryReplay can detect replays.
type CanaryRegistrar interface {
	InsertCanary(token, clientID string, ttl time.Duration) error
}

// Handler is the phase-2 shadow-app handler.
type Handler struct {
	cfg      *config.TarpitConfig
	profiles *ProfileStore
	renderer *Renderer
	injector PayloadInjector

	// Rules holders. When any of these is nil the handler falls back to
	// embedded defaults loaded at construction time.
	vuln     *rules.Holder[rules.Vulnerabilities]
	strategy *rules.Holder[rules.InjectionStrategy]
	decoys   *rules.Holder[rules.DecoyPaths]

	// Compiled regex cache for `match: regex` routes, keyed by the source
	// pattern. Invalidated on a strategy swap.
	regexMu  sync.RWMutex
	regexes  map[string]*regexp.Regexp
	stratVer *rules.InjectionStrategy

	// canaryReg receives every token we serve so the scorer can detect
	// replay later. Optional — nil disables registration (detection still
	// works for any tokens pre-seeded into the table by other means).
	canaryReg CanaryRegistrar
}

// PayloadInjector is implemented by the payloads package (phase 3).
type PayloadInjector interface {
	Inject(contentType, body string, ctx InjectionContext) string
}

type InjectionContext struct {
	Path     string
	ClientID string
	Visits   int
}

type noopInjector struct{}

func (noopInjector) Inject(_, body string, _ InjectionContext) string { return body }

// NewHandler builds a handler backed by embedded-default rules. Call
// SetRules to wire in hot-reloadable holders.
func NewHandler(cfg *config.TarpitConfig, store *ProfileStore, injector PayloadInjector) *Handler {
	if injector == nil {
		injector = noopInjector{}
	}
	vuln := new(rules.Vulnerabilities)
	strat := new(rules.InjectionStrategy)
	return &Handler{
		cfg:      cfg,
		profiles: store,
		renderer: NewRenderer(),
		injector: injector,
		vuln:     rules.NewHolder(vuln),
		strategy: rules.NewHolder(strat),
		regexes:  make(map[string]*regexp.Regexp),
	}
}

// DescribeTarpit returns the loaded decoy paths for inclusion in
// /__veilgate/.well-known. The browser SDK reads this and injects the paths
// as DOM decoys so every agent breadcrumb routes to a real tarpit response.
func (h *Handler) DescribeTarpit() rules.TarpitDescriptor {
	if h.decoys == nil {
		return rules.TarpitDescriptor{}
	}
	d := h.decoys.Load()
	if d == nil {
		return rules.TarpitDescriptor{}
	}
	return rules.TarpitDescriptor{Paths: d.Paths}
}

// SetDecoyPaths wires in the hot-reloadable decoy-paths holder.
func (h *Handler) SetDecoyPaths(holder *rules.Holder[rules.DecoyPaths]) {
	if holder != nil {
		h.decoys = holder
	}
}

// SetCanaryRegistrar wires the persist store for canary token registration.
// Call this once from main after wiring persist.Store.
func (h *Handler) SetCanaryRegistrar(r CanaryRegistrar) { h.canaryReg = r }

// SetRules wires in rule holders for hot-reload. Any nil holder is
// ignored (the handler keeps its current holder).
func (h *Handler) SetRules(
	templates *rules.Holder[rules.Templates],
	vuln *rules.Holder[rules.Vulnerabilities],
	strategy *rules.Holder[rules.InjectionStrategy],
) {
	if templates != nil {
		h.renderer.SetTemplates(templates)
	}
	if vuln != nil {
		h.vuln = vuln
	}
	if strategy != nil {
		h.strategy = strategy
		h.invalidateRegexCache()
	}
}

func (h *Handler) invalidateRegexCache() {
	h.regexMu.Lock()
	h.regexes = make(map[string]*regexp.Regexp)
	h.stratVer = nil
	h.regexMu.Unlock()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientID := clientIP(r)
	profile := h.profiles.Get(clientID)

	delay := randBetween(h.cfg.MinLatencyMs, h.cfg.MaxLatencyMs)
	time.Sleep(time.Duration(delay) * time.Millisecond)
	telemetry.TarpitLatencyMs.Add(float64(delay))

	resp := h.route(r, profile)

	resp.Body = h.injector.Inject(resp.ContentType, resp.Body, InjectionContext{
		Path:     r.URL.Path,
		ClientID: clientID,
		Visits:   profile.Visits,
	})

	if len(resp.Body) > h.cfg.MaxBodyBytes {
		resp.Body = resp.Body[:h.cfg.MaxBodyBytes]
	}

	// Register every token-shaped string in the response body so that a
	// subsequent request carrying the same token fires canary_replay.
	// Fire-and-forget in a goroutine — the hot path must not stall on DB I/O.
	if h.canaryReg != nil {
		if toks := fakeauth.ExtractCanaries(resp.Body); len(toks) > 0 {
			reg := h.canaryReg
			go func() {
				for _, tok := range toks {
					_ = reg.InsertCanary(tok, clientID, 24*time.Hour)
				}
			}()
		}
	}

	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", resp.ContentType)
	// Cross-origin clients (e.g. an SPA on a different domain) must be able
	// to read the tarpit response, otherwise the browser shows only "CORS
	// error" and the fake content never reaches the attacker.
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}
	w.WriteHeader(resp.Status)
	n, _ := w.Write([]byte(resp.Body))
	telemetry.TarpitBytesServed.Add(float64(n))

	telemetry.EstimatedAttackerCostUSD.Add(float64(n) / 1024.0 * 0.003)
}

// route consults injection_strategy.yaml's routes[] list, first match wins.
// The previously-hardcoded switch statement lives entirely in YAML now.
func (h *Handler) route(r *http.Request, p *ShadowProfile) Response {
	path := strings.ToLower(r.URL.Path)
	query := decodedQuery(r.URL.RawQuery)
	body := readSmallBody(r)
	strat := h.strategy.Load()
	vuln := h.vuln.Load()

	extra := map[string]any{
		"Path":  r.URL.Path,
		"Query": query,
		"Body":  body,
	}

	for _, rt := range strat.Routes {
		if h.routeMatches(rt, path, query, body, vuln) {
			return h.renderer.Render(rt.Template, p, extra)
		}
	}
	return h.renderer.Render("generic_not_found", p, extra)
}

func decodedQuery(raw string) string {
	if raw == "" {
		return ""
	}
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

func (h *Handler) routeMatches(rt rules.Route, path, query, body string, vuln *rules.Vulnerabilities) bool {
	haystack := path + " " + strings.ToLower(query) + " " + strings.ToLower(body)
	if vuln == nil {
		vuln = &rules.Vulnerabilities{}
	}
	switch rt.Match {
	case "exact":
		for _, v := range rt.Values {
			if path == strings.ToLower(v) {
				return true
			}
		}
	case "prefix":
		for _, v := range rt.Values {
			if strings.HasPrefix(path, strings.ToLower(v)) {
				return true
			}
		}
	case "contains":
		for _, v := range rt.Values {
			if strings.Contains(path, strings.ToLower(v)) {
				return true
			}
		}
	case "regex":
		for _, v := range rt.Values {
			if h.compileRegex(v).MatchString(path) {
				return true
			}
		}
	case "sqli":
		return hasPattern(path, vuln.SQLInjectionPatterns) ||
			hasPattern(query, vuln.SQLInjectionPatterns) ||
			hasPattern(body, vuln.SQLInjectionPatterns)
	case "list":
		// `values` is a list of list-names in vulnerabilities.yaml. Path-like
		// lists match only the path; payload-pattern lists match path+query+body.
		for _, listName := range rt.Values {
			for _, entry := range vuln.Lookup(listName) {
				if listMatches(listName, entry, path, haystack) {
					return true
				}
			}
		}
	case "any":
		return true
	}
	return false
}

func listMatches(listName, entry, path, haystack string) bool {
	needle := strings.ToLower(entry)
	if needle == "" {
		return false
	}
	switch listName {
	case "honeypot_paths", "fake_git_paths", "fake_env_paths":
		return path == needle || strings.Contains(path, needle)
	default:
		return strings.Contains(haystack, needle)
	}
}

// compileRegex returns a cached compiled regex. On strategy swap the cache
// is flushed so stale patterns don't linger.
func (h *Handler) compileRegex(pat string) *regexp.Regexp {
	cur := h.strategy.Load()
	h.regexMu.RLock()
	if h.stratVer == cur {
		if re, ok := h.regexes[pat]; ok {
			h.regexMu.RUnlock()
			return re
		}
	}
	h.regexMu.RUnlock()

	h.regexMu.Lock()
	defer h.regexMu.Unlock()
	if h.stratVer != cur {
		h.regexes = make(map[string]*regexp.Regexp)
		h.stratVer = cur
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		re = regexp.MustCompile(`$.^`) // matches nothing
	}
	h.regexes[pat] = re
	return re
}

// hasSQLInjectionPattern checks against vulnerabilities.sql_injection_patterns
// (replaces the previously-hardcoded list).
func hasSQLInjectionPattern(s string, v *rules.Vulnerabilities) bool {
	if v == nil {
		return false
	}
	return hasPattern(s, v.SQLInjectionPatterns)
}

func hasPattern(s string, patterns []string) bool {
	lower := strings.ToLower(s)
	for _, pat := range patterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true
		}
	}
	return false
}

func readSmallBody(r *http.Request) string {
	if r == nil || r.Body == nil || r.ContentLength < 0 || r.ContentLength > 64*1024 {
		return ""
	}
	body, err := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return ""
	}
	return string(body)
}

func randBetween(min, max int) int {
	if max <= min {
		return min
	}
	return min + rand.Intn(max-min)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return strings.TrimSpace(host)
	}
	return strings.TrimSpace(r.RemoteAddr)
}
