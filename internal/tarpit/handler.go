package tarpit

import (
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/rules"
	"github.com/C0oki3s/veilgate/internal/telemetry"
)

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

	// Compiled regex cache for `match: regex` routes, keyed by the source
	// pattern. Invalidated on a strategy swap.
	regexMu  sync.RWMutex
	regexes  map[string]*regexp.Regexp
	stratVer *rules.InjectionStrategy
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
	vuln, _ := rules.LoadVulnerabilities("")
	strat, _ := rules.LoadInjectionStrategy("")
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

	for k, v := range resp.Headers {
		w.Header().Set(k, v)
	}
	w.Header().Set("Content-Type", resp.ContentType)
	w.WriteHeader(resp.Status)
	n, _ := w.Write([]byte(resp.Body))
	telemetry.TarpitBytesServed.Add(float64(n))

	telemetry.EstimatedAttackerCostUSD.Add(float64(n) / 1024.0 * 0.003)
}

// route consults injection_strategy.yaml's routes[] list, first match wins.
// The previously-hardcoded switch statement lives entirely in YAML now.
func (h *Handler) route(r *http.Request, p *ShadowProfile) Response {
	path := strings.ToLower(r.URL.Path)
	query := r.URL.RawQuery
	strat := h.strategy.Load()
	vuln := h.vuln.Load()

	extra := map[string]any{
		"Path":  r.URL.Path,
		"Query": query,
	}

	for _, rt := range strat.Routes {
		if h.routeMatches(rt, path, query, vuln) {
			return h.renderer.Render(rt.Template, p, extra)
		}
	}
	return h.renderer.Render("generic_not_found", p, extra)
}

func (h *Handler) routeMatches(rt rules.Route, path, query string, vuln *rules.Vulnerabilities) bool {
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
		return hasSQLInjectionPattern(path, vuln) || hasSQLInjectionPattern(query, vuln)
	case "list":
		// `values` is a list of list-names in vulnerabilities.yaml.
		for _, listName := range rt.Values {
			for _, entry := range vuln.Lookup(listName) {
				if path == strings.ToLower(entry) || strings.Contains(path, strings.ToLower(entry)) {
					return true
				}
			}
		}
	case "any":
		return true
	}
	return false
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
	lower := strings.ToLower(s)
	for _, pat := range v.SQLInjectionPatterns {
		if strings.Contains(lower, strings.ToLower(pat)) {
			return true
		}
	}
	return false
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
