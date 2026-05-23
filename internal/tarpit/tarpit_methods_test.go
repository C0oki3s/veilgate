package tarpit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/rules"
)

type suffixInjector struct {
	suffix string
	seen   InjectionContext
}

func (i *suffixInjector) Inject(_ string, body string, ctx InjectionContext) string {
	i.seen = ctx
	return body + i.suffix
}

func TestRouteMatchesEveryMode(t *testing.T) {
	h := newTestHandler(t)
	vuln := &rules.Vulnerabilities{
		HoneypotPaths:        []string{"/hidden-admin"},
		SQLInjectionPatterns: []string{"union select", " or 1=1"},
	}
	cases := []struct {
		name  string
		route rules.Route
		path  string
		query string
		want  bool
	}{
		{"exact", rules.Route{Match: "exact", Values: []string{"/login"}}, "/login", "", true},
		{"prefix", rules.Route{Match: "prefix", Values: []string{"/api/"}}, "/api/users", "", true},
		{"contains", rules.Route{Match: "contains", Values: []string{"backup"}}, "/db/backup.sql", "", true},
		{"regex", rules.Route{Match: "regex", Values: []string{`^/v[0-9]+/health$`}}, "/v2/health", "", true},
		{"invalid regex", rules.Route{Match: "regex", Values: []string{"["}}, "/anything", "", false},
		{"sqli path", rules.Route{Match: "sqli"}, "/search/union select", "", true},
		{"sqli query", rules.Route{Match: "sqli"}, "/search", "id=1 or 1=1", true},
		{"list", rules.Route{Match: "list", Values: []string{"honeypot_paths"}}, "/hidden-admin", "", true},
		{"any", rules.Route{Match: "any"}, "/whatever", "", true},
		{"miss", rules.Route{Match: "exact", Values: []string{"/login"}}, "/logout", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := h.routeMatches(tc.route, strings.ToLower(tc.path), tc.query, "", vuln); got != tc.want {
				t.Fatalf("routeMatches() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRouteUsesFirstMatchingTemplateAndFallback(t *testing.T) {
	h := handlerWithRulesForTarpitTests()
	profile := h.profiles.Get("10.0.0.20")

	r := httptest.NewRequest(http.MethodGet, "/exact", nil)
	resp := h.route(r, profile)
	if resp.Status != 201 || !strings.Contains(resp.Body, "exact ") || !strings.Contains(resp.Body, "/exact") {
		t.Fatalf("exact route response mismatch: %+v", resp)
	}

	r = httptest.NewRequest(http.MethodGet, "/missing", nil)
	resp = h.route(r, profile)
	if resp.Status != 404 || !strings.Contains(resp.Body, "fallback /missing") {
		t.Fatalf("fallback response mismatch: %+v", resp)
	}
}

func TestServeHTTPAppliesInjectorBodyCapAndHeaders(t *testing.T) {
	inj := &suffixInjector{suffix: "0123456789"}
	cfg := &config.TarpitConfig{MinLatencyMs: 0, MaxLatencyMs: 0, MaxBodyBytes: 12}
	h := NewHandler(cfg, NewProfileStore(), inj)
	templates, vuln, strategy := tarpitTestRules()
	h.SetRules(rules.NewHolder(templates), rules.NewHolder(vuln), rules.NewHolder(strategy))

	r := httptest.NewRequest(http.MethodGet, "/exact", nil)
	r.RemoteAddr = "10.0.0.21:4444"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != 201 {
		t.Fatalf("status = %d", w.Code)
	}
	if got := w.Header().Get("X-Test"); got == "" {
		t.Fatalf("templated header = %q", got)
	}
	if len(w.Body.String()) != 12 {
		t.Fatalf("body cap not applied: len=%d body=%q", len(w.Body.String()), w.Body.String())
	}
	if inj.seen.Path != "/exact" || inj.seen.ClientID != "10.0.0.21" || inj.seen.Visits != 1 {
		t.Fatalf("injector context mismatch: %+v", inj.seen)
	}
}

func TestRendererMissingParseErrorSanitizeAndHotSwap(t *testing.T) {
	r := NewRenderer()
	p := &ShadowProfile{
		ClientID:      "client",
		Seed:          42,
		Visits:        3,
		FakeCompany:   "Acme Corp",
		FakeVersion:   "nginx/1.2.3",
		FakeStack:     "go",
		FakeAdminUser: "root",
		FakeAdminPass: "secret",
		Slug:          "acme",
	}

	if resp := r.Render("does_not_exist", p, nil); resp.Status != 500 || !strings.Contains(resp.Body, "not defined") {
		t.Fatalf("missing template response mismatch: %+v", resp)
	}

	first := &rules.Templates{Templates: map[string]rules.TemplateResponse{
		"broken": {
			Status:      200,
			ContentType: "text/plain",
			Body:        "{{",
		},
		"safe": {
			Status:      200,
			ContentType: "text/plain",
			Headers:     map[string]string{"X-Name": "{{.Company}}"},
			Body:        "{{sanitize .Path}}",
		},
		"users": {
			Status:      200,
			ContentType: "application/json",
			Body:        "{{users_list 2}}",
		},
	}}
	r.SetTemplates(rules.NewHolder(first))
	if resp := r.Render("broken", p, nil); resp.Status != 200 || !strings.Contains(resp.Body, "parse error") {
		t.Fatalf("broken template response mismatch: %+v", resp)
	}
	longPath := "<script>" + strings.Repeat("a", 250)
	resp := r.Render("safe", p, map[string]any{"Path": longPath})
	if strings.Contains(resp.Body, "<script>") || !strings.Contains(resp.Body, "&lt;script&gt;") || !strings.HasSuffix(resp.Body, "...") {
		t.Fatalf("sanitize output mismatch: %q", resp.Body)
	}
	if resp.Headers["X-Name"] != "Acme Corp" {
		t.Fatalf("templated header mismatch: %+v", resp.Headers)
	}
	if resp := r.Render("users", p, nil); !strings.Contains(resp.Body, `"total":2`) {
		t.Fatalf("users_list output mismatch: %q", resp.Body)
	}

	second := &rules.Templates{Templates: map[string]rules.TemplateResponse{
		"safe": {Status: 202, ContentType: "text/plain", Body: "swapped"},
	}}
	r.SetTemplates(rules.NewHolder(second))
	if resp := r.Render("safe", p, nil); resp.Status != 202 || resp.Body != "swapped" {
		t.Fatalf("hot-swapped template response mismatch: %+v", resp)
	}
}

func TestProfileStoreFallbackFakeDataSlugAndRand(t *testing.T) {
	store := NewProfileStore()
	store.SetFakeData(rules.NewHolder(&rules.FakeData{
		Companies:    []string{"!!!"},
		EmailDomains: []string{"fallback-domain"},
	}))
	p := store.Get("10.0.0.30")
	if p.FakeVersion != "nginx/1.20.2" || p.FakeStack != "node-express" || p.FakeAdminUser != "admin" || p.FakeAdminPass != "password123" {
		t.Fatalf("fallback fake data mismatch: %+v", p)
	}
	if p.Slug != "fallback-domain" {
		t.Fatalf("expected domain fallback slug, got %q", p.Slug)
	}
	a := p.Rand("same").Int63()
	b := p.Rand("same").Int63()
	if a != b {
		t.Fatalf("profile Rand should be deterministic for same salt: %d vs %d", a, b)
	}
	before := p.Visits
	again := store.Get("10.0.0.30")
	if again != p || again.Visits != before+1 {
		t.Fatalf("Get should reuse and increment profile, before=%d after=%d", before, again.Visits)
	}
}

func TestRandBetweenAndClientIPFallbacks(t *testing.T) {
	if got := randBetween(5, 5); got != 5 {
		t.Fatalf("randBetween equal bounds = %d", got)
	}
	if got := randBetween(8, 2); got != 8 {
		t.Fatalf("randBetween inverted bounds = %d", got)
	}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "not-a-hostport"
	if got := clientIP(r); got != "not-a-hostport" {
		t.Fatalf("clientIP fallback = %q", got)
	}
}

func handlerWithRulesForTarpitTests() *Handler {
	h := NewHandler(&config.TarpitConfig{
		MinLatencyMs: 0,
		MaxLatencyMs: 0,
		MaxBodyBytes: 1024 * 1024,
	}, NewProfileStore(), nil)
	templates, vuln, strategy := tarpitTestRules()
	h.SetRules(rules.NewHolder(templates), rules.NewHolder(vuln), rules.NewHolder(strategy))
	return h
}

func tarpitTestRules() (*rules.Templates, *rules.Vulnerabilities, *rules.InjectionStrategy) {
	templates := &rules.Templates{Templates: map[string]rules.TemplateResponse{
		"exact_template": {
			Status:      201,
			ContentType: "text/plain",
			Headers:     map[string]string{"X-Test": "{{.Company}}"},
			Body:        "exact {{.Company}} {{.Path}}",
		},
		"generic_not_found": {
			Status:      404,
			ContentType: "text/plain",
			Body:        "fallback {{.Path}}",
		},
	}}
	vuln := &rules.Vulnerabilities{
		HoneypotPaths:        []string{"/hidden-admin"},
		SQLInjectionPatterns: []string{"union select"},
	}
	strategy := &rules.InjectionStrategy{
		Routes: []rules.Route{
			{Match: "exact", Values: []string{"/exact"}, Template: "exact_template"},
			{Match: "any", Template: "generic_not_found"},
		},
	}
	return templates, vuln, strategy
}
