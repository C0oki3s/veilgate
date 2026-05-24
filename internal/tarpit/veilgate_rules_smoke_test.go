package tarpit

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/rules"
)

const veilgateRulesDir = "../../veilgate-rules"

func newVeilgateRulesHandler(t *testing.T) *Handler {
	t.Helper()
	tpls, err := rules.LoadTemplates(veilgateRulesDir)
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}
	vuln, err := rules.LoadVulnerabilities(veilgateRulesDir)
	if err != nil {
		t.Fatalf("load vulnerabilities: %v", err)
	}
	strat, err := rules.LoadInjectionStrategy(veilgateRulesDir)
	if err != nil {
		t.Fatalf("load injection strategy: %v", err)
	}
	h := NewHandler(&config.TarpitConfig{
		MinLatencyMs: 0,
		MaxLatencyMs: 0,
		MaxBodyBytes: 1024 * 1024,
	}, NewProfileStore(), nil)
	h.SetRules(rules.NewHolder(tpls), rules.NewHolder(vuln), rules.NewHolder(strat))
	return h
}

func TestVeilgateRulesOWASPRoutes(t *testing.T) {
	h := newVeilgateRulesHandler(t)
	tests := []struct {
		name     string
		method   string
		target   string
		body     string
		wantCode int
		wantBody string
	}{
		{"ssrf", http.MethodGet, "/api/v1/fetch?url=http://169.254.169.254/latest/meta-data/", "", 200, "instanceId"},
		{"xss", http.MethodGet, "/api/messages?body=<script>alert(1)</script>", "", 200, "adminReviewUrl"},
		{"path_traversal", http.MethodGet, "/api/files?path=../../../../etc/passwd", "", 200, "root:x:0:0"},
		{"command_injection", http.MethodGet, "/api/run?cmd=whoami;id", "", 200, "uid=1000"},
		{"xxe", http.MethodPost, "/api/xml", `<!DOCTYPE x [ <!ENTITY y SYSTEM "file:///etc/passwd"> ]><x>&y;</x>`, 200, "entitiesResolved"},
		{"ssti", http.MethodGet, "/api/render?template={{7*7}}", "", 200, "nunjucks"},
		{"nosql", http.MethodPost, "/api/users/search", `{"email":{"$ne":null}}`, 200, "matched"},
		{"prototype_pollution", http.MethodPost, "/api/profile", `{"__proto__":{"isAdmin":true}}`, 200, "polluted"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			r.RemoteAddr = "10.0.0.55:1234"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body missing %q: %s", tc.wantBody, w.Body.String())
			}
		})
	}
}

func TestVeilgateRulesSPAMiningRoutes(t *testing.T) {
	h := newVeilgateRulesHandler(t)
	tests := []struct {
		target   string
		wantCT   string
		wantBody string
	}{
		{"/package.json", "application/json", `"@`},
		{"/node_modules/@vitejs/plugin-react/index.js", "application/javascript", "__DEV_TOKEN__"},
		{"/assets/app.js.map", "application/json", "sourcesContent"},
	}
	for _, tc := range tests {
		r := httptest.NewRequest(http.MethodGet, tc.target, nil)
		r.RemoteAddr = "10.0.0.56:1234"
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, tc.wantCT) {
			t.Fatalf("%s content-type = %q, want %q", tc.target, ct, tc.wantCT)
		}
		if !strings.Contains(w.Body.String(), tc.wantBody) {
			t.Fatalf("%s body missing %q: %s", tc.target, tc.wantBody, w.Body.String())
		}
	}
}

func TestVeilgateRulesHighRiskRoutes(t *testing.T) {
	h := newVeilgateRulesHandler(t)
	tests := []struct {
		target   string
		wantCode int
		wantBody string
	}{
		{"/manager/html", 200, "Jenkins"},
		{"/swagger-ui.html", 200, "swagger"},
		{"/metrics", 200, "Prometheus"},
		{"/debug/pprof/", 200, "Types of profiles"},
		{"/rails/info/routes", 200, "Rails"},
		{"/kubernetes-dashboard", 200, "Kubernetes Dashboard"},
		{"/.env.production", 200, "DATABASE_URL"},
		{"/service/extension/", 200, "Zimbra"},
		{"/app/kibana", 200, "logs-"},
	}
	for _, tc := range tests {
		t.Run(tc.target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, tc.target, nil)
			r.RemoteAddr = "10.0.0.57:1234"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d; body=%s", w.Code, tc.wantCode, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.wantBody) {
				t.Fatalf("body missing %q: %s", tc.wantBody, w.Body.String())
			}
		})
	}
}

func TestVeilgateRulesRouteTemplatesAreDefined(t *testing.T) {
	tpls, err := rules.LoadTemplates(veilgateRulesDir)
	if err != nil {
		t.Fatalf("load templates: %v", err)
	}
	strat, err := rules.LoadInjectionStrategy(veilgateRulesDir)
	if err != nil {
		t.Fatalf("load injection strategy: %v", err)
	}
	for _, rt := range strat.Routes {
		if _, ok := tpls.Templates[rt.Template]; !ok {
			t.Fatalf("route template %q is not defined", rt.Template)
		}
	}
}

func TestVeilgateRulesDynamicDashboardTemplatesUseThirdPartyCDN(t *testing.T) {
	h := newVeilgateRulesHandler(t)
	tests := []string{
		"/jenkins",
		"/jira",
		"/kubernetes-dashboard",
		"/grafana",
		"/prometheus/graph",
		"/sidekiq",
		"/portainer",
		"/rabbitmq",
		"/minio",
		"/argocd",
	}
	for _, target := range tests {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, target, nil)
			r.RemoteAddr = "10.0.0.58:1234"
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			body := w.Body.String()
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, body)
			}
			if !strings.Contains(body, "cdn.jsdelivr.net") {
				t.Fatalf("expected third-party CDN asset in body: %s", body)
			}
			if !strings.Contains(body, "Chart") && !strings.Contains(body, "x-data") {
				t.Fatalf("expected dynamic dashboard JS in body: %s", body)
			}
		})
	}
}
