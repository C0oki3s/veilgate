package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/payloads"
	"github.com/C0oki3s/veilgate/internal/rules"
	"github.com/C0oki3s/veilgate/internal/tarpit"
)

type app struct {
	rulesDir string
	profiles *tarpit.ProfileStore
	renderer *tarpit.Renderer
	handler  *tarpit.Handler
	injector *payloads.Injector
	tpls     *rules.Templates
}

type renderRequest struct {
	Template string `json:"template"`
	Path     string `json:"path"`
	Query    string `json:"query"`
	Body     string `json:"body"`
	Inject   bool   `json:"inject"`
}

type renderResponse struct {
	Status      int               `json:"status"`
	ContentType string            `json:"contentType"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
}

type bruteForceRequest struct {
	Paths []string `json:"paths"`
}

type bruteForceResult struct {
	Path        string `json:"path"`
	Status      int    `json:"status"`
	ContentType string `json:"contentType"`
	BodyBytes   int    `json:"bodyBytes"`
	Snippet     string `json:"snippet"`
}

func main() {
	var (
		listen   = flag.String("listen", "127.0.0.1:8099", "address for the template web tester")
		rulesDir = flag.String("rules", "veilgate-rules", "rules directory to load")
	)
	flag.Parse()

	a, err := newApp(*rulesDir)
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/templates", a.listTemplates)
	mux.HandleFunc("/api/render", a.renderTemplate)
	mux.HandleFunc("/api/bruteforce", a.bruteForce)
	mux.HandleFunc("/_preview/", a.preview)
	mux.HandleFunc("/", a.indexOrPreview)

	log.Printf("template web tester listening on http://%s (rules=%s)", *listen, *rulesDir)
	log.Fatal(http.ListenAndServe(*listen, mux))
}

func newApp(rulesDir string) (*app, error) {
	tpls, err := rules.LoadTemplates(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load templates: %w", err)
	}
	vuln, err := rules.LoadVulnerabilities(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load vulnerabilities: %w", err)
	}
	strat, err := rules.LoadInjectionStrategy(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load injection strategy: %w", err)
	}
	fakeData, err := rules.LoadFakeData(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load fake data: %w", err)
	}
	lib, err := payloads.NewLibraryFromDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("load payloads: %w", err)
	}

	profiles := tarpit.NewProfileStore()
	profiles.SetFakeData(rules.NewHolder(fakeData))

	renderer := tarpit.NewRenderer()
	renderer.SetTemplates(rules.NewHolder(tpls))

	injector := payloads.NewInjector(lib, 3, true)
	handler := tarpit.NewHandler(&config.TarpitConfig{
		MinLatencyMs: 0,
		MaxLatencyMs: 0,
		MaxBodyBytes: 2 << 20,
	}, profiles, injector)
	handler.SetRules(rules.NewHolder(tpls), rules.NewHolder(vuln), rules.NewHolder(strat))

	return &app{
		rulesDir: rulesDir,
		profiles: profiles,
		renderer: renderer,
		handler:  handler,
		injector: injector,
		tpls:     tpls,
	}, nil
}

func (a *app) indexOrPreview(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (a *app) preview(w http.ResponseWriter, r *http.Request) {
	r2 := r.Clone(r.Context())
	r2.URL.Path = strings.TrimPrefix(r.URL.Path, "/_preview")
	if r2.URL.Path == "" {
		r2.URL.Path = "/"
	}
	r2.URL.RawPath = ""
	r2.RemoteAddr = "10.10.10.10:4444"

	rr := httptest.NewRecorder()
	a.handler.ServeHTTP(rr, r2)

	for k, vals := range rr.Header() {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	body := rr.Body.String()
	if shouldRewritePreview(rr.Header().Get("Content-Type")) {
		body = rewritePreviewURLs(body)
	}
	w.WriteHeader(rr.Code)
	_, _ = w.Write([]byte(body))
}

func (a *app) listTemplates(w http.ResponseWriter, r *http.Request) {
	names := make([]string, 0, len(a.tpls.Templates))
	for name := range a.tpls.Templates {
		names = append(names, name)
	}
	sort.Strings(names)
	writeJSON(w, http.StatusOK, map[string]any{
		"rulesDir":   a.rulesDir,
		"templates":  names,
		"pathSample": defaultWordlist,
	})
}

func (a *app) renderTemplate(w http.ResponseWriter, r *http.Request) {
	var req renderRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if req.Template == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "template is required"})
		return
	}
	if req.Path == "" {
		req.Path = "/"
	}

	profile := a.profiles.Get("template-web")
	resp := a.renderer.Render(req.Template, profile, map[string]any{
		"Path":  req.Path,
		"Query": req.Query,
		"Body":  req.Body,
	})
	if req.Inject {
		resp.Body = a.injector.Inject(resp.ContentType, resp.Body, tarpit.InjectionContext{
			Path:     req.Path,
			ClientID: "template-web",
			Visits:   profile.Visits,
		})
	}
	if shouldRewritePreview(resp.ContentType) {
		resp.Body = rewritePreviewURLs(resp.Body)
	}
	writeJSON(w, http.StatusOK, renderResponse{
		Status:      resp.Status,
		ContentType: resp.ContentType,
		Headers:     resp.Headers,
		Body:        resp.Body,
	})
}

func (a *app) bruteForce(w http.ResponseWriter, r *http.Request) {
	var req bruteForceRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2<<20)).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if len(req.Paths) == 0 {
		req.Paths = defaultWordlist
	}

	results := make([]bruteForceResult, 0, len(req.Paths))
	for _, path := range req.Paths {
		path = strings.TrimSpace(path)
		if path == "" || strings.HasPrefix(path, "#") {
			continue
		}
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}

		rr := httptest.NewRecorder()
		tr := httptest.NewRequest(http.MethodGet, path, nil)
		tr.RemoteAddr = "10.10.10.10:4444"
		a.handler.ServeHTTP(rr, tr)

		body := rr.Body.String()
		results = append(results, bruteForceResult{
			Path:        path,
			Status:      rr.Code,
			ContentType: rr.Header().Get("Content-Type"),
			BodyBytes:   len(body),
			Snippet:     snippet(body, 420),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func snippet(s string, max int) string {
	s = strings.TrimSpace(strings.Join(strings.Fields(s), " "))
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func shouldRewritePreview(contentType string) bool {
	return strings.Contains(contentType, "html") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "json")
}

func rewritePreviewURLs(body string) string {
	repls := []struct {
		from string
		to   string
	}{
		{`href="/`, `href="/_preview/`},
		{`href='/`, `href='/_preview/`},
		{`src="/`, `src="/_preview/`},
		{`src='/`, `src='/_preview/`},
		{`action="/`, `action="/_preview/`},
		{`action='/`, `action='/_preview/`},
		{`fetch("/`, `fetch("/_preview/`},
		{`fetch('/`, `fetch('/_preview/`},
		{`location.href = "/`, `location.href = "/_preview/`},
		{`location.href = '/`, `location.href = '/_preview/`},
		{`location.href="/`, `location.href="/_preview/`},
		{`location.href='/`, `location.href='/_preview/`},
		{`window.location = "/`, `window.location = "/_preview/`},
		{`window.location = '/`, `window.location = '/_preview/`},
	}
	for _, repl := range repls {
		body = strings.ReplaceAll(body, repl.from, repl.to)
	}

	// Do not double-prefix when a rendered response is passed through the
	// preview rewriter more than once.
	body = strings.ReplaceAll(body, `/_preview/_preview/`, `/_preview/`)
	body = strings.ReplaceAll(body, `/_preview//`, `/_preview/`)
	return body
}

var defaultWordlist = []string{
	"/admin",
	"/administrator",
	"/admin/login",
	"/login",
	"/dashboard",
	"/console",
	"/manage",
	"/manager/html",
	"/host-manager/html",
	"/phpmyadmin",
	"/phpMyAdmin",
	"/pma",
	"/adminer.php",
	"/wp-admin",
	"/wp-login.php",
	"/xmlrpc.php",
	"/.env",
	"/.env.production",
	"/.git/config",
	"/backup.zip",
	"/db.sql",
	"/server-status",
	"/nginx_status",
	"/status",
	"/metrics",
	"/graph",
	"/targets",
	"/debug",
	"/debug/pprof/",
	"/debug/vars",
	"/actuator",
	"/actuator/health",
	"/actuator/env",
	"/actuator/heapdump",
	"/jenkins",
	"/api/docs",
	"/swagger-ui.html",
	"/openapi.json",
	"/graphql",
	"/graphiql",
	"/playground",
	"/rails/info/routes",
	"/sidekiq",
	"/zimbra",
	"/service/extension/",
	"/confluence",
	"/login.action",
	"/jira",
	"/secure/Dashboard.jspa",
	"/grafana",
	"/prometheus/graph",
	"/kibana/app/discover",
	"/_cluster/health",
	"/_cat/indices",
	"/kubernetes-dashboard",
	"/openapi/v2",
	"/healthz",
	"/readyz",
	"/livez",
	"/service-account.json",
	"/appsettings.json",
}

var indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VeilGate Template Web Tester</title>
  <style>
    * { box-sizing: border-box; }
    body { margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #f7f8fa; color: #18202a; }
    header { padding: 18px 24px; background: #172033; color: #f8fafc; border-bottom: 1px solid #0f172a; }
    header h1 { margin: 0; font-size: 18px; font-weight: 650; }
    main { display: grid; grid-template-columns: 360px 1fr; gap: 16px; padding: 16px; height: calc(100vh - 61px); }
    section { background: #fff; border: 1px solid #dbe1ea; border-radius: 8px; overflow: hidden; min-height: 0; }
    .panel { padding: 14px; display: flex; flex-direction: column; gap: 10px; height: 100%; }
    label { display: block; font-size: 12px; font-weight: 650; color: #526070; margin-bottom: 4px; }
    select, input, textarea { width: 100%; border: 1px solid #c8d1dc; border-radius: 6px; padding: 8px 10px; font: inherit; font-size: 13px; background: #fff; color: #18202a; }
    textarea { min-height: 180px; resize: vertical; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    button { border: 0; border-radius: 6px; padding: 9px 12px; background: #2457d6; color: white; font-weight: 650; cursor: pointer; }
    button.secondary { background: #eef2f7; color: #18202a; border: 1px solid #c8d1dc; }
    .row { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; }
    .toggle { display: flex; align-items: center; gap: 8px; font-size: 13px; color: #344256; }
    .toggle input { width: auto; }
    .tabs { display: flex; gap: 6px; padding: 10px 10px 0; background: #f0f4f9; border-bottom: 1px solid #dbe1ea; }
    .tab { padding: 8px 10px; border-radius: 6px 6px 0 0; background: transparent; color: #344256; border: 1px solid transparent; border-bottom: 0; }
    .tab.active { background: #fff; color: #18202a; border-color: #dbe1ea; }
    .view { display: none; height: calc(100% - 45px); }
    .view.active { display: block; }
    iframe { width: 100%; height: 100%; border: 0; background: #fff; }
    pre { margin: 0; padding: 14px; height: 100%; overflow: auto; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; line-height: 1.5; white-space: pre-wrap; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; border-bottom: 1px solid #edf0f5; padding: 8px 10px; vertical-align: top; }
    th { position: sticky; top: 0; background: #f7f8fa; color: #526070; font-size: 12px; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
    .status { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 700; }
    .ok { color: #0f7b45; }
    .err { color: #b42318; }
    .results { height: 100%; overflow: auto; }
  </style>
</head>
<body>
  <header><h1>VeilGate Template Web Tester</h1></header>
  <main>
    <section>
      <div class="panel">
        <div>
          <label for="template">Template</label>
          <select id="template"></select>
        </div>
        <div class="row">
          <div>
            <label for="path">Render path</label>
            <input id="path" value="/admin">
          </div>
          <div>
            <label for="query">Query/body seed</label>
            <input id="query" value="debug=1">
          </div>
        </div>
        <label class="toggle"><input id="inject" type="checkbox" checked> Inject payloads into rendered template</label>
        <button onclick="renderTemplate()">Render Template</button>
        <button class="secondary" onclick="bruteForce()">Run URL Bruteforce</button>
        <div>
          <label for="wordlist">URL wordlist</label>
          <textarea id="wordlist"></textarea>
        </div>
      </div>
    </section>
    <section>
      <div class="tabs">
        <button id="tab-preview" class="tab active" onclick="showTab('preview')">Preview</button>
        <button id="tab-raw" class="tab" onclick="showTab('raw')">Raw</button>
        <button id="tab-results" class="tab" onclick="showTab('results')">Bruteforce</button>
      </div>
      <div id="preview" class="view active"><iframe id="frame" sandbox="allow-forms allow-scripts"></iframe></div>
      <div id="raw" class="view"><pre id="rawOut"></pre></div>
      <div id="results" class="view"><div class="results"><table><thead><tr><th>URL</th><th>Status</th><th>Content-Type</th><th>Snippet</th></tr></thead><tbody id="rows"></tbody></table></div></div>
    </section>
  </main>
  <script>
    async function init() {
      const r = await fetch('/api/templates');
      const data = await r.json();
      const sel = document.getElementById('template');
      sel.innerHTML = data.templates.map(n => '<option value="'+esc(n)+'">'+esc(n)+'</option>').join('');
      sel.value = data.templates.includes('admin_dashboard') ? 'admin_dashboard' : data.templates[0];
      document.getElementById('wordlist').value = data.pathSample.join('\n');
      await renderTemplate();
    }
    async function renderTemplate() {
      const payload = {
        template: document.getElementById('template').value,
        path: document.getElementById('path').value,
        query: document.getElementById('query').value,
        body: document.getElementById('query').value,
        inject: document.getElementById('inject').checked
      };
      const r = await fetch('/api/render', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify(payload)});
      const data = await r.json();
      document.getElementById('rawOut').textContent = JSON.stringify({status:data.status, contentType:data.contentType, headers:data.headers, body:data.body}, null, 2);
      document.getElementById('frame').srcdoc = withPreviewBase(data.body || '');
      showTab('preview');
    }
    async function bruteForce() {
      const paths = document.getElementById('wordlist').value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      const r = await fetch('/api/bruteforce', {method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({paths})});
      const data = await r.json();
      document.getElementById('rows').innerHTML = data.results.map(x => {
        const cls = x.status >= 200 && x.status < 400 ? 'ok' : (x.status === 404 ? 'err' : '');
        return '<tr><td><code>'+esc(x.path)+'</code></td><td class="status '+cls+'">'+x.status+'</td><td>'+esc(x.contentType)+'</td><td>'+esc(x.snippet)+'</td></tr>';
      }).join('');
      showTab('results');
    }
    function showTab(id) {
      document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
      document.getElementById('tab-' + id).classList.add('active');
      document.getElementById(id).classList.add('active');
    }
    function esc(s) {
      return String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    }
    function withPreviewBase(body) {
      const base = '<base href="/_preview/" target="_self">';
      if (/<head[^>]*>/i.test(body)) return body.replace(/<head([^>]*)>/i, '<head$1>' + base);
      return base + body;
    }
    init();
  </script>
</body>
</html>`
