package tarpit

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// Response is a fully-formed fake HTTP response.
type Response struct {
	Status      int
	ContentType string
	Body        string
	Headers     map[string]string
}

// Renderer executes templates.yaml bodies. Compiled templates are cached
// until the holder swaps; on swap we throw away the cache and recompile
// lazily. A RWMutex around the cache is fine because lookups dominate.
type Renderer struct {
	holder *rules.Holder[rules.Templates]

	mu       sync.RWMutex
	compiled map[string]*compiledResponse
	version  *rules.Templates // what we last compiled against
}

type compiledResponse struct {
	status      int
	contentType string
	headers     map[string]*template.Template
	body        *template.Template
}

// NewRenderer builds an empty renderer. Wire a holder via SetTemplates.
func NewRenderer() *Renderer {
	t := new(rules.Templates)
	return &Renderer{
		holder:   rules.NewHolder(t),
		compiled: make(map[string]*compiledResponse),
	}
}

// SetTemplates swaps in a hot-reloadable holder.
func (r *Renderer) SetTemplates(h *rules.Holder[rules.Templates]) {
	if r == nil || h == nil {
		return
	}
	r.mu.Lock()
	r.holder = h
	r.compiled = make(map[string]*compiledResponse)
	r.version = nil
	r.mu.Unlock()
}

// Render executes the named template against p + extra vars. If the
// template is missing or fails to execute we return a minimal 500 so
// the proxy never panics on a malformed operator edit.
func (r *Renderer) Render(name string, p *ShadowProfile, vars map[string]any) Response {
	compiled, ok := r.lookup(name)
	if !ok {
		return Response{
			Status:      500,
			ContentType: "text/plain",
			Body:        fmt.Sprintf("template %q not defined", name),
		}
	}
	data := r.buildData(p, vars)

	var buf bytes.Buffer
	if err := compiled.body.Execute(&buf, data); err != nil {
		return Response{
			Status:      500,
			ContentType: "text/plain",
			Body:        fmt.Sprintf("template %q failed: %v", name, err),
		}
	}
	headers := make(map[string]string, len(compiled.headers))
	var hb bytes.Buffer
	for k, tmpl := range compiled.headers {
		hb.Reset()
		if err := tmpl.Execute(&hb, data); err == nil {
			headers[k] = hb.String()
		}
	}
	return Response{
		Status:      compiled.status,
		ContentType: compiled.contentType,
		Body:        buf.String(),
		Headers:     headers,
	}
}

// buildData is the canonical template context — every template gets the
// same variable set so operators don't have to remember per-template
// naming.
func (r *Renderer) buildData(p *ShadowProfile, extra map[string]any) map[string]any {
	d := map[string]any{
		"Company":    p.FakeCompany,
		"Version":    p.FakeVersion,
		"Stack":      p.FakeStack,
		"AdminUser":  p.FakeAdminUser,
		"AdminPass":  p.FakeAdminPass,
		"Seed":       p.Seed,
		"Visits":     p.Visits,
		"Slug":       p.Slug,
		"TicketID":   1000 + (p.Seed % 9000),
		"VerifyPath": "/__veilgate/verify",
		"profile":    p,
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func (r *Renderer) lookup(name string) (*compiledResponse, bool) {
	r.mu.RLock()
	if r.version == r.holder.Load() {
		c, ok := r.compiled[name]
		r.mu.RUnlock()
		return c, ok
	}
	r.mu.RUnlock()

	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.holder.Load()
	if cur != r.version {
		r.compiled = r.compileAll(cur)
		r.version = cur
	}
	c, ok := r.compiled[name]
	return c, ok
}

func (r *Renderer) compileAll(t *rules.Templates) map[string]*compiledResponse {
	out := make(map[string]*compiledResponse, len(t.Templates))
	for name, tr := range t.Templates {
		c := &compiledResponse{
			status:      tr.Status,
			contentType: tr.ContentType,
			headers:     make(map[string]*template.Template, len(tr.Headers)),
		}
		body, err := template.New(name).Funcs(templateFuncs).Parse(tr.Body)
		if err != nil {
			// Keep rendering something sensible — don't let one bad template
			// wipe the rest.
			body, _ = template.New(name).Parse(fmt.Sprintf("template %q parse error: %v", name, err))
		}
		c.body = body
		for k, v := range tr.Headers {
			ht, err := template.New(name + ":" + k).Funcs(templateFuncs).Parse(v)
			if err != nil {
				continue
			}
			c.headers[k] = ht
		}
		out[name] = c
	}
	return out
}

// templateFuncs is the small, opinionated helper set templates can call.
// Everything here is deterministic so the per-client illusion stays coherent.
var templateFuncs = template.FuncMap{
	"add":    func(a, b int) int { return a + b },
	"mul":    func(a, b int64) int64 { return a * b },
	"mod":    func(a, b int) int { return a % b },
	"hex64":  func(n int64) string { return fmt.Sprintf("%x", uint64(n)) },
	"sanitize": func(s string) string {
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		if len(s) > 200 {
			s = s[:200] + "..."
		}
		return s
	},
	// Deterministic RNG helpers — salt is hashed with the profile seed
	// inside the renderer pipeline when we build the per-request profile.
	"rand_int": func(max int, salt string) int {
		if max <= 0 {
			return 0
		}
		h := hash32(salt)
		return int(h % uint32(max))
	},
	// users_list renders a small JSON user list. We implement this here
	// rather than as a template loop because the body format is fixed
	// and the iteration count is dynamic.
	"users_list": func(n int) string {
		if n < 0 {
			n = 0
		}
		parts := make([]string, 0, n)
		for i := 0; i < n; i++ {
			role := []string{"user", "admin", "viewer"}[i%3]
			parts = append(parts, fmt.Sprintf(
				`{"id":%d,"username":"user%d","email":"user%d@example.local","role":%q,"created":"2024-0%d-15T10:00:00Z"}`,
				i+1, i+1, i+1, role, 1+(i%9),
			))
		}
		return `{"users":[` + strings.Join(parts, ",") + `],"total":` + fmt.Sprintf("%d", n) + `}`
	},
}

// hash32 is a tiny FNV-1a — used by rand_int so templates get stable pseudo-random
// integers without pulling math/rand into the template scope.
func hash32(s string) uint32 {
	var h uint32 = 2166136261
	for i := 0; i < len(s); i++ {
		h ^= uint32(s[i])
		h *= 16777619
	}
	return h
}
