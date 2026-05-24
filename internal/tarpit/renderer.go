package tarpit

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/C0oki3s/veilgate/internal/fakeauth"
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
		"VerifyPath": "/_g/verify",
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

// templateFuncs is the helper set available in every template.
// Everything is deterministic on seed — same seed → same output — so the
// per-client fake identity stays coherent across requests.
var templateFuncs = template.FuncMap{
	// ── arithmetic ────────────────────────────────────────────────────────
	"add": func(a, b int) int { return a + b },
	"mul": func(a, b int64) int64 { return a * b },
	"mod": func(a, b int) int { return a % b },

	// ── legacy hex helper (kept for backwards compat in templates) ─────────
	"hex64": func(n int64) string { return fmt.Sprintf("%016x", uint64(n)) },

	// ── string helpers ─────────────────────────────────────────────────────
	"sanitize": func(s string) string {
		s = strings.ReplaceAll(s, "<", "&lt;")
		s = strings.ReplaceAll(s, ">", "&gt;")
		if len(s) > 200 {
			s = s[:200] + "..."
		}
		return s
	},

	// ── deterministic RNG ─────────────────────────────────────────────────
	"rand_int": func(max int, salt string) int {
		if max <= 0 {
			return 0
		}
		return int(hash32(salt) % uint32(max))
	},

	// cdn_url(path, seed) — deterministic real-looking CDN asset URL.
	// Use: {{cdn_url "/assets/app.css" .Seed}}
	"cdn_url": func(path string, seed int64) string {
		return cdnURL(path, seed)
	},

	// cdn_pkg(pkg, file) — public package CDN URL for common framework assets.
	// Use: {{cdn_pkg "@fontsource/inter" "index.css"}}
	"cdn_pkg": func(pkg, file string) string {
		pkg = strings.Trim(pkg, "/")
		file = strings.Trim(file, "/")
		if file == "" {
			return "https://cdn.jsdelivr.net/npm/" + pkg
		}
		return "https://cdn.jsdelivr.net/npm/" + pkg + "/" + file
	},

	// ── auth token generators (real crypto, deterministic on seed) ─────────

	// jwt_admin(email, seed) — HS256 JWT with admin role.
	// Use: {{jwt_admin .AdminUser .Seed}}
	"jwt_admin": fakeauth.JWTAdmin,

	// jwt_user(seed) — HS256 JWT with customer role.
	// Use: {{jwt_user .Seed}}
	"jwt_user": fakeauth.JWTUser,

	// jwt_svc(name, seed) — HS256 JWT for a service account.
	// Use: {{jwt_svc "monitoring" .Seed}}
	"jwt_svc": fakeauth.JWTSvc,

	// api_key(seed) — Stripe-style sk_live_<24 b62> key.
	"api_key": fakeauth.APIKey,

	// aws_key_id(seed) — AWS AKIA + 16 Base32 chars (long-term credential).
	"aws_key_id": fakeauth.AWSKeyID,

	// aws_sts_key_id(seed) — AWS ASIA + 16 Base32 chars (temporary STS credential).
	"aws_sts_key_id": fakeauth.AWSSTSKeyID,

	// aws_sts_token(seed) — realistic AWS STS session token (~280-char base64).
	"aws_sts_token": fakeauth.AWSSTSToken,

	// aws_secret(seed) — 40-char base64 AWS secret.
	"aws_secret": fakeauth.AWSSecret,

	// azure_token(tenantID, email, seed) — Azure AD access token with tid/oid/appid claims.
	"azure_token": fakeauth.AzureAccessToken,

	// azure_tenant_id(seed) — UUID v4 as an Azure tenant ID.
	"azure_tenant_id": fakeauth.AzureTenantID,

	// azure_sub_id(seed) — UUID v4 as an Azure subscription ID.
	"azure_sub_id": fakeauth.AzureSubscriptionID,

	// gcp_token(seed) — GCP OAuth2 access token: ya29.<~200 chars base64url>.
	"gcp_token": fakeauth.GCPAccessToken,

	// gcp_sa_email(name, project) — GCP service account email format.
	"gcp_sa_email": fakeauth.GCPServiceAccountEmail,

	// oci_suffix(seed) — 60-char OCI ID unique suffix for building OCIDs.
	"oci_suffix": fakeauth.OCIDSuffix,

	// ── Third-party service tokens ─────────────────────────────────────────

	// vault_token(seed) — HashiCorp Vault service token: hvs.<40 base64url>.
	"vault_token": fakeauth.VaultToken,

	// csrf_token(seed) — 64-char hex CSRF token (Django/Rails/Jenkins style).
	"csrf_token": fakeauth.CsrfToken,

	// oauth_refresh(seed) — 64-char base64url opaque OAuth2 refresh token.
	"oauth_refresh": fakeauth.OAuthRefreshToken,

	// stripe_whsec(seed) — Stripe webhook secret: whsec_<43 base64url>.
	"stripe_whsec": fakeauth.StripeWebhookSecret,

	// github_token(prefix, seed) — GitHub token: ghp_/gho_/ghs_<36 b62>.
	"github_token": fakeauth.GithubToken,

	// npm_token(seed) — npm access token: npm_<32 b62>.
	"npm_token": fakeauth.NPMToken,

	// dd_key(seed) — Datadog API/app key: 32 hex chars.
	"dd_key": fakeauth.DatadogKey,

	// cf_token(seed) — Cloudflare API token: 40 b62 chars.
	"cf_token": fakeauth.CloudflareToken,

	// twilio_sid(seed) — Twilio Account SID: AC<32 hex>.
	"twilio_sid": fakeauth.TwilioSID,

	// twilio_token(seed) — Twilio Auth Token: 32 hex chars.
	"twilio_token": fakeauth.TwilioToken,

	// contains_str(s, substr) — case-insensitive substring check for template conditionals.
	"contains_str": func(s, substr string) bool {
		return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
	},

	// lower(s) — lowercase a string (useful for normalising .Query in conditionals).
	"lower": strings.ToLower,

	// b64enc(s) — base64 standard encoding (for Kubernetes secret data fields).
	"b64enc": func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) },

	// jwt_secret(seed) — 64-char base64url signing secret for JWT_SECRET.
	"jwt_secret": fakeauth.JWTSecret,

	// redis_pass(seed) — 32 hex-char Redis AUTH password.
	"redis_pass": fakeauth.RedisPass,

	// sendgrid_key(seed) — SG.<22>.<43> SendGrid API key.
	"sendgrid_key": fakeauth.SendGridKey,

	// session_id(seed) — Express.js connect.sid style session token.
	"session_id": fakeauth.SessionID,

	// request_id(seed) — UUID v4 for X-Request-Id headers.
	"request_id": fakeauth.RequestID,

	// user_id(seed) — usr_<14 b62 chars>.
	"user_id": fakeauth.UserID,

	// slug_id(prefix, seed) — prefix_<12 b62 chars> for ord_/tkt_ IDs.
	"slug_id": fakeauth.SlugID,

	// ── compound renderers ─────────────────────────────────────────────────
	// users_list renders a fake JSON user list (body fixed, count dynamic).
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

func cdnURL(path string, seed int64) string {
	hosts := []string{
		"https://cdn.jsdelivr.net",
		"https://unpkg.com",
		"https://cdnjs.cloudflare.com",
		"https://cdn.skypack.dev",
	}
	if path == "" {
		path = "/assets/app.js"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	idx := int(uint64(seed) % uint64(len(hosts)))
	return fmt.Sprintf("%s%s?v=%x", hosts[idx], path, uint64(seed)&0xffffff)
}
