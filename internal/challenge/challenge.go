package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	htmltmpl "html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// defaultStartPageTmpl is the built-in HTML+JS page served at
// /_g/start when challenge.yaml does not set start_page_template.
// It is loaded in a hidden iframe by a cross-origin SPA; it solves the
// PoW nonce search, posts the proof to verify_path, and postMessages the
// resulting token back to the parent window. The entire challenge
// configuration is injected as a JSON blob at serve time — no secondary
// fetch required.
const defaultStartPageTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex,nofollow">
<title>Authenticating</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{height:100vh;display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif;background:#fafafa;color:#666}p{font-size:.875rem}</style>
</head>
<body>
<p>Authenticating…</p>
<script>
(async function(){
  var cfg={{.Config}};
  var nonce=0,enc=new TextEncoder();
  while(true){
    var h=await crypto.subtle.digest("SHA-256",enc.encode(cfg.challenge+":"+nonce));
    var hex=Array.from(new Uint8Array(h)).map(function(b){return b.toString(16).padStart(2,"0")}).join("");
    if(hex.startsWith(cfg.target))break;
    nonce++;
  }
  var resp=await fetch(cfg.verify_path,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({challenge:cfg.challenge,nonce:nonce,ts:cfg.ts,sig:cfg.sig})});
  if(!resp.ok){window.parent.postMessage({type:"veilgate-error",reason:"verify_failed",status:resp.status},cfg.origin);return;}
  var data=await resp.json();
  window.parent.postMessage({type:"veilgate-token",token:data.token,header:data.header||cfg.header,expires_in:data.expires_in},cfg.origin);
})().catch(function(err){window.parent.postMessage({type:"veilgate-error",reason:String(err)},"*");});
</script>
</body>
</html>`

// Handler serves a JS proof-of-work page. Real browsers solve it in <1s.
// Headless HTTP clients (the LLM-agent common case) never solve it at all.
// Sophisticated agents with headless Chromium will, which is by design —
// we're raising cost, not making the site invulnerable.
//
// Every knob — HTML body, difficulty, cookie name, TTL, verify path — is
// loaded from rules/challenge.yaml so operators can tune live.
type Handler struct {
	secret []byte
	maxTTL time.Duration // operator-configured ceiling; 0 means use default

	// Config fallbacks used when the holder is empty (constructor only
	// supplies the embedded defaults). main.go wires in the live holder
	// via SetRules.
	rules *rules.Holder[rules.ChallengeRules]

	mu      sync.Mutex
	tmpl    *template.Template
	tmplSrc string // the template source the current `tmpl` was compiled from
}

// NewHandler constructs the handler using embedded-default challenge rules.
// `secret` still comes from config (used for HMAC cookie signing).
// `difficultyOverride` and `ttlOverride` are applied only when non-zero.
// `maxTTL` is the operator-configured ceiling on token lifetime; 0 defaults
// to 60 minutes inside challengeTTL.
func NewHandler(secret string, difficultyOverride int, ttlOverride, maxTTL time.Duration) *Handler {
	cr := new(rules.ChallengeRules)
	if difficultyOverride > 0 {
		cr.Difficulty = difficultyOverride
	}
	if ttlOverride > 0 {
		cr.TokenTTLMinutes = int(ttlOverride / time.Minute)
	}
	return &Handler{
		secret: []byte(secret),
		maxTTL: maxTTL,
		rules:  rules.NewHolder(cr),
	}
}

// NewHandlerFromDir constructs the handler loading challenge rules from rulesDir.
// `maxTTL` is the operator-configured ceiling on token lifetime; 0 defaults
// to 60 minutes inside challengeTTL.
func NewHandlerFromDir(secret, rulesDir string, difficultyOverride int, ttlOverride, maxTTL time.Duration) (*Handler, error) {
	cr, err := rules.LoadChallenge(rulesDir)
	if err != nil {
		return nil, err
	}
	if difficultyOverride > 0 {
		cr.Difficulty = difficultyOverride
	}
	if ttlOverride > 0 {
		cr.TokenTTLMinutes = int(ttlOverride / time.Minute)
	}
	return &Handler{
		secret: []byte(secret),
		maxTTL: maxTTL,
		rules:  rules.NewHolder(cr),
	}, nil
}

// SetRules swaps in a hot-reloadable holder.
func (h *Handler) SetRules(holder *rules.Holder[rules.ChallengeRules]) {
	if h == nil || holder == nil {
		return
	}
	h.rules = holder
}

// ChallengeDescriptor captures the configured names a client SDK
// needs in order to participate in the PoW challenge flow: where to
// POST the proof, what header to attach the resulting token in, and
// what cookie name to expect on same-origin pages.
//
// Returned by Handler.DescribeChallenge for the
// /_g/config discovery endpoint.
type ChallengeDescriptor struct {
	VerifyPath  string `json:"verify_path"`
	StartPath   string `json:"start_path,omitempty"`
	TokenHeader string `json:"token_header"`
	CookieName  string `json:"cookie_name"`
}

// DescribeChallenge returns the current challenge-tier wire shape
// for the discovery endpoint. Reads from the live rules holder so
// hot-reloaded config flows through without a restart.
func (h *Handler) DescribeChallenge() ChallengeDescriptor {
	if h == nil || h.rules == nil {
		return ChallengeDescriptor{}
	}
	cr := h.rules.Load()
	return ChallengeDescriptor{
		VerifyPath:  cr.VerifyPath,
		StartPath:   h.StartPath(),
		TokenHeader: cr.TokenHeaderName,
		CookieName:  cr.CookieName,
	}
}

// StartPath returns the configured start-page path, defaulting to
// "/_g/start" when not set in rules.
func (h *Handler) StartPath() string {
	if h == nil || h.rules == nil {
		return "/_g/start"
	}
	if p := h.rules.Load().StartPath; p != "" {
		return p
	}
	return "/_g/start"
}

// ServeStart serves the iframe-loadable PoW interstitial page. The page
// solves the nonce search in JS and postMessages the resulting token to
// the parent window. It should be loaded in a hidden iframe by a
// cross-origin SPA that cannot receive cookies and does not want to
// block its own JS thread while searching for the nonce.
//
// The optional "origin" query parameter restricts the postMessage target
// to a specific origin (e.g. ?origin=https://app.example.com). When
// absent the target defaults to "*" — acceptable because the PoW token
// is not a long-lived secret and expires quickly.
func (h *Handler) ServeStart(w http.ResponseWriter, r *http.Request) {
	cr := h.rules.Load()

	nonce, err := newChallengeNonce()
	if err != nil {
		http.Error(w, "challenge seed failed", http.StatusInternalServerError)
		return
	}
	challengeTS := time.Now().UTC().Format(time.RFC3339Nano)
	challengeSig := h.sign(h.challengePayload(nonce, challengeTS))
	target := strings.Repeat("0", normalizedDifficulty(cr.Difficulty))

	allowedOrigin := r.URL.Query().Get("origin")
	if allowedOrigin == "" {
		allowedOrigin = "*"
	}

	hdr := cr.TokenHeaderName
	if hdr == "" {
		hdr = "X-App-Token"
	}

	cfg := struct {
		Challenge  string `json:"challenge"`
		Target     string `json:"target"`
		TS         string `json:"ts"`
		Sig        string `json:"sig"`
		VerifyPath string `json:"verify_path"`
		Header     string `json:"header"`
		Origin     string `json:"origin"`
	}{
		Challenge:  nonce,
		Target:     target,
		TS:         challengeTS,
		Sig:        challengeSig,
		VerifyPath: cr.VerifyPath,
		Header:     hdr,
		Origin:     allowedOrigin,
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	src := cr.StartPageTemplate
	if src == "" {
		src = defaultStartPageTmpl
	}
	tmpl, err := htmltmpl.New("start").Parse(src)
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	// Allow framing from any origin — this endpoint exists precisely to be
	// loaded as a cross-origin iframe. Do not set X-Frame-Options.
	// CSP frame-ancestors is set to "*" explicitly for operators who
	// apply a default-deny CSP at the edge.
	w.Header().Set("Content-Security-Policy", "frame-ancestors *")
	_ = tmpl.Execute(w, map[string]htmltmpl.JS{
		"Config": htmltmpl.JS(cfgJSON),
	})
}

// Passed returns true if the request carries a valid solved-challenge
// token. The token is accepted from either the configured cookie OR
// the configured header (X-App-Token by default). Header
// transport exists so cross-origin SPA fetches — which can't rely on
// cookies — can still authenticate by reading the token from the
// verify response body and attaching it on every API call.
func (h *Handler) Passed(r *http.Request) bool {
	cr := h.rules.Load()
	// Try cookie first (historical, same-origin path).
	if c, err := r.Cookie(cr.CookieName); err == nil {
		if h.validToken(c.Value, cr) {
			return true
		}
	}
	// Then try header transport (cross-origin SPA path).
	if name := strings.TrimSpace(cr.TokenHeaderName); name != "" {
		if v := strings.TrimSpace(r.Header.Get(name)); v != "" {
			if h.validToken(v, cr) {
				return true
			}
		}
	}
	return false
}

// validToken parses and validates a token of the form
// "<RFC3339 ts>.<HMAC-SHA256(secret, ts)>". Same shape regardless of
// whether the value arrived as a cookie or as a header.
func (h *Handler) validToken(value string, cr *rules.ChallengeRules) bool {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return false
	}
	tsStr, mac := parts[0], parts[1]
	ts, err := time.Parse(time.RFC3339, tsStr)
	if err != nil {
		return false
	}
	ttl := time.Duration(cr.TokenTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if time.Since(ts) > ttl {
		return false
	}
	expected := h.sign(tsStr)
	return hmac.Equal([]byte(mac), []byte(expected))
}

func (h *Handler) sign(payload string) string {
	m := hmac.New(sha256.New, h.secret)
	m.Write([]byte(payload))
	return hex.EncodeToString(m.Sum(nil))
}

// ServeHTTP handles two cases: showing the challenge, and verifying a solution.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cr := h.rules.Load()
	if r.URL.Path == cr.VerifyPath && r.Method == "POST" {
		h.verify(w, r, cr)
		return
	}
	h.serveChallenge(w, r, cr)
}

func (h *Handler) serveChallenge(w http.ResponseWriter, r *http.Request, cr *rules.ChallengeRules) {
	// SPA-aware path: when the request is an XHR/fetch rather than a
	// top-level document navigation, returning HTML is useless — the
	// SPA's JS can't execute the embedded <script>. Return a
	// structured 401 + JSON hint instead so the SPA can route the
	// user (or itself) through a separate challenge interstitial.
	if cr.SPAAwareResponse && isXHROrFetch(r) {
		h.serveSPAChallenge(w, r, cr)
		return
	}

	challenge, err := newChallengeNonce()
	if err != nil {
		http.Error(w, "challenge seed failed", http.StatusInternalServerError)
		return
	}
	challengeTS := time.Now().UTC().Format(time.RFC3339Nano)
	challengeSig := h.sign(h.challengePayload(challenge, challengeTS))
	target := strings.Repeat("0", normalizedDifficulty(cr.Difficulty))

	tmpl, err := h.compileTemplate(cr.HTMLTemplate)
	if err != nil {
		http.Error(w, "challenge template broken", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]string{
		"Challenge":    challenge,
		"Target":       target,
		"ChallengeTS":  challengeTS,
		"ChallengeSig": challengeSig,
		"VerifyPath":   cr.VerifyPath,
	}); err != nil {
		http.Error(w, "challenge render failed", http.StatusInternalServerError)
		return
	}

	ct := cr.ContentType
	if ct == "" {
		ct = "text/html; charset=utf-8"
	}
	sc := cr.StatusCode
	if sc == 0 {
		sc = http.StatusServiceUnavailable
	}
	// CORS: cross-origin callers (XHR/fetch from a different domain) must be
	// able to read this response. Without ACAO the browser shows only "CORS
	// error" and the challenge page is never visible to the client JS.
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(sc)
	_, _ = w.Write(buf.Bytes())
}

// serveSPAChallenge returns a structured 401 JSON response for
// XHR/fetch contexts where serving HTML would be useless. The body
// carries the same PoW metadata that the HTML page template gets,
// so an SPA can solve the challenge inline (SHA-256 nonce search),
// POST it to verify_path, and retry the original request with the
// returned token attached as the configured header. No popup or
// top-level navigation required — same shape as AWS WAF Bot Control's
// `getToken()` flow, just delivered as one JSON document.
func (h *Handler) serveSPAChallenge(w http.ResponseWriter, r *http.Request, cr *rules.ChallengeRules) {
	hdrName := cr.TokenHeaderName
	if hdrName == "" {
		hdrName = "X-App-Token"
	}

	challengeNonce, err := newChallengeNonce()
	if err != nil {
		http.Error(w, "challenge seed failed", http.StatusInternalServerError)
		return
	}
	challengeTS := time.Now().UTC().Format(time.RFC3339Nano)
	challengeSig := h.sign(h.challengePayload(challengeNonce, challengeTS))
	target := strings.Repeat("0", normalizedDifficulty(cr.Difficulty))

	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Expose-Headers", "WWW-Authenticate")
		w.Header().Set("Vary", "Origin")
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate",
		`Veilgate-Challenge realm="`+r.Host+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":        "challenge_required",
		"token_header": hdrName,
		"verify_path":  cr.VerifyPath,
		"challenge":    challengeNonce,
		"target":       target,
		"ts":           challengeTS,
		"sig":          challengeSig,
		"retry_after":  1,
	})
}

// isXHROrFetch returns true when the request is most likely an SPA
// XHR/fetch call rather than a top-level document navigation. We use
// three signals — any one is enough.
//
// Sec-Fetch-Dest is the most reliable (set by all modern browsers on
// every request, indicates the destination role: document, script,
// image, empty for fetch, etc.). X-Requested-With is the legacy XHR
// hint still set by jQuery and friends. Accept lacking text/html is a
// weak signal that the caller isn't expecting an HTML page back.
func isXHROrFetch(r *http.Request) bool {
	dest := strings.ToLower(r.Header.Get("Sec-Fetch-Dest"))
	switch dest {
	case "document", "iframe", "frame":
		return false
	case "empty", "object", "embed":
		// "empty" is the value Chrome/Firefox set on fetch() and
		// XMLHttpRequest from JS.
		return true
	}
	if strings.EqualFold(r.Header.Get("X-Requested-With"), "XMLHttpRequest") {
		return true
	}
	// Last-resort sniff: if the client lists JSON but not HTML in its
	// Accept, it's almost certainly an API consumer. Plain "*/*" is
	// ambiguous and we don't trigger on it.
	accept := strings.ToLower(r.Header.Get("Accept"))
	if accept != "" && !strings.Contains(accept, "text/html") &&
		(strings.Contains(accept, "application/json") ||
			strings.Contains(accept, "application/xml")) {
		return true
	}
	return false
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request, cr *rules.ChallengeRules) {
	ok, code := h.verifyPOW(r, cr)
	if !ok {
		http.Error(w, "challenge verification failed", code)
		return
	}
	ts := time.Now().Format(time.RFC3339)
	mac := h.sign(ts)
	tokenValue := ts + "." + mac
	// Use the same TTL that verifyPOW uses (capped at 10 min) so the
	// cookie and the HMAC validation window stay in sync. Previously
	// the cookie could have a 30-min lifetime while the HMAC rejected
	// the same token after 10 min — a confusing state where the browser
	// presented a valid-looking cookie that was always rejected.
	ttl := h.challengeTTL(cr)
	cookiePath := cr.CookiePath
	if cookiePath == "" {
		cookiePath = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cr.CookieName,
		Value:    tokenValue,
		Path:     cookiePath,
		Domain:   strings.TrimSpace(cr.CookieDomain),
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: parseSameSite(cr.CookieSameSite),
		Expires:  time.Now().Add(ttl),
	})

	// CORS for cross-origin SPAs reading the token from the response
	// body. Echo the Origin header (not "*") because the request may
	// be credentialed.
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}

	// Return token in body too so cross-origin SPAs that can't
	// receive cookies can grab it and attach as a header on
	// subsequent requests.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"token":      tokenValue,
		"expires_in": int(ttl.Seconds()),
		"header":     cr.TokenHeaderName,
	})
}

// parseSameSite maps the operator-supplied string to a SameSite mode.
// Unknown / empty values fall back to Strict (the historical default).
func parseSameSite(v string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "lax":
		return http.SameSiteLaxMode
	case "none":
		return http.SameSiteNoneMode
	case "strict", "":
		return http.SameSiteStrictMode
	default:
		return http.SameSiteStrictMode
	}
}

func (h *Handler) verifyPOW(r *http.Request, cr *rules.ChallengeRules) (bool, int) {
	type verifyRequest struct {
		Challenge string          `json:"challenge"`
		Nonce     json.RawMessage `json:"nonce"`
		TS        string          `json:"ts"`
		Sig       string          `json:"sig"`
	}

	const maxBody = 8 * 1024
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	var req verifyRequest
	if err := dec.Decode(&req); err != nil {
		return false, http.StatusBadRequest
	}
	if req.Challenge == "" || req.TS == "" || req.Sig == "" || len(req.Nonce) == 0 {
		return false, http.StatusBadRequest
	}
	if !hmac.Equal(
		[]byte(req.Sig),
		[]byte(h.sign(h.challengePayload(req.Challenge, req.TS))),
	) {
		return false, http.StatusUnauthorized
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, req.TS)
	if err != nil {
		return false, http.StatusBadRequest
	}
	now := time.Now().UTC()
	if issuedAt.After(now.Add(2 * time.Minute)) {
		return false, http.StatusUnauthorized
	}
	if now.Sub(issuedAt) > h.challengeTTL(cr) {
		return false, http.StatusUnauthorized
	}
	nonce, ok := parseNonce(req.Nonce)
	if !ok {
		return false, http.StatusBadRequest
	}
	digest := sha256.Sum256([]byte(req.Challenge + ":" + strconv.FormatInt(nonce, 10)))
	wantPrefix := strings.Repeat("0", normalizedDifficulty(cr.Difficulty))
	if !strings.HasPrefix(hex.EncodeToString(digest[:]), wantPrefix) {
		return false, http.StatusUnauthorized
	}
	return true, http.StatusNoContent
}

func (h *Handler) challengePayload(challenge, ts string) string {
	return "pow:" + challenge + ":" + ts
}

// compileTemplate caches the compiled template per source. When the holder
// swaps, the cache entry is invalidated the next time a request sees a
// different source string.
func (h *Handler) compileTemplate(src string) (*template.Template, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tmpl != nil && h.tmplSrc == src {
		return h.tmpl, nil
	}
	t, err := template.New("challenge").Parse(src)
	if err != nil {
		return nil, err
	}
	h.tmpl = t
	h.tmplSrc = src
	return t, nil
}

func max1(n int) int {
	if n < 1 {
		return 4
	}
	return n
}

func normalizedDifficulty(n int) int {
	n = max1(n)
	if n > 4 {
		return 4
	}
	return n
}

func (h *Handler) challengeTTL(cr *rules.ChallengeRules) time.Duration {
	ttl := time.Duration(cr.TokenTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	maxTTL := h.maxTTL
	if maxTTL <= 0 {
		maxTTL = 60 * time.Minute
	}
	if ttl > maxTTL {
		return maxTTL
	}
	return ttl
}

func parseNonce(raw json.RawMessage) (int64, bool) {
	s := strings.TrimSpace(string(raw))
	if s == "" {
		return 0, false
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		u, err := strconv.Unquote(s)
		if err != nil {
			return 0, false
		}
		s = u
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func newChallengeNonce() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		return true
	}
	return false
}
