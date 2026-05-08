package challenge

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/C0oki3s/veilgate/internal/rules"
)

// Handler serves a JS proof-of-work page. Real browsers solve it in <1s.
// Headless HTTP clients (the LLM-agent common case) never solve it at all.
// Sophisticated agents with headless Chromium will, which is by design —
// we're raising cost, not making the site invulnerable.
//
// Every knob — HTML body, difficulty, cookie name, TTL, verify path — is
// loaded from rules/challenge.yaml so operators can tune live.
type Handler struct {
	secret []byte

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
// `difficultyOverride` and `ttlOverride` are applied only when non-zero,
// matching the old API for compat with the existing main.go wiring.
func NewHandler(secret string, difficultyOverride int, ttlOverride time.Duration) *Handler {
	cr, _ := rules.LoadChallenge("")
	// Apply overrides on a copy so the embedded default isn't mutated.
	if difficultyOverride > 0 {
		cr.Difficulty = difficultyOverride
	}
	if ttlOverride > 0 {
		cr.TokenTTLMinutes = int(ttlOverride / time.Minute)
	}
	return &Handler{
		secret: []byte(secret),
		rules:  rules.NewHolder(cr),
	}
}

// SetRules swaps in a hot-reloadable holder.
func (h *Handler) SetRules(holder *rules.Holder[rules.ChallengeRules]) {
	if h == nil || holder == nil {
		return
	}
	h.rules = holder
}

// Passed returns true if the request carries a valid solved-challenge cookie.
func (h *Handler) Passed(r *http.Request) bool {
	cr := h.rules.Load()
	c, err := r.Cookie(cr.CookieName)
	if err != nil {
		return false
	}
	parts := strings.SplitN(c.Value, ".", 2)
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
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(sc)
	_, _ = w.Write(buf.Bytes())
}

func (h *Handler) verify(w http.ResponseWriter, r *http.Request, cr *rules.ChallengeRules) {
	ok, code := h.verifyPOW(r, cr)
	if !ok {
		http.Error(w, "challenge verification failed", code)
		return
	}
	ts := time.Now().Format(time.RFC3339)
	mac := h.sign(ts)
	ttl := time.Duration(cr.TokenTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	cookiePath := cr.CookiePath
	if cookiePath == "" {
		cookiePath = "/"
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cr.CookieName,
		Value:    ts + "." + mac,
		Path:     cookiePath,
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(ttl),
	})
	w.WriteHeader(http.StatusNoContent)
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
	if now.Sub(issuedAt) > challengeTTL(cr) {
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
	if n > 64 {
		return 64
	}
	return n
}

func challengeTTL(cr *rules.ChallengeRules) time.Duration {
	ttl := time.Duration(cr.TokenTTLMinutes) * time.Minute
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	if ttl > 10*time.Minute {
		ttl = 10 * time.Minute
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
