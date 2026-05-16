package challenge

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/C0oki3s/veilgate/internal/rules"
)

const testRulesDir = "../../rules"

func testNewHandler(t *testing.T, secret string) *Handler {
	t.Helper()
	h, err := NewHandlerFromDir(secret, testRulesDir, 0, 0)
	if err != nil {
		t.Fatalf("NewHandlerFromDir: %v", err)
	}
	return h
}

func TestVerifyPOWRejectsUnsignedPayload(t *testing.T) {
	h := testNewHandler(t, "test-secret")
	cr := h.rules.Load()
	cr.Difficulty = 1

	body := map[string]any{
		"challenge": "abc",
		"nonce":     1,
	}
	req := httptest.NewRequest(http.MethodPost, cr.VerifyPath, mustJSON(t, body))

	ok, code := h.verifyPOW(req, cr)
	if ok {
		t.Fatalf("expected verifyPOW to reject unsigned payload")
	}
	if code != http.StatusBadRequest {
		t.Fatalf("expected 400 for malformed payload, got %d", code)
	}
}

func TestVerifyPOWAcceptsValidPayload(t *testing.T) {
	h := testNewHandler(t, "test-secret")
	cr := h.rules.Load()
	cr.Difficulty = 1
	cr.TokenTTLMinutes = 1

	challenge := "deadbeefcafebabe"
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := solveNonce(t, challenge, strings.Repeat("0", normalizedDifficulty(cr.Difficulty)))
	sig := h.sign(h.challengePayload(challenge, ts))

	body := map[string]any{
		"challenge": challenge,
		"nonce":     nonce,
		"ts":        ts,
		"sig":       sig,
	}
	req := httptest.NewRequest(http.MethodPost, cr.VerifyPath, mustJSON(t, body))

	ok, code := h.verifyPOW(req, cr)
	if !ok {
		t.Fatalf("expected verifyPOW to accept valid payload, got code %d", code)
	}
	if code != http.StatusNoContent {
		t.Fatalf("expected 204 code on success, got %d", code)
	}
}

func TestVerifySetsSecureCookieWhenForwardedProtoHTTPS(t *testing.T) {
	h := testNewHandler(t, "test-secret")
	cr := h.rules.Load()
	cr.Difficulty = 1
	cr.TokenTTLMinutes = 1

	challenge := "f00dbabe1234"
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := solveNonce(t, challenge, strings.Repeat("0", normalizedDifficulty(cr.Difficulty)))
	sig := h.sign(h.challengePayload(challenge, ts))
	body := map[string]any{
		"challenge": challenge,
		"nonce":     strconv.FormatInt(nonce, 10),
		"ts":        ts,
		"sig":       sig,
	}

	req := httptest.NewRequest(http.MethodPost, cr.VerifyPath, mustJSON(t, body))
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	h.verify(rr, req, cr)

	// 200 OK with a JSON body that includes the token, plus a
	// Set-Cookie carrying the same value. We need the body so
	// cross-origin SPAs can read the token; 204 No Content forbids
	// a body per RFC 7231, so 200 is the right status now.
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "Secure") {
		t.Fatalf("expected secure flag in set-cookie, got %q", cookie)
	}
	var bodyResp struct {
		Token     string `json:"token"`
		ExpiresIn int    `json:"expires_in"`
		Header    string `json:"header"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &bodyResp); err != nil {
		t.Fatalf("response body not JSON: %v (body=%q)", err, rr.Body.String())
	}
	if bodyResp.Token == "" {
		t.Fatalf("response body missing token field")
	}
	// The cookie value and the body token must be identical — same
	// value, two transports.
	if !strings.Contains(cookie, bodyResp.Token) {
		t.Fatalf("cookie/body token mismatch: cookie=%q body=%q", cookie, bodyResp.Token)
	}
}

// TestVerifyCookieHonoursDomainAndSameSite checks that the
// operator-configured cookie scope makes it onto the Set-Cookie
// header. This is what enables app.example.com + api.example.com
// deployments — without Domain= the cookie stays host-only.
func TestVerifyCookieHonoursDomainAndSameSite(t *testing.T) {
	h := testNewHandler(t, "test-secret")
	cr := h.rules.Load()
	cr.Difficulty = 1
	cr.TokenTTLMinutes = 1
	cr.CookieDomain = ".example.com"
	cr.CookieSameSite = "lax"

	challenge := "0123456789abcdef"
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	nonce := solveNonce(t, challenge, strings.Repeat("0", normalizedDifficulty(cr.Difficulty)))
	sig := h.sign(h.challengePayload(challenge, ts))
	body := map[string]any{
		"challenge": challenge, "nonce": nonce, "ts": ts, "sig": sig,
	}
	req := httptest.NewRequest(http.MethodPost, cr.VerifyPath, mustJSON(t, body))
	rr := httptest.NewRecorder()
	h.verify(rr, req, cr)

	cookie := rr.Header().Get("Set-Cookie")
	// Go's net/http normalises ".example.com" → "example.com" in the
	// Domain attribute (RFC 6265 §4.1.2.3 says both have identical
	// subdomain-match semantics). Accept either form.
	if !strings.Contains(cookie, "Domain=.example.com") &&
		!strings.Contains(cookie, "Domain=example.com") {
		t.Fatalf("expected Domain=example.com or .example.com, got %q", cookie)
	}
	if !strings.Contains(cookie, "SameSite=Lax") {
		t.Fatalf("expected SameSite=Lax, got %q", cookie)
	}
}

// TestPassedAcceptsHeaderToken verifies that a token presented in the
// X-Veilgate-Token header (the cross-origin SPA transport) is
// accepted as well as a cookie. Without this, SPAs on a different
// origin couldn't authenticate.
func TestPassedAcceptsHeaderToken(t *testing.T) {
	h := testNewHandler(t, "test-secret")
	cr := h.rules.Load()
	cr.TokenTTLMinutes = 5
	cr.TokenHeaderName = "X-Veilgate-Token"

	// Forge a valid token the same way verify() does.
	ts := time.Now().Format(time.RFC3339)
	tokenValue := ts + "." + h.sign(ts)

	// Request with header but no cookie should pass.
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("X-Veilgate-Token", tokenValue)
	if !h.Passed(req) {
		t.Fatalf("Passed() rejected valid header token")
	}

	// Same value as cookie should also pass (back-compat).
	req2 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req2.AddCookie(&http.Cookie{Name: cr.CookieName, Value: tokenValue})
	if !h.Passed(req2) {
		t.Fatalf("Passed() rejected valid cookie")
	}

	// Tampered MAC should fail.
	req3 := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req3.Header.Set("X-Veilgate-Token", ts+".deadbeef")
	if h.Passed(req3) {
		t.Fatalf("Passed() accepted tampered header token")
	}
}

// TestServeChallengeSPAAware verifies that an XHR/fetch context
// receives a 401 JSON challenge instead of the 503 HTML page. The
// HTML is useless from a fetch() — there's no <script> execution —
// so the JSON shape lets the SPA route around the failure.
func TestServeChallengeSPAAware(t *testing.T) {
	h := testNewHandler(t, "test-secret")
	cr := h.rules.Load()
	cr.SPAAwareResponse = true
	// Keep PoW cheap so the round-trip stays well under the per-test
	// timeout. The handler itself is independent of difficulty.
	cr.Difficulty = 1

	// fetch() from an SPA — Sec-Fetch-Dest is "empty".
	req := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	h.serveChallenge(rr, req, cr)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected JSON content-type, got %q", ct)
	}
	if rr.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("expected WWW-Authenticate header on SPA challenge")
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("expected CORS allow-origin to echo Origin, got %q", got)
	}
	var body struct {
		Error       string `json:"error"`
		TokenHeader string `json:"token_header"`
		VerifyPath  string `json:"verify_path"`
		Challenge   string `json:"challenge"`
		Target      string `json:"target"`
		TS          string `json:"ts"`
		Sig         string `json:"sig"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body not JSON: %v", err)
	}
	if body.Error != "challenge_required" {
		t.Fatalf("expected error=challenge_required, got %q", body.Error)
	}
	if body.TokenHeader == "" {
		t.Fatalf("expected token_header in response body, got empty")
	}
	if body.VerifyPath == "" || body.Challenge == "" || body.Target == "" ||
		body.TS == "" || body.Sig == "" {
		t.Fatalf("expected PoW metadata in body (verify_path/challenge/target/ts/sig), got %+v", body)
	}

	// Round-trip: solve the PoW the SPA way, post to verify, attach the
	// returned token to a follow-up request, expect Passed() to accept it.
	nonce := solveNonce(t, body.Challenge, body.Target)
	verifyReq := httptest.NewRequest(http.MethodPost, body.VerifyPath, mustJSON(t, map[string]any{
		"challenge": body.Challenge,
		"nonce":     nonce,
		"ts":        body.TS,
		"sig":       body.Sig,
	}))
	verifyRR := httptest.NewRecorder()
	h.verify(verifyRR, verifyReq, cr)
	if verifyRR.Code != http.StatusOK {
		t.Fatalf("verify after SPA solve: expected 200, got %d (body=%s)", verifyRR.Code, verifyRR.Body.String())
	}
	var verifyBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(verifyRR.Body.Bytes(), &verifyBody); err != nil {
		t.Fatalf("verify response not JSON: %v", err)
	}
	if verifyBody.Token == "" {
		t.Fatalf("verify response missing token")
	}
	followUp := httptest.NewRequest(http.MethodGet, "/api/data", nil)
	followUp.Header.Set(body.TokenHeader, verifyBody.Token)
	if !h.Passed(followUp) {
		t.Fatalf("Passed() rejected token from SPA-solved challenge")
	}

	// Document navigation should still get the HTML challenge.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Sec-Fetch-Dest", "document")
	rr2 := httptest.NewRecorder()
	h.serveChallenge(rr2, req2, cr)

	if rr2.Code != http.StatusServiceUnavailable {
		t.Fatalf("document navigation: expected 503, got %d", rr2.Code)
	}
	if ct := rr2.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("document navigation: expected HTML content-type, got %q", ct)
	}
}

// TestIsXHROrFetchHeuristic checks the SPA-vs-document detection
// logic directly so future changes to the heuristic don't silently
// break the SPA path.
func TestIsXHROrFetchHeuristic(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{"empty headers", nil, false},
		{"document fetch", map[string]string{"Sec-Fetch-Dest": "document"}, false},
		{"fetch() from JS", map[string]string{"Sec-Fetch-Dest": "empty"}, true},
		{"iframe", map[string]string{"Sec-Fetch-Dest": "iframe"}, false},
		{"image fetch", map[string]string{"Sec-Fetch-Dest": "image"}, false},
		{"jQuery XHR", map[string]string{"X-Requested-With": "XMLHttpRequest"}, true},
		{"JSON-only accept", map[string]string{"Accept": "application/json"}, true},
		{"HTML accept", map[string]string{"Accept": "text/html,application/xhtml+xml"}, false},
		{"wildcard accept", map[string]string{"Accept": "*/*"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := isXHROrFetch(r); got != tc.want {
				t.Fatalf("isXHROrFetch(%v) = %v, want %v", tc.headers, got, tc.want)
			}
		})
	}
}

func solveNonce(t *testing.T, challenge, prefix string) int64 {
	t.Helper()
	for i := int64(0); i < 1_000_000; i++ {
		d := sha256.Sum256([]byte(challenge + ":" + strconv.FormatInt(i, 10)))
		if strings.HasPrefix(hex.EncodeToString(d[:]), prefix) {
			return i
		}
	}
	t.Fatalf("failed to solve nonce for challenge %q", challenge)
	return 0
}

func mustJSON(t *testing.T, v any) *bytes.Reader {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return bytes.NewReader(b)
}

func TestChallengeTTLIsCapped(t *testing.T) {
	cr := &rules.ChallengeRules{TokenTTLMinutes: 60}
	if got := challengeTTL(cr); got != 10*time.Minute {
		t.Fatalf("expected cap at 10m, got %v", got)
	}
}
