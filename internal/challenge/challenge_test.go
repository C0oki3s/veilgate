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

func TestVerifyPOWRejectsUnsignedPayload(t *testing.T) {
	h := NewHandler("test-secret", 0, 0)
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
	h := NewHandler("test-secret", 0, 0)
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
	h := NewHandler("test-secret", 0, 0)
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

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	cookie := rr.Header().Get("Set-Cookie")
	if !strings.Contains(cookie, "Secure") {
		t.Fatalf("expected secure flag in set-cookie, got %q", cookie)
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
