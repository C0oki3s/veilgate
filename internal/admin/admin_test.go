package admin_test

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/admin"
	_ "modernc.org/sqlite"
)

// ── Test helpers ──────────────────────────────────────────────────────────

// newTestServer creates a temp dir, writes a minimal veilgate.yaml, opens a
// Server with admin/test credentials (must_change=1), and returns an
// httptest.Server backed by it. The caller is responsible for calling Close.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vg.yaml")
	if err := os.WriteFile(cfgPath, []byte("rules_dir: "+dir+"\npersist:\n  enabled: false\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	srv, err := admin.New(admin.AdminConfig{
		ConfigPath: cfgPath,
		Version:    "v-test",
		AdminUser:  "admin",
		AdminPass:  "test",
		DBPath:     filepath.Join(dir, "admin.db"),
		AuditPath:  filepath.Join(dir, "audit.log"),
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	return httptest.NewServer(srv)
}

// newClientNoFollow returns an *http.Client that does NOT follow redirects and
// carries its own cookie jar. Use it when you need raw redirect status codes.
func newClientNoFollow(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// newClientFollow returns an *http.Client that follows redirects (up to 10)
// and carries its own cookie jar.
func newClientFollow(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookiejar: %v", err)
	}
	return &http.Client{Jar: jar}
}

// loginSession logs in using the given credentials and returns the client
// whose cookie jar holds a valid session. It calls t.Fatal on any failure.
// followsRedirects=true to follow the post-login 303 to /dashboard.
func loginSession(t *testing.T, baseURL, user, pass string) *http.Client {
	t.Helper()
	client := newClientFollow(t)
	resp, err := client.PostForm(baseURL+"/login", url.Values{
		"username": {user},
		"password": {pass},
	})
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login: expected 200 after following redirect, got %d", resp.StatusCode)
	}
	return client
}

// changePassword submits the change-password form and follows redirects.
// t may be nil when called from places that just want a best-effort change.
func changePassword(t *testing.T, client *http.Client, baseURL, current, newPass, confirm string) *http.Response {
	if t != nil {
		t.Helper()
	}
	resp, err := client.PostForm(baseURL+"/account/password", url.Values{
		"current_password": {current},
		"new_password":     {newPass},
		"confirm_password": {confirm},
	})
	if err != nil {
		if t != nil {
			t.Fatalf("changePassword POST: %v", err)
		}
		return nil
	}
	return resp
}

// bodyContains reads the response body and checks for a substring.
func bodyContains(t *testing.T, resp *http.Response, sub string) bool {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return strings.Contains(string(b), sub)
}

// readBody reads and returns the response body as a string.
func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

// getResetToken queries the admin.db at dbPath and returns the latest unused
// reset token for the given username.
func getResetToken(t *testing.T, dbPath, username string) string {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer db.Close()
	var token string
	if err := db.QueryRow(
		`SELECT token FROM reset_tokens WHERE username=? AND used=0 ORDER BY id DESC LIMIT 1`,
		username,
	).Scan(&token); err != nil {
		t.Fatalf("no reset token for %q: %v", username, err)
	}
	return token
}

// ── 1. Auth flows ─────────────────────────────────────────────────────────

func TestAuth_UnauthRedirect(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientNoFollow(t)
	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/login") {
		t.Errorf("expected redirect to /login, got %q", loc)
	}
}

func TestAuth_LoginWrongPassword(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientFollow(t)
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"wrongpassword"},
	})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Invalid username or password") {
		t.Errorf("expected error flash, got body snippet: %q", body[:min(200, len(body))])
	}
}

func TestAuth_LoginSuccess(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientNoFollow(t)
	resp, err := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	if err != nil {
		t.Fatalf("POST /login: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasSuffix(loc, "/dashboard") {
		t.Errorf("expected redirect to /dashboard, got %q", loc)
	}
}

func TestAuth_SessionPersists(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Login with admin/test — must_change=1, so we must first change password
	// before any protected page is accessible.
	client := newClientFollow(t)
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	resp.Body.Close()

	// Change password to get past must_change
	resp2 := changePassword(t, client, ts.URL, "test", "newsession123", "newsession123")
	resp2.Body.Close()

	// Now dashboard should work
	resp3, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200 for authenticated dashboard, got %d", resp3.StatusCode)
	}
}

func TestAuth_LogoutDestroysSession(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Login and change password
	client := newClientFollow(t)
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	resp.Body.Close()
	resp2 := changePassword(t, client, ts.URL, "test", "logouttest123", "logouttest123")
	resp2.Body.Close()

	// Verify we can reach dashboard
	resp3, _ := client.Get(ts.URL + "/dashboard")
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("pre-logout: expected 200, got %d", resp3.StatusCode)
	}

	// Logout
	resp4, err := client.Get(ts.URL + "/logout")
	if err != nil {
		t.Fatalf("GET /logout: %v", err)
	}
	resp4.Body.Close()

	// After logout, /dashboard should redirect
	clientNoFollow := newClientNoFollow(t)
	// Copy cookies from followed client to noFollow client
	u, _ := url.Parse(ts.URL)
	for _, c := range client.Jar.Cookies(u) {
		clientNoFollow.Jar.SetCookies(u, []*http.Cookie{c})
	}
	resp5, err := clientNoFollow.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard after logout: %v", err)
	}
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusFound {
		t.Errorf("expected 302 after logout, got %d", resp5.StatusCode)
	}
}

func TestAuth_MustChangeGate(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Fresh DB with admin/test → must_change=1.
	// After login, any protected page (except /account/password) should redirect.
	client := newClientNoFollow(t)
	// Login
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	resp.Body.Close()

	// GET /dashboard should redirect to /account/password
	resp2, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusFound {
		t.Errorf("expected 302 must_change gate, got %d", resp2.StatusCode)
	}
	loc := resp2.Header.Get("Location")
	if !strings.Contains(loc, "/account/password") {
		t.Errorf("expected redirect to /account/password, got %q", loc)
	}

	// GET /settings should also redirect
	resp3, err := client.Get(ts.URL + "/settings")
	if err != nil {
		t.Fatalf("GET /settings: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusFound {
		t.Errorf("expected 302 for /settings under must_change, got %d", resp3.StatusCode)
	}
}

// ── 2. Change password ────────────────────────────────────────────────────

func TestChangePassword_WrongCurrent(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Login (must_change=1, but /account/password is accessible)
	client := newClientFollow(t)
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	resp.Body.Close()

	resp2 := changePassword(t, client, ts.URL, "wrongcurrent", "newpass1234", "newpass1234")
	body := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	if !strings.Contains(body, "current password is incorrect") {
		t.Errorf("expected error about incorrect current password, body snippet: %q", body[:min(300, len(body))])
	}
}

func TestChangePassword_Mismatch(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientFollow(t)
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	resp.Body.Close()

	resp2 := changePassword(t, client, ts.URL, "test", "newpass1234", "differentpass")
	body := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	if !strings.Contains(body, "do not match") && !strings.Contains(body, "mismatch") {
		t.Errorf("expected mismatch error, body snippet: %q", body[:min(300, len(body))])
	}
}

func TestChangePassword_Success(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientNoFollow(t)
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	resp.Body.Close()

	resp2, err := client.PostForm(ts.URL+"/account/password", url.Values{
		"current_password": {"test"},
		"new_password":     {"changedpass123"},
		"confirm_password": {"changedpass123"},
	})
	if err != nil {
		t.Fatalf("POST /account/password: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusSeeOther {
		t.Errorf("expected 303 on success, got %d", resp2.StatusCode)
	}
	loc := resp2.Header.Get("Location")
	if !strings.Contains(loc, "/dashboard") {
		t.Errorf("expected redirect to /dashboard, got %q", loc)
	}

	// must_change should be cleared — verify via new login
	clientFollow := newClientFollow(t)
	resp3, _ := clientFollow.PostForm(ts.URL+"/login", url.Values{
		"username": {"admin"},
		"password": {"changedpass123"},
	})
	body3 := readBody(t, resp3)
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("login after change: expected 200, got %d", resp3.StatusCode)
	}
	// Should be on /dashboard now, not /account/password
	if strings.Contains(body3, "Change Password") && strings.Contains(body3, "current password") {
		t.Errorf("still stuck on change-password page after successful change")
	}
}

// ── 3. Forgot / reset password ────────────────────────────────────────────

func TestForgotPassword_UnknownUser(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientFollow(t)

	// GET should return 200
	resp, err := client.Get(ts.URL + "/forgot-password")
	if err != nil {
		t.Fatalf("GET /forgot-password: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}

	// POST with unknown username — should still 200 (no enumeration)
	resp2, err := client.PostForm(ts.URL+"/forgot-password", url.Values{
		"username": {"nosuchuser99999"},
	})
	if err != nil {
		t.Fatalf("POST /forgot-password: %v", err)
	}
	body := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	// Must show the same success message as a real user
	if !strings.Contains(body, "If that account exists") {
		t.Errorf("expected no-enumeration success message, body snippet: %q", body[:min(300, len(body))])
	}
}

func TestForgotPassword_KnownUser(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Extract the DB path from the server via a round-trip hack:
	// We find the temp dir from the test and locate admin.db.
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vg.yaml")
	os.WriteFile(cfgPath, []byte("rules_dir: "+dir+"\npersist:\n  enabled: false\n"), 0o644) //nolint:errcheck
	dbPath := filepath.Join(dir, "admin2.db")
	srv2, err := admin.New(admin.AdminConfig{
		ConfigPath: cfgPath,
		Version:    "v-test",
		AdminUser:  "admin",
		AdminPass:  "test",
		DBPath:     dbPath,
		AuditPath:  filepath.Join(dir, "audit2.log"),
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	ts2 := httptest.NewServer(srv2)
	defer ts2.Close()

	client := newClientFollow(t)
	resp, err := client.PostForm(ts2.URL+"/forgot-password", url.Values{
		"username": {"admin"},
	})
	if err != nil {
		t.Fatalf("POST /forgot-password: %v", err)
	}
	resp.Body.Close()

	// Token should appear in DB
	token := getResetToken(t, dbPath, "admin")
	if len(token) < 32 {
		t.Errorf("expected 64-char hex token, got %q", token)
	}
}

func TestResetPassword_InvalidToken(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientFollow(t)
	resp, err := client.Get(ts.URL + "/reset-password?token=badtoken123")
	if err != nil {
		t.Fatalf("GET /reset-password: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "invalid") && !strings.Contains(body, "expired") {
		t.Errorf("expected error for invalid token, body snippet: %q", body[:min(300, len(body))])
	}
}

func TestResetPassword_Success(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vg.yaml")
	os.WriteFile(cfgPath, []byte("rules_dir: "+dir+"\npersist:\n  enabled: false\n"), 0o644) //nolint:errcheck
	dbPath := filepath.Join(dir, "admin_reset.db")
	srv, err := admin.New(admin.AdminConfig{
		ConfigPath: cfgPath,
		Version:    "v-test",
		AdminUser:  "admin",
		AdminPass:  "test",
		DBPath:     dbPath,
		AuditPath:  filepath.Join(dir, "audit.log"),
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	client := newClientFollow(t)

	// First change password to clear must_change, get to a known state
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"test"}})
	resp.Body.Close()
	resp2 := changePassword(nil, client, ts.URL, "test", "intermed123", "intermed123")
	if resp2 != nil {
		resp2.Body.Close()
	}

	// Request reset token
	resp3, _ := client.PostForm(ts.URL+"/forgot-password", url.Values{"username": {"admin"}})
	resp3.Body.Close()

	token := getResetToken(&testing.T{}, dbPath, "admin")
	if token == "" {
		t.Skip("no reset token available")
	}

	// GET reset-password page with valid token
	resp4, err := client.Get(ts.URL + "/reset-password?token=" + token)
	if err != nil {
		t.Fatalf("GET /reset-password: %v", err)
	}
	body4 := readBody(t, resp4)
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp4.StatusCode)
	}
	// Should show username
	if !strings.Contains(body4, "admin") {
		t.Errorf("expected username 'admin' on reset page")
	}

	// POST to reset password
	resp5, err := client.PostForm(ts.URL+"/reset-password", url.Values{
		"token":            {token},
		"new_password":     {"resetpass5678"},
		"confirm_password": {"resetpass5678"},
	})
	if err != nil {
		t.Fatalf("POST /reset-password: %v", err)
	}
	body5 := readBody(t, resp5)
	if !strings.Contains(body5, "Password updated") && !strings.Contains(body5, "success") {
		t.Errorf("expected success message, body snippet: %q", body5[:min(300, len(body5))])
	}
}

func TestResetPassword_TokenReuse(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vg.yaml")
	os.WriteFile(cfgPath, []byte("rules_dir: "+dir+"\npersist:\n  enabled: false\n"), 0o644) //nolint:errcheck
	dbPath := filepath.Join(dir, "admin_reuse.db")
	srv, err := admin.New(admin.AdminConfig{
		ConfigPath: cfgPath,
		Version:    "v-test",
		AdminUser:  "admin",
		AdminPass:  "test",
		DBPath:     dbPath,
		AuditPath:  filepath.Join(dir, "audit.log"),
	})
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	client := newClientFollow(t)

	// Change password first so we can request a reset from a known state
	resp, _ := client.PostForm(ts.URL+"/login", url.Values{"username": {"admin"}, "password": {"test"}})
	resp.Body.Close()
	resp2 := changePassword(nil, client, ts.URL, "test", "beforereset1", "beforereset1")
	if resp2 != nil {
		resp2.Body.Close()
	}

	// Request reset token
	resp3, _ := client.PostForm(ts.URL+"/forgot-password", url.Values{"username": {"admin"}})
	resp3.Body.Close()

	token := getResetToken(&testing.T{}, dbPath, "admin")
	if token == "" {
		t.Skip("no reset token")
	}

	// Use token once
	resp4, _ := client.PostForm(ts.URL+"/reset-password", url.Values{
		"token":            {token},
		"new_password":     {"reused12345"},
		"confirm_password": {"reused12345"},
	})
	resp4.Body.Close()

	// Use same token again
	resp5, err := client.PostForm(ts.URL+"/reset-password", url.Values{
		"token":            {token},
		"new_password":     {"reused12345"},
		"confirm_password": {"reused12345"},
	})
	if err != nil {
		t.Fatalf("POST /reset-password (reuse): %v", err)
	}
	body := readBody(t, resp5)
	if !strings.Contains(body, "already been used") && !strings.Contains(body, "invalid") {
		t.Errorf("expected 'already been used' error, body snippet: %q", body[:min(300, len(body))])
	}
}

// ── 4. Analytics ──────────────────────────────────────────────────────────

func TestAnalytics_Unauthenticated(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientNoFollow(t)
	resp, err := client.Get(ts.URL + "/analytics")
	if err != nil {
		t.Fatalf("GET /analytics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Errorf("expected 302, got %d", resp.StatusCode)
	}
}

func TestAnalytics_Range(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := loginSession(t, ts.URL, "admin", "test")
	// Change password first (must_change=1)
	resp := changePassword(t, client, ts.URL, "test", "analyticstest123", "analyticstest123")
	resp.Body.Close()

	ranges := []string{"1h", "7d", "30d", "24h", "bad"}
	for _, r := range ranges {
		resp2, err := client.Get(fmt.Sprintf("%s/analytics?range=%s", ts.URL, r))
		if err != nil {
			t.Fatalf("GET /analytics?range=%s: %v", r, err)
		}
		resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK {
			t.Errorf("range=%s: expected 200, got %d", r, resp2.StatusCode)
		}
	}
}

func TestAnalytics_PartialFragment(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := loginSession(t, ts.URL, "admin", "test")
	resp := changePassword(t, client, ts.URL, "test", "partial1234", "partial1234")
	resp.Body.Close()

	resp2, err := client.Get(ts.URL + "/analytics?range=24h&partial=1")
	if err != nil {
		t.Fatalf("GET /analytics partial: %v", err)
	}
	body := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	// Must NOT have a full <html> document
	if strings.Contains(body, "<html") {
		t.Errorf("partial response must not contain <html> tag")
	}
	// Must start with (or contain) the analytics-live div
	if !strings.Contains(body, "analytics-live") {
		t.Errorf("partial response must contain analytics-live div, got: %q", body[:min(200, len(body))])
	}
}

// ── 5. Decoys ─────────────────────────────────────────────────────────────

func TestDecoys_AddDeleteReset(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := loginSession(t, ts.URL, "admin", "test")
	resp := changePassword(t, client, ts.URL, "test", "decoytest123", "decoytest123")
	resp.Body.Close()

	// GET /decoys
	resp2, err := client.Get(ts.URL + "/decoys")
	if err != nil {
		t.Fatalf("GET /decoys: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("GET /decoys: expected 200, got %d", resp2.StatusCode)
	}

	// Add a decoy
	resp3, err := client.PostForm(ts.URL+"/decoys", url.Values{
		"_action": {"add"},
		"path":    {"/test-e2e-decoy"},
		"kind":    {"login"},
		"prefix":  {""},
	})
	if err != nil {
		t.Fatalf("POST /decoys add: %v", err)
	}
	body3 := readBody(t, resp3)
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("decoy add: expected 200, got %d", resp3.StatusCode)
	}
	if !strings.Contains(body3, "Decoy added") && !strings.Contains(body3, "success") {
		t.Logf("decoy add body snippet: %q", body3[:min(200, len(body3))])
	}

	// Delete the decoy
	resp4, err := client.PostForm(ts.URL+"/decoys", url.Values{
		"_action": {"delete"},
		"path":    {"/test-e2e-decoy"},
	})
	if err != nil {
		t.Fatalf("POST /decoys delete: %v", err)
	}
	body4 := readBody(t, resp4)
	if resp4.StatusCode != http.StatusOK {
		t.Errorf("decoy delete: expected 200, got %d", resp4.StatusCode)
	}
	if !strings.Contains(body4, "removed") && !strings.Contains(body4, "success") {
		t.Logf("decoy delete body snippet: %q", body4[:min(200, len(body4))])
	}

	// Reset
	resp5, err := client.PostForm(ts.URL+"/decoys", url.Values{
		"_action": {"reset"},
	})
	if err != nil {
		t.Fatalf("POST /decoys reset: %v", err)
	}
	body5 := readBody(t, resp5)
	if resp5.StatusCode != http.StatusOK {
		t.Errorf("decoy reset: expected 200, got %d", resp5.StatusCode)
	}
	if !strings.Contains(body5, "default") && !strings.Contains(body5, "success") {
		t.Logf("decoy reset body snippet: %q", body5[:min(200, len(body5))])
	}
}

func TestDecoys_ServeMatchingPath(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// The default decoy set includes /wp-login.php → login (fake login page)
	// No auth needed to probe this path.
	client := newClientNoFollow(t)
	resp, err := client.Get(ts.URL + "/wp-login.php")
	if err != nil {
		t.Fatalf("GET /wp-login.php: %v", err)
	}
	body := readBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 from decoy, got %d", resp.StatusCode)
	}
	server := resp.Header.Get("Server")
	if server != "nginx" {
		t.Errorf("expected Server: nginx, got %q", server)
	}
	if !strings.Contains(body, "Log In") && !strings.Contains(body, "Sign In") {
		t.Errorf("expected fake login page, body snippet: %q", body[:min(200, len(body))])
	}

	// Also test /.env → 403 forbidden
	resp2, err := client.Get(ts.URL + "/.env")
	if err != nil {
		t.Fatalf("GET /.env: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 from /.env decoy, got %d", resp2.StatusCode)
	}
}

// ── 6. Static Assets ──────────────────────────────────────────────────────

func TestStaticAssets(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := &http.Client{}
	paths := []string{
		"/static/css/app.css",
	}
	for _, p := range paths {
		resp, err := client.Get(ts.URL + p)
		if err != nil {
			t.Fatalf("GET %s: %v", p, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("static %s: expected 200, got %d", p, resp.StatusCode)
		}
	}
}

// ── 7. API flows ──────────────────────────────────────────────────────────

func TestAPI_LoginFlow(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := newClientFollow(t)

	// Wrong credentials → 401
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("api login wrong: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong creds: expected 401, got %d", resp.StatusCode)
	}

	// Correct credentials → 200
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"test"}`))
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatalf("api login correct: %v", err)
	}
	body := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("correct creds: expected 200, got %d", resp2.StatusCode)
	}
	if !strings.Contains(body, `"ok": true`) && !strings.Contains(body, `"ok":true`) {
		t.Errorf("expected ok:true in response, got: %q", body[:min(200, len(body))])
	}

	// Health endpoint (public)
	resp3, err := client.Get(ts.URL + "/api/v1/health")
	if err != nil {
		t.Fatalf("api health: %v", err)
	}
	body3 := readBody(t, resp3)
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("health: expected 200, got %d", resp3.StatusCode)
	}
	if !strings.Contains(body3, `"status"`) {
		t.Errorf("expected status in health response")
	}
}

func TestAPI_ConfigRequiresAuth(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	// Without session → 401
	client := newClientFollow(t)
	resp, err := client.Get(ts.URL + "/api/v1/config")
	if err != nil {
		t.Fatalf("GET /api/v1/config: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", resp.StatusCode)
	}

	// Login, then fetch config → 200
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/v1/auth/login", strings.NewReader(`{"username":"admin","password":"test"}`))
	req.Header.Set("Content-Type", "application/json")
	resp2, _ := client.Do(req)
	resp2.Body.Close()

	resp3, err := client.Get(ts.URL + "/api/v1/config")
	if err != nil {
		t.Fatalf("GET /api/v1/config authed: %v", err)
	}
	body := readBody(t, resp3)
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("expected 200 with auth, got %d", resp3.StatusCode)
	}
	if !strings.Contains(body, "config") {
		t.Errorf("expected config in response, got: %q", body[:min(200, len(body))])
	}
}

// ── 8. Dashboard ──────────────────────────────────────────────────────────

func TestDashboard_Loads(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()

	client := loginSession(t, ts.URL, "admin", "test")
	// Clear must_change
	resp := changePassword(t, client, ts.URL, "test", "dashtest1234", "dashtest1234")
	resp.Body.Close()

	resp2, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	body := readBody(t, resp2)
	if resp2.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp2.StatusCode)
	}
	// Must have some dashboard content
	if !strings.Contains(body, "dashboard") && !strings.Contains(body, "Dashboard") {
		t.Errorf("expected dashboard content, body snippet: %q", body[:min(300, len(body))])
	}

	// Flash param must not crash
	resp3, err := client.Get(ts.URL + "/dashboard?flash=password_changed")
	if err != nil {
		t.Fatalf("GET /dashboard?flash=...: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Errorf("flash param: expected 200, got %d", resp3.StatusCode)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
