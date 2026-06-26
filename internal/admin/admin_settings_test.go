package admin_test

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/admin"
	"net/http/httptest"

	_ "modernc.org/sqlite"
)

// newTestServerWithConfig creates a test server seeded with an explicit config
// so tests can check that saved values appear in the YAML.
func newTestServerWithConfig(t *testing.T, yamlContent string) (*httptest.Server, string) {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "vg.yaml")
	if err := os.WriteFile(cfgPath, []byte(yamlContent), 0o644); err != nil {
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
	return httptest.NewServer(srv), cfgPath
}

// loginTestSession logs in with the default test credentials (admin/test).
// Because newTestServerWithConfig seeds must_change=1, we need to change
// the password first — we skip that by checking the current password flow.
func loginTestSession(t *testing.T, baseURL string) *http.Client {
	t.Helper()
	client := newClientFollow(t)

	// Login — the server auto-changes must_change to 0 on first validation.
	resp, err := client.PostForm(baseURL+"/login", url.Values{
		"username": {"admin"},
		"password": {"test"},
	})
	if err != nil {
		t.Fatalf("login POST: %v", err)
	}
	resp.Body.Close()

	// If redirected to /account/password (must_change), complete the flow.
	if resp.Request.URL.Path == "/account/password" {
		r2, err2 := client.PostForm(baseURL+"/account/password", url.Values{
			"current_password": {"test"},
			"new_password":     {"Test1234!"},
			"confirm_password": {"Test1234!"},
		})
		if err2 != nil {
			t.Fatalf("change password: %v", err2)
		}
		r2.Body.Close()
	}
	return client
}

// ── Settings page ─────────────────────────────────────────────────────────────

func TestSettingsPage_ReturnsOK(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	client := loginTestSession(t, ts.URL)

	resp, err := client.Get(ts.URL + "/settings?tab=detector")
	if err != nil {
		t.Fatalf("GET /settings: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "cdn_mode") {
		t.Error("settings page should contain cdn_mode field")
	}
	if !strings.Contains(body, "Cloudflare") {
		t.Error("settings page should show CDN mode options including Cloudflare")
	}
}

func TestSettingsPage_CDNModeDropdownOptions(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	client := loginTestSession(t, ts.URL)

	resp, err := client.Get(ts.URL + "/settings?tab=detector")
	if err != nil {
		t.Fatalf("GET /settings: %v", err)
	}
	body := readBody(t, resp)

	for _, want := range []string{"cloudflare", "cloudfront", "akamai", "fastly", "azure", "gcp", "nginx", "haproxy", "auto"} {
		if !strings.Contains(body, want) {
			t.Errorf("CDN mode option %q missing from settings page", want)
		}
	}
}

// ── Settings POST — cdn_mode ──────────────────────────────────────────────────

func TestSettingsSave_CDNModeCloudflare(t *testing.T) {
	initYAML := "rules_dir: /tmp\ndetector:\n  cdn_mode: \"\"\npersist:\n  enabled: false\n"
	ts, cfgPath := newTestServerWithConfig(t, initYAML)
	defer ts.Close()
	client := loginTestSession(t, ts.URL)

	resp, err := client.PostForm(ts.URL+"/settings", url.Values{
		"_tab":     {"detector"},
		"cdn_mode": {"cloudflare"},
	})
	if err != nil {
		t.Fatalf("POST /settings: %v", err)
	}
	resp.Body.Close()

	// Read the config file that was written.
	saved, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !strings.Contains(string(saved), "cloudflare") {
		t.Errorf("cdn_mode not persisted; config:\n%s", saved)
	}
}

func TestSettingsSave_CDNModeAuto(t *testing.T) {
	initYAML := "rules_dir: /tmp\ndetector:\n  cdn_mode: cloudflare\npersist:\n  enabled: false\n"
	ts, cfgPath := newTestServerWithConfig(t, initYAML)
	defer ts.Close()
	client := loginTestSession(t, ts.URL)

	resp, err := client.PostForm(ts.URL+"/settings", url.Values{
		"_tab":     {"detector"},
		"cdn_mode": {"auto"},
	})
	if err != nil {
		t.Fatalf("POST /settings: %v", err)
	}
	resp.Body.Close()

	saved, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	if !strings.Contains(string(saved), "auto") {
		t.Errorf("cdn_mode not updated to auto; config:\n%s", saved)
	}
}

func TestSettingsSave_CDNModeEmpty(t *testing.T) {
	initYAML := "rules_dir: /tmp\ndetector:\n  cdn_mode: cloudflare\npersist:\n  enabled: false\n"
	ts, cfgPath := newTestServerWithConfig(t, initYAML)
	defer ts.Close()
	client := loginTestSession(t, ts.URL)

	resp, err := client.PostForm(ts.URL+"/settings", url.Values{
		"_tab":     {"detector"},
		"cdn_mode": {""},
	})
	if err != nil {
		t.Fatalf("POST /settings: %v", err)
	}
	resp.Body.Close()

	saved, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read saved config: %v", err)
	}
	// Empty string either removes the key or sets it to "".
	// It must NOT contain "cdn_mode: cloudflare" any more.
	if strings.Contains(string(saved), "cdn_mode: cloudflare") {
		t.Errorf("cdn_mode should be cleared; config:\n%s", saved)
	}
}

// ── Settings page — unauthenticated ──────────────────────────────────────────

func TestSettingsPage_RequiresAuth(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	client := newClientNoFollow(t)

	resp, err := client.Get(ts.URL + "/settings")
	if err != nil {
		t.Fatalf("GET /settings: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("unauthenticated /settings: want 302/303 redirect, got %d", resp.StatusCode)
	}
}

// ── Decoy endpoints ───────────────────────────────────────────────────────────

func TestDecoyEndpoints_PageLoads(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	client := loginSession(t, ts.URL, "admin", "test")

	resp, err := client.Get(ts.URL + "/settings?tab=decoys")
	if err != nil {
		t.Fatalf("GET /settings?tab=decoys: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "decoy") && !strings.Contains(body, "Decoy") && !strings.Contains(body, "honeypot") {
		t.Error("decoys tab should mention decoy or honeypot")
	}
}

// ── Analytics API ─────────────────────────────────────────────────────────────

func TestAnalyticsPage_ReturnsOK(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	client := loginSession(t, ts.URL, "admin", "test")

	resp, err := client.Get(ts.URL + "/analytics")
	if err != nil {
		t.Fatalf("GET /analytics: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	readBody(t, resp) // consume body; just checking it doesn't 500
}

func TestDashboard_ReturnsOK(t *testing.T) {
	ts := newTestServer(t)
	defer ts.Close()
	client := loginSession(t, ts.URL, "admin", "test")

	resp, err := client.Get(ts.URL + "/dashboard")
	if err != nil {
		t.Fatalf("GET /dashboard: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "VeilGate") {
		t.Error("dashboard should contain VeilGate in body")
	}
}
