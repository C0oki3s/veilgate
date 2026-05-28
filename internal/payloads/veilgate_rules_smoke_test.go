package payloads

import (
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/tarpit"
)

const veilgateRulesDir = "../../veilgate-rules"

func TestVeilgateRulesPayloadInjection(t *testing.T) {
	lib, err := NewLibraryFromDir(veilgateRulesDir)
	if err != nil {
		t.Fatalf("NewLibraryFromDir(%q): %v", veilgateRulesDir, err)
	}
	inj := NewInjector(lib, 50, true)

	html := inj.Inject("text/html; charset=utf-8", `<html><body><h1>ok</h1></body></html>`, tarpit.InjectionContext{
		Path: "/", ClientID: "10.0.0.80", Visits: 1,
	})
	if !strings.Contains(html, "<!--") {
		t.Fatalf("expected HTML payload comment, got %q", html)
	}

	json := inj.Inject("application/json", `{"ok":true}`, tarpit.InjectionContext{
		Path: "/api/me", ClientID: "10.0.0.81", Visits: 1,
	})
	if json == `{"ok":true}` || !strings.Contains(json, `"_`) {
		t.Fatalf("expected JSON field injection, got %q", json)
	}

	js := inj.Inject("application/javascript", `console.log("ok");`, tarpit.InjectionContext{
		Path: "/assets/app.js", ClientID: "10.0.0.82", Visits: 1,
	})
	if !strings.Contains(js, "eyJ") || !strings.Contains(js, "sk_live_") {
		t.Fatalf("expected JS canary JWT and API key, got %q", js)
	}

	highRisk := inj.Inject("text/html; charset=utf-8", `<html><body><h1>ok</h1></body></html>`, tarpit.InjectionContext{
		Path: "/actuator/health", ClientID: "10.0.0.83", Visits: 1,
	})
	if !strings.Contains(highRisk, "exposure-audit") {
		t.Fatalf("expected high-risk exposure breadcrumb, got %q", highRisk)
	}
}
