package payloads

import (
	"strings"
	"testing"

	"github.com/C0oki3s/veilgate/internal/tarpit"
)

func TestInjectorHTMLAddsComments(t *testing.T) {
	inj := NewInjector(NewLibrary(), 3, false)
	body := `<html><head><title>x</title></head><body><h1>hi</h1></body></html>`
	out := inj.Inject("text/html; charset=utf-8", body, tarpit.InjectionContext{
		Path: "/", ClientID: "10.0.0.1", Visits: 1,
	})
	if !strings.Contains(out, "<!--") {
		t.Fatal("expected at least one HTML comment payload in output")
	}
	if !strings.Contains(out, "<h1>hi</h1>") {
		t.Fatal("original body content should be preserved")
	}
}

func TestInjectorJSONAddsField(t *testing.T) {
	inj := NewInjector(NewLibrary(), 3, false)
	body := `{"result":"ok"}`
	out := inj.Inject("application/json", body, tarpit.InjectionContext{
		Path: "/api", ClientID: "10.0.0.2", Visits: 1,
	})
	// Output must still end with } and must contain a payload marker.
	if !strings.HasSuffix(out, "}") {
		t.Fatalf("JSON output must end with }, got %q", out)
	}
	if !strings.Contains(out, "_scan_status") && !strings.Contains(out, "_previous_tool_output") {
		// Json-style payloads either "_scan_status" or "_previous_tool_output".
		// Due to random selection one must eventually appear across multiple calls.
		// Retry with different salt.
		out = inj.Inject("application/json", body, tarpit.InjectionContext{
			Path: "/api", ClientID: "10.0.0.99", Visits: 2,
		})
		if !strings.Contains(out, "_scan_status") && !strings.Contains(out, "_previous_tool_output") {
			t.Fatalf("expected json_field payload, got %q", out)
		}
	}
}

func TestInjectorLeavesMalformedJSONAlone(t *testing.T) {
	inj := NewInjector(NewLibrary(), 3, false)
	body := `not valid json`
	out := inj.Inject("application/json", body, tarpit.InjectionContext{
		Path: "/api", ClientID: "10.0.0.3", Visits: 1,
	})
	if out != body {
		t.Fatalf("malformed JSON should pass through unchanged, got %q", out)
	}
}

func TestInjectorUnknownContentTypePassesThrough(t *testing.T) {
	inj := NewInjector(NewLibrary(), 3, false)
	body := "binary data"
	out := inj.Inject("application/octet-stream", body, tarpit.InjectionContext{
		Path: "/x", ClientID: "10.0.0.4", Visits: 1,
	})
	if out != body {
		t.Fatalf("unknown content type should pass through, got %q", out)
	}
}

func TestLibraryPickDeterministic(t *testing.T) {
	lib := NewLibrary()
	a := lib.Pick("test-salt", 3)
	b := lib.Pick("test-salt", 3)
	if len(a) != len(b) {
		t.Fatal("same salt should produce same count")
	}
	for i := range a {
		if a[i].Category != b[i].Category || a[i].Style != b[i].Style {
			t.Fatalf("same salt should produce identical picks, got different at index %d", i)
		}
	}
}

func TestLibraryPickDifferentSalts(t *testing.T) {
	lib := NewLibrary()
	a := lib.Pick("salt-one", 5)
	b := lib.Pick("salt-two", 5)
	// Different salts should almost certainly produce a different ordering.
	same := true
	for i := range a {
		if i >= len(b) {
			same = false
			break
		}
		if a[i].Category != b[i].Category || a[i].Style != b[i].Style {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different salts produced identical ordering — randomness broken")
	}
}
