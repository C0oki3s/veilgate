package ml

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestPathRedactor_DefaultPatterns covers the four built-in shapes —
// UUID, long numeric ID, hex, base64 — and one passthrough.
func TestPathRedactor_DefaultPatterns(t *testing.T) {
	r := NewDefaultPathRedactor()
	cases := []struct {
		in, want string
	}{
		{"users", "users"},
		{"12345", "<id>"},
		{"4f1c8d2e-aa11-49bf-9c8c-22f3a8c0c3b1", "<uuid>"},
		{"1a2b3c4d5e6f7890abcdef0123456789", "<hex>"},
		{"AbCdEf0123456789_-XYZ_extra", "<token>"},
	}
	for _, c := range cases {
		if got := r.Apply(c.in); got != c.want {
			t.Fatalf("Apply(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestPathRedactor_AppliesInExtract is the one that matters for the
// privacy story: a URL like /users/12345/orders must produce buckets
// that include `<id>` and never include `12345`.
func TestPathRedactor_AppliesInExtract(t *testing.T) {
	prev := currentRedactor()
	SetActiveRedactor(NewDefaultPathRedactor())
	defer SetActiveRedactor(prev)

	r := httptest.NewRequest("GET", "/users/12345/orders", nil)
	v := NewExtractor().Extract(r, 0, "")

	leaked := false
	redacted := false
	for _, f := range v.Categorical {
		if f.Name != "path_ngram" {
			continue
		}
		if strings.Contains(f.Bucket, "12345") {
			leaked = true
		}
		if strings.Contains(f.Bucket, "<id>") {
			redacted = true
		}
	}
	if leaked {
		t.Fatalf("expected /users/12345/orders to be redacted; raw 12345 leaked into a path_ngram bucket: %+v", v.Categorical)
	}
	if !redacted {
		t.Fatalf("expected at least one path_ngram bucket to contain <id> after redaction: %+v", v.Categorical)
	}
}

// TestPathRedactor_CustomRule confirms that operator-supplied regexes
// extend the built-in set without disturbing it.
func TestPathRedactor_CustomRule(t *testing.T) {
	r := NewDefaultPathRedactor()
	r.AddCustom(`^MRN-\d+$`, "<patient>")
	if got := r.Apply("MRN-9001"); got != "<patient>" {
		t.Fatalf("custom rule failed: %q", got)
	}
	if got := r.Apply("orders"); got != "orders" {
		t.Fatalf("custom rule should not affect plain segments: %q", got)
	}
}

// TestPauseBucket spot-checks the LLM-cadence-tuned bucketing.
func TestPauseBucket(t *testing.T) {
	cases := map[float64]string{
		0:    "first",
		0.4:  "lt1",
		1.5:  "1_2",
		4:    "3_5",
		7:    "5_8",
		25:   "15_30",
		3600: "gt90",
	}
	for in, want := range cases {
		if got := pauseBucket(in); got != want {
			t.Fatalf("pauseBucket(%v) = %q, want %q", in, got, want)
		}
	}
}

// TestSecFetchCoherence covers the five outcome labels Extract uses.
func TestSecFetchCoherence(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if got := secFetchCoherence(r); got != "absent" {
		t.Fatalf("absent: got %q", got)
	}
	r.Header.Set("Sec-Fetch-Site", "none")
	if got := secFetchCoherence(r); got != "partial" {
		t.Fatalf("partial: got %q", got)
	}
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Fetch-Dest", "document")
	if got := secFetchCoherence(r); got != "navigate" {
		t.Fatalf("navigate: got %q", got)
	}
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	r.Header.Set("Sec-Fetch-Mode", "no-cors")
	r.Header.Set("Sec-Fetch-Dest", "image")
	if got := secFetchCoherence(r); got != "subresource" {
		t.Fatalf("subresource: got %q", got)
	}
}

// TestAcceptEncodingPosture covers the labels used by Extract.
func TestAcceptEncodingPosture(t *testing.T) {
	cases := map[string]string{
		"":                          "empty",
		"gzip, deflate, br":         "browser_full",
		"gzip, deflate, br, zstd":   "chromium_full",
		"gzip":                      "gzip_only",
		"identity":                  "permissive",
		"gzip, deflate":             "gzip_deflate",
	}
	for in, want := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		if in != "" {
			r.Header.Set("Accept-Encoding", in)
		}
		if got := acceptEncodingPosture(r); got != want {
			t.Fatalf("acceptEncodingPosture(%q) = %q, want %q", in, got, want)
		}
	}
}
