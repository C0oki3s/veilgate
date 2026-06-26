package proxy

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/C0oki3s/veilgate/internal/tlsfp"
)

func parseCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return n
}

func trustedNets(cidrs ...string) []*net.IPNet {
	out := make([]*net.IPNet, len(cidrs))
	for i, c := range cidrs {
		out[i] = parseCIDR(c)
	}
	return out
}

// ── FingerprintMiddleware ─────────────────────────────────────────────────────

func TestFingerprintMiddleware_TLSStoreHasPriority(t *testing.T) {
	store := tlsfp.NewStore(0)
	store.Put("1.2.3.4:55000", tlsfp.Fingerprint{JA4: "t13d_store_value"})

	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Veilgate-JA4")
	})

	h := FingerprintMiddleware(next, store, "cloudflare", trustedNets("1.2.3.4/32"))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:55000"
	req.Header.Set("cf-ja4", "t13d_cdn_value")

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "t13d_store_value" {
		t.Fatalf("want TLS-store value %q, got %q", "t13d_store_value", got)
	}
}

func TestFingerprintMiddleware_CDNHeaderFromTrustedProxy(t *testing.T) {
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Veilgate-JA4")
	})

	h := FingerprintMiddleware(next, nil, "cloudflare", trustedNets("10.0.0.0/8"))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	req.Header.Set("cf-ja4", "t13d_cloudflare_ja4")

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "t13d_cloudflare_ja4" {
		t.Fatalf("want %q, got %q", "t13d_cloudflare_ja4", got)
	}
}

func TestFingerprintMiddleware_CDNHeaderIgnoredFromUntrustedIP(t *testing.T) {
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Veilgate-JA4")
	})

	h := FingerprintMiddleware(next, nil, "cloudflare", trustedNets("10.0.0.0/8"))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345" // NOT in 10.0.0.0/8
	req.Header.Set("cf-ja4", "t13d_forged")

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "" {
		t.Fatalf("forged header from untrusted IP should be ignored, got %q", got)
	}
}

func TestFingerprintMiddleware_NoTrustedProxies_IgnoresCDNHeader(t *testing.T) {
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Veilgate-JA4")
	})

	h := FingerprintMiddleware(next, nil, "cloudflare", nil) // empty trusted_proxies
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	req.Header.Set("cf-ja4", "t13d_forged")

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "" {
		t.Fatalf("with no trusted_proxies CDN header must be ignored, got %q", got)
	}
}

func TestFingerprintMiddleware_AutoModePriorityOrder(t *testing.T) {
	// When auto mode is set, cf-ja4 must win over azure header.
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Veilgate-JA4")
	})

	h := FingerprintMiddleware(next, nil, "auto", trustedNets("0.0.0.0/0"))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "5.5.5.5:9000"
	req.Header.Set("cf-ja4", "t13d_cf")
	req.Header.Set("X-Azure-JA4-Fingerprint", "t13d_azure")

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "t13d_cf" {
		t.Fatalf("auto mode: want cf-ja4 (first in priority), got %q", got)
	}
}

func TestFingerprintMiddleware_UnknownCDNModeNoHeader(t *testing.T) {
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Veilgate-JA4")
	})

	h := FingerprintMiddleware(next, nil, "unknown-cdn", trustedNets("0.0.0.0/0"))
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.1.1.1:80"
	req.Header.Set("X-JA4", "t13d_value")

	h.ServeHTTP(httptest.NewRecorder(), req)

	if got != "" {
		t.Fatalf("unknown cdn_mode should inject no header, got %q", got)
	}
}

// ── ResolveCDNClientIP ────────────────────────────────────────────────────────

func TestResolveCDNClientIP_Cloudflare(t *testing.T) {
	nets := trustedNets("173.245.48.0/20")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "173.245.48.1:443"
	req.Header.Set("CF-Connecting-IP", "203.0.113.42")

	got := ResolveCDNClientIP(req, "cloudflare", nets)
	if got != "203.0.113.42" {
		t.Fatalf("want 203.0.113.42, got %q", got)
	}
}

func TestResolveCDNClientIP_CloudFrontStripsPort(t *testing.T) {
	nets := trustedNets("0.0.0.0/0")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:443"
	req.Header.Set("CloudFront-Viewer-Address", "203.0.113.99:54321")

	got := ResolveCDNClientIP(req, "cloudfront", nets)
	if got != "203.0.113.99" {
		t.Fatalf("cloudfront: want IP without port, got %q", got)
	}
}

func TestResolveCDNClientIP_RejectsNonIPValue(t *testing.T) {
	nets := trustedNets("0.0.0.0/0")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:443"
	req.Header.Set("CF-Connecting-IP", "not-an-ip; rm -rf /")

	got := ResolveCDNClientIP(req, "cloudflare", nets)
	if got != "" {
		t.Fatalf("non-IP value must be rejected, got %q", got)
	}
}

func TestResolveCDNClientIP_UntrustedSourceIgnored(t *testing.T) {
	nets := trustedNets("10.0.0.0/8")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:443" // NOT in 10.0.0.0/8
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")

	got := ResolveCDNClientIP(req, "cloudflare", nets)
	if got != "" {
		t.Fatalf("untrusted source: CDN real-IP header must be ignored, got %q", got)
	}
}

func TestResolveCDNClientIP_FastlyNotTrusted(t *testing.T) {
	// Fastly-Client-IP is documented as forgeable; cdn.go sets its header to ""
	nets := trustedNets("0.0.0.0/0")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:443"
	req.Header.Set("Fastly-Client-IP", "203.0.113.1")

	got := ResolveCDNClientIP(req, "fastly", nets)
	if got != "" {
		t.Fatalf("fastly: Fastly-Client-IP must never be trusted, got %q", got)
	}
}

func TestResolveCDNClientIP_EmptyCDNMode(t *testing.T) {
	nets := trustedNets("0.0.0.0/0")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:443"
	req.Header.Set("CF-Connecting-IP", "203.0.113.1")

	got := ResolveCDNClientIP(req, "", nets)
	if got != "" {
		t.Fatalf("empty cdn_mode: must return empty, got %q", got)
	}
}

// ── fromTrustedProxy ─────────────────────────────────────────────────────────

func TestFromTrustedProxy_IPv4Match(t *testing.T) {
	nets := trustedNets("192.168.1.0/24")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "192.168.1.55:1234"

	if !fromTrustedProxy(req, nets) {
		t.Fatal("192.168.1.55 should be inside 192.168.1.0/24")
	}
}

func TestFromTrustedProxy_IPv4NoMatch(t *testing.T) {
	nets := trustedNets("192.168.1.0/24")
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"

	if fromTrustedProxy(req, nets) {
		t.Fatal("10.0.0.1 must NOT be inside 192.168.1.0/24")
	}
}

func TestFromTrustedProxy_EmptyList(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:80"

	if fromTrustedProxy(req, nil) {
		t.Fatal("empty trusted_proxies must always return false")
	}
}
