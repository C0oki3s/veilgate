package proxy

import (
	"net"
	"net/http"
	"strings"

	"github.com/C0oki3s/veilgate/internal/tlsfp"
)

// CDN / reverse-proxy header reference (verified July 2025)
//
// ── Cloudflare ───────────────────────────────────────────────────────────────
//  cf-ja3-hash          MD5 JA3 fingerprint (Enterprise Bot Management only)
//  cf-ja4               JA4 fingerprint     (Enterprise Bot Management only)
//  CF-Connecting-IP     Real client IP — set by Cloudflare, cannot be forged
//                       IF the origin is IP-allowlisted to Cloudflare ranges.
//  True-Client-IP       Alias for CF-Connecting-IP on Enterprise/Spectrum.
//  CF-Ray               Request trace ID; absent on direct connections.
//  CF-IPCountry         ISO-3166-1 alpha-2 country (requires Managed Transform).
//  CF-Visitor           {"scheme":"https"} for protocol detection.
//  X-Forwarded-For      XFF chain; Cloudflare appends but doesn't sanitize prior values.
//
// ── AWS CloudFront ───────────────────────────────────────────────────────────
//  CloudFront-Viewer-JA3-Fingerprint  JA3 (opt-in via origin request policy)
//  CloudFront-Viewer-JA4-Fingerprint  JA4 (opt-in via origin request policy)
//  CloudFront-Viewer-TLS              {version}:{cipher}:{handshake_info}
//  CloudFront-Viewer-Address          {client_ip}:{source_port}
//  CloudFront-Viewer-Country          ISO-3166-1 country
//  CloudFront-Forwarded-Proto         http | https
//  X-Forwarded-For                    XFF chain
//  NOTE: CloudFront strips all CloudFront-* headers from CLIENT requests — an
//        attacker cannot inject them without bypassing CloudFront entirely.
//
// ── Akamai ──────────────────────────────────────────────────────────────────
//  True-Client-IP            Real client IP (must enable "Send True Client IP Header")
//  X-Akamai-Edgescape        Geo/ASN data string (requires EdgeScape add-on)
//  X-Akamai-Device-Characteristics  Device type (requires Device Char. product)
//  Akamai-Origin-Hop         Hop count from Akamai edge to origin
//  NO native JA3/JA4 header — Akamai consumes fingerprints internally in
//  Bot Manager and never forwards them to origin.
//
// ── Fastly ──────────────────────────────────────────────────────────────────
//  Fastly-Client-IP     Client IP — WARNING: forgeable by clients by design!
//                       Only safe if explicitly overridden in VCL.
//  Fastly-FF            Internal Fastly-to-Fastly routing token.
//  X-Forwarded-For      XFF (appended on TLS connections only).
//  Custom (VCL)         JA4 via tls.client.ja4 VCL variable — no standard name.
//                       Operator must configure: set bereq.http.X-JA4 = tls.client.ja4;
//
// ── Azure Front Door ─────────────────────────────────────────────────────────
//  X-Azure-JA4-Fingerprint  JA4 (standard tier — included by default as of 2025)
//  X-Azure-ClientIP         Real client IP
//  X-Azure-SocketIP         TCP socket source IP
//  X-Azure-Ref             Request trace reference string
//  X-Azure-FDID            Your specific Front Door GUID — validate to prevent
//                          origin bypass (Microsoft's recommended method).
//  X-Forwarded-For         XFF chain with socket IP appended.
//  X-FD-* headers are stripped from client requests by Azure.
//
// ── Google Cloud CDN / Application Load Balancer ─────────────────────────────
//  No automatic TLS fingerprint headers. Inject via custom header variables:
//    {tls_ja3_fingerprint} → configure custom header e.g. X-JA3: {tls_ja3_fingerprint}
//    {tls_ja4_fingerprint} → configure custom header e.g. X-JA4: {tls_ja4_fingerprint}
//  {client_ip_address}, {tls_version}, {tls_cipher_suite}, {tls_sni_hostname}
//  are also available as custom header variables.
//  X-Cloud-Trace-Context added automatically.
//  X-Forwarded-For always appended.
//
// ── Nginx (reverse proxy) ────────────────────────────────────────────────────
//  X-Real-IP        Real client IP (set via: proxy_set_header X-Real-IP $remote_addr)
//  X-Forwarded-For  set via: proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for
//  JA3/JA4 requires a compiled module (nginx-ssl-fingerprint, ngx_ssl_fingerprint_module)
//  and explicit set_header config — no standard header name.
//  Common convention: X-JA3-Hash, X-JA4.
//
// ── HAProxy ──────────────────────────────────────────────────────────────────
//  X-Forwarded-For  via option forwardfor
//  X-Real-IP        via http-request set-header (manual config)
//  PROXY protocol v1/v2 — no authentication; forgeable if backend not firewalled.
//  JA3 via Lua plugin (haproxy-ja3n-fingerprint) → typically X-SSL-JA3N.
//
// ── Vercel ───────────────────────────────────────────────────────────────────
//  x-vercel-forwarded-for   Tamper-resistant real IP (preferred over XFF on Vercel)
//  x-forwarded-for          XFF (Vercel overwrites existing values)
//  x-real-ip                Alias for XFF
//  x-vercel-id              Vercel region trace ID
//  No TLS fingerprint headers.
//
// ── Netlify ──────────────────────────────────────────────────────────────────
//  x-nf-client-connection-ip  TCP connection IP (reliable, can't be faked within Netlify)
//  x-forwarded-for            XFF chain
//  No TLS fingerprint headers.
//
// ── Security note ────────────────────────────────────────────────────────────
//  Every header above can be forged by an attacker who bypasses the CDN and
//  connects directly to the origin IP. The only reliable defense is a firewall
//  or network-level allowlist that blocks non-CDN IPs from reaching the origin.
//  VeilGate gates header trust on trusted_proxies — only honour these headers
//  when the TCP connection comes from a declared trusted CIDR.

// cdnJA4Headers maps cdn_mode → ordered list of header names to check for JA4.
// HTTP header lookup is case-insensitive in Go's net/http, so casing is just for
// documentation clarity. First non-empty value that passes the trusted-proxy
// check is used. Modes with no known header are left empty.
var cdnJA4Headers = map[string][]string{
	"cloudflare": {
		"cf-ja4",      // JA4 (Enterprise Bot Management)
		"cf-ja3-hash", // JA3 fallback (Enterprise Bot Management)
	},
	"cloudfront": {
		"CloudFront-Viewer-JA4-Fingerprint", // JA4 (opt-in origin policy)
		"CloudFront-Viewer-JA3-Fingerprint", // JA3 fallback (opt-in origin policy)
	},
	"akamai": {}, // No TLS fingerprint forwarded to origin.
	"fastly":  {}, // Operator must configure VCL to set a custom header; no standard name.
	"azure": {
		"X-Azure-JA4-Fingerprint", // JA4 (standard tier, included by default 2025+)
	},
	"gcp": {
		"X-JA4", // Operator must configure: {tls_ja4_fingerprint} → X-JA4 in LB policy
		"X-JA3", // JA3 fallback
	},
	"nginx": {
		"X-JA4",      // nginx-ssl-fingerprint / ngx_ssl_fingerprint_module
		"X-JA3-Hash", // common alternative
	},
	"haproxy": {
		"X-SSL-JA3N", // haproxy-ja3n-fingerprint Lua plugin
		"X-JA3-Hash",
		"X-JA4",
	},
	"auto": {
		// Try all known headers in priority order.
		"cf-ja4",                             // Cloudflare JA4
		"cf-ja3-hash",                        // Cloudflare JA3
		"X-Azure-JA4-Fingerprint",            // Azure Front Door
		"CloudFront-Viewer-JA4-Fingerprint",  // AWS CloudFront JA4
		"CloudFront-Viewer-JA3-Fingerprint",  // AWS CloudFront JA3
		"X-JA4",                              // GCP custom / nginx / HAProxy
		"X-JA3-Hash",                         // nginx / HAProxy fallback
		"X-SSL-JA3N",                         // HAProxy Lua plugin
	},
}

// CDNRealIPHeaders maps cdn_mode → the header carrying the real client IP.
// These complement the standard XFF chain and are often more reliable than XFF
// because they represent the CDN's own authoritative view of the client IP.
// Only trusted when the TCP connection comes from a declared trusted proxy CIDR.
var CDNRealIPHeaders = map[string]string{
	"cloudflare":  "CF-Connecting-IP",             // most reliable; set by Cloudflare
	"cloudfront":  "CloudFront-Viewer-Address",    // {ip}:{port} format — strip port
	"akamai":      "True-Client-IP",               // requires "Send True Client IP Header"
	"fastly":      "",                             // Fastly-Client-IP is forgeable by clients; don't trust
	"azure":       "X-Azure-ClientIP",
	"gcp":         "",                             // no standard header; use XFF
	"nginx":       "X-Real-IP",
	"haproxy":     "X-Real-IP",
	"auto":        "",
}

// FingerprintMiddleware returns an http.Handler that injects X-Veilgate-JA4
// before the request reaches the scorer.
//
// Priority:
//  1. TLS store: VeilGate terminated TLS itself — fingerprint is from the raw
//     ClientHello, impossible to forge. This path is taken in self-TLS mode.
//  2. CDN header: only honoured when the TCP remote address is inside one of
//     the trusted_proxies CIDRs — prevents direct-connection forgery.
//
// When neither yields a value, the request reaches the scorer without the header
// and all JA4-dependent signals (fleet rotation, custom ja4_prefix conditions,
// ML JA4 features) are simply skipped.
func FingerprintMiddleware(next http.Handler, store *tlsfp.Store, cdnMode string, trustedProxies []*net.IPNet) http.Handler {
	headers := cdnJA4Headers[strings.ToLower(cdnMode)]
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ja4 := ""

		// Path 1: self-terminated TLS — look up fingerprint by TCP remote addr.
		if store != nil {
			if fp, ok := store.Get(r.RemoteAddr); ok && fp.JA4 != "" {
				ja4 = fp.JA4
			}
		}

		// Path 2: CDN-injected fingerprint header — requires trusted proxy.
		if ja4 == "" && len(headers) > 0 && fromTrustedProxy(r, trustedProxies) {
			for _, h := range headers {
				if v := r.Header.Get(h); v != "" {
					ja4 = v
					break
				}
			}
		}

		if ja4 == "" {
			next.ServeHTTP(w, r)
			return
		}
		// Clone the request so we don't mutate the original (safe for concurrent use).
		rc := r.Clone(r.Context())
		rc.Header.Set("X-Veilgate-JA4", ja4)
		next.ServeHTTP(w, rc)
	})
}

// ResolveCDNClientIP checks CDN-specific real-IP headers and returns the client
// IP they carry, or empty string if not applicable. The caller should prefer
// this over XFF when cdn_mode is configured and the request comes from a trusted
// proxy, because CDN-specific headers are more reliable than XFF.
//
// For cloudfront, the CloudFront-Viewer-Address header is in "{ip}:{port}"
// format; the port is stripped.
func ResolveCDNClientIP(r *http.Request, cdnMode string, trustedProxies []*net.IPNet) string {
	if cdnMode == "" || !fromTrustedProxy(r, trustedProxies) {
		return ""
	}
	hdr := CDNRealIPHeaders[strings.ToLower(cdnMode)]
	if hdr == "" {
		return ""
	}
	v := strings.TrimSpace(r.Header.Get(hdr))
	if v == "" {
		return ""
	}
	// CloudFront sends "{ip}:{port}" — strip the port.
	if strings.ToLower(cdnMode) == "cloudfront" {
		if h, _, err := net.SplitHostPort(v); err == nil {
			v = h
		}
	}
	// Validate it's actually an IP to block injection via forged header values.
	if net.ParseIP(v) == nil {
		return ""
	}
	return v
}

// fromTrustedProxy reports whether r.RemoteAddr is inside one of the declared
// trusted proxy CIDRs. Same gate as resolveClientIP uses for XFF.
func fromTrustedProxy(r *http.Request, trustedProxies []*net.IPNet) bool {
	if len(trustedProxies) == 0 {
		return false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	return ip != nil && ipInAny(ip, trustedProxies)
}
