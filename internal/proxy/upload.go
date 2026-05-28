package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/telemetry"
	"github.com/C0oki3s/veilgate/internal/verifier"
)

var errUploadTooLarge = errors.New("upload body exceeds policy limit")

type uploadLimitContextKey struct{}

type uploadLimitState struct {
	exceeded atomic.Bool
}

// uploadLimitReadCloser counts streaming request bytes while the reverse proxy
// copies the body upstream. This covers chunked HTTP/1.1 and HTTP/2 bodies
// where Content-Length is unknown at policy-check time.
type uploadLimitReadCloser struct {
	inner     io.ReadCloser
	remaining int64
	state     *uploadLimitState
}

func (b *uploadLimitReadCloser) Read(p []byte) (int, error) {
	if b.remaining <= 0 {
		b.state.exceeded.Store(true)
		return 0, errUploadTooLarge
	}
	if int64(len(p)) > b.remaining {
		p = p[:b.remaining]
	}
	n, err := b.inner.Read(p)
	b.remaining -= int64(n)
	return n, err
}

func (b *uploadLimitReadCloser) Close() error {
	return b.inner.Close()
}

func uploadTransport(responseHeaderTimeout string) *http.Transport {
	timeout := time.Duration(0)
	if strings.TrimSpace(responseHeaderTimeout) != "" && strings.TrimSpace(responseHeaderTimeout) != "0" {
		if parsed, err := time.ParseDuration(responseHeaderTimeout); err == nil {
			timeout = parsed
		}
	}
	return &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: timeout,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

func uploadErrorHandler(defaultHandler func(http.ResponseWriter, *http.Request, error)) func(http.ResponseWriter, *http.Request, error) {
	return func(w http.ResponseWriter, r *http.Request, err error) {
		if errors.Is(err, errUploadTooLarge) || uploadLimitExceeded(r) {
			serveUploadBlocked(w, r, http.StatusRequestEntityTooLarge, "payload_too_large")
			return
		}
		defaultHandler(w, r, err)
	}
}

func (s *Server) matchUploadPolicy(r *http.Request) (*config.UploadPolicyConfig, int, bool) {
	var best *config.UploadPolicyConfig
	bestIndex := -1
	bestSpecificity := -1
	for i := range s.cfg.UploadPolicies {
		p := &s.cfg.UploadPolicies[i]
		for _, pattern := range p.Paths {
			if ok, specificity := uploadPathMatches(pattern, r.URL.Path); ok && specificity > bestSpecificity {
				best = p
				bestIndex = i
				bestSpecificity = specificity
			}
		}
	}
	return best, bestIndex, best != nil
}

func uploadPathMatches(pattern, path string) (bool, int) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return false, 0
	}
	if strings.HasSuffix(pattern, "/*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(path, prefix), len(prefix)
	}
	if path == pattern {
		return true, len(pattern) + 1_000_000
	}
	return false, 0
}

func rejectBadRequestFraming(w http.ResponseWriter, r *http.Request) bool {
	if ok, code := badRequestFraming(r); ok {
		serveUploadBlocked(w, r, http.StatusBadRequest, code)
		return true
	}
	return false
}

func badRequestFraming(r *http.Request) (bool, string) {
	contentLengthHeaders := r.Header.Values("Content-Length")
	if len(contentLengthHeaders) > 1 {
		return true, "bad_content_length"
	}
	transferEncodingHeaders := r.Header.Values("Transfer-Encoding")
	hasTransferEncoding := len(r.TransferEncoding) > 0 || len(transferEncodingHeaders) > 0
	if !hasTransferEncoding {
		return false, ""
	}
	if r.ProtoMajor >= 2 {
		return true, "bad_transfer_encoding"
	}
	if r.ProtoMajor == 1 && r.ProtoMinor == 0 {
		return true, "bad_transfer_encoding"
	}
	if len(contentLengthHeaders) > 0 || r.ContentLength >= 0 {
		return true, "bad_request_framing"
	}
	codings := transferCodings(r)
	if len(codings) != 1 || codings[0] != "chunked" {
		return true, "bad_transfer_encoding"
	}
	return false, ""
}

func transferCodings(r *http.Request) []string {
	if len(r.TransferEncoding) > 0 {
		out := make([]string, 0, len(r.TransferEncoding))
		for _, coding := range r.TransferEncoding {
			out = append(out, strings.ToLower(strings.TrimSpace(coding)))
		}
		return out
	}
	var out []string
	for _, raw := range r.Header.Values("Transfer-Encoding") {
		for _, part := range strings.Split(raw, ",") {
			if trimmed := strings.ToLower(strings.TrimSpace(part)); trimmed != "" {
				out = append(out, trimmed)
			}
		}
	}
	return out
}

func (s *Server) enforceUploadPolicy(w http.ResponseWriter, r *http.Request, p *config.UploadPolicyConfig) (blocked bool, authAccepted bool, authResult verifier.Result) {
	if !uploadMethodAllowed(p, r.Method) {
		serveUploadBlocked(w, r, http.StatusMethodNotAllowed, "method_not_allowed")
		return true, false, verifier.Result{}
	}
	if p.MaxBodyBytes > 0 && r.ContentLength > p.MaxBodyBytes {
		serveUploadBlocked(w, r, http.StatusRequestEntityTooLarge, "payload_too_large")
		return true, false, verifier.Result{}
	}
	if !uploadContentTypeAllowed(p, r.Header.Get("Content-Type")) {
		serveUploadBlocked(w, r, http.StatusUnsupportedMediaType, "unsupported_media_type")
		return true, false, verifier.Result{}
	}
	if p.RequireAuth {
		ok, res := s.credentialAccepted(r, p.VerifierPolicy)
		if !ok {
			serveUploadBlocked(w, r, http.StatusUnauthorized, "auth_required")
			return true, false, verifier.Result{}
		}
		return false, true, res
	}
	return false, false, verifier.Result{}
}

func withUploadBodyLimit(r *http.Request, p *config.UploadPolicyConfig) *http.Request {
	if p == nil || p.MaxBodyBytes <= 0 || r.Body == nil {
		return r
	}
	state := &uploadLimitState{}
	r.Body = &uploadLimitReadCloser{
		inner:     r.Body,
		remaining: p.MaxBodyBytes,
		state:     state,
	}
	return r.WithContext(context.WithValue(r.Context(), uploadLimitContextKey{}, state))
}

func uploadLimitExceeded(r *http.Request) bool {
	if r == nil {
		return false
	}
	state, ok := r.Context().Value(uploadLimitContextKey{}).(*uploadLimitState)
	return ok && state.exceeded.Load()
}

func uploadVerifierPolicy(p *config.UploadPolicyConfig) string {
	if p == nil {
		return ""
	}
	return p.VerifierPolicy
}

func uploadMethodAllowed(p *config.UploadPolicyConfig, method string) bool {
	if len(p.Methods) == 0 {
		return true
	}
	for _, allowed := range p.Methods {
		if strings.EqualFold(strings.TrimSpace(allowed), method) {
			return true
		}
	}
	return false
}

func uploadContentTypeAllowed(p *config.UploadPolicyConfig, raw string) bool {
	if len(p.AllowedContentTypes) == 0 {
		return true
	}
	if strings.TrimSpace(raw) == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		mediaType = strings.ToLower(strings.TrimSpace(strings.Split(raw, ";")[0]))
	}
	mediaType = strings.ToLower(mediaType)
	for _, allowed := range p.AllowedContentTypes {
		a := strings.ToLower(strings.TrimSpace(allowed))
		if a == "" {
			continue
		}
		if strings.HasSuffix(a, "/") {
			if strings.HasPrefix(mediaType, a) {
				return true
			}
			continue
		}
		if mediaType == a {
			return true
		}
	}
	return false
}

func (s *Server) credentialAccepted(r *http.Request, verifierPolicy string) (bool, verifier.Result) {
	if s.verifiers != nil {
		var res verifier.Result
		switch strings.ToLower(strings.TrimSpace(verifierPolicy)) {
		case "skip_body_hmac":
			// HMAC verification reads and restores the body. Upload routes can
			// skip it so large streaming bodies are not buffered or truncated
			// before the upload limit wrapper and reverse proxy see them.
			res = s.verifiers.VerifyExcept(r, map[string]struct{}{"hmac": {}})
		default:
			res = s.verifiers.Verify(r)
		}
		if res.Accepted {
			name := res.Name
			if name == "" {
				name = "unknown"
			}
			telemetry.VerifierResultTotal.WithLabelValues(name, "accepted").Inc()
			return true, res
		}
	}
	if s.challengeHandler != nil && s.challengeHandler.Passed(r) {
		telemetry.VerifierResultTotal.WithLabelValues("challenge", "accepted").Inc()
		return true, verifier.Result{Name: "challenge", Reason: "valid challenge token"}
	}
	telemetry.VerifierResultTotal.WithLabelValues("none", "rejected").Inc()
	return false, verifier.Result{}
}

func serveUploadBlocked(w http.ResponseWriter, r *http.Request, status int, errCode string) {
	applyCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": errCode})
}
