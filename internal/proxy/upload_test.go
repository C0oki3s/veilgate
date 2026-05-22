package proxy

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/verifier"
)

func uploadReadingUpstream(t *testing.T) (*httptest.Server, *int, *int64) {
	t.Helper()
	hits := 0
	var bytesRead int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		n, _ := io.Copy(io.Discard, r.Body)
		bytesRead += n
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("upstream-ok"))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits, &bytesRead
}

func buildUploadPolicyServer(t *testing.T, upstreamURL string, policies []config.UploadPolicyConfig) *Server {
	t.Helper()
	cfg := &config.Config{
		Mode:           "observe",
		Upstream:       upstreamURL,
		UploadPolicies: policies,
		Detector: config.DetectorConfig{
			ScoreChallengeThreshold: 40,
			ScoreTarpitThreshold:    70,
		},
	}
	tracker := detector.NewTracker(60)
	scorer := detector.NewScorer(tracker, nil, nil)
	tarpit := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	srv, err := NewServer(cfg, scorer, tarpit, nil, nil, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func readRawHTTPResponse(t *testing.T, addr, raw string) *http.Response {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial test server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte(raw)); err != nil {
		t.Fatalf("write raw request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read raw response: %v", err)
	}
	return resp
}

func TestUploadPolicyRejectsOversizedKnownBody(t *testing.T) {
	upstream, hits := upstreamProbe(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:                "small-uploads",
		Paths:               []string{"/api/upload/*"},
		Methods:             []string{http.MethodPost},
		MaxBodyBytes:        4,
		AllowedContentTypes: []string{"text/plain"},
	}})

	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("12345"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("Origin", "https://app.example.com")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
	}
	if *hits != 0 {
		t.Fatalf("oversized upload reached upstream (%d hits)", *hits)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://app.example.com" {
		t.Fatalf("ACAO = %q, want origin echo", got)
	}
}

func TestUploadPolicyRejectsStreamingBodyOverLimit(t *testing.T) {
	upstream, hits, _ := uploadReadingUpstream(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:                "stream-limit",
		Paths:               []string{"/api/upload/*"},
		Methods:             []string{http.MethodPost},
		MaxBodyBytes:        4,
		AllowedContentTypes: []string{"text/plain"},
	}})

	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("12345"))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body=%q)", rr.Code, rr.Body.String())
	}
	if *hits > 1 {
		t.Fatalf("expected at most one partial upstream attempt, got %d", *hits)
	}
}

func TestUploadPolicyAllowsStreamingBodyUnderLimit(t *testing.T) {
	upstream, hits, bytesRead := uploadReadingUpstream(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:                "stream-limit",
		Paths:               []string{"/api/upload/*"},
		Methods:             []string{http.MethodPost},
		MaxBodyBytes:        5,
		AllowedContentTypes: []string{"text/plain"},
	}})

	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("1234"))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "text/plain")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want upstream 200 (body=%q)", rr.Code, rr.Body.String())
	}
	if *hits != 1 {
		t.Fatalf("expected one upstream hit, got %d", *hits)
	}
	if *bytesRead != 4 {
		t.Fatalf("upstream read %d bytes, want 4", *bytesRead)
	}
}

func TestUploadPolicyRejectsUnsupportedContentType(t *testing.T) {
	upstream, hits := upstreamProbe(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:                "excel-only",
		Paths:               []string{"/api/upload/*"},
		Methods:             []string{http.MethodPost},
		MaxBodyBytes:        1024,
		AllowedContentTypes: []string{"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
	}})

	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("csv-ish"))
	req.Header.Set("Content-Type", "text/csv")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rr.Code)
	}
	if *hits != 0 {
		t.Fatalf("unsupported upload reached upstream (%d hits)", *hits)
	}
}

func TestUploadPolicyRejectsMethod(t *testing.T) {
	upstream, hits := upstreamProbe(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:    "post-only",
		Paths:   []string{"/api/upload/*"},
		Methods: []string{http.MethodPost},
	}})

	req := httptest.NewRequest(http.MethodPut, "/api/upload/file", strings.NewReader("body"))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", rr.Code)
	}
	if *hits != 0 {
		t.Fatalf("wrong-method upload reached upstream (%d hits)", *hits)
	}
}

func TestUploadPolicyRequiresAuth(t *testing.T) {
	upstream, hits := upstreamProbe(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:        "auth-upload",
		Paths:       []string{"/api/upload/*"},
		Methods:     []string{http.MethodPost},
		RequireAuth: true,
	}})

	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("body"))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if *hits != 0 {
		t.Fatalf("unauthenticated upload reached upstream (%d hits)", *hits)
	}
}

func TestUploadPolicyBearerAuthProxies(t *testing.T) {
	upstream, hits := upstreamProbe(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:                "auth-upload",
		Paths:               []string{"/api/upload/*"},
		Methods:             []string{http.MethodPost},
		MaxBodyBytes:        1024,
		AllowedContentTypes: []string{"image/"},
		RequireAuth:         true,
	}})
	tokensDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(tokensDir, "uploader.token"), []byte("upload-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	bv, err := verifier.NewBearerVerifier(verifier.BearerConfig{TokensDir: tokensDir})
	if err != nil {
		t.Fatalf("NewBearerVerifier: %v", err)
	}
	srv.SetVerifiers(verifier.NewChain(bv))

	req := httptest.NewRequest(http.MethodPost, "/api/upload/avatar", strings.NewReader("png"))
	req.Header.Set("Content-Type", "image/png")
	req.Header.Set("Authorization", "Bearer upload-token")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want upstream 200 (body=%q)", rr.Code, rr.Body.String())
	}
	if *hits != 1 {
		t.Fatalf("expected upload to reach upstream once, got %d", *hits)
	}
}

func TestUploadPolicyExactPathBeatsWildcard(t *testing.T) {
	srv := &Server{cfg: &config.Config{UploadPolicies: []config.UploadPolicyConfig{
		{Name: "wildcard", Paths: []string{"/api/upload/*"}, MaxBodyBytes: 100},
		{Name: "exact", Paths: []string{"/api/upload/avatar"}, MaxBodyBytes: 1},
	}}}
	req := httptest.NewRequest(http.MethodPost, "/api/upload/avatar", nil)

	p, _, ok := srv.matchUploadPolicy(req)
	if !ok {
		t.Fatal("expected upload policy match")
	}
	if p.Name != "exact" {
		t.Fatalf("matched policy %q, want exact", p.Name)
	}
}

type fakeVerifier struct {
	name     string
	accept   bool
	called   *bool
	clientID string
}

func (f fakeVerifier) Name() string { return f.name }

func (f fakeVerifier) Verify(*http.Request) verifier.Result {
	if f.called != nil {
		*f.called = true
	}
	if !f.accept {
		return verifier.Result{Name: f.name, Reason: "test reject"}
	}
	return verifier.Result{Accepted: true, Name: f.name, Client: f.clientID, Reason: "test accept"}
}

func TestUploadPolicySkipBodyHMACVerifierPolicy(t *testing.T) {
	hmacCalled := false
	bearerCalled := false
	srv := &Server{
		verifiers: verifier.NewChain(
			fakeVerifier{name: "hmac", accept: true, called: &hmacCalled, clientID: "hmac-client"},
			fakeVerifier{name: "bearer", accept: true, called: &bearerCalled, clientID: "bearer-client"},
		),
	}
	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("large"))

	ok, res := srv.credentialAccepted(req, "skip_body_hmac")
	if !ok {
		t.Fatal("expected non-HMAC verifier to accept")
	}
	if hmacCalled {
		t.Fatal("hmac verifier was called despite skip_body_hmac")
	}
	if !bearerCalled {
		t.Fatal("bearer verifier was not called")
	}
	if res.Name != "bearer" {
		t.Fatalf("accepted verifier = %q, want bearer", res.Name)
	}
}

func TestBadRequestFramingRejectsContentLengthAndTransferEncoding(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("body"))
	req.TransferEncoding = []string{"chunked"}
	req.Header.Set("Content-Length", "4")
	req.ContentLength = 4

	if bad, code := badRequestFraming(req); !bad || code != "bad_request_framing" {
		t.Fatalf("badRequestFraming = (%v, %q), want bad_request_framing", bad, code)
	}
}

func TestBadRequestFramingRejectsNonChunkedTransferEncoding(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("body"))
	req.TransferEncoding = []string{"gzip"}
	req.ContentLength = -1

	if bad, code := badRequestFraming(req); !bad || code != "bad_transfer_encoding" {
		t.Fatalf("badRequestFraming = (%v, %q), want bad_transfer_encoding", bad, code)
	}
}

func TestBadRequestFramingRejectsHTTP10TransferEncoding(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("body"))
	req.Proto = "HTTP/1.0"
	req.ProtoMajor = 1
	req.ProtoMinor = 0
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1

	if bad, code := badRequestFraming(req); !bad || code != "bad_transfer_encoding" {
		t.Fatalf("badRequestFraming = (%v, %q), want bad_transfer_encoding", bad, code)
	}
}

func TestBadRequestFramingRejectsHTTP2TransferEncoding(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/upload/file", strings.NewReader("body"))
	req.Proto = "HTTP/2.0"
	req.ProtoMajor = 2
	req.ProtoMinor = 0
	req.TransferEncoding = []string{"chunked"}
	req.ContentLength = -1

	if bad, code := badRequestFraming(req); !bad || code != "bad_transfer_encoding" {
		t.Fatalf("badRequestFraming = (%v, %q), want bad_transfer_encoding", bad, code)
	}
}

func TestRawHTTP11ChunkedUploadOverLimitReturns413(t *testing.T) {
	upstream, _, _ := uploadReadingUpstream(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:                "chunked-limit",
		Paths:               []string{"/api/upload/*"},
		Methods:             []string{http.MethodPost},
		MaxBodyBytes:        4,
		AllowedContentTypes: []string{"text/plain"},
	}})
	edge := httptest.NewUnstartedServer(srv.Handler())
	edge.Listener = NewFramingGuardListener(edge.Listener)
	edge.Start()
	t.Cleanup(edge.Close)

	resp := readRawHTTPResponse(t, edge.Listener.Addr().String(),
		"POST /api/upload/file HTTP/1.1\r\n"+
			"Host: example.test\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Content-Type: text/plain\r\n"+
			"\r\n"+
			"3\r\nabc\r\n"+
			"3\r\ndef\r\n"+
			"0\r\n\r\n")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestRawHTTP11ContentLengthTransferEncodingRejected(t *testing.T) {
	upstream, hits, _ := uploadReadingUpstream(t)
	srv := buildUploadPolicyServer(t, upstream.URL, []config.UploadPolicyConfig{{
		Name:         "chunked-limit",
		Paths:        []string{"/api/upload/*"},
		Methods:      []string{http.MethodPost},
		MaxBodyBytes: 100,
	}})
	edge := httptest.NewUnstartedServer(srv.Handler())
	edge.Listener = NewFramingGuardListener(edge.Listener)
	edge.Start()
	t.Cleanup(edge.Close)

	resp := readRawHTTPResponse(t, edge.Listener.Addr().String(),
		"POST /api/upload/file HTTP/1.1\r\n"+
			"Host: example.test\r\n"+
			"Content-Length: 4\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"0\r\n\r\n")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if *hits != 0 {
		t.Fatalf("CL+TE request reached upstream (%d hits)", *hits)
	}
}

func TestFramingGuardRejectsObsoleteFoldAndDuplicateContentLength(t *testing.T) {
	cases := []struct {
		name   string
		header string
	}{
		{
			name: "obsolete fold",
			header: "POST / HTTP/1.1\r\n" +
				"Host: example.test\r\n" +
				" Transfer-Encoding: chunked",
		},
		{
			name: "duplicate content length",
			header: "POST / HTTP/1.1\r\n" +
				"Host: example.test\r\n" +
				"Content-Length: 1\r\n" +
				"Content-Length: 1",
		},
		{
			name: "gzip chunked",
			header: "POST / HTTP/1.1\r\n" +
				"Host: example.test\r\n" +
				"Transfer-Encoding: gzip, chunked",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !badHTTPRequestFraming([]byte(tc.header)) {
				t.Fatal("expected raw HTTP framing guard to reject request")
			}
		})
	}
}

func TestFramingGuardAllowsSimpleChunkedHTTP11(t *testing.T) {
	header := "POST / HTTP/1.1\r\n" +
		"Host: example.test\r\n" +
		"Transfer-Encoding: chunked"
	if badHTTPRequestFraming([]byte(header)) {
		t.Fatal("simple HTTP/1.1 chunked request should be allowed")
	}
}
