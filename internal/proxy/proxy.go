package proxy

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/C0oki3s/veilgate/internal/challenge"
	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/ml"
	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/telemetry"
	"github.com/C0oki3s/veilgate/internal/verifier"
)

// Decision is what we've decided to do with a request.
type Decision int

const (
	DecisionReal Decision = iota
	DecisionChallenge
	DecisionTarpit
	DecisionObserve
)

func (d Decision) String() string {
	switch d {
	case DecisionReal:
		return "real"
	case DecisionChallenge:
		return "challenge"
	case DecisionTarpit:
		return "tarpit"
	case DecisionObserve:
		return "observe"
	}
	return "unknown"
}

// Server wires everything together.
type Server struct {
	cfg              *config.Config
	scorer           *detector.Scorer
	tracker          *detector.Tracker
	tarpitHandler    http.Handler
	challengeHandler ChallengeHandler
	verifiers        *verifier.Chain
	realProxy        http.Handler
	grpcProxy        http.Handler   // like realProxy but no ResponseHeaderTimeout + immediate flush
	uploadProxies    []http.Handler // route-specific proxies for upload policies
	upstreamURL      *url.URL       // stored for WebSocket TCP dial
	dashboard        *telemetry.Dashboard
	capture          *telemetry.Capture
	persist          *persist.Store
	mlExtractor      *ml.Extractor
	trustedProxies   []*net.IPNet
	log              zerolog.Logger
}

// SetVerifiers installs the verifier chain. Nil is safe — the server
// will simply skip the chain check and fall through to the existing
// PoW cookie / score pipeline.
func (s *Server) SetVerifiers(c *verifier.Chain) { s.verifiers = c }

// SetTracker hands the proxy a reference to the detector's per-client
// tracker so it can post the response status back via RecordStatus
// after writing the response. Required for the failure-recovery
// signal; the rest of the system tolerates a nil tracker.
func (s *Server) SetTracker(t *detector.Tracker) { s.tracker = t }

// statusRecorder is a tiny http.ResponseWriter wrapper that captures
// the WriteHeader status. Without it the proxy has no way to feed the
// failure-recovery signal — Go's stdlib doesn't expose the status
// after a response is written.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// SetCapture enables JSONL logging of every request for later ML training.
func (s *Server) SetCapture(c *telemetry.Capture) {
	s.capture = c
}

// SetPersist wires an event store. Events are queued with drop-on-full
// back-pressure so the proxy hot path stays free of disk stalls.
func (s *Server) SetPersist(p *persist.Store, e *ml.Extractor) {
	s.persist = p
	s.mlExtractor = e
}

// ChallengeHandler is optional; nil skips challenge step.
type ChallengeHandler interface {
	http.Handler
	Passed(r *http.Request) bool
}

// challengeDescriber is an optional interface the challenge handler
// can implement to feed the /__veilgate/.well-known discovery
// endpoint. Decoupled from ChallengeHandler so a future replacement
// handler can opt out by not implementing it.
type challengeDescriber interface {
	DescribeChallenge() challenge.ChallengeDescriptor
}

// challengeStarter is an optional interface the challenge handler
// can implement to serve the /__veilgate/start iframe-loadable PoW
// interstitial. Decoupled so a handler without a start page doesn't
// need to implement it.
type challengeStarter interface {
	StartPath() string
	ServeStart(w http.ResponseWriter, r *http.Request)
}

func NewServer(cfg *config.Config, scorer *detector.Scorer, tarpit http.Handler, ch ChallengeHandler, dash *telemetry.Dashboard, log zerolog.Logger) (*Server, error) {
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(upstream)
	// Don't leak our proxy identity to upstream.
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		r.Host = upstream.Host
	}
	rp.Transport = &http.Transport{
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
		ResponseHeaderTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	errHandler := func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}
	rp.ErrorHandler = errHandler

	// gRPC proxy: same director/host-rewrite as realProxy but with no
	// ResponseHeaderTimeout (gRPC streams are arbitrarily long) and
	// FlushInterval=-1 (flush each write immediately for streaming RPCs).
	grpcTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 5 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	grpcRP := httputil.NewSingleHostReverseProxy(upstream)
	grpcRP.Director = rp.Director
	grpcRP.Transport = grpcTransport
	grpcRP.FlushInterval = -1
	grpcRP.ErrorHandler = errHandler
	uploadProxies := make([]http.Handler, len(cfg.UploadPolicies))
	for i, p := range cfg.UploadPolicies {
		urp := httputil.NewSingleHostReverseProxy(upstream)
		urp.Director = rp.Director
		urp.Transport = uploadTransport(p.UpstreamResponseTimeout)
		urp.ErrorHandler = uploadErrorHandler(errHandler)
		uploadProxies[i] = urp
	}

	return &Server{
		cfg:              cfg,
		scorer:           scorer,
		tarpitHandler:    tarpit,
		challengeHandler: ch,
		realProxy:        rp,
		grpcProxy:        grpcRP,
		uploadProxies:    uploadProxies,
		upstreamURL:      upstream,
		dashboard:        dash,
		trustedProxies:   ParseTrustedProxies(cfg.Detector.TrustedProxies),
		log:              log,
	}, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

// discoveryDoc is the public JSON shape returned by
// /__veilgate/.well-known. Stable contract — clients pin to this.
// Optional fields are emitted only when populated so older clients
// safely ignore new fields.
type discoveryDoc struct {
	Challenge   *challenge.ChallengeDescriptor  `json:"challenge,omitempty"`
	Credentials []verifier.CredentialDescriptor `json:"credentials,omitempty"`
}

// serveDiscovery emits the well-known JSON. It is callable
// unauthenticated by design: a client SDK uses it on first contact
// before any credential is in hand. The response contains only
// configuration shape — never any secret, token, or PII.
func (s *Server) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	doc := discoveryDoc{}
	if cd, ok := s.challengeHandler.(challengeDescriber); ok {
		desc := cd.DescribeChallenge()
		doc.Challenge = &desc
	}
	if s.verifiers != nil {
		doc.Credentials = s.verifiers.Describe()
	}

	w.Header().Set("Content-Type", "application/json")
	// Short cache: discovery contents can change with rules
	// hot-reload, but per-request fetches would defeat the point of
	// a client-side cache. 60s is the same window the challenge
	// rules system targets for propagation.
	w.Header().Set("Cache-Control", "public, max-age=60")
	// CORS open: a browser SDK loaded from a different origin must be
	// able to fetch discovery. The body has no secrets and is the
	// same for every caller.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	_ = jsonEncode(w, doc)
}

// jsonEncode is a tiny wrapper that lets the discovery handler stay
// short. Inlined here rather than living in a helpers file so the
// entire discovery path is readable on one screen.
func jsonEncode(w http.ResponseWriter, v any) error {
	return json.NewEncoder(w).Encode(v)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	if rejectBadRequestFraming(w, r) {
		return
	}

	// CORS OPTIONS preflight — must run before routing, scoring, and challenge
	// logic. Browsers send these before every credentialed cross-origin request
	// and cannot carry cookies or challenge solutions, so blocking them only
	// prevents real traffic from reaching the proxy.
	if r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != "" {
		if strings.HasPrefix(r.URL.Path, "/__veilgate/") {
			// VeilGate-internal paths are served here, not by the upstream.
			// Synthesise the preflight response directly.
			w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			if v := r.Header.Get("Access-Control-Request-Headers"); v != "" {
				w.Header().Set("Access-Control-Allow-Headers", v)
			}
			w.Header().Set("Access-Control-Max-Age", "3600")
			w.Header().Set("Vary", "Origin")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		// All other paths: proxy the preflight to the upstream without
		// scoring or challenging. The upstream controls which origins and
		// headers it allows; VeilGate should not interfere.
		s.realProxy.ServeHTTP(w, r)
		return
	}

	// Let the challenge verify endpoint through untouched.
	if s.challengeHandler != nil && r.URL.Path == "/__veilgate/verify" {
		s.challengeHandler.ServeHTTP(w, r)
		return
	}
	// Discovery endpoint — advertises the configured challenge wire
	// shape and the verifier chain's credential descriptors so a
	// client SDK can auto-attach the right credential. No scoring,
	// no challenge, no upstream call: this is a meta endpoint that
	// returns static configuration as JSON.
	if r.URL.Path == "/__veilgate/.well-known" {
		s.serveDiscovery(w, r)
		return
	}
	// Start interstitial — iframe-loadable PoW page for cross-origin SPAs.
	// Routed before scoring so bots cannot poison the client's score by
	// hammering the start page (start page responses don't hit upstream).
	if cs, ok := s.challengeHandler.(challengeStarter); ok {
		if r.URL.Path == cs.StartPath() {
			cs.ServeStart(w, r)
			return
		}
	}

	uploadPolicy, uploadPolicyIndex, hasUploadPolicy := s.matchUploadPolicy(r)
	uploadAuthAccepted := false
	var uploadAuthResult verifier.Result
	if hasUploadPolicy {
		blocked, accepted, res := s.enforceUploadPolicy(w, r, uploadPolicy)
		if blocked {
			return
		}
		uploadAuthAccepted = accepted
		uploadAuthResult = res
		r = withUploadBodyLimit(r, uploadPolicy)
	}

	clientID := resolveClientIP(r, s.trustedProxies)
	score := s.scorer.Score(clientID, r)
	telemetry.ScoreHistogram.Observe(float64(score.Total))

	for _, sig := range score.Signals {
		telemetry.SignalHits.WithLabelValues(sig.Name).Inc()
		switch sig.Name {
		case "ip_reputation":
			// Reason is "client IP matches <cat> CIDR list" — pull cat out.
			if cat := extractIPRepCategory(sig.Reason); cat != "" {
				telemetry.IPReputationHits.WithLabelValues(cat).Inc()
			}
		case "ip_rotation_fleet":
			tier := "low"
			switch {
			case sig.Points >= 40:
				tier = "high"
			case sig.Points >= 25:
				tier = "mid"
			}
			telemetry.FleetRotationFires.WithLabelValues(tier).Inc()
		case "ua_rotation":
			telemetry.UARotationFires.Inc()
		case "ml_agent_score":
			telemetry.MLScore.Observe(float64(sig.Points))
		case "suspicious_ua":
			telemetry.ToolFamilyHits.WithLabelValues(telemetry.ToolFamilyFromUA(r.UserAgent())).Inc()
		}
	}

	decision := s.decide(score.Total)
	telemetry.ScoreByDecision.WithLabelValues(decision.String()).Observe(float64(score.Total))

	// Public-IP rotation cross-signal: track whether this client is a
	// public IP and whether it's part of a fleet rotation group.
	isPublic := s.scorer.IsPublicIP(clientID)
	if isPublic {
		rotating := "no"
		for _, sig := range score.Signals {
			if sig.Name == "ip_rotation_fleet" {
				rotating = "yes"
				tier := "low"
				switch {
				case sig.Points >= 40:
					tier = "high"
				case sig.Points >= 25:
					tier = "mid"
				}
				// Classify the public IP for the rotation event
				ipCat := "unknown_public"
				if cat, _, ok := s.scorer.ClassifyIP(clientID); ok {
					ipCat = cat
				}
				telemetry.PublicIPRotationEvents.WithLabelValues(tier, ipCat).Inc()
				// Extract distinct count from reason (approximate — parse the number)
				telemetry.PublicIPRotationDistinctIPs.Observe(float64(sig.Points))
				break
			}
		}
		telemetry.PublicIPRequests.WithLabelValues(rotating).Inc()
	}

	// Authenticator chain. Either a verifier (operator-issued HMAC
	// token, future JWT/mTLS) OR the PoW cookie/header counts as
	// "this client is trusted enough to skip the challenge tier."
	// Tarpit is intentionally NOT bypassed — a leaked HMAC secret or
	// stolen cookie can't whitewash attack-tier behaviour. The score
	// stays in charge of the worst-case outcome.
	if decision != DecisionTarpit {
		passed := uploadAuthAccepted
		res := uploadAuthResult
		if !passed {
			passed, res = s.credentialAccepted(r, uploadVerifierPolicy(uploadPolicy))
		}
		if passed {
			if res.Name != "" {
				s.log.Debug().
					Str("verifier", res.Name).
					Str("client", res.Client).
					Str("reason", res.Reason).
					Msg("verifier accepted request")
			}
			decision = DecisionReal
		}
	}

	// Log every decision for tuning.
	s.log.Info().
		Str("client", clientID).
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Int("score", score.Total).
		Str("decision", decision.String()).
		Interface("signals", score.Signals).
		Msg("request")

	telemetry.RequestsTotal.WithLabelValues(decision.String()).Inc()

	if s.dashboard != nil {
		s.dashboard.Record(telemetry.Event{
			Time:     time.Now(),
			Client:   clientID,
			Path:     r.URL.Path,
			Score:    score.Total,
			Decision: decision.String(),
		})
	}

	if s.capture != nil {
		names := make([]string, 0, len(score.Signals))
		for _, sig := range score.Signals {
			names = append(names, sig.Name)
		}
		s.capture.Write(telemetry.CaptureEvent{
			Time:      time.Now(),
			Client:    clientID,
			Method:    r.Method,
			Path:      r.URL.Path,
			UserAgent: r.UserAgent(),
			Referer:   r.Referer(),
			Accept:    r.Header.Get("Accept"),
			AcceptLan: r.Header.Get("Accept-Language"),
			AcceptEnc: r.Header.Get("Accept-Encoding"),
			SecFetch:  r.Header.Get("Sec-Fetch-Site"),
			Score:     score.Total,
			Signals:   names,
			Decision:  decision.String(),
		})
	}

	if s.persist != nil {
		names := make([]string, 0, len(score.Signals))
		for _, sig := range score.Signals {
			names = append(names, sig.Name)
		}
		var featuresJSON string
		if s.mlExtractor != nil {
			featuresJSON = s.mlExtractor.Extract(r, 0, r.Header.Get("X-Veilgate-JA4")).JSON()
		}
		s.persist.Record(persist.Event{
			Time:         time.Now().UTC(),
			ClientID:     clientID,
			Method:       r.Method,
			Path:         r.URL.Path,
			UserAgent:    r.UserAgent(),
			JA4:          r.Header.Get("X-Veilgate-JA4"),
			Score:        score.Total,
			Signals:      names,
			Decision:     decision.String(),
			FeaturesJSON: featuresJSON,
		})
	}

	// WebSocket upgrades and gRPC streams need protocol-specific handling.
	// The scoring/decision pipeline has already run above; we honour it
	// (challenged/tarpitted requests are rejected) but replace the
	// response body with machine-readable errors — HTML challenge pages
	// are useless to non-browser callers.
	if isHTTP2WebSocketConnect(r) {
		serveHTTP2WebSocketUnsupported(w, r)
		return
	}
	if isWebSocketUpgrade(r) {
		if decision == DecisionTarpit || decision == DecisionChallenge {
			serveUpgradeBlocked(w, r, decision)
		} else {
			s.serveWebSocket(w, r)
		}
		return
	}
	if isGRPC(r) {
		if decision == DecisionTarpit || decision == DecisionChallenge {
			serveGRPCBlocked(w, r, decision)
		} else {
			rec := &statusRecorder{ResponseWriter: w}
			s.grpcProxy.ServeHTTP(rec, r)
			if s.tracker != nil && rec.status > 0 {
				s.tracker.RecordStatus(clientID, rec.status, r.URL.Path, r.Method)
			}
		}
		return
	}

	proxyHandler := s.realProxy
	if hasUploadPolicy && uploadPolicyIndex >= 0 && uploadPolicyIndex < len(s.uploadProxies) && s.uploadProxies[uploadPolicyIndex] != nil {
		proxyHandler = s.uploadProxies[uploadPolicyIndex]
	}
	rec := &statusRecorder{ResponseWriter: w}
	switch decision {
	case DecisionTarpit:
		s.tarpitHandler.ServeHTTP(rec, r)
	case DecisionChallenge:
		if s.challengeHandler != nil {
			s.challengeHandler.ServeHTTP(rec, r)
		} else {
			proxyHandler.ServeHTTP(rec, r)
		}
	default:
		proxyHandler.ServeHTTP(rec, r)
	}

	// Feed the response status into the per-client tracker so the
	// failure-recovery signal can compare with the next request shape.
	if s.tracker != nil && rec.status > 0 {
		s.tracker.RecordStatus(clientID, rec.status, r.URL.Path, r.Method)
	}
}

func (s *Server) decide(score int) Decision {
	switch s.cfg.Mode {
	case "observe":
		// Never divert in observe mode -- we're just collecting signal data.
		return DecisionObserve
	case "challenge":
		if score >= s.cfg.Detector.ScoreChallengeThreshold {
			return DecisionChallenge
		}
		return DecisionReal
	case "tarpit":
		if score >= s.cfg.Detector.ScoreTarpitThreshold {
			return DecisionTarpit
		}
		if score >= s.cfg.Detector.ScoreChallengeThreshold {
			return DecisionChallenge
		}
		return DecisionReal
	case "auto":
		if score >= s.cfg.Detector.ScoreTarpitThreshold {
			return DecisionTarpit
		}
		if score >= s.cfg.Detector.ScoreChallengeThreshold {
			return DecisionChallenge
		}
		return DecisionReal
	}
	return DecisionReal
}

func clientIP(r *http.Request) string {
	return resolveClientIP(r, nil)
}

// resolveClientIP returns the effective client identifier.
//
// Why not just honor X-Forwarded-For: nuclei and similar probes inject
// things like "${jndi:ldap://...}" or "<script>alert(1)</script>" into the
// header to test for Log4Shell / XSS in downstream logging. If we pipe that
// through as the clientID, (a) it corrupts tracker state, (b) an attacker
// can spoof themselves onto trusted_ips by writing e.g. "127.0.0.1" into
// the header. So we only honor XFF when the direct RemoteAddr is inside
// the operator-declared trusted_proxies CIDR list, and we pick the
// right-most untrusted hop (standards-compliant RFC 7239 behaviour).
func resolveClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if len(trustedProxies) == 0 {
		return host
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil || !ipInAny(ip, trustedProxies) {
		return host
	}
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		return host
	}
	hops := strings.Split(xff, ",")
	// Walk right-to-left, returning the first hop that isn't itself a trusted proxy.
	for i := len(hops) - 1; i >= 0; i-- {
		h := strings.TrimSpace(hops[i])
		parsed := net.ParseIP(h)
		if parsed == nil {
			// Non-IP junk in header (injection attempt). Ignore it entirely.
			continue
		}
		if !ipInAny(parsed, trustedProxies) {
			return h
		}
	}
	return host
}

// extractIPRepCategory pulls the category token out of the canonical
// "client IP matches <cat> CIDR list" reason string. Returns empty
// if the reason doesn't match the expected shape.
func extractIPRepCategory(reason string) string {
	const prefix = "client IP matches "
	const suffix = " CIDR list"
	if !strings.HasPrefix(reason, prefix) || !strings.HasSuffix(reason, suffix) {
		return ""
	}
	cat := reason[len(prefix) : len(reason)-len(suffix)]
	return strings.TrimSpace(cat)
}

func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ParseTrustedProxies turns operator-supplied strings (bare IPs or CIDR
// blocks) into net.IPNet entries. Unparseable entries are silently dropped.
func ParseTrustedProxies(entries []string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(entries))
	for _, raw := range entries {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(raw); err == nil {
			out = append(out, n)
			continue
		}
		if ip := net.ParseIP(raw); ip != nil {
			mask := 32
			if ip.To4() == nil {
				mask = 128
			}
			if _, n, err := net.ParseCIDR(raw + "/" + itoa(mask)); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [4]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// ── protocol detection ────────────────────────────────────────────────────────

// isWebSocketUpgrade reports whether r is an HTTP/1.1 WebSocket upgrade
// handshake. Both headers must be present; comparison is case-insensitive.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		containsFold(r.Header.Get("Connection"), "upgrade")
}

// isGRPC reports whether r carries a gRPC content-type.
// Covers application/grpc, application/grpc+proto, application/grpc+json,
// and the gRPC-Web variants (application/grpc-web*).
func isGRPC(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

func isHTTP2WebSocketConnect(r *http.Request) bool {
	return r.ProtoMajor == 2 &&
		r.Method == http.MethodConnect &&
		strings.EqualFold(r.Header.Get(":protocol"), "websocket")
}

func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// ── WebSocket tunnel ──────────────────────────────────────────────────────────

// serveWebSocket tunnels a WebSocket connection to the upstream. The
// decision pipeline has already run; this is only called for Real/Observe
// decisions. It:
//  1. Dials the upstream (TLS when the upstream URL is https/wss).
//  2. Hijacks the incoming connection.
//  3. Forwards the upgrade request and proxies the upstream 101 response.
//  4. Bidirectionally copies bytes until either side closes.
func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	addr := s.upstreamURL.Host

	var upstreamConn net.Conn
	var err error
	switch strings.ToLower(s.upstreamURL.Scheme) {
	case "https", "wss":
		upstreamConn, err = tls.Dial("tcp", addr, &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: s.upstreamURL.Hostname(),
		})
	default:
		upstreamConn, err = net.DialTimeout("tcp", addr, 10*time.Second)
	}
	if err != nil {
		s.log.Error().Err(err).Str("upstream", addr).Msg("websocket: dial upstream")
		http.Error(w, "bad gateway", http.StatusBadGateway)
		return
	}
	defer upstreamConn.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "server does not support hijacking", http.StatusInternalServerError)
		return
	}
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		s.log.Error().Err(err).Msg("websocket: hijack")
		return
	}
	defer clientConn.Close()

	// Clone, rewrite Host, strip hop-by-hop headers, then send to upstream.
	outReq := r.Clone(r.Context())
	outReq.Host = s.upstreamURL.Host
	outReq.Header.Del("Te")
	outReq.Header.Del("Trailer")
	outReq.Header.Del("Trailers")
	outReq.Header.Del("Transfer-Encoding")
	if err := outReq.Write(upstreamConn); err != nil {
		s.wsRawError(clientConn, http.StatusBadGateway, "bad gateway")
		return
	}

	// Read the upstream's upgrade response and forward it verbatim.
	upstreamBuf := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(upstreamBuf, outReq)
	if err != nil {
		s.wsRawError(clientConn, http.StatusBadGateway, "bad gateway")
		return
	}
	if err := resp.Write(clientConn); err != nil {
		return
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Upstream refused the upgrade; response already forwarded.
		return
	}

	// Handshake complete — tunnel raw bytes in both directions.
	done := make(chan struct{}, 2)
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(upstreamConn, clientBuf) // clientBuf wraps clientConn
	}()
	go func() {
		defer func() { done <- struct{}{} }()
		io.Copy(clientConn, upstreamBuf) // upstreamBuf wraps upstreamConn
	}()
	<-done
}

// wsRawError writes a minimal HTTP error response to a hijacked connection
// (the normal http.Error helper won't work once hijacked).
func (s *Server) wsRawError(conn net.Conn, code int, msg string) {
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: %d\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n%s",
		code, http.StatusText(code), len(msg), msg)
	conn.Write([]byte(resp)) //nolint:errcheck
}

// ── blocked-protocol responses ────────────────────────────────────────────────

// serveUpgradeBlocked rejects a WebSocket upgrade with a machine-readable
// JSON body. HTML challenge pages are useless to WebSocket/RPC callers.
func serveUpgradeBlocked(w http.ResponseWriter, r *http.Request, decision Decision) {
	applyCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	if decision == DecisionTarpit {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`)) //nolint:errcheck
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	w.Write([]byte(`{"error":"challenge_required"}`)) //nolint:errcheck
}

// serveGRPCBlocked terminates a gRPC or gRPC-Web call with the appropriate
// gRPC status code:
//   - UNAUTHENTICATED (16) when the request needs to solve a challenge first.
//   - PERMISSION_DENIED (7) when the client is tarpitted.
//
// The HTTP status is 200 per the gRPC spec; the gRPC status lives in headers.
func serveGRPCBlocked(w http.ResponseWriter, r *http.Request, decision Decision) {
	applyCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/grpc")
	if decision == DecisionTarpit {
		w.Header().Set("grpc-status", "7") // PERMISSION_DENIED
		w.Header().Set("grpc-message", "forbidden")
	} else {
		w.Header().Set("grpc-status", "16") // UNAUTHENTICATED
		w.Header().Set("grpc-message", "challenge_required")
	}
	w.WriteHeader(http.StatusOK)
}

func serveHTTP2WebSocketUnsupported(w http.ResponseWriter, r *http.Request) {
	applyCORSHeaders(w, r)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"http2_websocket_unsupported"}`)) //nolint:errcheck
}

// applyCORSHeaders echoes the Origin as Access-Control-Allow-Origin when the
// request is cross-origin. Called on every response that VeilGate itself
// generates (blocked WebSocket/gRPC, challenge, tarpit) so that browsers can
// read error responses instead of seeing an opaque network error.
func applyCORSHeaders(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Vary", "Origin")
	}
}
