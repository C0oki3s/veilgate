package proxy

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"github.com/C0oki3s/veilgate/internal/config"
	"github.com/C0oki3s/veilgate/internal/detector"
	"github.com/C0oki3s/veilgate/internal/ml"
	"github.com/C0oki3s/veilgate/internal/persist"
	"github.com/C0oki3s/veilgate/internal/telemetry"
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
	realProxy        http.Handler
	dashboard        *telemetry.Dashboard
	capture          *telemetry.Capture
	persist          *persist.Store
	mlExtractor      *ml.Extractor
	trustedProxies   []*net.IPNet
	log              zerolog.Logger
}

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
	rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "bad gateway", http.StatusBadGateway)
	}

	return &Server{
		cfg:              cfg,
		scorer:           scorer,
		tarpitHandler:    tarpit,
		challengeHandler: ch,
		realProxy:        rp,
		dashboard:        dash,
		trustedProxies:   ParseTrustedProxies(cfg.Detector.TrustedProxies),
		log:              log,
	}, nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(s.serve)
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	// Let the challenge verify endpoint through untouched.
	if s.challengeHandler != nil && r.URL.Path == "/__veilgate/verify" {
		s.challengeHandler.ServeHTTP(w, r)
		return
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

	// A client that already solved the PoW is treated as human for this session.
	if s.challengeHandler != nil && s.challengeHandler.Passed(r) && decision != DecisionTarpit {
		decision = DecisionReal
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

	rec := &statusRecorder{ResponseWriter: w}
	switch decision {
	case DecisionTarpit:
		s.tarpitHandler.ServeHTTP(rec, r)
	case DecisionChallenge:
		if s.challengeHandler != nil {
			s.challengeHandler.ServeHTTP(rec, r)
		} else {
			s.realProxy.ServeHTTP(rec, r)
		}
	default:
		s.realProxy.ServeHTTP(rec, r)
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
