package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	RequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_requests_total",
		Help: "Total requests observed by route decision.",
	}, []string{"decision"}) // real, tarpit, challenge, observe

	ScoreHistogram = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "veilgate_score",
		Help:    "Distribution of agent-likelihood scores (0-100).",
		Buckets: []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
	})

	// ScoreByDecision splits the score histogram by the decision the
	// proxy made, so you can tell in one query whether a score band is
	// being routed to tarpit vs real. Useful for tuning thresholds.
	ScoreByDecision = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "veilgate_score_by_decision",
		Help:    "Score distribution split by routing decision.",
		Buckets: []float64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
	}, []string{"decision"})

	TarpitBytesServed = promauto.NewCounter(prometheus.CounterOpts{
		Name: "veilgate_tarpit_bytes_served_total",
		Help: "Total bytes served from the tarpit.",
	})

	TarpitLatencyMs = promauto.NewCounter(prometheus.CounterOpts{
		Name: "veilgate_tarpit_latency_ms_total",
		Help: "Total artificial latency added by the tarpit, milliseconds.",
	})

	EstimatedAttackerCostUSD = promauto.NewCounter(prometheus.CounterOpts{
		Name: "veilgate_attacker_cost_usd_total",
		Help: "Estimated attacker LLM API cost burned, USD.",
	})

	SignalHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_signal_hits_total",
		Help: "Count of detection signal hits by name.",
	}, []string{"signal"})

	// IPReputationHits — counts clients that landed in a known-bad
	// CIDR, split by category (tor_exit, cloud, anonymizer, rfc1918_leak).
	IPReputationHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_ip_reputation_hits_total",
		Help: "Hits on rules/ip_reputation.yaml by category.",
	}, []string{"category"})

	// FleetRotationFires — one increment per request where the fleet
	// fingerprint passed a rotation tier, labelled by the severity tier.
	FleetRotationFires = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_fleet_rotation_fires_total",
		Help: "Number of requests that tripped the IP-rotation fleet detector.",
	}, []string{"tier"}) // "low", "mid", "high"

	// FleetFingerprintIPs — histogram of distinct-IP counts per
	// fingerprint, sampled whenever a new request lands. A big hump
	// above 10 means a proxy pool is active.
	FleetFingerprintIPs = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "veilgate_fleet_fingerprint_ips",
		Help:    "Distinct IPs per behavioural fingerprint, sampled per-request.",
		Buckets: []float64{1, 2, 3, 5, 8, 13, 25, 50, 100, 250},
	})

	// UARotationFires — one per request where a client IP exceeded the
	// UA-pool threshold.
	UARotationFires = promauto.NewCounter(prometheus.CounterOpts{
		Name: "veilgate_ua_rotation_fires_total",
		Help: "Requests that tripped the per-IP UA-rotation detector.",
	})

	// ToolFamilyHits — each suspicious-UA hit mapped to a canonical
	// tool family. Lets you graph "sqlmap vs nikto vs nuclei vs ffuf"
	// without grepping logs.
	ToolFamilyHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_tool_family_hits_total",
		Help: "Suspicious-UA hits bucketed into canonical attacker tool families.",
	}, []string{"family"})

	// MLScore — histogram of the ML signal points a request contributed.
	MLScore = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "veilgate_ml_score_points",
		Help:    "Points contributed by the ml_agent_score signal when it fires.",
		Buckets: []float64{5, 10, 15, 20, 25, 30, 35, 40},
	})

	// PersistQueueDepth — current depth of the async persist channel.
	// Saturation means the proxy is dropping events, which VeilGate
	// does by design to keep the hot path from stalling — but you
	// want this at 0 almost always.
	PersistQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "veilgate_persist_queue_depth",
		Help: "Current depth of the persist-store write queue.",
	})

	// ClientCardinality — gauge of currently-tracked client IPs.
	ClientCardinality = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "veilgate_tracked_clients",
		Help: "Unique client IPs currently in the per-IP tracker.",
	})

	// FleetFingerprintCardinality — gauge of currently-tracked
	// behavioural fingerprints.
	FleetFingerprintCardinality = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "veilgate_fleet_fingerprints",
		Help: "Unique behavioural fingerprints currently tracked.",
	})

	// MinerCandidates — counter of candidates the ML miner wrote to
	// rules/learned.yaml. Bump once per miner tick that produced at
	// least one entry.
	MinerCandidates = promauto.NewCounter(prometheus.CounterOpts{
		Name: "veilgate_miner_candidates_total",
		Help: "Total rule candidates the ML miner has emitted into learned.yaml.",
	})

	// PublicIPRequests — counts requests arriving from public (non-RFC1918)
	// IPs, labelled by whether they are part of a rotation group.
	PublicIPRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_public_ip_requests_total",
		Help: "Requests from public (non-RFC1918) IPs, labelled by rotation status.",
	}, []string{"rotating"}) // "yes" or "no"

	// PublicIPRotationDistinctIPs — histogram of distinct public IPs
	// observed per behavioural fingerprint when the fleet detector fires.
	// A spike above 5 means a cloud/VPN IP-rotation campaign is active.
	PublicIPRotationDistinctIPs = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "veilgate_public_ip_rotation_distinct",
		Help:    "Distinct public IPs per fingerprint when fleet rotation fires.",
		Buckets: []float64{2, 3, 5, 8, 13, 25, 50, 100},
	})

	// PublicIPRotationEvents — counter of rotation-detection events that
	// specifically involved public (non-RFC1918) IPs. This is the cross-
	// signal: fleet rotation + public IP origin.
	PublicIPRotationEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_public_ip_rotation_events_total",
		Help: "Fleet rotation events where all participating IPs are public.",
	}, []string{"tier", "ip_category"}) // tier=low/mid/high, ip_category=cloud/tor_exit/anonymizer/unknown_public

	// MLFitDuration — histogram of Isolation Forest refit duration in
	// seconds. Watch this in Prometheus to confirm parallel tree
	// building actually helps on your box.
	MLFitDuration = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "veilgate_ml_fit_duration_seconds",
		Help:    "Time taken by one Isolation Forest refit (parallel tree construction).",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30},
	})

	// MLFitRows — histogram of training rows handed to each fit after
	// any TrainMaxRows subsampling. Lets you see how capped your fits are.
	MLFitRows = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "veilgate_ml_fit_rows",
		Help:    "Number of rows fed to the Isolation Forest per fit.",
		Buckets: []float64{100, 500, 1000, 2000, 5000, 10000, 25000},
	})

	// MLFitsTotal — counter of completed fits, labelled by status:
	// "ok", "skipped_busy" (previous fit still running), "skipped_cold"
	// (not enough rows yet), "skipped_disabled" (ml.enabled=false).
	MLFitsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "veilgate_ml_fits_total",
		Help: "Completed ML refit runs by status.",
	}, []string{"status"})

	// BayesObservedTotal — gauge of labelled examples Bayes has seen.
	// Useful to watch burn-in progress at a glance.
	BayesObservedTotal = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "veilgate_ml_bayes_observed",
		Help: "Total weak-labelled examples sent to the online Bayes classifier.",
	})
)

// ToolFamilyFromUA maps a suspicious-UA match substring back to a
// canonical Prometheus label. Kept here (rather than in the detector)
// so both the scorer emit-path and any replay tooling use the same
// mapping. Unknown tools fall through to "other".
func ToolFamilyFromUA(ua string) string {
	// Lowercase the UA once; callers pass whatever case they have.
	s := toLower(ua)
	// Ordered longest-first so "python-requests" wins over "requests".
	for _, pair := range toolFamilyMap {
		if containsStr(s, pair[0]) {
			return pair[1]
		}
	}
	return "other"
}

// Kept as pair-of-strings rather than a map so order is stable.
var toolFamilyMap = [][2]string{
	{"python-requests", "python-requests"},
	{"python-urllib", "python-urllib"},
	{"python-httpx", "python-httpx"},
	{"go-http-client", "go-http-client"},
	{"libwww-perl", "nikto"},
	{"nikto", "nikto"},
	{"sqlmap", "sqlmap"},
	{"nuclei", "nuclei"},
	{"ffuf", "ffuf"},
	{"gobuster", "gobuster"},
	{"dirsearch", "dirsearch"},
	{"feroxbuster", "feroxbuster"},
	{"subfinder", "subfinder"},
	{"httpx", "httpx"},
	{"katana", "katana"},
	{"gospider", "gospider"},
	{"wpscan", "wpscan"},
	{"wapiti", "wapiti"},
	{"arjun", "arjun"},
	{"wafw00f", "wafw00f"},
	{"trufflehog", "trufflehog"},
	{"gitleaks", "gitleaks"},
	{"zaproxy", "zap"},
	{"zap/", "zap"},
	{"burp", "burp"},
	{"caido", "caido"},
	{"xsstrike", "xsstrike"},
	{"commix", "commix"},
	{"curl/", "curl"},
	{"wget/", "wget"},
	{"httpie", "httpie"},
	{"headlesschrome", "headless-chrome"},
	{"playwright", "playwright"},
	{"puppeteer", "puppeteer"},
	{"strix", "strix"},
	{"pentestgpt", "pentestgpt"},
}

// Local helpers so this file has no imports beyond prometheus. Matches
// strings.ToLower / strings.Contains semantics for ASCII, which is all
// we need for User-Agent comparisons.
func toLower(s string) string {
	b := []byte(s)
	for i := 0; i < len(b); i++ {
		if b[i] >= 'A' && b[i] <= 'Z' {
			b[i] += 'a' - 'A'
		}
	}
	return string(b)
}

func containsStr(hay, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	if len(needle) > len(hay) {
		return false
	}
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
