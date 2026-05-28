package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

// OTelSink is the OpenTelemetry backend for the Bus. It creates OTel-native
// instruments for all VeilGate metrics — completely independent of the
// Prometheus registry. OnEvent dispatches on Event.Kind so a single sink
// covers every boundary (request, tarpit, challenge, ML fit, periodic).
type OTelSink struct {
	// request hot-path
	requests         otelmetric.Int64Counter
	score            otelmetric.Float64Histogram
	scoreByDecision  otelmetric.Float64Histogram
	signalHits       otelmetric.Int64Counter
	ipRepHits        otelmetric.Int64Counter
	fleetFires       otelmetric.Int64Counter
	uaRotFires       otelmetric.Int64Counter
	mlScore          otelmetric.Float64Histogram
	toolFamilyHits   otelmetric.Int64Counter
	pubIPRequests    otelmetric.Int64Counter
	pubIPRotEvents   otelmetric.Int64Counter
	pubIPRotDistinct otelmetric.Float64Histogram
	reqDuration      otelmetric.Float64Histogram
	// endpoint correlation
	epRequests     otelmetric.Int64Counter
	epScoreTier    otelmetric.Int64Counter
	epSignal       otelmetric.Int64Counter
	epAttackFamily otelmetric.Int64Counter
	// tarpit
	tarpitLatency  otelmetric.Int64Counter
	tarpitBytes    otelmetric.Int64Counter
	tarpitCost     otelmetric.Float64Counter
	tarpitTemplate otelmetric.Int64Counter
	// challenge
	challengeIssued otelmetric.Int64Counter
	challengeSolved otelmetric.Int64Counter
	challengeFailed otelmetric.Int64Counter
	// ml fit
	mlFits        otelmetric.Int64Counter
	mlFitDuration otelmetric.Float64Histogram
	mlFitRows     otelmetric.Float64Histogram
	mlBayesObs    otelmetric.Int64Gauge
	// periodic gauges
	trackedClients otelmetric.Int64Gauge
	fleetFPs       otelmetric.Int64Gauge
	fleetFPIPs     otelmetric.Float64Histogram
	persistQD      otelmetric.Int64Gauge
	persistDropped otelmetric.Int64Counter
	mlBayesEntries otelmetric.Int64Gauge
}

// NewOTelSink creates all instruments on the given MeterProvider.
// The OTel SDK returns a no-op instrument (never nil) on error, so all
// instruments are always safe to call — the sink is always returned.
func NewOTelSink(mp otelmetric.MeterProvider) *OTelSink {
	m := mp.Meter("veilgate")
	s := &OTelSink{}

	scoreBuckets := otelmetric.WithExplicitBucketBoundaries(10, 20, 30, 40, 50, 60, 70, 80, 90, 100)

	// ── Request hot-path ────────────────────────────────────────────────────
	s.requests, _ = m.Int64Counter("veilgate.requests.total",
		otelmetric.WithDescription("Total requests by routing decision."))
	s.score, _ = m.Float64Histogram("veilgate.score",
		otelmetric.WithDescription("Agent-likelihood score distribution (0-100)."),
		scoreBuckets)
	s.scoreByDecision, _ = m.Float64Histogram("veilgate.score.by_decision",
		otelmetric.WithDescription("Score distribution split by routing decision."),
		scoreBuckets)
	s.signalHits, _ = m.Int64Counter("veilgate.signal.hits.total",
		otelmetric.WithDescription("Detection signal hits by name."))
	s.ipRepHits, _ = m.Int64Counter("veilgate.ip_reputation.hits.total",
		otelmetric.WithDescription("IP reputation list hits by category."))
	s.fleetFires, _ = m.Int64Counter("veilgate.fleet_rotation.fires.total",
		otelmetric.WithDescription("Fleet IP-rotation detector fires by tier."))
	s.uaRotFires, _ = m.Int64Counter("veilgate.ua_rotation.fires.total",
		otelmetric.WithDescription("Per-IP UA-rotation detector fires."))
	s.mlScore, _ = m.Float64Histogram("veilgate.ml.score_points",
		otelmetric.WithDescription("Points contributed by ml_agent_score signal."),
		otelmetric.WithExplicitBucketBoundaries(5, 10, 20, 30, 50, 75, 100))
	s.toolFamilyHits, _ = m.Int64Counter("veilgate.tool_family.hits.total",
		otelmetric.WithDescription("Suspicious-UA hits by canonical attacker tool family."))
	s.pubIPRequests, _ = m.Int64Counter("veilgate.public_ip.requests.total",
		otelmetric.WithDescription("Requests from public IPs labelled by fleet-rotation status."))
	s.pubIPRotEvents, _ = m.Int64Counter("veilgate.public_ip.rotation_events.total",
		otelmetric.WithDescription("Fleet rotation events from public IPs, by tier and IP category."))
	s.pubIPRotDistinct, _ = m.Float64Histogram("veilgate.public_ip.rotation_distinct_ips",
		otelmetric.WithDescription("Distinct public IPs per fingerprint when fleet rotation fires."),
		otelmetric.WithExplicitBucketBoundaries(2, 5, 10, 20, 50))
	s.reqDuration, _ = m.Float64Histogram("veilgate.request.duration",
		otelmetric.WithDescription("End-to-end proxy request latency in seconds, by routing decision."),
		otelmetric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 2, 5, 10, 30))

	// ── Endpoint correlation ─────────────────────────────────────────────────
	s.epRequests, _ = m.Int64Counter("veilgate.endpoint.requests.total",
		otelmetric.WithDescription("All scored requests per endpoint+method+decision."))
	s.epScoreTier, _ = m.Int64Counter("veilgate.endpoint.score_tier.total",
		otelmetric.WithDescription("Request count per endpoint+score-tier+decision."))
	s.epSignal, _ = m.Int64Counter("veilgate.endpoint.signal.total",
		otelmetric.WithDescription("Detection signal hits per endpoint+method+decision."))
	s.epAttackFamily, _ = m.Int64Counter("veilgate.endpoint.attack_family.total",
		otelmetric.WithDescription("Attack-family hits per endpoint+method+decision."))

	// ── Tarpit ───────────────────────────────────────────────────────────────
	s.tarpitLatency, _ = m.Int64Counter("veilgate.tarpit.latency_ms.total",
		otelmetric.WithDescription("Total artificial latency added by tarpit, milliseconds."))
	s.tarpitBytes, _ = m.Int64Counter("veilgate.tarpit.bytes_served.total",
		otelmetric.WithDescription("Total bytes served from the tarpit."))
	s.tarpitCost, _ = m.Float64Counter("veilgate.tarpit.cost_usd.total",
		otelmetric.WithDescription("Estimated attacker LLM API cost burned, USD."))
	s.tarpitTemplate, _ = m.Int64Counter("veilgate.tarpit.template_type.total",
		otelmetric.WithDescription("Tarpit responses served per content-type category."))

	// ── Challenge ────────────────────────────────────────────────────────────
	s.challengeIssued, _ = m.Int64Counter("veilgate.challenge.issued.total",
		otelmetric.WithDescription("Total PoW challenge pages served, by form (html/spa)."))
	s.challengeSolved, _ = m.Int64Counter("veilgate.challenge.solved.total",
		otelmetric.WithDescription("Total PoW challenge proofs successfully verified."))
	s.challengeFailed, _ = m.Int64Counter("veilgate.challenge.failed.total",
		otelmetric.WithDescription("Failed PoW challenge verifications by reason."))

	// ── ML fit ───────────────────────────────────────────────────────────────
	s.mlFits, _ = m.Int64Counter("veilgate.ml.fits.total",
		otelmetric.WithDescription("Completed ML refit runs by status."))
	s.mlFitDuration, _ = m.Float64Histogram("veilgate.ml.fit_duration",
		otelmetric.WithDescription("Time taken by one Isolation Forest refit, seconds."),
		otelmetric.WithExplicitBucketBoundaries(0.1, 0.5, 1, 2, 5, 10, 30, 60))
	s.mlFitRows, _ = m.Float64Histogram("veilgate.ml.fit_rows",
		otelmetric.WithDescription("Rows fed to the Isolation Forest per refit."),
		otelmetric.WithExplicitBucketBoundaries(100, 500, 1000, 5000, 10000, 50000))
	s.mlBayesObs, _ = m.Int64Gauge("veilgate.ml.bayes_observed",
		otelmetric.WithDescription("Total weak-labelled examples sent to the online Bayes classifier."))

	// ── Periodic gauges ──────────────────────────────────────────────────────
	s.trackedClients, _ = m.Int64Gauge("veilgate.tracked_clients",
		otelmetric.WithDescription("Unique client IPs currently in the per-IP tracker."))
	s.fleetFPs, _ = m.Int64Gauge("veilgate.fleet_fingerprints",
		otelmetric.WithDescription("Unique behavioural fingerprints currently tracked."))
	s.fleetFPIPs, _ = m.Float64Histogram("veilgate.fleet_fingerprint_ips",
		otelmetric.WithDescription("Distinct IPs per behavioural fingerprint, sampled every 30 s."),
		otelmetric.WithExplicitBucketBoundaries(2, 5, 10, 20, 50))
	s.persistQD, _ = m.Int64Gauge("veilgate.persist.queue_depth",
		otelmetric.WithDescription("Current depth of the persist-store write queue."))
	s.persistDropped, _ = m.Int64Counter("veilgate.persist.dropped.total",
		otelmetric.WithDescription("Total events dropped due to persist write-queue back-pressure."))
	s.mlBayesEntries, _ = m.Int64Gauge("veilgate.ml.bayes_entries",
		otelmetric.WithDescription("Current distinct (feature, bucket) pairs in the Bayes histogram."))

	return s
}

// OnEvent satisfies Sink. Dispatches on Event.Kind to the appropriate handler.
func (s *OTelSink) OnEvent(e Event) {
	switch e.Kind {
	case KindRequest:
		s.onRequest(e.Request)
	case KindTarpit:
		s.onTarpit(e.Tarpit)
	case KindChallenge:
		s.onChallenge(e.Challenge)
	case KindMLFit:
		s.onMLFit(e.MLFit)
	case KindPeriodic:
		s.onPeriodic(e.Periodic)
	}
}

func (s *OTelSink) onRequest(e RequestEvent) {
	ctx := context.Background()
	dec := attribute.String("decision", e.Decision)

	s.requests.Add(ctx, 1, otelmetric.WithAttributes(dec))
	s.score.Record(ctx, float64(e.Score))
	s.scoreByDecision.Record(ctx, float64(e.Score), otelmetric.WithAttributes(dec))
	s.reqDuration.Record(ctx, e.DurationSec, otelmetric.WithAttributes(dec))

	for _, sig := range e.Signals {
		s.signalHits.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("signal", sig.Name)))
		if sig.Name == "ua_rotation" {
			s.uaRotFires.Add(ctx, 1)
		}
		if sig.Name == "ml_agent_score" {
			s.mlScore.Record(ctx, float64(sig.Points))
		}
	}

	if e.IPRepCategory != "" {
		s.ipRepHits.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("category", e.IPRepCategory)))
	}
	if e.FleetTier != "" {
		s.fleetFires.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("tier", e.FleetTier)))
	}
	if e.ToolFamily != "" {
		s.toolFamilyHits.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("family", e.ToolFamily)))
	}

	if e.IsPublicIP {
		rotating := "no"
		if e.IsFleetRotating {
			rotating = "yes"
		}
		s.pubIPRequests.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("rotating", rotating)))
	}
	if e.IsPublicIP && e.IsFleetRotating && e.FleetTier != "" {
		s.pubIPRotEvents.Add(ctx, 1, otelmetric.WithAttributes(
			attribute.String("tier", e.FleetTier),
			attribute.String("ip_category", e.PubIPRotCat),
		))
		for _, sig := range e.Signals {
			if sig.Name == "ip_rotation_fleet" {
				s.pubIPRotDistinct.Record(ctx, float64(sig.Points))
				break
			}
		}
	}

	// Endpoint correlation — mirrors ObserveEndpoint on the Prometheus side.
	bucket := NormalizePath(e.Path)
	meth := e.Method
	if len(meth) > 10 {
		meth = meth[:10]
	}
	s.epRequests.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("path_bucket", bucket),
		attribute.String("method", meth),
		dec,
	))
	s.epScoreTier.Add(ctx, 1, otelmetric.WithAttributes(
		attribute.String("path_bucket", bucket),
		attribute.String("tier", ScoreTier(e.Score)),
		dec,
	))
	if len(e.Signals) > 0 {
		families := make(map[string]struct{}, 4)
		for _, sig := range e.Signals {
			s.epSignal.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("path_bucket", bucket),
				attribute.String("signal", sig.Name),
				attribute.String("method", meth),
				dec,
			))
			families[SignalFamily(sig.Name)] = struct{}{}
		}
		for fam := range families {
			s.epAttackFamily.Add(ctx, 1, otelmetric.WithAttributes(
				attribute.String("path_bucket", bucket),
				attribute.String("family", fam),
				attribute.String("method", meth),
				dec,
			))
		}
	}
}

func (s *OTelSink) onTarpit(e TarpitEvent) {
	ctx := context.Background()
	s.tarpitLatency.Add(ctx, e.DelayMs)
	s.tarpitBytes.Add(ctx, int64(e.BytesServed))
	s.tarpitCost.Add(ctx, e.CostUSD)
	s.tarpitTemplate.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("type", e.ContentType)))
}

func (s *OTelSink) onChallenge(e ChallengeEvent) {
	ctx := context.Background()
	switch e.Action {
	case "issued":
		s.challengeIssued.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("form", e.Form)))
	case "solved":
		s.challengeSolved.Add(ctx, 1)
	case "failed":
		s.challengeFailed.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("reason", e.FailReason)))
	}
}

func (s *OTelSink) onMLFit(e MLFitEvent) {
	ctx := context.Background()
	s.mlFits.Add(ctx, 1, otelmetric.WithAttributes(attribute.String("status", e.Status)))
	if e.Status == "ok" {
		s.mlFitDuration.Record(ctx, e.DurationSec)
		s.mlFitRows.Record(ctx, float64(e.Rows))
		s.mlBayesObs.Record(ctx, e.BayesObs)
	}
}

func (s *OTelSink) onPeriodic(e PeriodicEvent) {
	ctx := context.Background()
	s.trackedClients.Record(ctx, int64(e.TrackedClients))
	s.fleetFPs.Record(ctx, int64(e.FleetFingerprints))
	for _, n := range e.FleetFingerprintIPs {
		s.fleetFPIPs.Record(ctx, float64(n))
	}
	s.persistQD.Record(ctx, int64(e.PersistQueueDepth))
	if e.PersistDroppedDelta > 0 {
		s.persistDropped.Add(ctx, e.PersistDroppedDelta)
	}
	s.mlBayesEntries.Record(ctx, int64(e.MLBayesEntries))
}
