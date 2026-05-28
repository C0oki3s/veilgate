package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	otelmetric "go.opentelemetry.io/otel/metric"
)

func attrDecision(d string) attribute.KeyValue { return attribute.String("decision", d) }
func attrSignal(s string) attribute.KeyValue   { return attribute.String("signal", s) }

// OTelSink is the OpenTelemetry backend for the Bus. It holds OTel-native
// instruments registered directly on the MeterProvider — completely independent
// of the Prometheus registry. No bridge, no shared state.
type OTelSink struct {
	requests otelmetric.Int64Counter
	score    otelmetric.Float64Histogram
	signals  otelmetric.Int64Counter
}

// NewOTelSink creates instruments on the given MeterProvider.
// Returns nil without error when instrument creation fails so the caller
// can treat a nil sink as a no-op rather than a fatal startup error.
func NewOTelSink(mp otelmetric.MeterProvider) *OTelSink {
	meter := mp.Meter("veilgate")

	requests, err := meter.Int64Counter(
		"veilgate.requests.total",
		otelmetric.WithDescription("Total requests by routing decision."),
	)
	if err != nil {
		return nil
	}

	score, err := meter.Float64Histogram(
		"veilgate.score",
		otelmetric.WithDescription("Distribution of agent-likelihood scores (0-100)."),
		otelmetric.WithExplicitBucketBoundaries(10, 20, 30, 40, 50, 60, 70, 80, 90, 100),
	)
	if err != nil {
		return nil
	}

	signals, err := meter.Int64Counter(
		"veilgate.signal.hits.total",
		otelmetric.WithDescription("Detection signal hits by name."),
	)
	if err != nil {
		return nil
	}

	return &OTelSink{
		requests: requests,
		score:    score,
		signals:  signals,
	}
}

// OnRequest satisfies Sink. Records all three instruments for every event.
func (s *OTelSink) OnRequest(e RequestEvent) {
	ctx := context.Background()

	s.requests.Add(ctx, 1,
		otelmetric.WithAttributes(attrDecision(e.Decision)),
	)
	s.score.Record(ctx, float64(e.Score),
		otelmetric.WithAttributes(attrDecision(e.Decision)),
	)
	for _, name := range e.SignalNames {
		s.signals.Add(ctx, 1,
			otelmetric.WithAttributes(attrSignal(name)),
		)
	}
}
