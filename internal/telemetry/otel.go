// Package telemetry — OpenTelemetry tracer setup.
//
// InitTracer reads OTEL_EXPORTER_OTLP_ENDPOINT from the environment.
// When the variable is empty (the default in non-observability deployments)
// it installs a no-op tracer so all instrumented code compiles and runs
// without emitting a single byte. When the variable is set to an OTLP/HTTP
// endpoint (e.g. "http://otel-collector:4318") the SDK ships spans there.
//
// Call InitTracer once from main; the returned shutdown func must be deferred.
// All packages that instrument code call otel.Tracer("veilgate") to obtain
// the global tracer — they do not need to import this file.
package telemetry

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/trace"
)

const tracerName = "veilgate"

// Tracer is the global VeilGate tracer. Packages that add spans call
// Tracer.Start instead of importing the otel SDK directly, so the
// import graph stays clean and the tracer name stays consistent.
var Tracer = otel.Tracer(tracerName)

// InitTracer sets up the global TracerProvider. Returns a shutdown func that
// flushes and closes the exporter — call it via defer in main.
//
// If OTEL_EXPORTER_OTLP_ENDPOINT is empty the function is a no-op and
// returns a no-op shutdown. This keeps the default deployment free of any
// collector dependency.
func InitTracer(ctx context.Context) (shutdown func(context.Context) error, err error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// No collector configured — leave the global noop provider in place.
		return func(context.Context) error { return nil }, nil
	}

	exp, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exp,
			trace.WithMaxExportBatchSize(512),
			trace.WithBatchTimeout(5*time.Second),
		),
		trace.WithSampler(sampler()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Refresh the global Tracer var now that the provider is wired.
	Tracer = otel.Tracer(tracerName)

	return tp.Shutdown, nil
}

// sampler returns the configured sampler. Reads OTEL_TRACES_SAMPLER /
// OTEL_TRACES_SAMPLER_ARG following the OTel spec; defaults to 1% sampling
// so a stock deployment does not drown a collector on high-throughput traffic.
func sampler() trace.Sampler {
	switch os.Getenv("OTEL_TRACES_SAMPLER") {
	case "always_on":
		return trace.AlwaysSample()
	case "always_off":
		return trace.NeverSample()
	default:
		// parentbased_traceidratio at 1 % — upstream spans are honoured,
		// local spans start at 1 %.
		return trace.ParentBased(trace.TraceIDRatioBased(0.01))
	}
}
