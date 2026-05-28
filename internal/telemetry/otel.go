// Package telemetry — OpenTelemetry setup for traces, metrics, and logs.
//
// Call InitTelemetry once from main with the operator config. When no OTLP
// endpoint is configured (config or env) the function is a pure no-op —
// zero overhead, no collector dependency for operators that don't need it.
//
// All three signals share the same transport block (endpoint + headers +
// TLS flag) so a single config section covers any OTel-compatible backend:
// SigNoz, Grafana Cloud, Honeycomb, Jaeger, Datadog OTLP, a local
// OpenTelemetry Collector, etc.
package telemetry

import (
	"context"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	otellog "go.opentelemetry.io/otel/log"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	"github.com/C0oki3s/veilgate/internal/config"
)

const tracerName = "veilgate"

// Tracer is the global VeilGate tracer. Packages that add spans call
// Tracer.Start without importing the OTel SDK directly.
var Tracer = otel.Tracer(tracerName)

// Logger is the global VeilGate OTel logger used by the zerolog bridge.
var Logger otellog.Logger

// TelemetryShutdown flushes and closes all active OTel providers.
type TelemetryShutdown func(context.Context) error

// InitTelemetry wires the OTel TracerProvider, MeterProvider, and
// LoggerProvider from the operator config.
//
// Endpoint resolution order:
//  1. config.telemetry.otlp.endpoint
//  2. OTEL_EXPORTER_OTLP_ENDPOINT environment variable (backward compat)
//
// Traces: on by default when an endpoint is configured; set
// telemetry.traces.disabled: true to suppress.
//
// Logs push: opt-in via telemetry.logs.enabled: true.
//
// Metrics push: opt-in via telemetry.metrics_push.enabled: true.
// The existing Prometheus pull endpoint (/metrics) is unaffected.
func InitTelemetry(ctx context.Context, cfg config.TelemetryConfig) (TelemetryShutdown, error) {
	endpoint := cfg.OTLP.Endpoint
	if endpoint == "" {
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	}
	if endpoint == "" {
		return noopShutdown, nil
	}

	headers := cfg.OTLP.Headers
	var shutdowns []func(context.Context) error

	// ── Traces ───────────────────────────────────────────────────────────────
	// On by default; operator must set traces.disabled: true to opt out.
	if !cfg.Traces.Disabled {
		opts := []otlptracehttp.Option{otlptracehttp.WithEndpoint(endpoint)}
		if cfg.OTLP.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		if len(headers) > 0 {
			opts = append(opts, otlptracehttp.WithHeaders(headers))
		}
		exp, err := otlptracehttp.New(ctx, opts...)
		if err != nil {
			return noopShutdown, err
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp,
				sdktrace.WithMaxExportBatchSize(512),
				sdktrace.WithBatchTimeout(5*time.Second),
			),
			sdktrace.WithSampler(buildSampler(cfg.Traces.SampleRate)),
		)
		otel.SetTracerProvider(tp)
		otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		))
		Tracer = otel.Tracer(tracerName)
		shutdowns = append(shutdowns, tp.Shutdown)
	}

	// ── Metrics push ─────────────────────────────────────────────────────────
	// Opt-in: runs alongside the existing Prometheus pull endpoint.
	if cfg.MetricsPush.Enabled {
		opts := []otlpmetrichttp.Option{otlpmetrichttp.WithEndpoint(endpoint)}
		if cfg.OTLP.Insecure {
			opts = append(opts, otlpmetrichttp.WithInsecure())
		}
		if len(headers) > 0 {
			opts = append(opts, otlpmetrichttp.WithHeaders(headers))
		}
		exp, err := otlpmetrichttp.New(ctx, opts...)
		if err != nil {
			return noopShutdown, err
		}
		interval := parseDuration(cfg.MetricsPush.Interval, 30*time.Second)
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp,
				sdkmetric.WithInterval(interval),
			)),
		)
		otel.SetMeterProvider(mp)
		shutdowns = append(shutdowns, mp.Shutdown)

		// Register the OTel sink on the global bus so all veilgate.* OTel
		// instruments are populated independently of the Prometheus registry.
		if sink := NewOTelSink(mp); sink != nil {
			DefaultBus.Register(sink)
		}
	}

	// ── Logs ─────────────────────────────────────────────────────────────────
	// Opt-in: zerolog bridge forwards each line as an OTLP LogRecord.
	if cfg.Logs.Enabled {
		opts := []otlploghttp.Option{otlploghttp.WithEndpoint(endpoint)}
		if cfg.OTLP.Insecure {
			opts = append(opts, otlploghttp.WithInsecure())
		}
		if len(headers) > 0 {
			opts = append(opts, otlploghttp.WithHeaders(headers))
		}
		exp, err := otlploghttp.New(ctx, opts...)
		if err != nil {
			return noopShutdown, err
		}
		lp := sdklog.NewLoggerProvider(
			sdklog.WithProcessor(sdklog.NewBatchProcessor(exp)),
		)
		global.SetLoggerProvider(lp)
		Logger = global.Logger(tracerName)
		shutdowns = append(shutdowns, lp.Shutdown)
	}

	return func(ctx context.Context) error {
		for _, fn := range shutdowns {
			_ = fn(ctx)
		}
		return nil
	}, nil
}

func noopShutdown(_ context.Context) error { return nil }

// parseDuration parses a Go duration string ("30s", "5m", "1h", etc.).
// Returns fallback when the string is empty or cannot be parsed.
func parseDuration(s string, fallback time.Duration) time.Duration {
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}

// buildSampler converts the 0.0–1.0 sample_rate to an OTel sampler.
// 0 (unset) falls back to OTEL_TRACES_SAMPLER env var for backward compat,
// then to 1 % parentbased_traceidratio.
func buildSampler(rate float64) sdktrace.Sampler {
	if rate == 0 {
		switch os.Getenv("OTEL_TRACES_SAMPLER") {
		case "always_on":
			return sdktrace.AlwaysSample()
		case "always_off":
			return sdktrace.NeverSample()
		}
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(0.01))
	}
	if rate >= 1.0 {
		return sdktrace.AlwaysSample()
	}
	return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(rate))
}
