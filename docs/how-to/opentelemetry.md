# How to set up OpenTelemetry tracing

> **Goal:** Ship VeilGate request traces to a collector (Jaeger, Tempo,
> SigNoz) so you can inspect individual scored requests, see which
> signals fired on each, and filter traces by attack family or score
> tier.

**On this page:**

1. [How it works](#how-it-works)
2. [Step 1 — point to a collector](#step-1--point-to-a-collector)
3. [Step 2 — control sampling rate](#step-2--control-sampling-rate)
4. [Step 3 — what each span contains](#step-3--what-each-span-contains)
5. [Step 4 — filter and investigate traces](#step-4--filter-and-investigate-traces)
6. [Collector recipes](#collector-recipes)
7. [Related](#related)

## How it works

VeilGate uses the OpenTelemetry SDK. When
`OTEL_EXPORTER_OTLP_ENDPOINT` is unset (the default) the tracer is a
pure no-op — zero overhead, no collector dependency. Set the variable
to activate OTLP/HTTP export.

Two spans are emitted per tarpitted or scored request:

| Span | Emitted by | Covers |
| --- | --- | --- |
| `veilgate.serve` | `internal/proxy/proxy.go` | The full proxy pipeline: scoring, decision, response routing. |
| `veilgate.tarpit` | `internal/tarpit/handler.go` | Tarpit delay + content rendering, nested under `veilgate.serve`. |

The tracer is initialised in `cmd/veilgate/main.go` and the global
`telemetry.Tracer` var is available to any package without a direct SDK
import.

## Step 1 — point to a collector

Set the endpoint environment variable before starting VeilGate:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
./veilgate -config /etc/veilgate/veilgate.yaml
```

Or in a systemd unit:

```ini
[Service]
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
ExecStart=/usr/local/bin/veilgate -config /etc/veilgate/veilgate.yaml
```

VeilGate uses OTLP over HTTP (port 4318). If your collector only
accepts gRPC (port 4317) you will need an OTLP HTTP-to-gRPC bridge
or switch to an HTTP-capable collector.

## Step 2 — control sampling rate

By default VeilGate traces 1 % of requests using
`parentbased_traceidratio`. Upstream traces that arrive with a
`traceparent` header that is already sampled are always honoured.

Override via environment variable:

```bash
# Trace every request (development / low-traffic only)
export OTEL_TRACES_SAMPLER=always_on

# Trace no requests (disable tracing without removing the endpoint)
export OTEL_TRACES_SAMPLER=always_off

# Keep the default 1 % ratio (production)
export OTEL_TRACES_SAMPLER=parentbased_traceidratio
```

At 1 % on 10 000 req/s you get 100 traces/s — enough for investigation
without drowning a collector.

## Step 3 — what each span contains

### `veilgate.serve`

| Attribute | Example | Meaning |
| --- | --- | --- |
| `veilgate.decision` | `tarpit` | Routing outcome. |
| `veilgate.score` | `74` | Total detector score (0–100). |
| `veilgate.score_tier` | `high` | Severity bucket (critical / high / medium / low). |
| `veilgate.attack_families` | `["recon","evasion"]` | Distinct attack families that fired on this request. |
| `http.method` | `GET` | HTTP method. |
| `http.path` | `/api/users/123` | Raw request path. |
| `net.peer.ip` | `203.0.113.42` | Resolved client IP (after trusted-proxy headers). |

Status is set to `Error` when the decision is `tarpit` or `challenge`,
so you can filter by error spans to find all diverted requests.

Each signal that fired is attached as a **span event** named `signal`:

| Event field | Example | Meaning |
| --- | --- | --- |
| `name` | `schema_first` | Signal name. |
| `points` | `20` | Points contributed to the score. |
| `reason` | `non-browser client's first requests targeted API schema` | Human-readable explanation. |

### `veilgate.tarpit`

| Attribute | Example | Meaning |
| --- | --- | --- |
| `tarpit.content_type` | `json` | Content category served (json / html / graphql / text / other). |
| `tarpit.delay_ms` | `2340` | Artificial delay imposed, in milliseconds. |
| `http.path` | `/api/users/123` | Request path. |

## Step 4 — filter and investigate traces

### Find all tarpitted requests

In Jaeger / Grafana Tempo / SigNoz, filter by:

```
service = veilgate
span.veilgate.decision = tarpit
```

### Find all injection attacks

```
service = veilgate
span.veilgate.attack_families contains injection
```

### Find critical-score requests on auth endpoints

```
service = veilgate
span.veilgate.score_tier = critical
span.http.path =~ /api/auth.*
```

### See every signal on one trace

Open any `veilgate.serve` span and expand the **Events** section. Each
fired signal appears as an event with its name, points, and reason —
the complete explanation of why VeilGate made the decision it did.

## Collector recipes

### Jaeger all-in-one (local development)

```bash
docker run -d --name jaeger \
  -p 4318:4318 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest

export OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4318
export OTEL_TRACES_SAMPLER=always_on
```

Open `http://localhost:16686`, select service `veilgate`.

### Grafana Tempo + Alloy

```yaml
# alloy config snippet
otelcol.receiver.otlp "veilgate" {
  http { endpoint = "0.0.0.0:4318" }
  output {
    traces = [otelcol.exporter.otlp.tempo.input]
  }
}
```

### SigNoz

SigNoz accepts OTLP/HTTP natively on port 4318. Set the endpoint to
your SigNoz host and add the API key header via the OTel SDK environment:

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=https://ingest.us2.signoz.cloud:443
export OTEL_EXPORTER_OTLP_HEADERS="signoz-access-token=<your-api-key>"
```

Traces will appear under `veilgate` in the SigNoz service map. The
`veilgate.attack_families` attribute can be used as a filter in the
SigNoz trace explorer.

## Related

- [How-to: Monitor with Prometheus](monitor-with-prometheus.md)
- [How-to: Endpoint correlation](endpoint-correlation.md)
- [Prometheus query cookbook](../operations/prometheus-queries.md)
- [Module veilgate_metrics](../modules/veilgate_metrics.md)

---

*Previous: [Monitor with Prometheus](monitor-with-prometheus.md) · Next: [Endpoint correlation](endpoint-correlation.md)*
