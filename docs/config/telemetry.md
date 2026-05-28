# `telemetry:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `telemetry:`
> **Reload:** restart required.

Ships traces, structured logs, and metrics to any OpenTelemetry-compatible
backend. All three signals share the same OTLP/HTTP transport block, so a
single `telemetry:` section covers SigNoz, Grafana Cloud, Honeycomb, Datadog,
Jaeger, a self-hosted OpenTelemetry Collector, or any other OTLP receiver.

The Prometheus pull endpoint (`metrics.listen`) is unaffected — both can be
active simultaneously.

**On this page:**

- [`telemetry.otlp`](#telemetryotlp)
  - [`endpoint`](#endpoint)
  - [`headers`](#headers)
  - [`insecure`](#insecure)
- [`telemetry.traces`](#telemetrytraces)
  - [`disabled`](#disabled)
  - [`sample_rate`](#sample_rate)
- [`telemetry.logs`](#telemetrylogs)
  - [`enabled`](#enabled-logs)
- [`telemetry.metrics_push`](#telemetrymetrics_push)
  - [`enabled`](#enabled-metrics_push)
  - [`interval`](#interval)
- [Backend quick-start recipes](#backend-quick-start-recipes)
- [Example](#example)
- [Related](#related)

---

## `telemetry.otlp`

Shared transport block. All three signal exporters (traces, logs, metrics)
use the same endpoint, headers, and TLS settings.

### `endpoint`

| Type | Required | Default |
| --- | --- | --- |
| string (URL) | no | `""` (disabled) |

Base URL of the OTLP/HTTP receiver. Do not add a path suffix — VeilGate
appends the signal-specific paths (`/v1/traces`, `/v1/logs`, `/v1/metrics`)
automatically.

```yaml
telemetry:
  otlp:
    endpoint: "https://ingest.us2.signoz.cloud:443"
```

When this field is empty VeilGate falls back to the
`OTEL_EXPORTER_OTLP_ENDPOINT` environment variable. If neither is set,
the telemetry section is a complete no-op with zero overhead.

---

### `headers`

| Type | Required | Default |
| --- | --- | --- |
| map[string]string | no | `{}` |

HTTP headers sent on every OTLP request. The most common use is an API key
or bearer token required by the backend.

```yaml
telemetry:
  otlp:
    headers:
      signoz-access-token: "your-api-key"
```

Header names are case-insensitive on the wire. Use the exact name required
by your backend — see [Backend quick-start recipes](#backend-quick-start-recipes)
for per-vendor examples.

---

### `insecure`

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

Set `true` to disable TLS certificate verification. Only use this for plain
`http://` endpoints (local collectors, Docker Compose, development).

```yaml
telemetry:
  otlp:
    endpoint: "http://otel-collector:4318"
    insecure: true
```

---

## `telemetry.traces`

Controls the distributed trace exporter. Traces are **on by default** when
an endpoint is configured — no extra flag is needed to start shipping spans.

### `disabled`

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

Set `true` to suppress traces even when an endpoint is configured. Useful
when you only want logs or metrics from VeilGate but not spans.

```yaml
telemetry:
  traces:
    disabled: true
```

---

### `sample_rate`

| Type | Required | Default |
| --- | --- | --- |
| float (0.0–1.0) | no | `0.01` |

Fraction of requests to trace. `0.01` = 1 % (default). `1.0` = every
request. Values outside `[0.0, 1.0]` are clamped.

Use `1.0` in development or during an incident investigation; keep at
`0.01` or lower on high-traffic production instances to avoid overwhelming
the collector.

The sampler is parent-based: if an incoming request already carries a
`traceparent` header that is sampled, that decision is always honoured
regardless of this setting.

```yaml
telemetry:
  traces:
    sample_rate: 0.05   # 5 % — appropriate for moderate traffic
```

When `sample_rate` is `0` (unset), VeilGate reads the
`OTEL_TRACES_SAMPLER` environment variable for backward compatibility
(`always_on`, `always_off`, `parentbased_traceidratio`), then falls back
to 1 %.

---

## `telemetry.logs`

Controls the structured log exporter. **Opt-in** — set `enabled: true`
to activate.

When enabled, every zerolog line is forwarded to the OTLP endpoint as a
structured `LogRecord` in addition to the normal stderr output. Log lines
are never lost: stderr is always written regardless of this setting.

Each log line becomes a `LogRecord` with:

| OTel field | Source |
| --- | --- |
| `Severity` | zerolog `level` field (`debug`, `info`, `warn`, `error`, `fatal`) |
| `Body` | zerolog `message` field |
| `Attributes` | all remaining JSON fields as key/value pairs |
| `Timestamp` | wall clock at the time the line is written |

### `enabled` {#enabled-logs}

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

```yaml
telemetry:
  logs:
    enabled: true
```

---

## `telemetry.metrics_push`

Controls the OTLP metrics push exporter. **Opt-in** — set `enabled: true`
to activate.

Runs alongside the existing Prometheus pull endpoint (`metrics.listen`).
Both can be active at once: Prometheus scrapes `/metrics` on its own
schedule, and the push exporter sends the same counters and histograms
to the OTLP backend on the configured interval.

### `enabled` {#enabled-metrics_push}

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

```yaml
telemetry:
  metrics_push:
    enabled: true
```

---

### `interval`

| Type | Required | Default |
| --- | --- | --- |
| duration string | no | `"30s"` |

How often metrics are pushed to the OTLP endpoint. Accepts Go duration
strings: `"30s"`, `"1m"`, `"5m"`, `"1h"`. Values below 1 second are
treated as the default.

| Value | When to use |
| --- | --- |
| `"30s"` | Default — good balance of freshness and collector load |
| `"1m"` | Slightly lower overhead; still near-real-time |
| `"5m"` | Matches a Prometheus scrape interval if you want both aligned |
| `"1h"` | Very low-traffic or cost-sensitive deployments |

```yaml
telemetry:
  metrics_push:
    enabled: true
    interval: "1m"
```

---

## Backend quick-start recipes

### SigNoz (cloud)

```yaml
telemetry:
  otlp:
    endpoint: "https://ingest.us2.signoz.cloud:443"
    headers:
      signoz-access-token: "your-api-key"
  traces:
    sample_rate: 0.01
  logs:
    enabled: true
  metrics_push:
    enabled: true
    interval: "1m"
```

### Grafana Cloud (Alloy / OTLP gateway)

```yaml
telemetry:
  otlp:
    endpoint: "https://otlp-gateway-prod-eu-west-0.grafana.net"
    headers:
      authorization: "Bearer glc_your-token"
  traces:
    sample_rate: 0.01
  metrics_push:
    enabled: true
    interval: "1m"
```

### Honeycomb

```yaml
telemetry:
  otlp:
    endpoint: "https://api.honeycomb.io"
    headers:
      x-honeycomb-team: "your-api-key"
      x-honeycomb-dataset: "veilgate"
  traces:
    sample_rate: 0.05
  logs:
    enabled: true
```

### Datadog (OTLP intake)

```yaml
telemetry:
  otlp:
    endpoint: "https://otlp.datadoghq.com"
    headers:
      dd-api-key: "your-api-key"
  traces:
    sample_rate: 0.01
  metrics_push:
    enabled: true
    interval: "30s"
```

### Local OpenTelemetry Collector (Docker / dev)

```yaml
telemetry:
  otlp:
    endpoint: "http://otel-collector:4318"
    insecure: true
  traces:
    sample_rate: 1.0    # trace everything in dev
  logs:
    enabled: true
  metrics_push:
    enabled: true
    interval: "30s"
```

Matching Collector config snippet:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: "0.0.0.0:4318"

exporters:
  # Fan out to any backend from here
  otlp/signoz:
    endpoint: "ingest.us2.signoz.cloud:443"
    headers:
      signoz-access-token: "your-key"
  prometheus:
    endpoint: "0.0.0.0:8889"

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlp/signoz]
    metrics:
      receivers: [otlp]
      exporters: [prometheus, otlp/signoz]
    logs:
      receivers: [otlp]
      exporters: [otlp/signoz]
```

### Jaeger (all-in-one, local dev)

```yaml
telemetry:
  otlp:
    endpoint: "http://localhost:4318"
    insecure: true
  traces:
    sample_rate: 1.0
```

```bash
docker run -d --name jaeger \
  -p 4318:4318 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest
```

Open `http://localhost:16686`, select service `veilgate`.

---

## Example

Full `telemetry:` block with every field shown:

```yaml
telemetry:
  otlp:
    endpoint: "https://ingest.us2.signoz.cloud:443"
    headers:
      signoz-access-token: "your-api-key"
    insecure: false

  traces:
    disabled: false       # true to suppress traces
    sample_rate: 0.01     # 1 % — use 1.0 in dev

  logs:
    enabled: true         # forward zerolog lines as OTLP LogRecords

  metrics_push:
    enabled: true         # push alongside Prometheus pull
    interval: "1m"        # "30s" | "1m" | "5m" | "1h"
```

### Code path

- [`internal/config/config.go`](../../internal/config/config.go) — `TelemetryConfig`, `OTLPConfig`, `TracesConfig`, `LogsConfig`, `MetricsPushConfig`
- [`internal/telemetry/otel.go`](../../internal/telemetry/otel.go) — `InitTelemetry`, provider setup, `buildSampler`, `parseDuration`
- [`internal/telemetry/otel_logbridge.go`](../../internal/telemetry/otel_logbridge.go) — `OTelLogWriter`, zerolog → OTLP log bridge
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — calls `InitTelemetry`, wires the log bridge into the zerolog writer

### Operational notes

- Bind `metrics.listen` to loopback (`127.0.0.1:9090`) even when using OTLP push — the Prometheus endpoint exposes the same sensitive operational data.
- Keep API keys in environment variables or a secrets manager rather than
  committing them directly in `veilgate.yaml`.
- At 1 % sampling on 10 000 req/s you get ~100 traces/s — enough for
  investigation without drowning a collector. Scale `sample_rate` up only
  during active incidents.
- `insecure: true` should never be used in production; it disables all
  certificate verification on the exporter connection.

---

## Related

- [How-to: OpenTelemetry](../how-to/opentelemetry.md)
- [How-to: Monitor with Prometheus](../how-to/monitor-with-prometheus.md)
- [How-to: Endpoint correlation](../how-to/endpoint-correlation.md)
- [`metrics:`](metrics.md) — Prometheus pull endpoint
- [Prometheus query cookbook](../operations/prometheus-queries.md)

---

*Previous: [`persist:`](persist.md) · Next: [`metrics:`](metrics.md)*
