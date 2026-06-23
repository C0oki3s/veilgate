# How to set up OpenTelemetry observability

> **Goal:** Ship VeilGate request traces, structured logs, and metrics to a
> collector (SigNoz, Grafana, Honeycomb, Jaeger) so you can inspect individual
> scored requests, see which signals fired on each, filter by attack family or
> score tier, and correlate logs with traces using the same severity levels VeilGate
> uses for routing decisions.

**On this page:**

1. [What VeilGate exports](#what-veilgate-exports)
2. [Step 1 — configure the OTLP endpoint](#step-1--configure-the-otlp-endpoint)
3. [Step 2 — enable logs and metrics push](#step-2--enable-logs-and-metrics-push)
4. [Step 3 — control trace sampling](#step-3--control-trace-sampling)
5. [What each signal contains](#what-each-signal-contains)
   - [Traces — `veilgate.serve` and `veilgate.tarpit`](#traces)
   - [Structured logs — per-request log records](#structured-logs)
   - [Metrics — full OTel instrument catalogue](#metrics)
6. [Filtering and investigating in SigNoz](#filtering-and-investigating-in-signoz)
7. [Collector recipes](#collector-recipes)
8. [Related](#related)

---

## What VeilGate exports

VeilGate supports all three OTel signals. Each is opt-in or controlled by a
separate flag in the `telemetry:` config block:

| Signal | Activation | What you get |
| --- | --- | --- |
| **Traces** | Set `telemetry.otlp.endpoint` (or `OTEL_EXPORTER_OTLP_ENDPOINT`) | One `veilgate.serve` span per request; `veilgate.tarpit` child span for tarpitted requests. Each fired signal is a span event. |
| **Structured logs** | `telemetry.logs.enabled: true` | Every zerolog line forwarded as an OTel `LogRecord` with correct `Severity` mapping. Tarpit → ERROR, challenge → WARN, real/observe → INFO. |
| **Metrics** | `telemetry.metrics_push.enabled: true` | All 35+ counters, histograms, and gauges pushed to the OTLP endpoint on a configurable interval alongside the existing Prometheus pull endpoint. |

When `telemetry.otlp.endpoint` is unset (the default), VeilGate is a pure
no-op — zero overhead, no collector dependency.

---

## Step 1 — configure the OTLP endpoint

In `veilgate.yaml`:

```yaml
telemetry:
  otlp:
    endpoint: "https://ingest.us2.signoz.cloud:443"
    headers:
      signoz-access-token: "your-api-key"
```

Or via environment variables (backward-compatible):

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
./veilgate -config /etc/veilgate/veilgate.yaml
```

In a systemd unit:

```ini
[Service]
Environment=OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
ExecStart=/usr/local/bin/veilgate -config /etc/veilgate/veilgate.yaml
```

VeilGate uses OTLP over HTTP (port 4318). For gRPC-only collectors you will
need an HTTP-to-gRPC bridge or an OTel Collector fronting the backend.

---

## Step 2 — enable logs and metrics push

Logs and metrics push are opt-in. Add these to your `telemetry:` block:

```yaml
telemetry:
  otlp:
    endpoint: "https://ingest.us2.signoz.cloud:443"
    headers:
      signoz-access-token: "your-api-key"

  traces:
    sample_rate: 0.01    # 1 % — enough for investigation

  logs:
    enabled: true        # forward zerolog → OTLP LogRecord

  metrics_push:
    enabled: true        # push counters/histograms alongside Prometheus
    interval: "1m"       # "30s" | "1m" | "5m"
```

See [`telemetry:` config reference](../config/telemetry.md) for the full field
documentation.

---

## Step 3 — control trace sampling

By default VeilGate traces 1 % of requests (`parentbased_traceidratio`).
Incoming `traceparent` headers that are already sampled are always honoured.

Override via `telemetry.traces.sample_rate` in config:

```yaml
telemetry:
  traces:
    sample_rate: 0.05   # 5 % — appropriate for moderate traffic
```

Or via environment variable for backward compatibility:

```bash
export OTEL_TRACES_SAMPLER=always_on    # trace everything (dev only)
export OTEL_TRACES_SAMPLER=always_off   # disable tracing
```

At 1 % on 10 000 req/s you get ~100 traces/s — enough for investigation
without drowning a collector.

---

## What each signal contains

### Traces

Two spans are emitted per request (traces only, not all requests):

**`veilgate.serve`** — the full proxy pipeline:

| Attribute | Example | Meaning |
| --- | --- | --- |
| `veilgate.decision` | `tarpit` | Routing outcome: `real`, `challenge`, `tarpit`, `observe`. |
| `veilgate.score` | `74` | Total detector score (0–100). |
| `veilgate.score_tier` | `high` | Threat level: `critical` / `high` / `medium` / `low`. |
| `veilgate.attack_families` | `["recon","injection"]` | Distinct attack families that fired on this request. |
| `http.method` | `GET` | HTTP method. |
| `http.path` | `/api/users/123` | Raw request path. |
| `net.peer.ip` | `203.0.113.42` | Resolved client IP (after trusted-proxy headers). |

Status is set to `Error` for `tarpit` and `challenge` decisions so trace UIs
can filter diverted requests by error status.

Each signal that fired is attached as a **span event** named `signal`:

| Event field | Example | Meaning |
| --- | --- | --- |
| `name` | `schema_first` | Signal name. |
| `points` | `20` | Points contributed to the score. |
| `reason` | `non-browser client's first requests targeted API schema` | Human-readable explanation. |

**`veilgate.tarpit`** — tarpit delay + content rendering (nested under `veilgate.serve`):

| Attribute | Example | Meaning |
| --- | --- | --- |
| `tarpit.content_type` | `json` | Content category served: `json` / `html` / `graphql` / `text` / `other`. |
| `tarpit.delay_ms` | `2340` | Artificial delay imposed, in milliseconds. |
| `http.path` | `/api/users/123` | Request path. |

---

### Structured logs

When `telemetry.logs.enabled: true`, every zerolog JSON line is forwarded to
the OTLP `LogsExporter` as a structured `LogRecord`. Log lines always appear
on `stderr` regardless of this setting — the bridge is additive.

Each log line becomes a `LogRecord` with:

| OTel field | Source |
| --- | --- |
| `Severity` | zerolog `level` field mapped to OTel severity number |
| `Body` | zerolog `message` field |
| `Attributes` | all remaining JSON key/value pairs |
| `Timestamp` | wall clock at write time |

**Severity mapping:**

| zerolog level | OTel Severity | SigNoz colour |
| --- | --- | --- |
| `trace` | TRACE | — |
| `debug` | DEBUG | — |
| `info` | INFO | Blue |
| `warn` | WARN | Yellow |
| `error` | ERROR | Red |
| `fatal` / `panic` | FATAL | — |

**Decision-based severity** (v1.1.5): request log lines use the level that
matches the routing decision — `tarpit → error`, `challenge → warn`,
`real/observe → info`. This means filtering `severity = ERROR` in SigNoz shows
all tarpitted requests; `severity = WARN` shows all challenged requests.

**`threat_level` attribute** (v1.1.5): every request log line also carries a
`threat_level` field:

| Score range | `threat_level` |
| --- | --- |
| 0–29 | `low` |
| 30–59 | `medium` |
| 60–79 | `high` |
| 80–100 | `critical` |

Example log attributes in SigNoz:

```
level:        error
message:      request
decision:     tarpit
threat_level: critical
score:        92
client:       203.0.113.42
path:         /api/admin/debug
method:       GET
signals:      [{"name":"injection_marker","points":60},{"name":"honeypot_hit","points":80}]
```

---

### Metrics

All 35+ OTel instruments are equivalent to the Prometheus metrics and use the
same naming convention (dots instead of underscores, no unit suffix for counters).
Both can be active simultaneously — the OTel push exporter and the Prometheus
pull endpoint operate independently.

#### Traffic and decisions

| OTel instrument | Prometheus equivalent | Type | Labels |
| --- | --- | --- | --- |
| `veilgate.requests.total` | `veilgate_requests_total` | Counter | `decision` |
| `veilgate.request.duration` | `veilgate_request_duration_seconds` | Histogram | `decision` |
| `veilgate.score` | `veilgate_score` | Histogram | — |
| `veilgate.score.by_decision` | `veilgate_score_by_decision` | Histogram | `decision` |

#### Detector signals

| OTel instrument | Prometheus equivalent | Type | Labels |
| --- | --- | --- | --- |
| `veilgate.signal.hits.total` | `veilgate_signal_hits_total` | Counter | `signal` |
| `veilgate.ip_reputation.hits.total` | `veilgate_ip_reputation_hits_total` | Counter | `category` |
| `veilgate.fleet_rotation.fires.total` | `veilgate_fleet_rotation_fires_total` | Counter | `tier` |
| `veilgate.ua_rotation.fires.total` | `veilgate_ua_rotation_fires_total` | Counter | — |
| `veilgate.tool_family.hits.total` | `veilgate_tool_family_hits_total` | Counter | `family` |
| `veilgate.ml.score_points` | `veilgate_ml_score_points` | Histogram | — |
| `veilgate.public_ip.requests.total` | `veilgate_public_ip_requests_total` | Counter | `rotating` |
| `veilgate.public_ip.rotation_events.total` | `veilgate_public_ip_rotation_events_total` | Counter | `tier`, `ip_category` |
| `veilgate.public_ip.rotation_distinct_ips` | `veilgate_public_ip_rotation_distinct` | Histogram | — |

#### Endpoint correlation

| OTel instrument | Prometheus equivalent | Type | Labels |
| --- | --- | --- | --- |
| `veilgate.endpoint.requests.total` | `veilgate_endpoint_request_total` | Counter | `path_bucket`, `method`, `decision` |
| `veilgate.endpoint.score_tier.total` | `veilgate_endpoint_score_tier_total` | Counter | `path_bucket`, `tier`, `decision` |
| `veilgate.endpoint.signal.total` | `veilgate_endpoint_signal_total` | Counter | `path_bucket`, `signal`, `method`, `decision` |
| `veilgate.endpoint.attack_family.total` | `veilgate_endpoint_attack_family_total` | Counter | `path_bucket`, `family`, `method`, `decision` |

#### Tarpit

| OTel instrument | Prometheus equivalent | Type |
| --- | --- | --- |
| `veilgate.tarpit.latency_ms.total` | `veilgate_tarpit_latency_ms_total` | Counter |
| `veilgate.tarpit.bytes_served.total` | `veilgate_tarpit_bytes_served_total` | Counter |
| `veilgate.tarpit.cost_usd.total` | `veilgate_attacker_cost_usd_total` | Counter |
| `veilgate.tarpit.template_type.total` | `veilgate_tarpit_template_type_total` | Counter (label: `type`) |
| `veilgate.tarpit.active_sessions` *(v1.1.5)* | `veilgate_tarpit_active_sessions` | Gauge |

#### Challenge

| OTel instrument | Prometheus equivalent | Type |
| --- | --- | --- |
| `veilgate.challenge.issued.total` | `veilgate_challenge_issued_total` | Counter |
| `veilgate.challenge.solved.total` | `veilgate_challenge_solved_total` | Counter |
| `veilgate.challenge.failed.total` | `veilgate_challenge_failed_total` | Counter (label: `reason`) |

#### ML

| OTel instrument | Prometheus equivalent | Type |
| --- | --- | --- |
| `veilgate.ml.fits.total` | `veilgate_ml_fits_total` | Counter (label: `status`) |
| `veilgate.ml.fit_duration` | `veilgate_ml_fit_duration_seconds` | Histogram |
| `veilgate.ml.fit_rows` | `veilgate_ml_fit_rows` | Histogram |
| `veilgate.ml.bayes_observed` | `veilgate_ml_bayes_observed` | Gauge |
| `veilgate.ml.bayes_entries` | `veilgate_ml_bayes_entries` | Gauge |
| `veilgate.ml.bayes_evictions.total` *(v1.1.5)* | `veilgate_ml_bayes_evictions_total` | Counter |
| `veilgate.ml.miner_candidates.total` *(v1.1.5)* | `veilgate_miner_candidates_total` | Counter |

#### Recommender *(v1.1.4+)*

| OTel instrument | Prometheus equivalent | Type |
| --- | --- | --- |
| `veilgate.recommender.suggestions_last` *(v1.1.5)* | `veilgate_recommender_suggestions_last` | Gauge |
| `veilgate.recommender.analysis_duration` *(v1.1.5)* | `veilgate_recommender_analysis_duration_seconds` | Histogram |

#### Verifier *(v1.1.5)*

| OTel instrument | Prometheus equivalent | Type |
| --- | --- | --- |
| `veilgate.verifier.result.total` | `veilgate_verifier_result_total` | Counter (labels: `verifier_type`, `result`) |

#### Infrastructure (periodic gauges)

| OTel instrument | Prometheus equivalent | Type |
| --- | --- | --- |
| `veilgate.tracked_clients` | `veilgate_tracked_clients` | Gauge |
| `veilgate.fleet_fingerprints` | `veilgate_fleet_fingerprints` | Gauge |
| `veilgate.fleet_fingerprint_ips` | `veilgate_fleet_fingerprint_ips` | Histogram |
| `veilgate.persist.queue_depth` | `veilgate_persist_queue_depth` | Gauge |
| `veilgate.persist.dropped.total` | `veilgate_persist_dropped_total` | Counter |

---

## Filtering and investigating in SigNoz

### All tarpitted requests

```
severity = ERROR
```

Because tarpit decisions log at `error` level, this single filter captures
all of them. Combine with `decision = tarpit` in the attributes panel to
verify.

### All challenged requests

```
severity = WARN
```

### Critical-score requests (score ≥ 80)

```
body.threat_level = critical
```

### Injection attacks on auth endpoints

In the trace explorer:

```
service = veilgate
span.veilgate.attack_families contains injection
span.http.path LIKE /api/auth%
```

### See every signal on one request

In the logs explorer, click any `error`-severity request log line and
expand the attributes. The `signals` attribute contains the full JSON array
of fired signals with names, points, and reasons.

In the trace explorer, open the `veilgate.serve` span and expand **Events**.
Each fired signal appears as a named event.

### Score distribution by threat level

In SigNoz Metrics → Builder, query:
```
veilgate.score.by_decision
```
Group by `decision` to see score histograms per routing outcome.

---

## Collector recipes

### SigNoz cloud

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

### Local OTel Collector (Docker / dev)

```yaml
telemetry:
  otlp:
    endpoint: "http://otel-collector:4318"
    insecure: true
  traces:
    sample_rate: 1.0
  logs:
    enabled: true
  metrics_push:
    enabled: true
    interval: "30s"
```

```bash
docker run -d --name jaeger \
  -p 4318:4318 \
  -p 16686:16686 \
  jaegertracing/all-in-one:latest
```

Open `http://localhost:16686`, select service `veilgate`.

### OTel Collector config snippet (fan-out to SigNoz + Prometheus)

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: "0.0.0.0:4318"

exporters:
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

---

## Related

- [`telemetry:` config reference](../config/telemetry.md)
- [How-to: Monitor with Prometheus](monitor-with-prometheus.md)
- [How-to: Endpoint correlation](endpoint-correlation.md)
- [Prometheus query cookbook](../operations/prometheus-queries.md)
- [Module veilgate_metrics](../modules/veilgate_metrics.md)
- [Detection Signals](../functionalities/detection-signals.md)

---

*Previous: [Monitor with Prometheus](monitor-with-prometheus.md) · Next: [Endpoint correlation](endpoint-correlation.md)*
