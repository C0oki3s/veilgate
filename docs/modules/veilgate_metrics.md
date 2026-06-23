# Module veilgate_metrics

The `veilgate_metrics` module exposes Prometheus metrics and the built-in
dashboard. It is served by a separate HTTP server from the proxy listener.

This listener exposes security-sensitive operational state and should not be
public.

## Example Configuration

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

## Directives

- `metrics.listen`
- `rules/dashboard.yaml`

## `metrics.listen`

Syntax:  `listen: "<address>:<port>"`  
Default: `":9090"`  
Context: `metrics`

Defines the listener used for `/metrics` and the dashboard root `/`.
Prometheus scrapes `/metrics`. The dashboard reads metrics and displays recent
events, score charts, signal panels, rotation panels, and search helpers.

### Code path

- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) starts the metrics server.
- [`internal/telemetry/metrics.go`](../../internal/telemetry/metrics.go) defines metrics.
- [`internal/telemetry/dashboard.go`](../../internal/telemetry/dashboard.go) renders the dashboard.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) updates metrics and dashboard events.

### Operational notes

- Bind to `127.0.0.1:9090` or a private network in production.
- Use SSH tunneling, VPN, or an authenticated internal reverse proxy for access.
- Public metrics can reveal detector thresholds, active attack patterns, and
  security decisions.

### Validation

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## `rules/dashboard.yaml`

Syntax:  dashboard configuration file  
Default: embedded dashboard rules  
Context: `rules_dir`

Controls dashboard refresh rate, stat cards, chart definitions, color palette,
score thresholds, and visible panels.

### Code path

- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go) loads dashboard rules.
- [`internal/telemetry/dashboard.go`](../../internal/telemetry/dashboard.go) renders the page.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) hot-reloads dashboard rules.

### Operational notes

- Dashboard configuration can be hot-reloaded when `rules_dir` is set.
- Do not put secrets in dashboard labels or panel text.

## Metrics Reference

All VeilGate metrics are defined in
[`internal/telemetry/metrics.go`](../../internal/telemetry/metrics.go) and
exposed via two parallel paths:

- **Prometheus pull** — `http://127.0.0.1:9090/metrics` (always on)
- **OTel push** — OTLP/HTTP when `telemetry.metrics_push.enabled: true`

Both paths carry the same data. OTel instrument names use dots; Prometheus
names use underscores. The mapping is 1:1.

### Traffic and decisions

| Prometheus | OTel | Type | Labels |
| --- | --- | --- | --- |
| `veilgate_requests_total` | `veilgate.requests.total` | Counter | `decision` |
| `veilgate_request_duration_seconds` | `veilgate.request.duration` | Histogram | `decision` |
| `veilgate_score` | `veilgate.score` | Histogram | — |
| `veilgate_score_by_decision` | `veilgate.score.by_decision` | Histogram | `decision` |

### Detector signals

| Prometheus | OTel | Type | Labels |
| --- | --- | --- | --- |
| `veilgate_signal_hits_total` | `veilgate.signal.hits.total` | Counter | `signal` |
| `veilgate_ip_reputation_hits_total` | `veilgate.ip_reputation.hits.total` | Counter | `category` |
| `veilgate_fleet_rotation_fires_total` | `veilgate.fleet_rotation.fires.total` | Counter | `tier` |
| `veilgate_ua_rotation_fires_total` | `veilgate.ua_rotation.fires.total` | Counter | — |
| `veilgate_tool_family_hits_total` | `veilgate.tool_family.hits.total` | Counter | `family` |
| `veilgate_ml_score_points` | `veilgate.ml.score_points` | Histogram | — |
| `veilgate_public_ip_requests_total` | `veilgate.public_ip.requests.total` | Counter | `rotating` |
| `veilgate_public_ip_rotation_events_total` | `veilgate.public_ip.rotation_events.total` | Counter | `tier`, `ip_category` |
| `veilgate_public_ip_rotation_distinct` | `veilgate.public_ip.rotation_distinct_ips` | Histogram | — |

### Endpoint correlation

| Prometheus | OTel | Labels |
| --- | --- | --- |
| `veilgate_endpoint_request_total` | `veilgate.endpoint.requests.total` | `path_bucket`, `method`, `decision` |
| `veilgate_endpoint_signal_total` | `veilgate.endpoint.signal.total` | `path_bucket`, `signal`, `method`, `decision` |
| `veilgate_endpoint_attack_family_total` | `veilgate.endpoint.attack_family.total` | `path_bucket`, `family`, `method`, `decision` |
| `veilgate_endpoint_score_tier_total` | `veilgate.endpoint.score_tier.total` | `path_bucket`, `tier`, `decision` |

`path_bucket` normalises UUID/numeric segments to `{id}`, depth capped at 4.

### Challenge

| Prometheus | OTel | Labels |
| --- | --- | --- |
| `veilgate_challenge_issued_total` | `veilgate.challenge.issued.total` | `form` |
| `veilgate_challenge_solved_total` | `veilgate.challenge.solved.total` | — |
| `veilgate_challenge_failed_total` | `veilgate.challenge.failed.total` | `reason` |

### Tarpit

| Prometheus | OTel | Type |
| --- | --- | --- |
| `veilgate_tarpit_bytes_served_total` | `veilgate.tarpit.bytes_served.total` | Counter |
| `veilgate_tarpit_latency_ms_total` | `veilgate.tarpit.latency_ms.total` | Counter |
| `veilgate_tarpit_active_sessions` | `veilgate.tarpit.active_sessions` | Gauge |
| `veilgate_tarpit_template_type_total` | `veilgate.tarpit.template_type.total` | Counter (`type`) |
| `veilgate_attacker_cost_usd_total` | `veilgate.tarpit.cost_usd.total` | Counter |

### ML

| Prometheus | OTel | Type |
| --- | --- | --- |
| `veilgate_ml_fits_total` | `veilgate.ml.fits.total` | Counter (`status`) |
| `veilgate_ml_fit_duration_seconds` | `veilgate.ml.fit_duration` | Histogram |
| `veilgate_ml_fit_rows` | `veilgate.ml.fit_rows` | Histogram |
| `veilgate_ml_bayes_observed` | `veilgate.ml.bayes_observed` | Gauge |
| `veilgate_ml_bayes_entries` | `veilgate.ml.bayes_entries` | Gauge |
| `veilgate_ml_bayes_evictions_total` | `veilgate.ml.bayes_evictions.total` | Counter |
| `veilgate_miner_candidates_total` | `veilgate.ml.miner_candidates.total` | Counter |

### Recommender

| Prometheus | OTel | Type |
| --- | --- | --- |
| `veilgate_recommender_suggestions_last` | `veilgate.recommender.suggestions_last` | Gauge |
| `veilgate_recommender_analysis_duration_seconds` | `veilgate.recommender.analysis_duration` | Histogram |

### Verifier

| Prometheus | OTel | Labels |
| --- | --- | --- |
| `veilgate_verifier_result_total` | `veilgate.verifier.result.total` | `verifier_type`, `result` |

### Infrastructure

| Prometheus | OTel | Type |
| --- | --- | --- |
| `veilgate_tracked_clients` | `veilgate.tracked_clients` | Gauge |
| `veilgate_fleet_fingerprints` | `veilgate.fleet_fingerprints` | Gauge |
| `veilgate_fleet_fingerprint_ips` | `veilgate.fleet_fingerprint_ips` | Histogram |
| `veilgate_persist_queue_depth` | `veilgate.persist.queue_depth` | Gauge |
| `veilgate_persist_dropped_total` | `veilgate.persist.dropped.total` | Counter |

### Operational notes

- All Prometheus metrics use `promauto` — they appear at `/metrics` from the
  first scrape with no warm-up required.
- OTel instruments are created in `NewOTelSink()` and pushed via
  `DefaultBus` → `OTelSink.OnEvent()`. If the bus queue is full, events are
  dropped rather than blocking the proxy hot path.
- `veilgate_attacker_cost_usd_total` is synthetic (estimated LLM API spend);
  treat as order-of-magnitude.

## Example PromQL Queries

```promql
# Decision distribution rate
sum by (decision) (rate(veilgate_requests_total[5m]))

# Top signal hits over 15 min
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[15m])))

# 95th-percentile score
histogram_quantile(0.95, sum by (le) (rate(veilgate_score_bucket[15m])))

# Score p99 for real traffic (use to set challenge threshold)
histogram_quantile(0.99,
  sum by (le) (rate(veilgate_score_by_decision_bucket{decision="real"}[1h])))

# Tarpit throughput bytes/s
rate(veilgate_tarpit_bytes_served_total[1m])

# ML fit health
rate(veilgate_ml_fits_total{status="ok"}[5m])

# Bayes cap pressure
increase(veilgate_ml_bayes_evictions_total[1h])

# Verifier accepted rate
sum by (verifier_type) (rate(veilgate_verifier_result_total{result="accepted"}[5m]))
```

## Troubleshooting

### Metrics are public

Bind to loopback and use an SSH tunnel:

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

```bash
ssh -L 9090:127.0.0.1:9090 user@host
curl http://127.0.0.1:9090/metrics
```

### Expected metric is not present

VeilGate only emits a counter label after that path has been executed. If
`veilgate_tarpit_bytes_served_total` is absent, no tarpit requests have been
served yet. This is expected for a fresh deployment in `observe` mode.

## Related

- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_persistence](veilgate_persistence.md)
- [Metrics dashboard](../functionalities/metrics-dashboard.md)
- [Grafana dashboard](../../deployments/grafana/muraena-dashboard.json)

- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_persistence](veilgate_persistence.md)
- [Metrics dashboard](../functionalities/metrics-dashboard.md)
- [Grafana dashboard](../../deployments/grafana/muraena-dashboard.json)

- [Operations](../operations/README.md)
- [Module veilgate_persistence](veilgate_persistence.md)
- [Module veilgate_detector](veilgate_detector.md)

