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

All VeilGate Prometheus metrics are defined in
[`internal/telemetry/metrics.go`](../../internal/telemetry/metrics.go) using
`promauto` — they self-register on import with no manual registration call.

### Traffic and decision metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `veilgate_requests_total` | Counter | `decision` | Total requests by final decision (`real`, `observe`, `challenge`, `tarpit`). |
| `veilgate_score` | Histogram | — | Score value distribution (0–100) for all requests. |
| `veilgate_score_by_decision` | Histogram | `decision` | Score distribution split by final decision. |

### Signal and detector metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `veilgate_signal_hits_total` | Counter | `signal` | Fires per detector signal name. |
| `veilgate_ip_reputation_hits_total` | Counter | `category` | IP reputation hits by CIDR category label. |
| `veilgate_fleet_rotation_fires_total` | Counter | `tier` | Fleet rotation signal fires by tier label. |
| `veilgate_ua_rotation_fires_total` | Counter | — | UA rotation signal fires. |
| `veilgate_tool_family_hits_total` | Counter | `family` | Suspicious user-agent hits grouped by tool family (curl, python-requests, sqlmap, etc.). |
| `veilgate_public_ip_requests_total` | Counter | — | Requests from public IP space (not RFC1918). |

### Tarpit metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `veilgate_tarpit_bytes_served_total` | Counter | — | Total bytes written to tarpit clients. |
| `veilgate_tarpit_latency_ms_total` | Counter | — | Total injected artificial delay in milliseconds. |
| `veilgate_attacker_cost_usd_total` | Counter | — | Estimated cost imposed on attacker (compute-time basis). |

### ML metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `veilgate_ml_fits_total` | Counter | `result` | Isolation Forest refit attempts (`ok`, `error`, `skipped`). |
| `veilgate_ml_score_points` | Histogram | — | Points contributed by the ML signal when it fires. |
| `veilgate_ml_observations_total` | Counter | — | Training observations submitted. |

### Persistence and infrastructure metrics

| Metric | Type | Labels | Description |
| --- | --- | --- | --- |
| `veilgate_persist_queue_depth` | Gauge | — | Current buffered-channel depth for async writes. |
| `veilgate_persist_drops_total` | Counter | — | Dropped events due to full queue. |
| `veilgate_tracked_clients` | Gauge | — | Active `ClientState` entries in the tracker. |
| `veilgate_fleet_fingerprints` | Gauge | — | Tracked behavior fingerprint count (fleet rotation). |
| `veilgate_fleet_fingerprint_ips` | Gauge | — | IP count in the behavior fingerprint index. |

### Operational notes

- All metrics are registered with `promauto`; they appear at `/metrics` from
  the first request with no warm-up required.
- Histograms use Prometheus default buckets unless overridden in
  `internal/telemetry/metrics.go`.
- `veilgate_attacker_cost_usd_total` is a synthetic metric based on estimated
  CPU time; treat as approximate.

## Example PromQL Queries

```promql
# Decision distribution rate
sum by (decision) (rate(veilgate_requests_total[5m]))

# Top signal hits
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[15m])))

# 95th-percentile score
histogram_quantile(0.95, sum by (le) (rate(veilgate_score_bucket[15m])))

# Tarpit throughput bytes/s
rate(veilgate_tarpit_bytes_served_total[1m])

# Persistence queue utilization
veilgate_persist_queue_depth / <configured queue_size>

# ML fit health
rate(veilgate_ml_fits_total{result="error"}[5m])
```

## Grafana Dashboard

VeilGate ships a pre-built Grafana dashboard at
[`deployments/grafana/muraena-dashboard.json`](../../deployments/grafana/muraena-dashboard.json).
Import it via `Dashboards → Import → Upload JSON file`.

The dashboard panels include:
- Decision distribution time series
- Score percentile trends
- Top-10 signals heat map
- Fleet and UA rotation event log
- Persistence queue depth gauge
- ML fit status log

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

