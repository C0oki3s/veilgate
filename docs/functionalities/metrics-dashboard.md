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

| Metric | Meaning |
| --- | --- |
| `veilgate_requests_total{decision=...}` | Requests by final decision. |
| `veilgate_score` | Score histogram. |
| `veilgate_score_by_decision{decision=...}` | Score histogram split by decision. |
| `veilgate_signal_hits_total{signal=...}` | Detector signal hit count. |
| `veilgate_ip_reputation_hits_total{category=...}` | IP reputation hits by category. |
| `veilgate_fleet_rotation_fires_total{tier=...}` | Fleet rotation signal fires. |
| `veilgate_ua_rotation_fires_total` | UA rotation signal fires. |
| `veilgate_tool_family_hits_total{family=...}` | Suspicious UA hits grouped by tool family. |
| `veilgate_persist_queue_depth` | Current persistence queue depth. |
| `veilgate_tracked_clients` | Current tracked client count. |
| `veilgate_fleet_fingerprints` | Current tracked behavior fingerprint count. |
| `veilgate_ml_fits_total{status=...}` | ML refit attempts by status. |

Example PromQL:

```promql
sum by (decision) (rate(veilgate_requests_total[5m]))
```

```promql
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[15m])))
```

```promql
histogram_quantile(0.95, sum by (le) (rate(veilgate_score_bucket[15m])))
```

## Troubleshooting

### Metrics are public

Change the listener:

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

Access with an SSH tunnel:

```bash
ssh -L 9090:127.0.0.1:9090 user@host
```

## Related

- [Operations](../operations/README.md)
- [Module veilgate_persistence](../modules/veilgate_persistence.md)
- [Module veilgate_detector](../modules/veilgate_detector.md)

