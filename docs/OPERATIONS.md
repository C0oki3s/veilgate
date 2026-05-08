# Operations

This guide covers metrics, dashboards, routine checks, and common tuning tasks.

## Metrics Endpoint

Metrics are served from:

```text
http://<metrics-listen>/metrics
```

Default:

```yaml
metrics:
  listen: ":9090"
```

Keep this listener private. It exposes information about detection decisions,
rule hits, and traffic shape.

## Useful Metrics

| Metric | Use |
| --- | --- |
| `veilgate_requests_total{decision=...}` | Request count by final decision. |
| `veilgate_score` | Score distribution. |
| `veilgate_signal_hits_total{signal=...}` | Which signals are firing. |
| `veilgate_tarpit_bytes_served_total` | Volume served to tarpitted clients. |
| `veilgate_tarpit_latency_ms_total` | Added tarpit delay. |
| `veilgate_attacker_cost_usd_total` | Rough cost-burn estimate. |
| `veilgate_public_ip_requests_total` | Public IP traffic classification. |
| `veilgate_ml_fits_total` | ML training/refit activity. |

## Prometheus Queries

Request rate by decision:

```promql
sum by (decision) (rate(veilgate_requests_total[5m]))
```

Top firing signals:

```promql
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[15m])))
```

95th percentile score:

```promql
histogram_quantile(0.95, sum by (le) (rate(veilgate_score_bucket[15m])))
```

Tarpit traffic rate:

```promql
rate(veilgate_tarpit_bytes_served_total[5m])
```

## Dashboard

The built-in dashboard is served from the metrics listener root:

```text
http://localhost:9090/
```

For now, the supported public dashboard path is the built-in dashboard. Grafana
examples are intentionally kept out of the supported deployment surface.

## Tuning Workflow

1. Run in `observe`.
2. Watch score distributions for normal browser traffic.
3. Review high-score requests and their signal list.
4. Tune `rules/detector.yaml` and threshold fields.
5. Add true internal systems to `trusted_ips` only when needed.
6. Move to `challenge`.
7. Move to `tarpit` for high-confidence traffic.

## Alert Ideas

High tarpit rate:

```promql
sum(rate(veilgate_requests_total{decision="tarpit"}[5m])) > 5
```

Unexpected challenge spike:

```promql
sum(rate(veilgate_requests_total{decision="challenge"}[10m])) > 20
```

Event queue pressure:

```promql
increase(veilgate_persist_dropped_total[15m]) > 0
```

## Troubleshooting

### Normal Traffic Scores Too High

- Confirm browser requests include expected `Accept-*` and `Sec-Fetch-*` headers.
- Check whether a CDN or proxy strips headers.
- Review `trusted_proxies`; do not trust arbitrary `X-Forwarded-For`.
- Raise thresholds only after understanding which signals fire.

### No TLS Fingerprints

- Confirm `tls.enabled: true`.
- Confirm clients connect with `https://`.
- Confirm TLS is not terminated before VeilGate.

### Metrics Are Public

Bind metrics to localhost:

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

Or place it behind VPN, auth, or an internal load balancer.

### SQLite Grows Too Large

- Set `persist.retention_days`.
- Set `persist.dump_path` if you want CSV archives before trimming.
- Monitor disk usage for `events.db`, WAL files, and dumps.
