# How to monitor VeilGate with Prometheus and Grafana

> **Goal:** Move from the live dashboard at `:9090/` to a real
> time-series view with Prometheus retention and Grafana visualisation.

**On this page:**

1. [The metrics endpoint](#the-metrics-endpoint)
2. [Step 1 — scrape from Prometheus](#step-1--scrape-from-prometheus)
3. [Step 2 — import the Grafana dashboard](#step-2--import-the-grafana-dashboard)
4. [Step 3 — set up the alerts you actually need](#step-3--set-up-the-alerts-you-actually-need)
5. [Useful queries](#useful-queries)
6. [Related](#related)

## The metrics endpoint

VeilGate exposes Prometheus metrics on the `metrics.listen` address
(default `127.0.0.1:9090`). The default config keeps it private —
metrics expose internal state and the dashboard renders unauthenticated
event lines, neither of which should be on the public internet.

```bash
curl -sS http://127.0.0.1:9090/metrics | head -40
```

The metrics surface and the human dashboard share the same port; the
dashboard is at `/`, metrics at `/metrics`.

## Step 1 — scrape from Prometheus

If Prometheus runs on the same host:

```yaml
# /etc/prometheus/prometheus.yml
scrape_configs:
  - job_name: veilgate
    scrape_interval: 15s
    static_configs:
      - targets: ['127.0.0.1:9090']
        labels:
          service: veilgate
          env: prod
```

If Prometheus is remote, expose `:9090` only over an internal
network, an SSH tunnel, or a mTLS-protected listener (front
VeilGate metrics with nginx and require client certs).

## Step 2 — import the Grafana dashboard

The repo ships a starter dashboard:

```
deployments/grafana/muraena-dashboard.json
```

Import it via *Grafana → Dashboards → Import → Upload JSON file*. The
dashboard pulls from a Prometheus datasource named `Prometheus` (rename
to match yours).

Panels included:

- Decisions per second (`real` / `challenge` / `tarpit`).
- Score histogram heatmap.
- Top signals by hit rate.
- Estimated attacker cost over time.
- Per-decision score distribution.
- ML burn-in progress (`bayes_observed_total`).

## Step 3 — set up the alerts you actually need

Resist the temptation to alert on score histograms — they fluctuate
continuously and you'll get pager fatigue. The alerts that earn a page:

### Service down

```promql
up{job="veilgate"} == 0
```

Alert if true for >2 m.

### Persist queue dropping events

```promql
increase(veilgate_persist_dropped_total[5m]) > 0
```

This means the proxy is faster than the disk; either traffic spiked or
the disk is saturated.

### Canary replay seen

```promql
increase(veilgate_signal_hits_total{signal="canary_replay"}[10m]) > 0
```

This is **near-perfect proof** of an LLM agent reusing a tarpit-served
credential. Page on it.

### Mode-change drift

If your config tooling can read it: alert when the running mode (visible
on the dashboard JSON or via `journalctl` parsing) differs from the
expected mode. There is no Prometheus metric for `mode` directly — track
it via your config-management telemetry.

### ML refit stalled

```promql
time() - veilgate_ml_last_fit_seconds_timestamp > 600
```

If the Isolation Forest hasn't refitted in 10+ minutes when you have
sustained traffic, the refit goroutine is stuck. Restart the service.

## Useful queries

### Decision split over the last 24h

```promql
sum by (decision) (increase(veilgate_requests_total[24h]))
```

### p99 score for traffic that landed at `real`

```promql
histogram_quantile(0.99,
  sum by (le) (rate(veilgate_score_by_decision_bucket{decision="real"}[1h])))
```

The right number for `score_challenge_threshold` is approximately this
value plus 5.

### Top signals by 1h hit rate

```promql
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[1h])))
```

### Estimated attacker cost rate

```promql
rate(veilgate_attacker_cost_usd_total[5m]) * 60
```

Reads as "USD per minute" of attacker spend.

### Cardinality of distinct clients

```promql
veilgate_client_cardinality
```

A sudden jump means a new attacker fleet, a CDN config change, or a
new customer geography. Investigate whichever is least expected.

## Related

- [Config: metrics](../config/metrics.md)
- [Use case: Compliance & audit evidence](../usecases/compliance-evidence.md)
- [Prometheus query cookbook](../operations/prometheus-queries.md) — query cookbook

---

*Previous: [Handle a Right-to-Erasure (RTBF) request](handle-rtbf.md) · Next: [Configuration reference](../config/README.md)*
