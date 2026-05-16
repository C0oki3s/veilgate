# Prometheus Query Cookbook

This page collects common PromQL queries for VeilGate operations. The metrics
are emitted by `internal/telemetry` and exposed on the listener configured by
`metrics.listen`.

## Request Decisions

```promql
sum by (decision) (rate(veilgate_requests_total[5m]))
```

Use this to confirm how much traffic is reaching `real`, `observe`,
`challenge`, and `tarpit` outcomes.

## Top Detector Signals

```promql
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[15m])))
```

Use this during observe mode to identify which signals would create user
friction before enabling challenge or tarpit enforcement.

## Score Distribution

```promql
histogram_quantile(0.95, sum by (le) (rate(veilgate_score_bucket[15m])))
```

Use this to watch whether normal traffic is drifting toward the challenge or
tarpit thresholds.

## Tarpit Cost

```promql
increase(veilgate_attacker_cost_usd_total[24h])
```

Use this to estimate defensive cost imposed on clients that were diverted into
the tarpit.

## ML Activity

```promql
sum by (result) (increase(veilgate_ml_fits_total[1h]))
```

Use this to confirm whether the online ML refit loop is running and whether
fits are succeeding.

## Canary Replay

```promql
increase(veilgate_signal_hits_total{signal="canary_replay"}[10m])
```

Any non-zero result should be investigated. A canary replay means a token served
inside the tarpit appeared in a later request.

## Related

- [Config: metrics](../config/metrics.md)
- [Module veilgate_metrics](../modules/veilgate_metrics.md)
- [Monitor with Prometheus](../how-to/monitor-with-prometheus.md)
