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

## Request Latency by Decision

```promql
histogram_quantile(0.99,
  sum by (le, decision) (rate(veilgate_request_duration_seconds_bucket[5m])))
```

Separate p99 latency per decision. Tarpit latency will be high by design
(artificial delay). The `real` bucket shows your upstream response time
plus VeilGate scoring overhead.

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

## Endpoint Correlation

### Most attacked endpoints (all signal types)

```promql
topk(10, sum by (path_bucket) (
  rate(veilgate_endpoint_signal_total[1h])
))
```

### Attack families per endpoint — heat map

```promql
sum by (path_bucket, family) (
  rate(veilgate_endpoint_attack_family_total[1h])
)
```

Use in Grafana as a heatmap panel: x = time, y = `path_bucket`, colour =
`family`. Shows at a glance which endpoints are under which type of attack.

### Which endpoints attract injection attacks?

```promql
topk(10, sum by (path_bucket) (
  rate(veilgate_endpoint_attack_family_total{family="injection"}[1h])
))
```

### Critical-tier endpoints right now

```promql
topk(10, sum by (path_bucket) (
  rate(veilgate_endpoint_score_tier_total{tier="critical"}[15m])
))
```

### Signal breakdown for one endpoint

```promql
sum by (signal, decision) (
  veilgate_endpoint_signal_total{path_bucket="/api/auth/{id}"}
)
```

### Attack pressure per endpoint (signals per request)

```promql
sum by (path_bucket) (rate(veilgate_endpoint_signal_total[5m]))
/
sum by (path_bucket) (rate(veilgate_endpoint_request_total[5m]))
```

Normalises for traffic volume — an endpoint with 10 signals out of 10
requests is under heavier pressure than one with 100 signals out of
100 000 requests.

## Challenge Funnel

```promql
sum(rate(veilgate_challenge_issued_total[1h]))
sum(rate(veilgate_challenge_solved_total[1h]))
sum by (reason) (rate(veilgate_challenge_failed_total[1h]))
```

The solve rate (solved / issued) indicates what fraction of challenged
clients are real browsers. A very low solve rate usually means the
challenge threshold is catching automated clients effectively.

## Tarpit Cost

```promql
increase(veilgate_attacker_cost_usd_total[24h])
```

Use this to estimate defensive cost imposed on clients that were diverted into
the tarpit.

### Tarpit active sessions right now

```promql
veilgate_tarpit_active_sessions
```

A persistent non-zero value means agents are currently blocked in the
tarpit delay loop. Spikes indicate burst attacks.

### Tarpit content type breakdown

```promql
sum by (type) (rate(veilgate_tarpit_template_type_total[1h]))
```

## ML Activity

```promql
sum by (result) (increase(veilgate_ml_fits_total[1h]))
```

Use this to confirm whether the online ML refit loop is running and whether
fits are succeeding.

### Bayes cap health

```promql
veilgate_ml_bayes_entries
rate(veilgate_ml_bayes_evictions_total[5m])
```

`entries` close to 100 000 with a non-zero eviction rate means the cap
is active. A high eviction rate under adversarial traffic (random UUIDs
in paths) is expected; in normal traffic it should be near zero.

## Verifier Outcomes

```promql
sum by (verifier_type, result) (
  rate(veilgate_verifier_result_total[5m])
)
```

Use this to see what fraction of requests are accepted by each verifier
type (bearer, hmac, challenge) versus rejected.

## Persist Health

```promql
veilgate_persist_queue_depth
rate(veilgate_persist_dropped_total[5m])
```

`queue_depth` should be near zero in normal operation. A non-zero drop
rate means the disk cannot keep up; either traffic spiked or the disk
is saturated.

## Canary Replay

```promql
increase(veilgate_signal_hits_total{signal="canary_replay"}[10m])
```

Any non-zero result should be investigated. A canary replay means a token served
inside the tarpit appeared in a later request.

## Signal Recommender

```promql
veilgate_recommender_suggestions_last
veilgate_recommender_analysis_duration_seconds
```

`suggestions_last` tracks how many candidate custom signals the last
analysis pass found. A drop to zero after sustained traffic usually
means the confidence threshold needs tuning.

## Related

- [Config: metrics](../config/metrics.md)
- [Module veilgate_metrics](../modules/veilgate_metrics.md)
- [Monitor with Prometheus](../how-to/monitor-with-prometheus.md)
- [How-to: Endpoint correlation](../how-to/endpoint-correlation.md)
- [How-to: OpenTelemetry](../how-to/opentelemetry.md)
