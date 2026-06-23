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

VeilGate exposes all metrics via two parallel paths:
- **Prometheus pull** — `http://127.0.0.1:9090/metrics` (always on)
- **OTel push** — OTLP/HTTP to any backend when `telemetry.metrics_push.enabled: true`

All instruments are equivalent. OTel names use dots; Prometheus names use underscores.
Both paths are active simultaneously — they do not interfere with each other.

### Traffic and decisions

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_requests_total` | `veilgate.requests.total` | `decision` | Requests by final decision (real / challenge / tarpit / observe). |
| `veilgate_request_duration_seconds` | `veilgate.request.duration` | `decision` | End-to-end proxy latency histogram per routing decision. |
| `veilgate_score` | `veilgate.score` | — | Score histogram (0–100). |
| `veilgate_score_by_decision` | `veilgate.score.by_decision` | `decision` | Score histogram split by decision. |

### Detector signals

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_signal_hits_total` | `veilgate.signal.hits.total` | `signal` | Per-signal hit counter. |
| `veilgate_ip_reputation_hits_total` | `veilgate.ip_reputation.hits.total` | `category` | IP reputation hits by category (tor_exit, cloud, anonymizer …). |
| `veilgate_fleet_rotation_fires_total` | `veilgate.fleet_rotation.fires.total` | `tier` | Fleet rotation fires by severity tier (low / mid / high). |
| `veilgate_ua_rotation_fires_total` | `veilgate.ua_rotation.fires.total` | — | UA rotation fires. |
| `veilgate_tool_family_hits_total` | `veilgate.tool_family.hits.total` | `family` | Suspicious UA hits by tool family (sqlmap, nuclei, ffuf …). |
| `veilgate_public_ip_requests_total` | `veilgate.public_ip.requests.total` | `rotating` | Public-IP requests labelled yes/no for rotation status. |
| `veilgate_public_ip_rotation_events_total` | `veilgate.public_ip.rotation_events.total` | `tier`, `ip_category` | Rotation events that involved only public IPs. |
| `veilgate_public_ip_rotation_distinct` | `veilgate.public_ip.rotation_distinct_ips` | — | Distinct IPs per fingerprint histogram when fleet rotation fires. |
| `veilgate_ml_score_points` | `veilgate.ml.score_points` | — | Points contributed by `ml_agent_score` when it fires. |

### Endpoint correlation

These four metrics form the attack-correlation graph. See
[How-to: Endpoint correlation](../how-to/endpoint-correlation.md) for
query patterns.

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_endpoint_request_total` | `veilgate.endpoint.requests.total` | `path_bucket`, `method`, `decision` | Every scored request — use as the rate denominator. |
| `veilgate_endpoint_signal_total` | `veilgate.endpoint.signal.total` | `path_bucket`, `signal`, `method`, `decision` | Exact signal per endpoint + method + decision. |
| `veilgate_endpoint_attack_family_total` | `veilgate.endpoint.attack_family.total` | `path_bucket`, `family`, `method`, `decision` | Signal hits grouped into 9 attack families. |
| `veilgate_endpoint_score_tier_total` | `veilgate.endpoint.score_tier.total` | `path_bucket`, `tier`, `decision` | Attack severity per endpoint (critical / high / medium / low). |

`path_bucket` has UUID and numeric ID segments replaced with `{id}` and
depth capped at 4 segments to prevent cardinality explosion.

### Challenge

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_challenge_issued_total` | `veilgate.challenge.issued.total` | `form` | PoW challenge pages served (html / spa). |
| `veilgate_challenge_solved_total` | `veilgate.challenge.solved.total` | — | Proofs successfully verified. |
| `veilgate_challenge_failed_total` | `veilgate.challenge.failed.total` | `reason` | Failed verifications by reason (bad_request / unauthorized). |

### Tarpit

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_tarpit_bytes_served_total` | `veilgate.tarpit.bytes_served.total` | — | Bytes served from the tarpit. |
| `veilgate_tarpit_latency_ms_total` | `veilgate.tarpit.latency_ms.total` | — | Total artificial latency added, in milliseconds. |
| `veilgate_tarpit_active_sessions` | `veilgate.tarpit.active_sessions` | — | Gauge of in-flight tarpit ServeHTTP calls. *(v1.1.5 OTel)* |
| `veilgate_tarpit_template_type_total` | `veilgate.tarpit.template_type.total` | `type` | Responses by content-type category (json / html / graphql / text / other). |
| `veilgate_attacker_cost_usd_total` | `veilgate.tarpit.cost_usd.total` | — | Estimated attacker LLM API cost burned, USD. |

### ML

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_ml_fits_total` | `veilgate.ml.fits.total` | `status` | Isolation Forest refits by status (ok / skipped_cold / skipped_busy / skipped_disabled). |
| `veilgate_ml_fit_duration_seconds` | `veilgate.ml.fit_duration` | — | Time taken per Isolation Forest refit. |
| `veilgate_ml_fit_rows` | `veilgate.ml.fit_rows` | — | Training rows per fit after subsampling. |
| `veilgate_ml_bayes_observed` | `veilgate.ml.bayes_observed` | — | Labelled examples sent to the online Bayes classifier (burn-in gauge). |
| `veilgate_ml_bayes_entries` | `veilgate.ml.bayes_entries` | — | Current distinct (feature, bucket) pairs in the Bayes histogram. |
| `veilgate_ml_bayes_evictions_total` | `veilgate.ml.bayes_evictions.total` | — | Pairs evicted due to the 100 k cap. *(v1.1.5 OTel)* |
| `veilgate_miner_candidates_total` | `veilgate.ml.miner_candidates.total` | — | Rule candidates the ML miner has emitted into learned.yaml. *(v1.1.5 OTel)* |

### Recommender

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_recommender_suggestions_last` | `veilgate.recommender.suggestions_last` | — | Suggestions produced in the last analysis run. *(v1.1.5 OTel)* |
| `veilgate_recommender_analysis_duration_seconds` | `veilgate.recommender.analysis_duration` | — | Time taken by one recommender analysis pass. *(v1.1.5 OTel)* |

### Persistence

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_persist_queue_depth` | `veilgate.persist.queue_depth` | — | Current depth of the async write queue. |
| `veilgate_persist_dropped_total` | `veilgate.persist.dropped.total` | — | Events dropped due to write-queue back-pressure. |

### Verifier

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_verifier_result_total` | `veilgate.verifier.result.total` | `verifier_type`, `result` | Verifier chain outcomes (accepted / rejected) by verifier type. *(v1.1.5 OTel)* |

### Infrastructure

| Prometheus metric | OTel instrument | Labels | Meaning |
| --- | --- | --- | --- |
| `veilgate_tracked_clients` | `veilgate.tracked_clients` | — | Unique client IPs currently in the per-IP tracker. |
| `veilgate_fleet_fingerprints` | `veilgate.fleet_fingerprints` | — | Unique behavioural fingerprints currently tracked. |
| `veilgate_fleet_fingerprint_ips` | `veilgate.fleet_fingerprint_ips` | — | Distinct IPs per fingerprint histogram. |

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

