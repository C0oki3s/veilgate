# How to investigate attacks with endpoint correlation

> **Goal:** Use VeilGate's endpoint-correlation metrics to answer
> "which endpoints are under attack, what kind of attack, and how
> severe?" — without grep-ing logs.

**On this page:**

1. [The four metrics](#the-four-metrics)
2. [Path normalisation](#path-normalisation)
3. [Attack families](#attack-families)
4. [Score tiers](#score-tiers)
5. [Grafana panel recipes](#grafana-panel-recipes)
6. [Investigation workflow](#investigation-workflow)
7. [Related](#related)

## The four metrics

Every scored request increments four counter vectors that share the
`path_bucket` label as their correlation key. Join them in a single
PromQL query to get the full picture of an endpoint under attack.

| Metric | Labels | What it answers |
| --- | --- | --- |
| `veilgate_endpoint_request_total` | `path_bucket`, `method`, `decision` | How much traffic hits this endpoint? (denominator) |
| `veilgate_endpoint_score_tier_total` | `path_bucket`, `tier`, `decision` | How severe are the attacks? |
| `veilgate_endpoint_attack_family_total` | `path_bucket`, `family`, `method`, `decision` | What attack category is targeting this endpoint? |
| `veilgate_endpoint_signal_total` | `path_bucket`, `signal`, `method`, `decision` | Which exact signals fire on this endpoint? |

Use `veilgate_endpoint_request_total` as the denominator in rate queries
so high-traffic endpoints and low-traffic endpoints are comparable:

```promql
# Signal hit rate per endpoint — normalised for traffic volume
rate(veilgate_endpoint_signal_total[5m])
/
on(path_bucket, method, decision)
rate(veilgate_endpoint_request_total[5m])
```

## Path normalisation

Raw paths contain UUIDs and numeric IDs that would create thousands of
unique Prometheus label values. VeilGate normalises them before emitting
metrics:

| Raw path | Normalised `path_bucket` |
| --- | --- |
| `/api/users/550e8400-e29b-41d4-a716-446655440000` | `/api/users/{id}` |
| `/v1/orders/99182/items` | `/v1/orders/{id}/items` |
| `/api/session/abc123def456789012` | `/api/session/{id}` |
| `/api/a/b/c/d/e/f/g` | `/api/a/b/c` (capped at 4 segments) |

Rules applied in order:
1. UUID segments (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) → `{id}`
2. Pure numeric segments (`12345`) → `{id}`
3. Long hex tokens (≥ 20 hex characters) → `{id}`
4. Depth capped at 4 segments — `/api/a/b/c/d/e` becomes `/api/a/b/c`

## Attack families

The 40+ individual signal names are grouped into 9 families for the
`veilgate_endpoint_attack_family_total` metric. A single request can
increment multiple families.

| Family | Signals included | What it means |
| --- | --- | --- |
| `recon` | schema_first, api_blueprint_miss, path_bruteforce, wordlist_path, fanout_extreme, fanout_high, graph_flat | Client is mapping the API surface before attacking. |
| `auth` | auth_probe_sequence, no_cookie_return, cookie_stateless, canary_replay | Client is targeting authentication or credential endpoints. |
| `injection` | injection_marker, oob_interaction, encoding_chain | Client is sending payloads (SQLi, XSS, SSTI, OOB) or obfuscating them. |
| `evasion` | header_mutation, ua_rotation, tls_agent, h2_agent | Client is actively changing fingerprints to avoid detection. |
| `fingerprint` | sparse_headers, empty_ua, suspicious_ua, sec_fetch_absent, sec_fetch_partial, ae_browser_empty, ae_browser_no_br, h3_mismatch, tls_bot, tls_non_browser, h2_bot, h2_non_browser | Passive non-browser signatures. Not necessarily malicious alone, but contributes to score. |
| `behavioral` | cache_miss_anomaly, regular_timing, bundle_mining, recovery_pivot, graph_doc_heavy | Session-level anomalies that look like automated polling or scripted traversal. |
| `fleet` | ip_rotation_fleet, ip_reputation | Requests from known bad IPs or a rotating proxy pool. |
| `toolchain` | toolchain_full, toolchain_partial, toolchain_hmm, toolchain_hmm_partial | Recognised pentest tool sequences (sqlmap, nikto, nuclei, ffuf…). |
| `ml` | ml_agent_score | Isolation Forest + Bayes composite score exceeded the confidence threshold. |

## Score tiers

`veilgate_endpoint_score_tier_total` uses four tiers:

| Tier | Score range | Typical outcome |
| --- | --- | --- |
| `critical` | ≥ 80 | Almost certainly automated; tarpitted or challenged. |
| `high` | 60 – 79 | Strong bot signals; usually challenged or tarpitted. |
| `medium` | 40 – 59 | Suspicious but ambiguous; reviewed or observed. |
| `low` | < 40 | Minor signals only; typically passed to upstream. |

## Grafana panel recipes

### Top endpoints by attack pressure (table)

```promql
topk(20, sum by (path_bucket) (
  rate(veilgate_endpoint_signal_total[1h])
))
```

Panel type: **Table**. Sort by value descending.

### Attack family heat map

```promql
sum by (path_bucket, family) (
  increase(veilgate_endpoint_attack_family_total[1h])
)
```

Panel type: **Heatmap**. X axis = `family`, Y axis = `path_bucket`.
This gives a visual grid of "which attack type hits which endpoint."

### Severity distribution per endpoint (bar chart)

```promql
sum by (path_bucket, tier) (
  rate(veilgate_endpoint_score_tier_total[1h])
)
```

Panel type: **Bar chart**, stacked. Colour by `tier`.

### Full signal breakdown for one endpoint (bar chart)

```promql
sum by (signal, decision) (
  veilgate_endpoint_signal_total{path_bucket="/api/auth/{id}"}
)
```

Replace `/api/auth/{id}` with the path bucket you are investigating.

## Investigation workflow

**Step 1 — identify the most pressured endpoints**

```promql
topk(10, sum by (path_bucket) (
  rate(veilgate_endpoint_score_tier_total{tier=~"critical|high"}[15m])
))
```

**Step 2 — determine the attack family**

```promql
sum by (family) (
  rate(veilgate_endpoint_attack_family_total{path_bucket="/api/auth/{id}"}[15m])
)
```

If `auth` and `injection` are both high, someone is probing
authentication endpoints with injection payloads — a credential
stuffing campaign with payload obfuscation.

**Step 3 — drill into exact signals**

```promql
sum by (signal) (
  rate(veilgate_endpoint_signal_total{path_bucket="/api/auth/{id}"}[15m])
)
```

**Step 4 — cross to OTel traces**

Open your trace backend (Jaeger / Tempo / SigNoz) and filter by:

```
span.http.path =~ /api/auth.*
span.veilgate.attack_families contains auth
```

Each trace shows the full scored request with every signal event
attached, including the exact reason string that explains why the signal
fired.

**Step 5 — consider a custom signal**

If a specific pattern keeps appearing (e.g. every `injection_marker`
hit on `/api/auth/{id}` involves `POST` and a `%27` in the body), you
can codify it as a `custom_signal` in `rules/signals.yaml` with higher
points. The signal recommender will suggest candidates automatically
after enough traffic accumulates.

## Related

- [How-to: Monitor with Prometheus](monitor-with-prometheus.md)
- [How-to: OpenTelemetry](opentelemetry.md)
- [Prometheus query cookbook](../operations/prometheus-queries.md)
- [Config: rules customization](../config/rules/customization.md)

---

*Previous: [OpenTelemetry](opentelemetry.md) · Next: [Observe and tune](observe-and-tune.md)*
