# `metrics:`

> **File:** `/etc/veilgate/veilgate.yaml` &nbsp;·&nbsp;
> **Section:** `metrics:` &nbsp;·&nbsp;
> **Reload:** restart required.

VeilGate exposes Prometheus metrics and the live operator dashboard on
the same listener. Both are unauthenticated — keep this listener
private.

**On this page:**

- [`listen`](#listen)
- [What's exposed](#whats-exposed)
- [Securing the endpoint](#securing-the-endpoint)
- [Example](#example)
- [Related](#related)

## Parameters

### `listen`

| Type | Required | Default |
| --- | --- | --- |
| string | no | `:9090` |

Address the metrics + dashboard listener binds to. Use
`127.0.0.1:9090` to bind only to loopback — the default config in
[DEPLOYMENT.md](../DEPLOYMENT.md) does this and accesses the dashboard
via SSH tunnel.

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

If you need it reachable on the internal network only, bind to the
internal interface address explicitly:

```yaml
metrics:
  listen: "10.0.5.20:9090"
```

## What's exposed

Two endpoints on the same listener:

| Path | Content |
| --- | --- |
| `/metrics` | Prometheus exposition format |
| `/` | Live HTML dashboard with score histogram, signal hits, decision counts, attacker-cost estimate |

Notable Prometheus metrics:

- `veilgate_requests_total{decision="real|challenge|tarpit"}`
- `veilgate_score` — histogram of total scores
- `veilgate_score_by_decision{decision="..."}` — same, split by decision
- `veilgate_signal_hits_total{signal="..."}` — per-signal hit counter
- `veilgate_tarpit_bytes_served_total`
- `veilgate_tarpit_latency_ms_total`
- `veilgate_attacker_cost_usd_total` — bytes-served × $0.003 / KiB
- `veilgate_client_cardinality` — distinct clients tracked
- `veilgate_fleet_fingerprint_cardinality` — distinct behavioural fingerprints
- `veilgate_ip_reputation_hits_total{category="..."}`
- `veilgate_ml_fits_total{result="..."}` — Isolation Forest refit outcomes
- `veilgate_ml_fit_duration_seconds`
- `veilgate_ml_fit_rows`
- `veilgate_bayes_observed_total` — burn-in progress

A full query cookbook lives at
[`docs/PROMETHEUS_QUERIES.md`](../PROMETHEUS_QUERIES.md).

## Securing the endpoint

Three options, in order of strength:

1. **Bind to loopback** and access via SSH tunnel (the default; works
   everywhere; zero extra moving parts).
2. **Bind to an internal interface** behind a network ACL.
3. **Front it with another reverse proxy** (Caddy / nginx) that
   terminates mTLS or basic-auth before forwarding to `127.0.0.1:9090`.

Do not put `metrics.listen` on a public IP without one of these in
front of it. Anyone who reaches the dashboard can read live event lines
including paths, UAs, and decision rationale — that is sensitive
operational data.

## Example

```yaml
metrics:
  listen: "127.0.0.1:9090"
```

Access from a workstation:

```bash
ssh -L 9090:127.0.0.1:9090 user@veilgate-host
# then open http://localhost:9090/
```

## Related

- [How-to: Monitor with Prometheus + Grafana](../how-to/monitor-with-prometheus.md)
- [`rules/dashboard.yaml`](rules/dashboard.md) — panel layout
  *(see the rules dashboard reference page when added)*

---

*Previous: [`challenge:`](challenge.md) · Next: [`persist:`](persist.md)*
