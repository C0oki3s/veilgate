# `metrics:`

> **File:** `/etc/veilgate/veilgate.yaml`
> **Section:** `metrics:`
> **Reload:** restart required.

VeilGate exposes Prometheus metrics and the live operator dashboard on
the same listener. The `/api/*` sub-paths can be protected with a
bearer token via `api_key`.

**On this page:**

- [`disabled`](#disabled)
- [`listen`](#listen)
- [`api_key`](#api_key)
- [What's exposed](#whats-exposed)
- [Securing the endpoint](#securing-the-endpoint)
- [Example](#example)
- [Related](#related)

## Parameters

### `disabled`

| Type | Required | Default |
| --- | --- | --- |
| bool | no | `false` |

Set `true` to turn off the Prometheus pull endpoint and operator
dashboard entirely. No listener is opened, no port is bound.

Use this when you only want OTLP push (`telemetry.metrics_push`) and
don't need a local Prometheus scrape target.

```yaml
metrics:
  disabled: true
```

---

### `listen`

| Type | Required | Default |
| --- | --- | --- |
| string | no | `127.0.0.1:9090` |

Address the metrics + dashboard listener binds to. The default binds
to loopback only — the endpoint is not reachable from the network
without an explicit bind change or SSH tunnel.

```yaml
metrics:
  listen: "127.0.0.1:9090"   # default — loopback only
```

To expose on all interfaces (e.g. for a Prometheus scraper on the same
LAN), bind to `0.0.0.0` and pair it with `api_key`:

```yaml
metrics:
  listen: ":9090"
  api_key: "long-random-secret"
```

To restrict to a specific internal interface:

```yaml
metrics:
  listen: "10.0.5.20:9090"
```

## `api_key`

| Type | Required | Default |
| --- | --- | --- |
| string | no | `""` (no auth) |

Bearer token that must be present on all requests to `/api/*` endpoints
(e.g. `/api/signal-suggestions`). When empty, those endpoints are open
to any caller that can reach the metrics listener.

The token is compared in constant time using HMAC equality to prevent
timing attacks.

```yaml
metrics:
  listen: "127.0.0.1:9090"
  api_key: "change-me-to-a-long-random-secret"
```

Clients must send the token as an `Authorization` header:

```bash
curl -H "Authorization: Bearer change-me-to-a-long-random-secret" \
  http://127.0.0.1:9090/api/signal-suggestions
```

If the key is wrong the server responds `401 Unauthorized` with a
`WWW-Authenticate: Bearer realm="veilgate"` header.

## What's exposed

Two endpoints on the same listener:

| Path | Content |
| --- | --- |
| `/metrics` | Prometheus exposition format |
| `/` | Live HTML dashboard with score histogram, signal hits, decision counts, attacker-cost estimate |

Notable Prometheus metrics:

- `veilgate_requests_total{decision="real|challenge|tarpit"}`
- `veilgate_score` - histogram of total scores
- `veilgate_score_by_decision{decision="..."}` - same, split by decision
- `veilgate_signal_hits_total{signal="..."}` - per-signal hit counter
- `veilgate_tarpit_bytes_served_total`
- `veilgate_tarpit_latency_ms_total`
- `veilgate_attacker_cost_usd_total` - bytes-served x $0.003 / KiB
- `veilgate_client_cardinality` - distinct clients tracked
- `veilgate_fleet_fingerprint_cardinality` - distinct behavioral fingerprints
- `veilgate_ip_reputation_hits_total{category="..."}`
- `veilgate_ml_fits_total{result="..."}` - Isolation Forest refit outcomes
- `veilgate_ml_fit_duration_seconds`
- `veilgate_ml_fit_rows`
- `veilgate_bayes_observed_total` - burn-in progress

A full query cookbook lives at
[Prometheus query cookbook](../operations/prometheus-queries.md).

## Securing the endpoint

Three options, in order of strength:

1. **Bind to loopback** and access via SSH tunnel (the default; works
   everywhere; zero extra moving parts).
2. **Bind to an internal interface** behind a network ACL.
3. **Front it with another reverse proxy** (Caddy / nginx) that
   terminates mTLS or basic-auth before forwarding to `127.0.0.1:9090`.

Do not put `metrics.listen` on a public IP without one of these in
front of it. Anyone who reaches the dashboard can read live event lines
including paths, UAs, and decision rationale - that is sensitive
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
- [`rules/dashboard.yaml`](rules/dashboard.md) - panel layout

---

*Previous: [`challenge:`](challenge.md) | Next: [`persist:`](persist.md)*
