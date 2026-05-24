# Use case: API recon blocking

> **Summary:** Public APIs attract continuous automated discovery — schema
> probing, parameter enumeration, IDOR walking. VeilGate tags this traffic
> via per-IP fan-out, path-bruteforce, and toolchain signals, then
> diverts repeat offenders to a fake API surface.

**On this page:**

1. [The problem](#the-problem)
2. [The VeilGate setup](#the-veilgate-setup)
3. [Faking the API surface](#faking-the-api-surface)
4. [Metrics that prove it's working](#metrics-that-prove-its-working)
5. [Operational gotchas](#operational-gotchas)
6. [Related](#related)

## The problem

A typical API attack looks like:

- An agent hits `/api/swagger` or `/openapi.json` and learns your
  schema in one request.
- It walks every `GET /api/v1/users/{id}` from `1` to `10000`,
  collecting whatever the missing-auth endpoint returns.
- It rotates UAs each request to dodge static rules.
- It enumerates query parameters via `arjun` or `paramspider` against
  every endpoint it found.

The defender's headache: each individual request looks harmless. The
*pattern across requests* is the signal.

## The VeilGate setup

VeilGate's per-IP fan-out and path-bruteforce signals are tuned for
exactly this pattern. Lower the thresholds slightly because API traffic
is naturally lower-rate than browser traffic, so the discriminating
ratio shifts.

### `/etc/veilgate/veilgate.yaml`

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
rules_dir: "~/.veilgate/rules"
mode: "tarpit"

detector:
  score_tarpit_threshold: 65
  score_challenge_threshold: 35
  window_seconds: 60               # tighter window for API rates
  probe_paths:
    - /api/v1/internal/admin
    - /api/v2/debug/dump
    - /api/internal/keys
    - /openapi-internal.json
```

### `~/.veilgate/rules/detector.yaml`

```yaml
path_bruteforce:
  tiers:
    - distinct_paths: 80           # APIs see fewer distinct paths
      points: 40
    - distinct_paths: 30
      points: 25
    - distinct_paths: 12
      points: 10

wordlist_paths:
  points: 30
  substrings:
    - /api/v1/users/
    - /api/v2/admin/
    - /openapi
    - /swagger
    - /graphql
```

### `~/.veilgate/rules/injection_strategy.yaml`

Use the API-shaped templates so the tarpit returns plausible fake JSON
rather than HTML pages.

```yaml
routes:
  - match: prefix
    values: [/api/]
    template: api_json_fake
  - match: prefix
    values: [/openapi, /swagger]
    template: openapi_fake
```

## Faking the API surface

For API tarpitting to be convincing, the templates need to return
JSON that looks structurally real. VeilGate ships fake templates in
`rules/templates.yaml`; extend them with your own:

```yaml
templates:
  api_json_fake:
    status: 200
    content_type: application/json
    body: |
      {
        "data": [
          {"id": 1, "name": "{{.Profile.AdminUser}}", "role": "admin"},
          {"id": 2, "name": "{{.Profile.AdminUser2}}", "role": "user"}
        ],
        "meta": {"version": "{{.Profile.Version}}", "next_cursor": null}
      }
  openapi_fake:
    status: 200
    content_type: application/json
    body: |
      {
        "openapi": "3.0.0",
        "info": {"title": "{{.Profile.Company}} API", "version": "{{.Profile.Version}}"},
        "paths": {
          "/api/v1/admin/secret": {"get": {"summary": "internal"}},
          "/api/v1/users/{id}":   {"get": {"summary": "fetch user"}}
        }
      }
```

The tarpit fills in `{{.Profile.*}}` deterministically per-IP, so an
agent that comes back later sees the same fake company / users / version
and keeps following the false trail.

## Metrics that prove it's working

- `veilgate_signal_hits_total{signal="path_bruteforce"}` — should
  spike on agent traffic, near-zero for legit API consumers.
- `veilgate_signal_hits_total{signal="fanout_high"}` —
  per-IP-per-minute distinct-path counter.
- `veilgate_requests_total{decision="tarpit"}` over time — should be a
  small fraction of total. If it climbs above 5 % of traffic,
  thresholds are too tight for an API.
- `veilgate_tarpit_bytes_served_total` — the volume of fake-JSON
  bytes you're serving back. Pair with `veilgate_attacker_cost_usd_total`.

## Operational gotchas

- **Legitimate API consumers might walk many endpoints quickly.**
  Mobile apps fetch initial state from a dozen endpoints on launch.
  Add their egress UAs / IPs to `detector.trusted_ips` or to a custom
  rule that grants them headroom.
- **GraphQL is harder.** A single endpoint with many query shapes
  defeats path-bruteforce. Lean on rate-of-distinct-query-hashes (a
  custom signal — write it as a learned candidate) and on the JSON
  body markers in `injection_markers`.
- **Don't tarpit `/health` or `/version`.** Add them to
  `detector.trusted_ips` patterns or expose them on a separate
  hostname.

## Related

- [LLM-agent defence](llm-agent-defense.md)
- [Compliance & audit evidence](compliance-evidence.md)
- [How-to: Add honeypot paths and tune detection](../how-to/observe-and-tune.md)
- [Config: detector → path_bruteforce, wordlist_paths](../config/rules/detector.md)
- [Config: rules/templates.yaml](../config/rules/templates.md)

---

*Previous: [LLM-agent defence](llm-agent-defense.md) · Next: [Compliance & audit evidence](compliance-evidence.md)*
