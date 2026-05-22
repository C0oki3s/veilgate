# Configuration Reference

VeilGate reads one YAML file at startup. The default path is:

```bash
./veilgate -config configs/veilgate.yaml
```

If `rules_dir` points at a directory, rule files are loaded from disk and
hot-reloaded where supported. If `rules_dir` is empty, embedded defaults are
used.

## Top-Level Fields

```yaml
listen: ":8080"
upstream: "http://localhost:3000"
mode: "observe"
rules_dir: "~/.veilgate/rules"
```

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `listen` | string | `:8080` | Proxy listener. HTTPS when `tls.enabled` is true. |
| `upstream` | string | none | Real app URL for clean traffic. |
| `mode` | string | `observe` | One of `observe`, `challenge`, `tarpit`, `auto`. |
| `rules_dir` | string | empty | Directory containing editable YAML rules. |

## Upload Policies

```yaml
upload_policies:
  - name: "user-files"
    paths:
      - "/api/upload"
      - "/api/upload/*"
    methods: ["POST", "PUT"]
    max_body_bytes: 104857600
    allowed_content_types:
      - "multipart/form-data"
      - "application/pdf"
      - "image/"
    require_auth: true
    verifier_policy: "skip_body_hmac"
    upstream_response_timeout: "5m"
```

Upload policies explicitly mark routes that can carry file bodies. They reject
wrong methods, declared bodies above `max_body_bytes`, unsupported declared
content types, and unauthenticated uploads before proxying. See
[upload policy config](../config/upload-policies.md).

## Modes

| Mode | Behavior |
| --- | --- |
| `observe` | Score and record traffic, always proxy upstream. |
| `challenge` | Medium-score traffic gets proof of work; high-score traffic is still proxied. |
| `tarpit` | Medium-score traffic gets proof of work; high-score traffic enters the fake app. |
| `auto` | Scores below threshold are proxied, middle scores get proof of work, and high scores enter the fake app. |

Use `observe` before enabling user-facing enforcement.

## TLS

```yaml
tls:
  enabled: false
  cert_file: "cert.pem"
  key_file: "key.pem"
```

When enabled, VeilGate terminates TLS and parses the ClientHello to compute
JA3/JA4 fingerprints. Put a real TLS terminator in front of VeilGate only if you
do not need TLS fingerprinting at VeilGate itself.

## Detector

```yaml
detector:
  score_tarpit_threshold: 70
  score_challenge_threshold: 40
  window_seconds: 90
  trusted_ips: []
  trusted_proxies: []
  honeypot_paths:
    - "/admin-panel-v2"
    - "/api/internal/debug"
    - "/.git/config"
```

| Field | Notes |
| --- | --- |
| `score_challenge_threshold` | Requests at or above this score may be challenged. |
| `score_tarpit_threshold` | Requests at or above this score may be tarpitted in `tarpit` or `auto` mode. |
| `window_seconds` | Rolling window for per-client behavior. |
| `trusted_ips` | Exact client IDs that bypass scoring. Keep this short. |
| `trusted_proxies` | CIDRs whose `X-Forwarded-For` may be trusted. Empty is safest. |
| `honeypot_paths` | Paths that should not be hit by normal users. |

`trusted_proxies` should contain only proxies you operate. VeilGate ignores
spoofed `X-Forwarded-For` unless the direct peer is in this list.

## Challenge

```yaml
challenge:
  secret: "set-with-VEILGATE_SECRET-or-config"
  difficulty: 4
  ttl_minutes: 30
```

`VEILGATE_SECRET` overrides `challenge.secret` at runtime.

VeilGate refuses to start outside `observe` mode when the default challenge
secret is still configured. Use a long random value:

```bash
export VEILGATE_SECRET="$(openssl rand -hex 32)"
```

Challenge page behavior is configured in `rules/challenge.yaml`.

## Tarpit

```yaml
tarpit:
  min_latency_ms: 500
  max_latency_ms: 3000
  max_body_bytes: 102400
```

| Field | Notes |
| --- | --- |
| `min_latency_ms` | Lower bound for response delay. |
| `max_latency_ms` | Upper bound for response delay. |
| `max_body_bytes` | Caps generated tarpit response size. |

## Persistence

```yaml
persist:
  enabled: true
  path: "./data/events.db"
  retention_days: 30
  queue_size: 4096
  dump_path: "./data/dumps"
  cache_size_kb: 65536
```

The SQLite store records events, feature rollups, audit entries, learned rule
candidates, and tarpit canary state. New database files are created with tight
permissions.

`dump_path` writes gzipped CSV dumps before retention trimming. Set it to an
empty string to trim without exporting.

## Capture

```yaml
capture:
  enabled: false
  path: "./data/requests.jsonl"
  max_mb: 100
```

JSONL capture is a legacy firehose. Prefer `persist.enabled: true` unless you
already have a JSONL pipeline.

Capture files can contain IPs, paths, user agents, and headers. Enable scrub
rules before collecting production traffic.

## Metrics

```yaml
metrics:
  listen: ":9090"
```

The metrics listener serves Prometheus metrics and the built-in dashboard. Keep
it on a private network, behind VPN, or bound to localhost.

## Rule Files

Common files under `rules/`:

| File | Purpose |
| --- | --- |
| `detector.yaml` | Signal weights and matching rules. |
| `ip_reputation.yaml` | CIDR categories, public/private IP logic, rotation thresholds. |
| `tls_fingerprints.yaml` | JA3/JA4 known fingerprints and browser-like prefixes. |
| `payloads.yaml` | Prompt-injection and decoy payload library. |
| `templates.yaml` | Shadow app response templates. |
| `injection_strategy.yaml` | Route-to-template and payload strategy. |
| `fake_data.yaml` | Fake company, stack, user, and credential pools. |
| `challenge.yaml` | Proof-of-work HTML and cookie settings. |
| `ml.yaml` | Online ML settings, miner settings, path redaction. |
| `dashboard.yaml` | Built-in dashboard layout. |

Treat rule files as code. Review them, version them, and deploy them through the
same change process as application security policy.
