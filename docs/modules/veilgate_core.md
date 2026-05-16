# Module veilgate_core

The `veilgate_core` module describes the top-level runtime fields that decide
where VeilGate listens, which upstream application receives clean traffic, which
operating mode is active, and where external rule files are loaded from.

These fields are read from `veilgate.yaml` by `internal/config.Load()` and
wired by `cmd/veilgate/main.go`. This module is the VeilGate equivalent of
NGINX's top-level `http { }` block and `server { }` directives — it sets the
listener, upstream, and global behavior before any per-request decision logic
applies.

## Example Configuration

```yaml
# Full production-ready example
listen: ":8080"
upstream: "http://127.0.0.1:3000"
mode: "observe"                   # Start here. Move to auto after tuning.
rules_dir: "/etc/veilgate/rules"  # Leave empty to use embedded defaults.

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70
  window_seconds: 90
  trusted_ips: []
  trusted_proxies: []
  honeypot_paths:
    - "/.git/config"
    - "/.env.backup"
    - "/wp-admin-old"
    - "/api/internal/debug"

tls:
  enabled: false          # Enable for JA3/JA4 fingerprinting.
  cert_file: "cert.pem"
  key_file: "key.pem"

challenge:
  secret: "${VEILGATE_SECRET}"
  difficulty: 4
  ttl_minutes: 30

tarpit:
  min_latency_ms: 500
  max_latency_ms: 3000
  max_body_bytes: 102400

persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"
  retention_days: 30
  queue_size: 4096
  dump_path: "/var/lib/veilgate/dumps"
  cache_size_kb: 65536

metrics:
  listen: "127.0.0.1:9090"
```

## Directives

- `listen`
- `upstream`
- `mode`
- `rules_dir`

## `listen`

Syntax:  `listen: "<address>:<port>"`  
Default: `":8080"`  
Context: top-level

Defines the client-facing proxy listener. Corresponds to NGINX's `listen`
directive. The value follows Go's `net.Listen` address format: omitting the
host (`":8080"`) binds to all interfaces; including it (`"127.0.0.1:8080"`)
binds to a single interface.

When `tls.enabled` is false, `cmd/veilgate/main.go` calls `http.ListenAndServe`.
When `tls.enabled` is true, it calls `listenTLS()` which wraps the TCP listener
with `internal/tlsfp.Listener` before handing it to the TLS stack. The wrapper
intercepts the first TLS record, extracts the ClientHello, and computes JA3/JA4
fingerprints before Go's TLS code consumes the connection.

```go
// cmd/veilgate/main.go (schematic)
if cfg.TLS.Enabled {
    tlsListener := tlsfp.WrapListener(l, fpStore)
    httpServer.ServeTLS(tlsListener, cfg.TLS.CertFile, cfg.TLS.KeyFile)
} else {
    httpServer.ListenAndServe()
}
```

### Code path

- [`internal/config/config.go`](../../internal/config/config.go) — field definition and default.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — HTTP server creation and TLS listener setup.
- [`internal/tlsfp/listener.go`](../../internal/tlsfp/listener.go) — ClientHello interceptor.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) — request handling after listener.

### Operational notes

- Keep the proxy listener and metrics listener on separate ports.
- Binding to `:443` requires `CAP_NET_BIND_SERVICE` or a fronting load balancer.
- If TLS terminates before VeilGate (CDN, ALB, nginx), TLS fingerprint signals
  are unavailable at this layer.
- In container deployments, bind to `0.0.0.0:8080` and control exposure at
  the service/ingress level rather than relying on the bind address.

### Validation

```bash
# Plain HTTP
curl -i http://localhost:8080/

# TLS mode
curl -k -i https://localhost:8080/

# Confirm listener is bound
ss -tlnp | grep 8080
```

## `upstream`

Syntax:  `upstream: "<scheme>://<host>:<port>"`  
Default: none (required)  
Context: top-level

Defines the real application origin used for `real` traffic and observe-mode
forwarding. This is the closest VeilGate equivalent to NGINX's `proxy_pass`
target, but VeilGate selects whether to proxy before forwarding.

`internal/proxy.NewServer()` parses this URL and builds a
`httputil.NewSingleHostReverseProxy`. The director rewrites the outbound
request host to the upstream host. The transport sets connection timeouts,
attempts HTTP/2, and enforces TLS 1.2 minimum for HTTPS upstreams.

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `NewServer()` parses `cfg.Upstream`.
- `httputil.NewSingleHostReverseProxy` handles forwarding.
- Error on upstream failure: `502 bad gateway` (no retry).

### Operational notes

- Do not point `upstream` back at the VeilGate listener; this creates a loop.
- Use `http://127.0.0.1:3000` for co-located apps.
- If the upstream requires HTTPS, use `https://` and ensure the upstream
  certificate is trusted by the system CA pool or configure accordingly.
- `502` from VeilGate indicates upstream connectivity failure.

### Validation

```bash
curl -i http://localhost:8080/
# In observe mode: response from the upstream app
```

## `mode`

Syntax:  `mode: "observe" | "challenge" | "tarpit" | "auto"`  
Default: `"observe"`  
Context: top-level

Controls how VeilGate applies detector scores to traffic. The detector runs in
all modes. Mode only determines whether the score changes routing.

| Mode | Score band | Decision |
| --- | --- | --- |
| `observe` | any | `observe` (always proxied upstream) |
| `challenge` | `< challenge` | `real` |
| `challenge` | `≥ challenge` | `challenge` |
| `tarpit` | `< challenge` | `real` |
| `tarpit` | `≥ challenge` and `< tarpit` | `challenge` |
| `tarpit` | `≥ tarpit` | `tarpit` |
| `auto` | `< challenge` | `real` |
| `auto` | `≥ challenge` and `< tarpit` | `challenge` |
| `auto` | `≥ tarpit` | `tarpit` |

In `observe` mode, the decision is always `observe` (proxied upstream)
regardless of score. High scores appear in metrics and logs but do not divert
traffic. This is the safe rollout mode.

```go
// internal/proxy/proxy.go
func (s *Server) decide(score int) Decision {
    switch s.cfg.Mode {
    case "observe":
        return DecisionObserve
    case "challenge":
        if score >= s.cfg.Detector.ScoreChallengeThreshold {
            return DecisionChallenge
        }
        return DecisionReal
    case "tarpit":
        if score >= s.cfg.Detector.ScoreTarpitThreshold { return DecisionTarpit }
        if score >= s.cfg.Detector.ScoreChallengeThreshold { return DecisionChallenge }
        return DecisionReal
    case "auto":
        if score >= s.cfg.Detector.ScoreTarpitThreshold { return DecisionTarpit }
        if score >= s.cfg.Detector.ScoreChallengeThreshold { return DecisionChallenge }
        return DecisionReal
    }
    return DecisionReal
}
```

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `decide(score int)`
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `serve()` dispatches selected handler.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) produces the score.

### Operational notes

- **Always start with `observe`.** Run for at least a week before enabling
  enforcement on production traffic.
- Move to `challenge` after verifying normal user traffic scores below
  `score_challenge_threshold`.
- Move to `tarpit` or `auto` only after false positives are understood and
  thresholds are tuned.
- Changing `mode` requires a restart (`systemctl restart veilgate`).
- A valid challenge token or verifier can bypass `challenge` decisions but not
  `tarpit` decisions.

### Validation

```bash
# Send scanner-like request
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config

# Watch decision distribution
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

## `rules_dir`

Syntax:  `rules_dir: "<path>"`  
Default: empty (embedded defaults)  
Context: top-level

Defines the directory from which editable YAML rule files are loaded at startup
and on hot reload. If empty, VeilGate uses embedded defaults compiled into the
binary. If a specific file is missing from the directory, that file's embedded
default is used.

Hot reload uses `fsnotify` with a debounce of approximately 500ms. Supported
hot-reload files: `detector.yaml`, `ip_reputation.yaml`, `tls_fingerprints.yaml`,
`templates.yaml`, `injection_strategy.yaml`, `payloads.yaml`, `fake_data.yaml`,
`challenge.yaml`, `ml.yaml`, `dashboard.yaml`, `vulnerabilities.yaml`,
`learned.yaml`.

Files **not** hot-reloaded (require restart): `veilgate.yaml` itself.

### Code path

- [`internal/rules/loader.go`](../../internal/rules/loader.go) — loads detector, TLS, payload files.
- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go) — loads templates, fake data, etc.
- [`internal/rules/watcher.go`](../../internal/rules/watcher.go) — file watcher and reload dispatch.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) — registers reload handlers per rule type.

### Operational notes

- Treat `rules/` as security policy; review changes like code.
- Mount read-only in Kubernetes/container deployments where possible.
- A parse error in a reload leaves the previous in-memory rules active.
- Restrict ownership: `chown root:veilgate /etc/veilgate/rules && chmod 640 *.yaml`.

### Validation

```bash
ls -la /etc/veilgate/rules/
# Edit a rule file, wait ~1s, verify change takes effect without restart
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## Related

- [Module veilgate_proxy](veilgate_proxy.md)
- [Module veilgate_rules](veilgate_rules.md)
- [Module veilgate_tls_fingerprinting](veilgate_tls_fingerprinting.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [Top-level config reference](../config/top-level.md)

## Example Configuration

```yaml
listen: ":8080"
upstream: "http://localhost:3000"
mode: "observe"
rules_dir: "./rules"
```

## Directives

- `listen`
- `upstream`
- `mode`
- `rules_dir`

## `listen`

Syntax:  `listen: "<address>:<port>"`  
Default: `":8080"`  
Context: top-level

Defines the client-facing proxy listener. In local development this is usually
`:8080`. In production it may be a private interface behind an edge proxy or a
public address if VeilGate itself terminates client traffic.

When `tls.enabled` is false, the listener accepts plain HTTP. When
`tls.enabled` is true, `cmd/veilgate.listenTLS()` opens the same address,
wraps it with `internal/tlsfp.Listener`, and then serves TLS. That is the mode
required for JA3/JA4 fingerprint extraction at VeilGate.

### Code path

- [`internal/config/config.go`](../../internal/config/config.go) defines the field and default.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) creates the main HTTP server.
- [`cmd/veilgate/main.go#L71`](../../cmd/veilgate/main.go#L71) handles TLS listener setup.
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) handles requests after listener setup.

### Operational notes

- Keep the proxy listener and metrics listener separate.
- If TLS is terminated before VeilGate, TLS fingerprint signals will not fire
  at this layer.
- Binding to `:443` normally requires service privileges or a fronting
  load balancer.

### Validation

```bash
curl -i http://localhost:8080/
```

For TLS mode:

```bash
curl -k -i https://localhost:8080/
```

## `upstream`

Syntax:  `upstream: "<scheme>://<host>:<port>"`  
Default: none  
Context: top-level

Defines the real application origin used for `real` traffic and observe-mode
forwarding. This is the closest VeilGate equivalent to an NGINX `proxy_pass`
target, but VeilGate decides whether to proxy before forwarding.

`internal/proxy.NewServer()` parses this URL and builds a
`httputil.NewSingleHostReverseProxy`. The director rewrites the outbound
request host to the upstream host. The transport sets connection timeouts,
attempts HTTP/2, and uses TLS 1.2 or newer when the upstream is HTTPS.

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go)
- `internal/proxy.NewServer()`
- Go standard library `httputil.NewSingleHostReverseProxy`

### Operational notes

- Do not point `upstream` back to the VeilGate listener, or the proxy loops.
- Prefer internal addresses such as `http://127.0.0.1:3000` or a private
  service address.
- If the upstream fails, VeilGate returns `502 bad gateway`.

### Validation

```bash
curl -i http://localhost:8080/
```

Expected result: in `observe` mode or for low-score traffic, the response
comes from the upstream application.

## `mode`

Syntax:  `mode: "observe" | "challenge" | "tarpit" | "auto"`  
Default: `"observe"`  
Context: top-level

Controls how VeilGate applies detector scores to traffic. The detector runs in
all modes. The mode only decides whether the score changes routing.

| Mode | Behavior |
| --- | --- |
| `observe` | Score, log, and record traffic, but proxy everything upstream. |
| `challenge` | Requests at or above `detector.score_challenge_threshold` receive the challenge handler. |
| `tarpit` | Requests at or above `detector.score_tarpit_threshold` receive the tarpit handler; the middle band receives challenge. |
| `auto` | Below challenge threshold proxies upstream; middle band challenges; high band tarpits. |

### Code path

- [`internal/proxy/proxy.go#L346`](../../internal/proxy/proxy.go#L346) maps mode and score to a decision.
- [`internal/proxy/proxy.go#L163`](../../internal/proxy/proxy.go#L163) dispatches the selected handler.
- [`internal/detector/scorer.go#L177`](../../internal/detector/scorer.go#L177) calculates the score.

### Operational notes

- Start with `observe` for baseline collection.
- Move to `challenge` after reviewing high-scoring legitimate traffic.
- Use `tarpit` or `auto` only after false positives are understood.
- A valid challenge token or verifier can bypass challenge-tier decisions, but
  not tarpit-tier decisions.

### Validation

```bash
curl -A "python-requests/2.31.0" http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

## `rules_dir`

Syntax:  `rules_dir: "<path>"`  
Default: empty, meaning embedded defaults  
Context: top-level

Defines the directory from which editable YAML rule files are loaded. If it is
empty, VeilGate uses embedded defaults compiled into the binary. If it is set
and a specific file is missing, that file falls back to its embedded default.

Supported files include detector rules, TLS fingerprints, tarpit templates,
payloads, fake data, challenge rules, ML rules, and dashboard rules.

### Code path

- [`internal/rules/loader.go`](../../internal/rules/loader.go) reads detector, TLS, and payload files.
- [`internal/rules/extra_loaders.go`](../../internal/rules/extra_loaders.go) reads additional rule files.
- [`internal/rules/watcher.go`](../../internal/rules/watcher.go) watches and hot-reloads supported files.
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) registers reload handlers.

### Operational notes

- Treat `rules/` as security policy.
- Review rule changes like code changes.
- Mount rule files read-only in production when possible.
- Bad reloads should leave the previous in-memory rules active.

### Validation

```bash
ls -la ./rules
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## Related

- [Module veilgate_rules](veilgate_rules.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [Top-level config reference](../config/top-level.md)

