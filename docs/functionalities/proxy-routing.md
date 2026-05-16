# Module veilgate_core

The `veilgate_core` module describes the top-level runtime fields that decide
where VeilGate listens, which upstream application receives clean traffic, which
operating mode is active, and where external rule files are loaded from.

These fields are read from `veilgate.yaml` by `internal/config.Load()` and then
wired by `cmd/veilgate/main.go`.

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

- [Module veilgate_rules](../modules/veilgate_rules.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [Top-level config reference](../config/top-level.md)

