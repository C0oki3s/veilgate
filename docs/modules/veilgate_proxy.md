# Module veilgate_proxy

The `veilgate_proxy` module documents how VeilGate acts as a reverse proxy,
resolves client identity, applies the mode-and-threshold decision function,
dispatches to the correct handler, and protects detector state from spoofed
forwarded headers.

The proxy module is implemented by `internal/proxy.Server`. Every inbound
request passes through `Server.serve()`, which calls `Scorer.Score()`, applies
the bypass chain, dispatches the selected handler, and records post-response
telemetry. The handler never blocks on persistence or metrics; all writes are
asynchronous or counter-increments.

## Client Protocols

VeilGate accepts HTTP/1.1 and HTTP/2 on the client-facing listener.

| Listener mode | Supported client protocols | Notes |
| --- | --- | --- |
| `tls.enabled: true` | HTTP/1.1 and HTTP/2 | TLS advertises `h2` and `http/1.1` with ALPN. |
| `tls.enabled: false` | HTTP/1.1 and h2c | The plain listener is wrapped with `h2c.NewHandler`, so prior-knowledge HTTP/2 and h2c upgrade requests enter the same proxy pipeline. |

WebSocket tunnelling currently supports the HTTP/1.1 upgrade flow. HTTP/2
WebSocket extended CONNECT is detected and returns `501` JSON rather than
falling through to the HTTP/1.1 hijacker path.

## How the Proxy Differs from NGINX `proxy_pass`

| NGINX concept | VeilGate equivalent | Difference |
| --- | --- | --- |
| `proxy_pass` | `upstream` + `httputil.NewSingleHostReverseProxy` | VeilGate decides whether to proxy before forwarding |
| `real_ip_from` | `detector.trusted_proxies` | VeilGate ignores XFF when the direct peer is untrusted |
| `access_log` | structured zerolog JSON per request | Includes score, decision, and signal list, not just access data |
| `location` routing | tarpit route strategy in `injection_strategy.yaml` | YAML-driven, not nginx.conf location blocks |
| upstream health check | `502 bad gateway` on dial failure | No active health check; uses Go transport error handling |

## Example Configuration

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
mode: "auto"

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70
  window_seconds: 90
  trusted_ips: []
  trusted_proxies:
    - "10.0.0.0/8"

metrics:
  listen: "127.0.0.1:9090"

persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"
  retention_days: 30
```

## Directives

- `upstream`
- `detector.trusted_ips`
- `detector.trusted_proxies`
- runtime decisions: `real`, `observe`, `challenge`, `tarpit`

## `upstream`

Syntax:  `upstream: "<scheme>://<host>:<port>"`  
Default: none (required)  
Context: top-level

Defines the real application origin used for `real` and `observe` traffic.
`internal/proxy.NewServer()` parses this URL and builds a
`httputil.NewSingleHostReverseProxy`. The director function rewrites the
outbound request `Host` header to the upstream host. The transport is
configured with:

- `ForceAttemptHTTP2: true` — attempts HTTP/2 to the upstream when supported.
- Dial timeout: 5 seconds.
- Response header timeout: 15 seconds.
- TLS minimum version: TLS 1.2.
- `rp.ErrorHandler` returns `502 bad gateway` on upstream dial failure.

```go
// internal/proxy/proxy.go
rp.Transport = &http.Transport{
    ForceAttemptHTTP2:     true,
    TLSHandshakeTimeout:   5 * time.Second,
    ResponseHeaderTimeout: 15 * time.Second,
    TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
}
rp.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
    http.Error(w, "bad gateway", http.StatusBadGateway)
}
```

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `NewServer()`
- Go standard library `net/http/httputil.NewSingleHostReverseProxy`

### Operational notes

- Do not point `upstream` back at the VeilGate listener (creates a loop).
- Use `http://127.0.0.1:3000` for a co-located application.
- Use `https://` upstream when the upstream requires TLS; VeilGate uses TLS 1.2+.
- `502` responses from VeilGate indicate upstream connectivity failure, not
  VeilGate internal errors.

### Validation

```bash
curl -i http://localhost:8080/
# Expected in observe mode: upstream app response
```

## `detector.trusted_proxies`

Syntax:  `trusted_proxies: ["<ip-or-cidr>", ...]`  
Default: `[]`  
Context: `detector`

Defines which direct peer addresses are allowed to supply trusted
`X-Forwarded-For` information. If the direct TCP peer is not in this list,
VeilGate ignores `X-Forwarded-For` and uses the direct remote address.

This matters because scanner traffic often injects payloads into forwarded
headers. Blindly trusting `X-Forwarded-For` would let an attacker spoof
allowlisted IPs, create fake tracker keys, or poison detection state.

From the code comment in `internal/proxy/proxy.go`:

> `nuclei` and similar probes inject things like `${jndi:ldap://...}` or
> `<script>alert(1)</script>` into the header to test for Log4Shell / XSS in
> downstream logging. If we pipe that through as the clientID, (a) it corrupts
> tracker state, (b) an attacker can spoof themselves onto trusted_ips by
> writing e.g. `127.0.0.1` into the header.

`resolveClientIP()` walks the `X-Forwarded-For` chain right-to-left and
returns the right-most hop that is not itself a trusted proxy. Non-IP values
in the chain are silently ignored.

```go
// internal/proxy/proxy.go
for i := len(hops) - 1; i >= 0; i-- {
    parsed := net.ParseIP(strings.TrimSpace(hops[i]))
    if parsed == nil {
        continue // Non-IP junk in header. Ignore it entirely.
    }
    if !ipInAny(parsed, trustedProxies) {
        return h
    }
}
```

`ParseTrustedProxies()` accepts both exact IP addresses (converted to `/32`
or `/128` internally) and CIDR blocks. Unparseable entries are silently dropped.

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `resolveClientIP()`
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `ParseTrustedProxies()`
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) receives the resolved `clientID`

### Operational notes

- Add only proxies or load balancers you operate.
- Do not add broad public ranges or `0.0.0.0/0`.
- In multi-proxy chains, VeilGate walks right-to-left and selects the
  right-most untrusted valid IP.
- Verify this value after each infrastructure change that modifies the path
  between the internet and VeilGate.

### Validation

```bash
# Spoofed header should NOT become the client ID when peer is untrusted
curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:8080/

# Check the 'client' field in the structured log:
# {"level":"info","client":"<actual-peer-ip>",...}
```

## `detector.trusted_ips`

Syntax:  `trusted_ips: ["<client-id>", ...]`  
Default: `[]`  
Context: `detector`

Defines client IDs that bypass scoring entirely. When matched, the scorer
returns score `0` with a single `trusted_ip` signal and does not evaluate
any other detector signals. The proxy routes the request to `real` (or
`observe` in observe mode).

```go
// internal/detector/scorer.go
if _, ok := s.trustedIPs[clientID]; ok {
    return Score{Total: 0, Signals: []Signal{{
        Name: "trusted_ip", Points: 0, Reason: "allowlisted",
    }}}
}
```

Blank entries in the YAML list (`- ""`) are silently filtered at construction
time so an accidental empty string does not allowlist all empty-identity
requests.

### Code path

- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `Score()`
- [`internal/config/config.go`](../../internal/config/config.go)

### Operational notes

- Use only for internal health checks or known monitoring systems.
- Do not add `127.0.0.1` during smoke tests unless you intend to bypass scoring
  for all loopback traffic.
- A trusted IP is a total bypass, not a point reduction. It skips the entire
  signal evaluation pipeline.

### Validation

```bash
curl http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep 'signal="trusted_ip"'
```

## `/_g/verify` Bypass

Syntax:  internal path handling  
Default: always active when `challengeHandler != nil`  
Context: runtime

The verify endpoint receives proof-of-work solutions from the challenge page.
It is passed directly to `challengeHandler.ServeHTTP()` before scoring.

```go
// internal/proxy/proxy.go
if s.challengeHandler != nil && r.URL.Path == "/_g/verify" {
    s.challengeHandler.ServeHTTP(w, r)
    return
}
```

The path is configured in `rules/challenge.yaml → verify_path`. The default
`/_g/verify` avoids colliding with typical application routes.

### Operational notes

- Do not route this path to the upstream application; it is consumed by the
  challenge handler.
- Keep the path stable if clients or SPAs cache the verify URL.

## Verifier and Challenge Token Bypass

After the initial decision is selected, the proxy checks verifiers and
challenge tokens for non-tarpit decisions:

```go
// internal/proxy/proxy.go
if decision != DecisionTarpit {
    if s.verifiers != nil {
        if res := s.verifiers.Verify(r); res.Accepted {
            decision = DecisionReal
        }
    }
    if !passed && s.challengeHandler != nil && s.challengeHandler.Passed(r) {
        decision = DecisionReal
    }
}
```

**Key invariant:** tarpit decisions are intentionally not bypassed by verifiers
or challenge tokens. A valid HMAC signature or solved challenge cookie can only
upgrade `challenge` to `real`. It cannot upgrade `tarpit` to `real`. This
prevents a leaked verifier secret or stolen challenge cookie from providing a
full bypass against high-confidence attack-tier behavior.

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `serve()`
- [`internal/verifier/verifier.go`](../../internal/verifier/verifier.go) → `Chain.Verify()`
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) → `Handler.Passed()`

## Request Logging

Every request is logged using structured zerolog JSON at a level that reflects
the routing decision — `tarpit → error`, `challenge → warn`,
`real / observe → info`. In SigNoz and Grafana this maps to red / yellow / blue.

Every log line also carries a `threat_level` field (`low` / `medium` / `high` /
`critical`) derived from the score range (0–29 / 30–59 / 60–79 / 80–100).

```json
{
  "level": "error",
  "client": "203.0.113.10",
  "method": "GET",
  "path": "/.git/config",
  "score": 85,
  "decision": "tarpit",
  "threat_level": "critical",
  "signals": [
    {"Name":"honeypot_hit","Points":50,"Reason":"requested path in honeypot list"},
    {"Name":"suspicious_ua","Points":35,"Reason":"UA matched suspicious substring"}
  ]
}
```

The `signals` field is a JSON array of all fired signals with name, points, and
reason. Use it to diagnose false positives and understand score composition.

When `telemetry.logs.enabled: true`, each log line is also forwarded to the
OTLP backend as a structured `LogRecord` with the same severity mapping. The
`OTelLogWriter` bridge (`internal/telemetry/otel_logbridge.go`) handles the
zerolog-JSON → OTel-LogRecord conversion.

## Status Recorder

After writing a response, the proxy feeds the HTTP status code back into the
tracker for the `failure_recovery` signal:

```go
// internal/proxy/proxy.go
rec := &statusRecorder{ResponseWriter: w}
// ... handler writes response ...
if s.tracker != nil && rec.status > 0 {
    s.tracker.RecordStatus(clientID, rec.status, r.URL.Path, r.Method)
}
```

`statusRecorder` wraps `http.ResponseWriter` to capture the first call to
`WriteHeader()`. This is required because Go's stdlib does not expose the status
after a response is written.

## Runtime Decision Labels

Syntax:  internal decision label  
Default: selected per request  
Context: runtime

VeilGate uses four decision labels, visible in logs, metrics (`decision` label),
capture records, persistence records, and dashboard events:

| Decision | Handler | Mode condition |
| --- | --- | --- |
| `real` | `httputil.ReverseProxy` to upstream | Below challenge threshold, or bypass accepted |
| `observe` | `httputil.ReverseProxy` to upstream | Any score when `mode: "observe"` |
| `challenge` | `challenge.Handler` | Score ≥ challenge threshold in `challenge`/`tarpit`/`auto` |
| `tarpit` | `tarpit.Handler` | Score ≥ tarpit threshold in `tarpit`/`auto` |

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `decide()` (mode + threshold logic)
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `serve()` (handler dispatch)
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) → `Decision.String()` (label serialization)

### Validation

```bash
# Observe distribution
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total

# Prometheus: rate by decision
# sum by (decision) (rate(veilgate_requests_total[5m]))
```

## Telemetry Emitted by the Proxy

After each request, `serve()` emits a `KindRequest` event to `DefaultBus`,
which fans it to all registered sinks (Prometheus, OTelSink, dashboard) without
blocking the hot path. Both Prometheus and OTel instruments are updated from the
same event.

| Telemetry | Mechanism |
| --- | --- |
| `veilgate_requests_total` / `veilgate.requests.total` | `DefaultBus.Emit(KindRequest)` |
| `veilgate_score` / `veilgate.score` histogram | same event |
| `veilgate_signal_hits_total` / `veilgate.signal.hits.total` | per fired signal |
| `veilgate_request_duration_seconds` / `veilgate.request.duration` | same event |
| Endpoint correlation counters | same event (4 metrics per request) |
| Structured log record (OTel) | `OTelLogWriter` bridge — zerolog line → OTLP `LogRecord` |
| OTel trace span | `telemetry.Tracer` — `veilgate.serve` span |
| Dashboard event | `telemetry.Dashboard.Record()` |
| JSONL capture | `telemetry.Capture.Write()` (when enabled) |
| SQLite persistence | `persist.Store.Record()` (when enabled) |

See [Module veilgate_metrics](veilgate_metrics.md) for the full metric catalogue.

## Limitations

VeilGate is not a general-purpose reverse proxy. It forwards accepted traffic
to one upstream and selects deception handlers by score. It does not support:

- Multiple upstream targets or virtual hosts.
- Static file serving.
- Path-based routing to different backends.
- Request transformation beyond `Host` rewriting.
- Active upstream health checks.

Use NGINX, Envoy, or a load balancer for complex routing requirements upstream
of or downstream from VeilGate.

## Related

- [Module veilgate_core](veilgate_core.md)
- [Module veilgate_detector](veilgate_detector.md)
- [Module veilgate_verifier](veilgate_verifier.md)
- [Decision Flow](../internals/decision_flow.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
