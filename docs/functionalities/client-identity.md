# Module veilgate_proxy

The `veilgate_proxy` module documents how VeilGate acts as a reverse proxy,
resolves client identity, applies decisions, and protects detector state from
spoofed forwarded headers.

The proxy module is implemented primarily by `internal/proxy.Server`.

## Example Configuration

```yaml
listen: ":8080"
upstream: "http://127.0.0.1:3000"
mode: "auto"

detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70
  trusted_ips: []
  trusted_proxies:
    - "10.0.0.0/8"
```

## Directives

- `upstream`
- `detector.trusted_ips`
- `detector.trusted_proxies`
- runtime decisions: `real`, `observe`, `challenge`, `tarpit`

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

### Code path

- [`internal/proxy/proxy.go#L390`](../../internal/proxy/proxy.go#L390) resolves the effective client ID.
- [`internal/proxy/proxy.go#L435`](../../internal/proxy/proxy.go#L435) parses trusted proxy IPs and CIDRs.
- [`internal/detector/scorer.go#L177`](../../internal/detector/scorer.go#L177) receives the resolved `clientID`.

### Operational notes

- Add only proxies or load balancers you operate.
- Do not add broad public ranges.
- In multi-proxy chains, VeilGate walks right-to-left and selects the
  right-most untrusted valid IP.

### Validation

```bash
curl -H "X-Forwarded-For: 127.0.0.1" http://localhost:8080/
```

If the direct peer is not trusted, this spoofed header should not become the
client identity.

## `detector.trusted_ips`

Syntax:  `trusted_ips: ["<client-id>", ...]`  
Default: `[]`  
Context: `detector`

Defines client IDs that bypass scoring. When matched, the scorer returns score
`0` with a `trusted_ip` signal and does not evaluate other detector signals.

### Code path

- [`internal/detector/scorer.go`](../../internal/detector/scorer.go)
- [`internal/config/config.go`](../../internal/config/config.go)

### Operational notes

- Use only for internal health checks or known monitoring.
- Avoid adding `127.0.0.1` during local scanner tests, because local test
  traffic would bypass scoring.
- This is a full scoring bypass, not a point reduction.

### Validation

```bash
curl http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep veilgate_signal_hits_total
```

## Runtime Decision Labels

Syntax:  internal decision label  
Default: selected per request  
Context: runtime

VeilGate uses four decision labels:

| Decision | Meaning |
| --- | --- |
| `real` | Request is proxied to the configured upstream. |
| `observe` | Request is proxied upstream, but recorded as observe. |
| `challenge` | Request is handled by the challenge handler. |
| `tarpit` | Request is handled by the tarpit handler. |

These labels appear in logs, metrics, capture records, persistence records, and
dashboard events.

### Code path

- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go)
- `Decision.String()`
- `Server.decide()`
- `Server.serve()`

### Operational notes

- Use `sum by (decision) (rate(veilgate_requests_total[5m]))` to monitor final
  routing behavior.
- In `observe` mode, high scores still appear in metrics and persistence but
  do not divert traffic.

### Validation

```bash
curl http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

## Limitations

VeilGate is not a general-purpose NGINX replacement. It forwards accepted
traffic to one upstream and selects deception handlers by score. Use NGINX,
Envoy, or a load balancer for complex virtual host and static file routing.

## Related

- [Module veilgate_core](../modules/veilgate_core.md)
- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_verifier](../modules/veilgate_verifier.md)

