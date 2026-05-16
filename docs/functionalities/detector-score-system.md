# Module veilgate_detector

The `veilgate_detector` module calculates a score for each request using
request shape, path and payload indicators, network reputation, protocol
fingerprints, rolling client history, deception feedback, and optional ML.

The score is additive and capped at `100`. The proxy uses that score with
`mode`, `detector.score_challenge_threshold`, and
`detector.score_tarpit_threshold`.

## Example Configuration

```yaml
detector:
  score_challenge_threshold: 40
  score_tarpit_threshold: 70
  window_seconds: 90
  trusted_ips: []
  trusted_proxies: []
  honeypot_paths:
    - "/.git/config"
    - "/.env.backup"
```

## Directives

- `score_challenge_threshold`
- `score_tarpit_threshold`
- `window_seconds`
- `honeypot_paths`
- `trusted_ips`
- `trusted_proxies`

## `score_challenge_threshold`

Syntax:  `score_challenge_threshold: <integer>`  
Default: `40`  
Context: `detector`

Defines the minimum detector score at which VeilGate may serve the
proof-of-work challenge. In `challenge`, `tarpit`, and `auto` modes, requests
at or above this value can be diverted away from the upstream.

### Code path

- [`internal/detector/scorer.go#L177`](../../internal/detector/scorer.go#L177) calculates score.
- [`internal/proxy/proxy.go#L346`](../../internal/proxy/proxy.go#L346) compares score to threshold.
- [`internal/challenge/challenge.go`](../../internal/challenge/challenge.go) serves the challenge.

### Operational notes

- Lower values increase challenge frequency.
- Higher values reduce friction but allow more automation through.
- Tune in `observe` mode before enforcement.

### Validation

```bash
curl -A "httpx/0.27.0" http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep veilgate_score
```

## `score_tarpit_threshold`

Syntax:  `score_tarpit_threshold: <integer>`  
Default: `70`  
Context: `detector`

Defines the minimum detector score at which VeilGate serves the tarpit handler.
Tarpit decisions are not bypassed by a valid challenge token or HMAC verifier.

### Code path

- [`internal/proxy/proxy.go#L346`](../../internal/proxy/proxy.go#L346)
- [`internal/proxy/proxy.go`](../../internal/proxy/proxy.go) applies the no-bypass rule for tarpit.
- [`internal/tarpit/handler.go`](../../internal/tarpit/handler.go)

### Operational notes

- Treat this as the high-confidence attack boundary.
- Avoid setting it too close to normal user scores.
- Review score histograms and top signals before enabling tarpit mode.

### Validation

```bash
curl -A "sqlmap/1.7" "http://localhost:8080/.git/config?id=1%20union%20select"
curl http://127.0.0.1:9090/metrics | grep 'decision="tarpit"'
```

## `window_seconds`

Syntax:  `window_seconds: <seconds>`  
Default: `90`  
Context: `detector`

Sets the rolling history window used by stateful signals. The tracker stores
recent requests per client and makes them available to timing, fanout,
toolchain, cookie, graph, UA rotation, and failure-recovery signals.

### Code path

- [`internal/detector/tracker.go`](../../internal/detector/tracker.go)
- [`cmd/veilgate/main.go`](../../cmd/veilgate/main.go) constructs the tracker.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) consumes tracker state.

### Operational notes

- Longer windows catch slower campaigns but retain more state.
- Shorter windows reduce memory use but may miss low-rate scanning.

### Validation

```bash
for i in 1 2 3 4 5; do curl -s http://localhost:8080/path-$i >/dev/null; done
curl http://127.0.0.1:9090/metrics | grep veilgate_tracked_clients
```

## `honeypot_paths`

Syntax:  `honeypot_paths: ["<path>", ...]`  
Default: built-in starter list if omitted  
Context: `detector`

Defines paths that should not receive legitimate traffic. A hit adds a strong
signal because normal users should not request those routes.

### Code path

- [`internal/config/config.go`](../../internal/config/config.go) supplies default paths.
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) scores hits.
- [`configs/veilgate.yaml`](../../configs/veilgate.yaml) contains sample paths.

### Operational notes

- Do not include real application paths.
- Add paths that scanners commonly try but your app will never serve.
- A mistaken honeypot path can create false positives.

### Validation

```bash
curl http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep honeypot
```

## Signal Groups

Signals include:

| Group | Examples |
| --- | --- |
| Header shape | `sparse_headers`, `empty_ua`, `suspicious_ua` |
| Browser consistency | `ae_browser_empty`, `ae_browser_no_br`, `sec_fetch_absent` |
| Path and payload | `honeypot_hit`, `wordlist_path`, `injection_marker`, `oob_interaction` |
| Stateful behavior | `regular_timing`, `path_bruteforce`, `fanout_high`, `cookie_stateless` |
| Protocol | `tls_agent`, `h2_agent`, `h3_mismatch` |
| Deception feedback | `canary_replay` |
| ML | `ml_agent_score` |

## Related

- [Module veilgate_rules](../modules/veilgate_rules.md)
- [Module veilgate_ml](../modules/veilgate_ml.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)

