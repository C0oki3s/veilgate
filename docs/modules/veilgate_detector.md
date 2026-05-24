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
  probe_paths:
    - "/.git/config"
    - "/.env.backup"
```

## Directives

- `score_challenge_threshold`
- `score_tarpit_threshold`
- `window_seconds`
- `probe_paths`
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

## `probe_paths`

Syntax:  `probe_paths: ["<path>", ...]`  
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

All signals are evaluated by `detector.Scorer.Score()` in
[`internal/detector/scorer.go`](../../internal/detector/scorer.go) and are
additive. The total is capped at `100` after summation.

| Group | Signals | Stateful |
| --- | --- | --- |
| Request shape | `sparse_headers`, `suspicious_ua` | no |
| Browser consistency | `ae_browser_empty`, `ae_browser_no_br`, `sec_fetch_absent`, `sec_fetch_incoherent`, `h3_mismatch` | no |
| Path and payload | `honeypot_hit`, `wordlist_path`, `injection_marker`, `oob_interaction` | `honeypot_hit` only |
| Network identity | `ip_reputation`, `ip_rotation_fleet`, `ua_rotation` | `ip_rotation_fleet`, `ua_rotation` |
| Stateful behavior | `regular_timing`, `path_bruteforce`, `fanout_high`, `cookie_stateless`, `request_graph_topology`, `failure_recovery`, `toolchain_sequence`, `toolchain_hmm` | yes (all) |
| Protocol fingerprint | `tls_agent`, `tls_bot`, `h2_agent`, `h2_bot`, `h2_non_browser` | no |
| Deception feedback | `canary_replay` | yes |
| ML | `ml_agent_score` | yes (weak-label training) |

### Request shape signals

**`sparse_headers`** — fired by `scoreHeaders(r)`

Counts how many browser-typical headers (`Accept-Language`, `Accept-Encoding`,
`Sec-Fetch-Site`, `Sec-Fetch-Mode`) the request is missing. Point value is
tier-based from `rules/detector.yaml → browser_headers.tiers`.

Suppressed when: the UA looks like a real browser token (`Chrome/`, `Firefox/`,
`Safari/`, `Edg/`) **and** at least one expected header is present. This
prevents false positives on browser subresource fetches. `HeadlessChrome` is
explicitly excluded from suppression.

**`suspicious_ua`** — fired by `scoreUserAgent(r)`

Case-insensitive substring match against `rules/detector.yaml →
suspicious_user_agents.substrings`. First match wins. Default point value: `35`.
Includes HTTP library identifiers, scanner frameworks, and LLM agent strings.

### Browser consistency signals

**`sec_fetch_absent`** — fired by `scoreSecFetch(r)`

All three `Sec-Fetch-*` headers (`Sec-Fetch-Site`, `Sec-Fetch-Mode`,
`Sec-Fetch-Dest`) are missing from a request whose User-Agent claims to be a
real browser.

**`sec_fetch_incoherent`** — fired by `scoreSecFetch(r)`

`Sec-Fetch-*` values are present but internally inconsistent.

**`ae_browser_empty`** — fired by `scoreAcceptEncoding(r)`

`Accept-Encoding` header is completely absent.

**`ae_browser_no_br`** — fired by `scoreAcceptEncoding(r)`

`Accept-Encoding` is present but does not include `br` (Brotli), while the UA
claims to be a real browser. All major desktop browsers advertise Brotli support.

**`h3_mismatch`** — fired by `scoreH3Mismatch(r)`

Client received an HTTP/3 upgrade offer but connected over HTTP/1.1 or HTTP/2.
Set when `X-Veilgate-H3-Expected` is present in the request from an upstream
component.

### Path and payload signals

**`honeypot_hit`** — fired by honeypot path check in `Score()`

First hit: `+50`. Repeated hits from the same client: `+80`. These are the
highest-confidence single signals in the system; a single hit nearly always
crosses `score_challenge_threshold`. The per-client hit counter is stored in
`ClientState.HoneypotHits`.

```go
// internal/detector/scorer.go
if _, hit := s.honeypotPaths[r.URL.Path]; hit {
    state.HoneypotHits++
    hits := state.HoneypotHits
    points := 50
    if hits > 1 { points = 80 }
}
```

**`wordlist_path`** — fired by `scoreWordlistPath(r)`

Request path matches a known scanner wordlist entry from `rules/detector.yaml
→ wordlist_paths`. Examples: `/backup.zip`, `/.htpasswd`, `/server-status`.

**`injection_marker`** — fired by `scoreInjection(r)`

Path or query string contains SQL injection, XSS, or command injection
substrings from `rules/detector.yaml → injection_markers`. This is a scoring
signal, not a WAF parser; it does not block or sanitize.

**`oob_interaction`** — fired by `scoreOOB(r)`

Path or query contains an out-of-band callback indicator: Burp Collaborator
hostnames, `interact.sh` URLs, SSRF probe patterns.

### Network identity signals

**`ip_reputation`** — fired by `scoreIPReputation(clientID)`

Client IP matches a CIDR in a named category from `rules/ip_reputation.yaml`:
`tor`, `cloud`, `vpn`, `proxy`. Point value is per-category. The reason string
encodes the category for metric labeling.

**`ip_rotation_fleet`** — fired by `scoreFleetRotation(clientID, r, ja4)`

Many distinct client IPs have used the same behavioral fingerprint
`(ua, path-pattern, ja4)` within `fleet_rotation.window_seconds`. Tier-based
scoring: `low`, `mid`, `high` based on distinct IP count thresholds from
`rules/ip_reputation.yaml → fleet_rotation.tiers`.

**`ua_rotation`** — fired by `scoreUARotation(state)`

Single client IP has cycled through more distinct User-Agent strings than the
configured threshold within the rolling window. Tracked in
`ClientState.UniqueUAs`.

### Stateful behavior signals

All of the following require multiple requests from the same client within
`window_seconds`. They use data from `ClientState.Events` maintained by
`internal/detector.Tracker`.

**`regular_timing`** — fired by `scoreTiming(events)`

Inter-request interval coefficient of variation (CV) falls below the configured
threshold, indicating mechanically regular request cadence.

**`path_bruteforce`** — fired by `scorePathBruteforce(events)`

Client has requested more than the configured threshold of distinct paths
within the window. Captures directory enumeration behavior.

**`fanout_high`** — fired by `scoreFanout(state)`

High diversity of distinct path prefixes within the window.

**`cookie_stateless`** — fired by `scoreCookieEcology(state)`

`CookiesSent / RequestsTotal` ratio falls below threshold after a `Set-Cookie`
has been sent by upstream. Stateless library clients do not carry cookies back.

**`request_graph_topology`** — fired by `scoreRequestGraph(state)`

`SubresourceFetches / DocumentFetches` ratio is too low, indicating a flat
list of independent requests rather than tree-shaped browser navigation.
`Sec-Fetch-Dest` is used to classify each request type.

**`failure_recovery`** — fired by `scoreFailureRecovery(state, r)`

Client received a `4xx` or `5xx` response and retried with a different path
or method. Real users retry the same resource with credentials; agents pivot
to different paths after errors.

```go
// internal/proxy/proxy.go
if s.tracker != nil && rec.status > 0 {
    s.tracker.RecordStatus(clientID, rec.status, r.URL.Path, r.Method)
}
```

**`toolchain_sequence`** — fired by `scoreToolchain(events)`

Sequence of `ToolStage` values (`recon`, `probe`, `exploit`) follows a
recognizable tool-pipeline pattern within the window.

**`toolchain_hmm`** — fired by `scoreToolchainHMM(events)`

Full stage-sequence probability under a model of human browsing is
sufficiently low.

### Protocol fingerprint signals

**`tls_agent` / `tls_bot`** — fired by `scoreTLS(r.RemoteAddr)`

Requires `tls.enabled: true`. VeilGate peeks at the TLS ClientHello before
Go's TLS stack consumes the connection. The fingerprint is classified against
`rules/tls_fingerprints.yaml`. Exact and prefix matches produce different
labels.

Code path:
- `internal/tlsfp` — ClientHello parsing and fingerprint storage
- `internal/detector/tls.go` — `TLSLookup` interface

**`h2_agent` / `h2_bot` / `h2_non_browser`** — fired by `scoreH2(r.RemoteAddr)`

HTTP/2 SETTINGS frame fingerprint is classified against known non-browser
profiles. Requires the `h2fp.Classifier` to be wired via `Scorer.SetH2Lookup()`.

Code path:
- `internal/h2fp` — SETTINGS fingerprint store

### Deception feedback signals

**`canary_replay`** — fired by `scoreCanaryReplay(clientID, r)`

A canary token previously issued by the tarpit appears in a subsequent request.
This is the strongest cross-request signal: it proves the client processed and
acted on tarpit content.

Requires: `persist.enabled: true` and `persist.Store` wired as `CanaryLookup`.

```go
// internal/detector/scorer.go
type CanaryLookup interface {
    HitCanary(token, clientID string) (origClientID string, hit bool)
}
```

### ML signal

**`ml_agent_score`** — fired by `mlScorer.Score(vec)`

Optional online ML signal from `internal/ml`. Adds up to `rules/ml.yaml →
score_max_points` (default: `40`). The model is trained via weak labels derived
from the deterministic rule-based score. ML is not the primary enforcement
engine; treat it as a supporting signal.

## Score Summation

```go
// internal/detector/scorer.go
total := 0
for _, sig := range result.Signals {
    total += sig.Points
}
if total > 100 {
    total = 100
}
```

Scores are additive. The cap at `100` means a single very high-confidence
signal does not prevent other signals from being evaluated or recorded —
all firing signals appear in the log and metrics even when the total is capped.

## Signal Metrics

Every signal that fires is counted in Prometheus:

```promql
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[15m])))
```

Use this to identify which signals drive most of your decisions and to
distinguish false-positive-generating signals from legitimate bot signals.

## Related

- [Detector Signal Flow](../internals/detector_signal_flow.md)
- [Module veilgate_http2_fingerprinting](veilgate_http2_fingerprinting.md)
- [Module veilgate_rules](veilgate_rules.md)
- [Module veilgate_ml](veilgate_ml.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [`rules/detector.yaml`](../config/rules/detector.md)
- [`rules/ip_reputation.yaml`](../config/rules/ip-reputation.md)
