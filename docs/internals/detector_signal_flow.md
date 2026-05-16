# Detector Signal Flow

This page maps every detector signal to its implementation in
`internal/detector/scorer.go`, its default weight, the rule file that controls
it, and the conditions under which it fires.

The detector is purely additive. `Scorer.Score()` evaluates all applicable
signals, sums their `Points` fields, and clamps the total at `100`.
No single signal can push the total above `100`; the cap is enforced after
summation.

## Entry Point

```
internal/proxy.Server.serve()
  └─ detector.Scorer.Score(clientID, r)
       ├─ tracker.Record(clientID, evt)        → per-client ClientState
       ├─ honeypot check                        → honeypot_hit
       ├─ scoreHeaders(r)                       → sparse_headers
       ├─ scoreUserAgent(r)                     → suspicious_ua / empty_ua
       ├─ scoreTiming(events)                   → regular_timing
       ├─ scoreToolchain(events)                → toolchain_sequence
       ├─ scorePathBruteforce(events)           → path_bruteforce
       ├─ scoreWordlistPath(r)                  → wordlist_path
       ├─ scoreInjection(r)                     → injection_marker
       ├─ scoreOOB(r)                           → oob_interaction
       ├─ scoreIPReputation(clientID)           → ip_reputation
       ├─ scoreFleetRotation(clientID, r, ja4)  → ip_rotation_fleet
       ├─ scoreUARotation(state)                → ua_rotation
       ├─ scoreTLS(r.RemoteAddr)                → tls_agent / tls_bot
       ├─ scoreH2(r.RemoteAddr)                 → h2_agent / h2_bot / h2_non_browser
       ├─ scoreSecFetch(r)                      → sec_fetch_absent / sec_fetch_incoherent
       ├─ scoreAcceptEncoding(r)                → ae_browser_empty / ae_browser_no_br
       ├─ scoreH3Mismatch(r)                    → h3_mismatch
       ├─ scoreRequestGraph(state)              → request_graph_topology
       ├─ scoreCookieEcology(state)             → cookie_stateless
       ├─ scoreFanout(state)                    → fanout_high
       ├─ scoreFailureRecovery(state, r)        → failure_recovery
       ├─ scoreToolchainHMM(events)             → toolchain_hmm
       ├─ scoreCanaryReplay(clientID, r)        → canary_replay
       └─ ML signal (mlScorer.Score(vec))       → ml_agent_score
```

Code reference: [`internal/detector/scorer.go`](../../internal/detector/scorer.go)

---

## Signals Reference

### `honeypot_hit`

**Group:** Deception / Path  
**Default points:** `50` (first hit), `80` (repeated hits)  
**Rule source:** `detector.honeypot_paths` in `veilgate.yaml`  
**Stateful:** yes — `ClientState.HoneypotHits` accumulates

VeilGate maintains a set of path strings that no legitimate user should ever
request. When the request path matches any entry in the set, `honeypot_hit`
fires. A first hit adds 50 points. A second or later hit from the same client
adds 80 points. Both values may push the score over `score_tarpit_threshold`
on their own.

The per-client counter `HoneypotHits` is incremented under `ClientState.mu`
before the points are assigned. This is the only stateful write that happens
directly inside `Score()` rather than inside the tracker.

```go
// internal/detector/scorer.go
if _, hit := s.honeypotPaths[r.URL.Path]; hit {
    state.HoneypotHits++
    hits := state.HoneypotHits
    points := 50
    if hits > 1 { points = 80 }
    ...
}
```

**Operational notes:**

- Do not include real application routes in `honeypot_paths`.
- Add paths that scanners try automatically: `/.git/config`, `/.env.backup`,
  `/wp-admin/`, `/phpmyadmin/`, `/actuator/env`.
- A single honeypot hit alone typically crosses `score_challenge_threshold`.
- Two hits from the same client typically crosses `score_tarpit_threshold`.

**Validation:**

```bash
curl -A "Mozilla/5.0" http://localhost:8080/.git/config
curl http://127.0.0.1:9090/metrics | grep 'signal="honeypot_hit"'
```

---

### `sparse_headers`

**Group:** Request shape  
**Default points:** tier-based, see `rules/detector.yaml → browser_headers`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** no

Counts how many "browser-typical" headers the request is missing. The
`browser_headers.hints` list defines which headers are expected. Tiers in
`browser_headers.tiers` map `missing >= N` to a points value.

```yaml
# rules/detector.yaml (example)
browser_headers:
  hints:
    - Accept-Language
    - Accept-Encoding
    - Sec-Fetch-Site
    - Sec-Fetch-Mode
  tiers:
    - missing: 3
      points: 14
    - missing: 2
      points: 7
```

**Special case:** if the request has at least one hint present *and* the
User-Agent looks like a real browser (`Chrome/`, `Firefox/`, `Safari/`, `Edg/`,
`Edge/`, `Opera/`), the signal is suppressed. This prevents false positives
from subresource fetches (CSS, JS, images) which legitimately omit some
headers. `HeadlessChrome` is explicitly excluded from this suppression.

```go
// internal/detector/scorer.go
if present > 0 && looksLikeBrowserUA(r.UserAgent()) {
    return Signal{}
}
```

**Operational notes:**

- Tune tier thresholds if edge browsers or API clients with valid business
  justification are being challenged.
- View which signals fire on a sample request with the structured log output.

---

### `suspicious_ua`

**Group:** Request shape  
**Default points:** `35`  
**Rule source:** `rules/detector.yaml → suspicious_user_agents.substrings`  
**Stateful:** no

Case-insensitive substring scan of the `User-Agent` header against an
operator-configurable list. The first matching substring wins and returns the
configured `points` value.

Shipped defaults include HTTP library identifiers (`python-requests`,
`python-httpx`, `aiohttp`, `go-http-client`, `okhttp`, `curl/`), scanner
frameworks (`sqlmap`, `nuclei`, `nikto`), exploit tools, and LLM agent
identifiers.

**Empty UA** is a separate sub-case: when `User-Agent` is absent, the scorer
returns `empty_ua` instead, which typically has a different configured weight.

**Operational notes:**

- Add tool strings as you observe them in production traffic.
- Do not add tokens so broad they match real browser UA substrings.
- Agent-specific identifiers (`pentestgpt`, `strix`) are high-confidence;
  library identifiers (`curl/`) can generate false positives in API-heavy
  environments.

---

### `regular_timing`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml → timing`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — uses `ClientState.Events` timestamps

Measures the coefficient of variation (CV) of inter-request timing over the
rolling window. Automated tools issue requests at mechanically regular
intervals. Human browsing exhibits variance.

When CV falls below a configured threshold (indicating very regular timing),
the signal fires. The implementation uses the request timestamps stored in
`ClientState.Events` and requires at least a minimum number of events before
evaluating.

**Operational notes:**

- This signal requires multiple requests from the same client in the window.
- Fast CDN-cached sites may never show enough requests per client to fire this.
- High-volume APIs are better targets for this signal than content sites.

---

### `toolchain_sequence`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml → toolchain`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — uses `ClientState.Events` with `ToolStage`

Each request is classified as `recon`, `probe`, `exploit`, or empty based on
path patterns from `rules/detector.yaml`. The stage string is stored as
`ClientEvent.ToolStage`. When the scorer observes a sequence such as
`recon → probe → exploit` within the window, `toolchain_sequence` fires.

This mimics a simplified HMM over tool behavior stages. Many automated
vulnerability assessment workflows follow a predictable recon → probe →
exploit pattern.

```go
// ClientEvent.ToolStage is set by classifyToolStage() during Record()
evt := ClientEvent{
    ToolStage: classifyToolStage(r, s.rules),
    ...
}
```

---

### `toolchain_hmm`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — uses `ClientState.Events` stage sequence

A more refined version of `toolchain_sequence`. Evaluates the full sequence of
`ToolStage` values in the event window and scores it against expected
tool-pipeline patterns. If the sequence probability under the model is
sufficiently low for human browsing, the signal fires.

**Code path:**

- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreToolchainHMM(events)`

---

### `path_bruteforce`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml → path_bruteforce`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — distinct path count per client window

Counts the number of distinct paths a client has requested in the rolling
window. When the count exceeds the configured threshold, `path_bruteforce`
fires. This captures wordlist-based directory enumeration where the same
client requests many different paths in rapid succession.

**Operational notes:**

- Tune the distinct-path threshold against your site's typical browser
  exploration depth.
- A site with many AJAX sub-paths may need a higher threshold to avoid false
  positives on normal SPA navigation.

**Validation:**

```bash
for i in $(seq 1 30); do curl -s "http://localhost:8080/path-$i" > /dev/null; done
curl http://127.0.0.1:9090/metrics | grep 'signal="path_bruteforce"'
```

---

### `wordlist_path`

**Group:** Path and payload  
**Default points:** configured in `rules/detector.yaml → wordlist_paths`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** no

Compares the request path against a list of known scanner wordlist paths. These
are paths that automated tools enumerate but legitimate users never request,
such as `/backup.zip`, `/config.bak`, `/admin/config.php`, `/.htpasswd`,
`/server-status`.

Unlike `honeypot_hit`, these paths are matched from a larger static list rather
than an operator-defined deception path. Both signals can fire on the same
request.

---

### `injection_marker`

**Group:** Path and payload  
**Default points:** configured in `rules/detector.yaml → injection_markers`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** no

Scans the request path and query string for SQL injection, cross-site scripting,
and command injection marker substrings. Examples: `' OR 1=1`, `<script>`,
`UNION SELECT`, `../`, `${jndi:`.

This is a scoring signal, not a full WAF parser. It does not attempt to
block or sanitize. It adds points when patterns are detected, contributing to
the total score alongside other signals.

**Important limitation:** VeilGate does not parse complex injection payloads
the way a dedicated WAF does. This signal is designed to add evidence to the
score, not to catch every injection variant.

---

### `oob_interaction`

**Group:** Path and payload  
**Default points:** configured in `rules/detector.yaml → oob_interaction`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** no

Detects out-of-band callback indicators in request paths and query strings:
Burp Collaborator-style hostnames, `interact.sh` URLs, SSRF probe patterns,
and similar. When found, the signal fires with high confidence because
legitimate users do not include external callback URLs in their requests.

---

### `ip_reputation`

**Group:** Network identity  
**Default points:** varies by category, from `rules/ip_reputation.yaml`  
**Rule source:** `rules/ip_reputation.yaml`  
**Stateful:** no

Classifies the resolved client IP against CIDR lists in
`rules/ip_reputation.yaml`. Categories typically include:

| Category | Examples |
| --- | --- |
| `tor` | Tor exit node CIDRs |
| `cloud` | AWS, GCP, Azure, DigitalOcean egress ranges |
| `vpn` | Commercial VPN provider egress ranges |
| `proxy` | Open proxy / anonymizer CIDRs |

When the client IP falls inside a known category CIDR, `ip_reputation` fires
with the configured points for that category. The reason string encodes the
category: `"client IP matches <category> CIDR list"`.

The proxy extracts the category from the reason string using
`extractIPRepCategory()` to populate the `veilgate_ip_reputation_hits_total`
metric label.

```go
// internal/proxy/proxy.go
if cat := extractIPRepCategory(sig.Reason); cat != "" {
    telemetry.IPReputationHits.WithLabelValues(cat).Inc()
}
```

**Code path:**

- [`internal/rules/ip_reputation.go`](../../internal/rules/ip_reputation.go) — CIDR classification
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreIPReputation()`

**Operational notes:**

- CIDR lists in `rules/ip_reputation.yaml` must be maintained by the operator.
- Cloud egress ranges change over time; refresh periodically.
- A false positive on a cloud IP may indicate a legitimate cloud-based user.

---

### `ip_rotation_fleet`

**Group:** Network identity  
**Default points:** tier-based (low/mid/high), from `rules/ip_reputation.yaml`  
**Rule source:** `rules/ip_reputation.yaml → fleet_rotation`  
**Stateful:** yes — `FleetTracker` per behavioral fingerprint

Fleet rotation detection identifies coordinated scanning from many IP addresses
sharing the same behavioral fingerprint. The `FleetTracker` maps
`(ua, path-pattern, ja4)` tuples to the set of distinct client IPs that have
used that fingerprint inside a rolling time window.

When the distinct-IP count for a fingerprint exceeds the configured tier
thresholds, requests carrying that fingerprint are scored by tier:

```yaml
# rules/ip_reputation.yaml
fleet_rotation:
  window_seconds: 600
  max_fingerprints: 20000
  tiers:
    - distinct_ips: 10
      points: 15
      label: low
    - distinct_ips: 25
      points: 25
      label: mid
    - distinct_ips: 50
      points: 40
      label: high
```

```go
// internal/detector/scorer.go
if sig, fp, distinct := s.scoreFleetRotation(clientID, r, extractJA4(r)); sig.Points > 0 {
    result.Signals = append(result.Signals, sig)
}
```

The proxy records `veilgate_fleet_rotation_fires_total{tier=...}` and
`veilgate_public_ip_rotation_events_total` when this signal fires on a public IP.

**Operational notes:**

- Useful for detecting credential-stuffing campaigns and distributed scanners
  that rotate source IPs.
- Window and tier thresholds should be tuned against your normal public-IP
  request volume.

---

### `ua_rotation`

**Group:** Network identity  
**Default points:** configured in `rules/ip_reputation.yaml → ua_rotation`  
**Rule source:** `rules/ip_reputation.yaml`  
**Stateful:** yes — `ClientState.UniqueUAs`

Detects a single client IP rotating through many distinct User-Agent strings
within the rolling window. This is characteristic of tools like `dirsearch`
with the `-H` UA rotation flag or `ffuf` with a UA wordlist.

`ClientState.UniqueUAs` is a `map[string]time.Time` updated in the tracker.
When the cardinality exceeds the configured threshold, `ua_rotation` fires.

**Code path:**

- [`internal/detector/tracker.go`](../../internal/detector/tracker.go) — `UniqueUAs` map
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreUARotation(state)`

---

### `tls_agent` / `tls_bot`

**Group:** Protocol fingerprint  
**Default points:** configured in `rules/tls_fingerprints.yaml`  
**Rule source:** `rules/tls_fingerprints.yaml`  
**Stateful:** no  
**Requires:** `tls.enabled: true`

When VeilGate terminates TLS, `internal/tlsfp.Listener` peeks at the
ClientHello and computes JA3/JA4 fingerprints before the Go TLS stack
consumes the connection. The fingerprints are stored in a per-connection
map keyed by `RemoteAddr`.

`internal/detector.Scorer.scoreTLS()` looks up the fingerprint for
`r.RemoteAddr` and classifies it using `rules/tls_fingerprints.yaml`:

- **exact match:** a known bad fingerprint fires with its configured points.
- **prefix match:** fingerprints whose JA4 starts with a known non-browser
  prefix fire with prefix-level points.
- **not matched:** no signal.

A `tls_agent` label indicates a known HTTP library fingerprint. A `tls_bot`
label indicates a known scanner or automation tool fingerprint.

**Code path:**

- [`internal/tlsfp/ja4.go`](../../internal/tlsfp/ja4.go) — ClientHello parsing
- [`internal/tlsfp/database.go`](../../internal/tlsfp/database.go) — fingerprint storage
- [`internal/detector/tls.go`](../../internal/detector/tls.go) — `TLSLookup` interface
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreTLS()`

**Operational notes:**

- Signal requires VeilGate to hold the TLS private key.
- If TLS terminates before VeilGate (nginx, CDN, ALB), this signal does not
  fire. JA3/JA4 quality is lost at the VeilGate layer.
- The `X-Veilgate-JA4` header can carry a pre-computed JA4 from an edge
  component, but this is advisory and not used for the TLS fingerprint signal
  itself.

---

### `h2_agent` / `h2_bot` / `h2_non_browser`

**Group:** Protocol fingerprint  
**Default points:** configured in `rules/tls_fingerprints.yaml` (HTTP/2 section)  
**Rule source:** `rules/tls_fingerprints.yaml`  
**Stateful:** no  
**Requires:** HTTP/2 connection hook wired via `SetH2Lookup()`

When an HTTP/2 connection is established, the SETTINGS frame contains a
client-specific combination of values. VeilGate's `internal/h2fp.Classifier`
stores the SETTINGS fingerprint per `RemoteAddr`.

`Scorer.scoreH2()` looks up the fingerprint and classifies it using the same
`TLSLookup` interface. The signal fires when the fingerprint matches a known
non-browser profile.

**Code path:**

- [`internal/h2fp`](../../internal/h2fp) — HTTP/2 SETTINGS fingerprint store
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreH2()`
- `Scorer.SetH2Lookup()` — wiring in `cmd/veilgate/main.go`

---

### `sec_fetch_absent` / `sec_fetch_incoherent`

**Group:** Browser consistency  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** no

Modern browsers emit `Sec-Fetch-Site`, `Sec-Fetch-Mode`, and `Sec-Fetch-Dest`
headers on all requests. Library clients and simple HTTP tools typically do not.

The scorer checks:

- **absent:** all three `Sec-Fetch-*` headers missing from a request that
  claims to be a browser (UA contains `Chrome/`, `Firefox/`, etc.).
- **incoherent:** values that are internally inconsistent, e.g.,
  `Sec-Fetch-Mode: navigate` with `Sec-Fetch-Dest: empty`.

```go
// internal/detector/scorer.go
func (s *Scorer) scoreSecFetch(r *http.Request) Signal {
    ...
}
```

**Operational notes:**

- Legitimate subresource fetches (CSS, JS, images) may omit `Sec-Fetch-*`
  headers. The scorer combines this with the browser UA check to reduce false
  positives.

---

### `ae_browser_empty` / `ae_browser_no_br`

**Group:** Browser consistency  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** no

All major desktop browsers advertise `Accept-Encoding: gzip, deflate, br`
(Brotli support). Library clients commonly omit `br` or emit an empty
`Accept-Encoding`.

- **`ae_browser_empty`:** `Accept-Encoding` is absent entirely.
- **`ae_browser_no_br`:** `Accept-Encoding` is present but does not include
  `br`, while the `User-Agent` claims to be a real browser.

**Code path:**

- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreAcceptEncoding(r)`

---

### `h3_mismatch`

**Group:** Protocol fingerprint  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** no

When an edge component indicates that a client received an HTTP/3 upgrade offer
(via `Alt-Svc`) but the connection arrived over HTTP/1.1 or HTTP/2 instead of
HTTP/3, that mismatch is a signal. Real browsers upgrade opportunistically;
many library clients ignore or cannot process `Alt-Svc` headers.

The signal fires when `X-Veilgate-H3-Expected` is set by an upstream component
but the connection is not HTTP/3.

---

### `request_graph_topology`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — `ClientState.DocumentFetches`, `ClientState.SubresourceFetches`

Real browser sessions produce tree-shaped request graphs: an HTML document
fetch followed by many subresource fetches (images, scripts, stylesheets).
Automated tools tend to issue flat lists of independent document-level requests.

The scorer computes the ratio of `SubresourceFetches / DocumentFetches`. A low
ratio over a sufficient number of requests indicates library-like behavior.

`ClientEvent.SecFetchDest` is used to classify each request:
- `SecFetchDest == "document"` increments `DocumentFetches`.
- All other non-empty values increment `SubresourceFetches`.

**Code path:**

- [`internal/detector/tracker.go`](../../internal/detector/tracker.go) — `DocumentFetches`, `SubresourceFetches`
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreRequestGraph(state)`

---

### `cookie_stateless`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — `ClientState.CookiesSent`, `ClientState.RequestsTotal`

VeilGate tracks whether a client sends cookies on requests after the proxy (or
upstream) has set cookies. A legitimate browser carries cookies back on
subsequent requests. A stateless HTTP client that ignores `Set-Cookie` is
library-shaped.

The signal fires when the `CookiesSent / RequestsTotal` ratio falls below a
configured threshold after a sufficient number of requests.

**Code path:**

- [`internal/detector/tracker.go`](../../internal/detector/tracker.go) — `CookiesSent`, `RequestsTotal`, `HasCookie`
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreCookieEcology(state)`

---

### `fanout_high`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — distinct path count in window

Measures path diversity per client: the number of distinct path prefixes
(first two path segments) requested within the rolling window. High fanout
indicates broad enumeration rather than focused browsing.

This is related to `path_bruteforce` but focuses on path diversity rather
than raw count.

---

### `failure_recovery`

**Group:** Stateful behavior  
**Default points:** configured in `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — `ClientState.LastStatus`, `ClientState.LastNon200Path`, `ClientState.LastNon200Method`

Real users who receive a `401 Unauthorized` retry the same request with
credentials. LLM agents and automated tools that receive a `4xx` or `5xx`
often retry with a different path, method, or parameter set.

After the proxy writes a response, it calls `tracker.RecordStatus()` to update
`ClientState.LastStatus`, `LastNon200Path`, and `LastNon200Method`. On the
next request from the same client, the scorer compares the current request
shape to the last non-`2xx` response. A shape change (different path or method
after an error) fires `failure_recovery`.

```go
// internal/proxy/proxy.go — after response is written
if s.tracker != nil && rec.status > 0 {
    s.tracker.RecordStatus(clientID, rec.status, r.URL.Path, r.Method)
}
```

**Code path:**

- [`internal/detector/tracker.go`](../../internal/detector/tracker.go) → `RecordStatus()`
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreFailureRecovery(state, r)`

---

### `canary_replay`

**Group:** Deception feedback  
**Default points:** high, see `rules/detector.yaml`  
**Rule source:** `rules/detector.yaml`  
**Stateful:** yes — cross-request, requires `persist.Store` wired as `CanaryLookup`

This is the strongest cross-request signal available. When the tarpit serves
fake content, it can embed canary tokens (unique strings, fake credentials,
fabricated URLs). `internal/persist.Store` records these tokens keyed by client
ID when they are issued.

When a later request from any client contains a canary token in its path,
query, body, or headers, `scoreCanaryReplay()` calls `s.canary.HitCanary()`.
The result provides:

- **same client:** the token was replayed by the same client that received it.
  This confirms the client processed the tarpit response.
- **different client:** the token appeared in a request from a different client.
  This indicates the fake credential or URL leaked into another system or agent.

Both cases fire `canary_replay` and are strong indicators of automated
processing.

```go
// internal/detector/scorer.go
type CanaryLookup interface {
    HitCanary(token, clientID string) (origClientID string, hit bool)
}
```

**Code path:**

- [`internal/persist/store.go`](../../internal/persist/store.go) — `HitCanary()` implementation
- [`internal/detector/scorer.go`](../../internal/detector/scorer.go) → `scoreCanaryReplay()`
- `Scorer.SetCanaryLookup()` — wired in `cmd/veilgate/main.go`

**Operational notes:**

- Canary replay requires `persist.enabled: true` and the persist store to be
  wired as the canary lookup.
- Canary tokens must be emitted by the tarpit into responses. Template and
  payload rules control this.
- Without persistence, canary signals do not fire.

---

### `ml_agent_score`

**Group:** ML  
**Default points:** up to `rules/ml.yaml → score_max_points` (default `40`)  
**Rule source:** `rules/ml.yaml`  
**Stateful:** yes — weak-label training via `Scorer.Observe()`

An optional additive signal from the online ML scorer. `ml.Extractor` builds
a feature vector from the request (path, UA, headers, timing gap, JA4, etc.).
`ml.Scorer.Score()` evaluates the vector and returns a `Fired` flag plus a
`Points` value scaled to `[0, score_max_points]`.

The scorer also calls `mlScorer.Observe(vec, total, agentThreshold)` after
the final score is computed. This feeds the observation as a weak-labeled
sample into the online learner, using the deterministic rule-based total as
the label boundary.

```go
// internal/detector/scorer.go
if s.mlScorer != nil && s.mlExtractor != nil {
    mlVec = s.mlExtractor.Extract(r, gapSeconds(events), extractJA4(r))
    if res := s.mlScorer.Score(mlVec); res.Fired {
        result.Signals = append(result.Signals, Signal{
            Name:   "ml_agent_score",
            Points: res.Points,
            ...
        })
    }
}
// After summation:
if s.mlScorer != nil && len(mlVec.Categorical) > 0 {
    s.mlScorer.Observe(mlVec, total, s.agentThreshold)
}
```

**Operational notes:**

- ML is not the primary enforcement engine. Treat it as supporting evidence.
- The ML signal can add up to `score_max_points` to the total.
- The ML model improves over time as it observes more labeled examples.
- Disable ML if you need a fully deterministic scoring pipeline.
- See [Module veilgate_ml](../modules/veilgate_ml.md) for training configuration.

---

## Score Summation and Cap

After all signal functions run:

```go
total := 0
for _, sig := range result.Signals {
    total += sig.Points
}
if total > 100 {
    total = 100
}
result.Total = total
```

The score is stored in `ClientState.Score` and returned to the proxy. The proxy
passes it to `decide()` which applies `mode` and threshold comparisons.

---

## Signal Metrics

Every signal that fires is recorded in Prometheus:

```go
for _, sig := range score.Signals {
    telemetry.SignalHits.WithLabelValues(sig.Name).Inc()
}
```

Useful PromQL:

```promql
topk(10, sum by (signal) (rate(veilgate_signal_hits_total[15m])))
```

```promql
sum by (signal) (increase(veilgate_signal_hits_total[1h]))
```

---

## Related

- [Module veilgate_detector](../modules/veilgate_detector.md)
- [Module veilgate_rules](../modules/veilgate_rules.md)
- [Decision Flow](decision_flow.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [`rules/detector.yaml`](../config/rules/detector.md)
- [`rules/ip_reputation.yaml`](../config/rules/ip-reputation.md)
- [`rules/tls_fingerprints.yaml`](../config/rules/tls-fingerprints.md)
