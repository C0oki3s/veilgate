# Detection Signals

VeilGate evaluates up to 43 built-in signals per request. Each signal that fires
contributes a fixed point value to the total score (0–100). Signals are additive —
multiple signals firing on the same request are summed, then capped at 100. The
total score determines the routing decision and the `threat_level` log attribute.

## Score tiers and routing impact

| Score range | Threat level | Default routing (auto/tarpit mode) |
| --- | --- | --- |
| 0–29 | `low` | `real` — proxied upstream |
| 30–59 | `medium` | `real` or `challenge` depending on `score_challenge_threshold` |
| 40+ (default) | — | `challenge` — PoW page served |
| 60–79 | `high` | `challenge` (above threshold) |
| 70+ (default) | — | `tarpit` — fake application response |
| 80–100 | `critical` | `tarpit` |

Thresholds are configured in `veilgate.yaml` under `detector.score_challenge_threshold`
(default 40) and `detector.score_tarpit_threshold` (default 70). These do not
correspond directly to the `threat_level` label — the thresholds and the label
bands are independent values operators tune separately.

**Log severity routing** (v1.1.5): request log lines use a level that reflects
the decision — `tarpit → error`, `challenge → warn`, `real/observe → info`. In
SigNoz and Grafana these map to red, yellow, and blue colour bands. The
`threat_level` attribute (`low`/`medium`/`high`/`critical`) is also attached to
every request log line.

## Configuring signals

Every built-in signal can be enabled/disabled or have its default points
overridden in `rules/signals.yaml` — no rebuild required:

```yaml
signals:
  injection_marker:
    enabled: true
    points: 65        # raise above tarpit threshold
  ae_browser_no_br:
    enabled: false    # CDN strips br hint, causes false positives
```

Changes are hot-reloaded within ~500 ms. See
[`rules/signals.yaml` reference](../config/rules/signals.md) for the full API
including custom signals.

---

## Signal reference

### Header shape

These signals fire on a single request — no history required.

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `empty_ua` | 20 | No `User-Agent` header. HTTP libraries often omit it; real browsers always send it. Low-confidence alone but reinforces other signals. |
| `suspicious_ua` | 35 | User-Agent contains a known scanner or library substring: sqlmap, nuclei, nikto, ffuf, gobuster, dirsearch, feroxbuster, python-requests, python-httpx, go-http-client, curl, wget, burp, caido, zaproxy, playwright, puppeteer, headless-chrome, and ~30 more. |
| `sparse_headers` | 8–15 | Missing browser-typical headers. Tiered: 3+ missing headers = 15 pts; 2 missing = 8 pts. Checked headers: `Accept-Language`, `Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`, `Sec-Ch-Ua`. |

### Browser consistency

These signals gate on a browser-shaped UA and fire when the accompanying
header set contradicts that claim.

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `sec_fetch_absent` | 15 | Browser-shaped UA but all three `Sec-Fetch-*` headers absent. Every browser since 2020 sends the triple on navigations and fetches. |
| `sec_fetch_partial` | 8 | Browser-shaped UA but only 1–2 of `Sec-Fetch-Site`/`Sec-Fetch-Mode`/`Sec-Fetch-Dest` present. |
| `ae_browser_empty` | 12 | Browser-shaped UA but `Accept-Encoding` is absent. Every real browser advertises at least `gzip, deflate`. |
| `ae_browser_no_br` | 8 | Browser-shaped UA but `Accept-Encoding` does not include `br` (brotli). All Chromium, Firefox, and Safari versions since ~2017 advertise brotli. Disable this signal if your upstream CDN strips the `br` hint before requests reach VeilGate. |
| `h3_mismatch` | 10 | Browser-shaped UA but the client never upgraded to HTTP/3 despite repeated `Alt-Svc` hints from the server. Set by the proxy layer; only meaningful when the upstream serves HTTP/3. |

### Timing

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `regular_timing` | 12–25 | Inter-request interval is suspiciously uniform (mean 1.5–10 s, coefficient of variation below the configured threshold). LLM agents and test harnesses produce this pattern; human navigation does not. Tiered: strict CV ≤ 0.35 = 25 pts; loose CV ≤ 0.55 = 12 pts. Requires at least 6 events in the window. |

### Toolchain / pentest pipeline

These signals model the classic recon → probe → exploit sequence.

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `toolchain_full` | 30 | Client hit all three pentest stages within the rolling window: recon paths (`robots.txt`, `sitemap.xml`, `.git/config` …), probe paths (`/admin`, `/login`, `/api/docs` …), and an exploit marker (SQL/XSS/RCE payload). |
| `toolchain_partial` | 15 | Exactly two stages observed — recon+probe or probe+exploit — without completing the full sequence. |
| `toolchain_hmm` | 25 | The **ordered** recon→probe→exploit sequence was observed in the event history. Stronger than the set-based signals above because order matters and is hard to produce accidentally. |
| `toolchain_hmm_partial` | 12 | Ordered two-stage subsequence (recon→probe or probe→exploit). Weaker leading indicator before the third stage fires. |

### Path and payload analysis

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `path_bruteforce` | 10–40 | Client hit many distinct paths inside the tracker window — fingerprint of dirsearch/ffuf/feroxbuster/nikto wordlist bruteforcers even when they rotate User-Agent pools. Tiered: 15+ paths = 10 pts; 50+ = 25 pts; 200+ = 40 pts. |
| `wordlist_path` | 25 | Request path matches a known scanner wordlist entry from SecLists, dirsearch `default.yml`, or nikto `db_tests.db`. Catches bruteforcers even when the UA is spoofed or rotated. |
| `injection_marker` | 60 | Attack payload marker found in path, query, headers, or body: SQL injection, XSS, SSRF, command injection, path traversal (`../`), Log4Shell (`jndi:ldap://…`), template injection (`{{7*7}}`), and similar. At 60 pts, this signal alone pushes a request above the default tarpit threshold. |
| `oob_interaction` | 60 | Request references an out-of-band callback host: Burp Collaborator (`*.burpcollaborator.net`), interactsh (`*.oast.me`, `*.oast.fun`), webhook.site, canarytokens.org, etc. Virtually never present in legitimate traffic. |
| `encoding_chain` | 8–20 | Request uses double (`%25XX`) or triple (`%2525`) URL-encoding — a classic WAF-bypass technique. Single-occurrence = 8 pts; multiple occurrences = 15 pts; triple-encoding = 20 pts. |

### IP reputation and rotation

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `ip_reputation` | Varies | Client IP falls within a known-bad CIDR: Tor exit nodes, cloud egress ranges, public VPN endpoints, datacenter ranges. Category determines points — configured in `rules/ip_reputation.yaml`. |
| `ip_rotation_fleet` | 15–35 | Multiple distinct client IPs share the same behavioral fingerprint (UA family + JA4 prefix + header bitmap + HTTP method mix) inside the rolling window. Canonical proxy pool / VPN rotation signature. Tiered by number of distinct IPs sharing the fingerprint. |
| `ua_rotation` | 20 | One client IP sent requests under many distinct User-Agent strings within the tracker window. Real browsers never change UA mid-session; dirsearch/ffuf with a UA pool does this constantly. |

### TLS and HTTP/2 fingerprinting

These signals require TLS termination at VeilGate (`tls.enabled: true`) for
TLS signals, and HTTP/2 connection hook wiring for H2 signals. Both are skipped
when VeilGate sits behind a TLS-terminating load balancer.

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `tls_agent` | Configurable | JA4/JA3 TLS ClientHello fingerprint matches a known HTTP library or security scanner (python-httpx, nuclei, sqlmap, etc.). High confidence when match confidence ≥ 80. Points come from the match entry in `rules/tls_fingerprints.yaml`. |
| `tls_bot` | Configurable | JA4/JA3 fingerprint matches a known bot (search-engine crawler, monitoring probe). Lower risk than agent/scanner matches. |
| `tls_non_browser` | Configurable | TLS fingerprint does not match any known browser entry. Catch-all for library-shaped clients without a named match. |
| `h2_agent` | Configurable | HTTP/2 SETTINGS frame fingerprint matches a known agent library. Complements TLS fingerprinting; together they are very hard to spoof independently. |
| `h2_bot` | Configurable | HTTP/2 SETTINGS fingerprint matches a known bot. |
| `h2_non_browser` | Configurable | HTTP/2 SETTINGS looks library-shaped (no known browser match). |

### Session and behavioral signals

These signals require multiple requests from the same client and read from the
rolling `ClientState` maintained by `internal/detector.Tracker`. The tracker
window is `detector.window_seconds` (default 90 s).

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `graph_flat` | 15 | Client made many requests but none carried a `Sec-Fetch-Dest: script/image/style/font` value. Real browsers produce a tree-shaped pattern (document then many subresources); agents produce a flat list of independent document fetches. |
| `graph_doc_heavy` | 12 | Document fetches outnumber subresource fetches 4:1 or more. Crawler topology — automated page-to-page navigation that does not follow embedded resource links. |
| `cookie_stateless` | 15 | Client made 10+ requests without ever sending a `Cookie` header. Real browsers accumulate cookies from `Set-Cookie` responses; stateless HTTP clients and most libraries do not maintain a cookie jar. |
| `fanout_high` | 20 | Client accessed 60+ distinct paths in the last 60 seconds. Finer-grained than `path_bruteforce`; fires before the wordlist threshold saturates. Effective against slow-rate scanners. |
| `fanout_extreme` | 35 | Client accessed 200+ distinct paths in the last 60 seconds. Almost exclusively scanner and fuzz-harness traffic at this rate. |
| `recovery_pivot` | 15 | The immediately-preceding response was 4xx and the next request changed both path and method — shape-change retry. Real users retry with the same path or add credentials; LLM agents often pivot to a different endpoint after receiving an error. |
| `bundle_mining` | 20 | Client fetched a JavaScript bundle asset then issued several `/api/*` requests within 60 seconds with no HTML document navigation in between. The canonical "agent downloaded SPA, extracted routes, began probing" pattern. |
| `header_mutation` | 8–25 | The stable-header presence bitmap (`Accept-Language`, `Accept-Encoding`, `Sec-Ch-Ua`, `Sec-Ch-Ua-Mobile`, `Sec-Ch-Ua-Platform`) changed multiple times during the session. Volatile headers (`Referer`, `Cookie`, `Cache-Control`, `Sec-Fetch-*`) are excluded to avoid false positives. Tiered by mutation count. |
| `schema_first` | 20 | A non-browser client's first three requests targeted an API schema endpoint (`openapi`, `swagger`, `api-docs`, `graphql/schema`, `graphiql`, …). The browser-UA gate prevents false positives from Swagger UI and Redoc. |
| `cache_miss_anomaly` | 10–20 | The same path was fetched 5+ times in a 3-minute burst without any conditional headers (`If-None-Match`, `If-Modified-Since`). SPA libraries (React Query, SWR, Apollo) cache aggressively; polling agents repeatedly re-fetch identical resources without caching. Tiered by fetch count and interval. |
| `no_cookie_return` | 12 | The tarpit served a `Set-Cookie` header but the client never returned any `Cookie` in subsequent requests. Suppressed for cross-origin requests (CORS/SameSite guard). Stateless HTTP clients and agents typically do not maintain a cookie jar. |
| `auth_probe_sequence` | 15–25 | Client probed 4+ distinct authentication endpoint categories (`/login`, `/oauth/token`, `/sso`, `/jwt`, `/password`, `/api/session`, …) within 5 minutes across 10+ total requests. Normal OAuth flows touch 2–3 auth paths; systematic auth scanning covers many categories. |

### Deception feedback

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `canary_replay` | 80 | A token previously served inside a tarpit response was submitted in a subsequent request. Near-perfect proof of automated processing: a real user would never see the canary value, let alone reuse it as a credential. Backed by the persist store — requires `persist.enabled: true`. |

### API blueprint miss

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `api_blueprint_miss` | 15 | Request targeted the operator's documented API namespace (e.g. `/api`, `/v1`) but the exact path was not found in the provided blueprint (`api_blueprint.yaml` / `openapi.yaml`). Common indicator of automated endpoint enumeration. Disabled automatically when no blueprint file is present in `rules_dir`. See [How-to: API blueprinting](../how-to/api-blueprint.md). |

### Honeypot

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `honeypot_hit` | 50 (first hit), 80 (repeat) | Client requested a path listed as a honeypot in `detector.probe_paths`. No legitimate user or crawler should ever visit these paths. The highest-confidence single-request signal available. |

### Machine learning

| Signal | Default pts | What it detects |
| --- | --- | --- |
| `ml_agent_score` | Dynamic (0–100) | Combined Isolation Forest (numeric session feature anomaly) + Naive Bayes (categorical per-request features) score, trained online from observe-mode traffic. Fires only when confidence exceeds the `min_confidence_to_fire` threshold in `ml.yaml`. Points are proportional to ML confidence and may be tuned via `points:` in `signals.yaml`. |

### Trusted IP (special case)

When the client IP is listed in `detector.trusted_ips`, the scorer returns
`Score{Total: 0}` immediately — no signals are evaluated. The `trusted_ip`
signal name appears in the score output for audit purposes with 0 points.

---

## Signal evaluation order

Signals are evaluated in this order inside `Scorer.Score()`:

1. Trusted IP check (short-circuits; skips all signals)
2. Honeypot hit
3. Header shape (`scoreHeaders`, `scoreUserAgent`)
4. Timing (`scoreTiming`)
5. Toolchain set-based (`scoreToolchain`)
6. Path bruteforce (`scorePathBruteforce`)
7. Wordlist path (`scoreWordlistPath`)
8. Injection markers (`scoreInjection`)
9. OOB interaction (`scoreOOB`)
10. IP reputation (`scoreIPReputation`)
11. Fleet rotation (`scoreFleetRotation`)
12. UA rotation (`scoreUARotation`)
13. TLS fingerprint (`scoreTLS`)
14. HTTP/2 fingerprint (`scoreH2`)
15. Sec-Fetch coherence (`scoreSecFetch`)
16. Accept-Encoding posture (`scoreAcceptEncoding`)
17. H3 mismatch (`scoreH3Mismatch`)
18. Request graph shape (`scoreRequestGraph`)
19. Cookie ecology (`scoreCookieEcology`)
20. Fanout (`scoreFanout`)
21. Failure recovery pivot (`scoreFailureRecovery`)
22. Toolchain HMM (`scoreToolchainHMM`)
23. Bundle mining (`scoreBundleMining`)
24. Header mutation (`scoreHeaderMutation`)
25. Schema-first (`scoreSchemaFirst`)
26. Cache-miss anomaly (`scoreCacheMissAnomaly`)
27. No-cookie return (`scoreNoCookieReturn`)
28. Encoding chain (`scoreEncodingChain`)
29. Auth probe sequence (`scoreAuthProbeSequence`)
30. Custom signals (`scoreCustomSignals`)
31. API blueprint miss (`scoreAPIBlueprintMiss`)
32. Canary replay (`scoreCanaryReplay`)
33. ML (`ml.Scorer.Score`)

After all signals fire, `applySignalConfig()` filters out disabled signals and
applies any point overrides from `signals.yaml`. The total is summed and capped at 100.

---

## Attack families

For endpoint-correlation metrics, each signal is bucketed into one of nine
attack families. The family label appears on
`veilgate_endpoint_attack_family_total` (Prometheus) and
`veilgate.endpoint.attack_family.total` (OTel).

| Family | Signals |
| --- | --- |
| `recon` | `honeypot_hit`, `path_bruteforce`, `wordlist_path`, `fanout_high`, `fanout_extreme`, `schema_first`, `api_blueprint_miss` |
| `auth` | `auth_probe_sequence`, `no_cookie_return`, `cookie_stateless` |
| `injection` | `injection_marker`, `oob_interaction`, `encoding_chain` |
| `evasion` | `ua_rotation`, `ip_rotation_fleet`, `sparse_headers`, `ae_browser_empty`, `ae_browser_no_br`, `sec_fetch_absent`, `sec_fetch_partial` |
| `fingerprint` | `tls_agent`, `tls_bot`, `tls_non_browser`, `h2_agent`, `h2_bot`, `h2_non_browser`, `h3_mismatch` |
| `behavioral` | `graph_flat`, `graph_doc_heavy`, `bundle_mining`, `recovery_pivot`, `header_mutation`, `cache_miss_anomaly` |
| `fleet` | `ip_reputation`, `ip_rotation_fleet` |
| `toolchain` | `toolchain_full`, `toolchain_partial`, `toolchain_hmm`, `toolchain_hmm_partial`, `regular_timing` |
| `ml` | `ml_agent_score` |

---

## Related

- [`rules/signals.yaml`](../config/rules/signals.md) — enable/disable, points overrides, custom signals
- [`rules/detector.yaml`](../config/rules/detector.md) — default points, scoring tiers, timing config
- [Detector score system](detector-score-system.md) — score bands, thresholds, threat_level
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [How-to: Observe and tune](../how-to/observe-and-tune.md)
- [How-to: API blueprinting](../how-to/api-blueprint.md)
- [Module veilgate_detector](../modules/veilgate_detector.md)
