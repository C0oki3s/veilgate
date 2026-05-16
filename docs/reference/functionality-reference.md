# veilgate functionality reference

Every knob, signal, and subsystem in veilgate, with three things for
each: **how it works**, **how to enable it in `veilgate.yaml`**, and
**what changes at runtime when you do**.

This is the "show me everything that exists" reference. For
task-oriented walkthroughs see the [how-to guides](../how-to/README.md);
for the per-section configuration pages see the [config reference](../config/README.md).

**Quick map:**

- [Top-level keys](#top-level-keys) — listen, upstream, mode, rules_dir
- [TLS termination + JA3/JA4 fingerprinting](#tls-termination--ja3ja4-fingerprinting)
- [Detector (the score system)](#detector-the-score-system)
- [Tarpit handler](#tarpit-handler)
- [Challenge handler (PoW + cookie + header)](#challenge-handler-pow--cookie--header)
- [Metrics + dashboard](#metrics--dashboard)
- [Request capture (JSONL)](#request-capture-jsonl)
- [Persistence (SQLite event store)](#persistence-sqlite-event-store)
- [Verifier chain (server-to-server auth)](#verifier-chain-server-to-server-auth)
- [Detection signals (driven by `rules/detector.yaml`)](#detection-signals)
- [IP reputation, fleet rotation, UA rotation (`rules/ip_reputation.yaml`)](#ip-reputation-fleet-rotation-ua-rotation)
- [Online ML signal (`rules/ml.yaml`)](#online-ml-signal)
- [TLS fingerprint catalogue (`rules/tls_fingerprints.yaml`)](#tls-fingerprint-catalogue)
- [Tarpit content (`rules/templates.yaml`, `rules/injection_strategy.yaml`, `rules/payloads.yaml`)](#tarpit-content)
- [Cross-cutting features](#cross-cutting-features)

---

## Top-level keys

### `listen`

**What it is:** the address the proxy binds to.

**How it works:** Go's `http.Server` listens on this address. Plain
HTTP unless `tls.enabled: true`. Format is `host:port` or just
`:port` for all interfaces.

**YAML:**
```yaml
listen: ":8080"
```

**Defaults to `:8080`.** Change requires a process restart.

**What happens when included:** the proxy binds the given socket at
startup. If the port is already in use, veilgate exits with a fatal
log. Most operators set this to `:443` (with TLS) or `:8080` (behind
a reverse-proxy terminator like nginx).

---

### `upstream`

**What it is:** the origin URL veilgate forwards "real" requests to.

**How it works:** a `httputil.NewSingleHostReverseProxy` is built
against this URL. The proxy rewrites `r.Host` to match the upstream,
disables proxy-identity leaks, and forwards. Bad-gateway errors are
caught and returned as plain `502 bad gateway` instead of leaking the
upstream's identity.

**YAML:**
```yaml
upstream: "http://internal-app.svc.cluster.local:9000"
```

**Required.** If unparseable, veilgate fails to start with a fatal
log.

**What happens when included:** every request that the score system
decides is `DecisionReal` (and isn't intercepted by the challenge or
tarpit handler) is forwarded to this URL. The upstream is responsible
for whatever its real content is — veilgate doesn't transform the
body.

---

### `mode`

**What it is:** what veilgate does with scored requests.

**How it works:** the score system runs unconditionally on every
request. `mode` controls how the proxy *acts* on the score
([proxy.go:318-346](../../internal/proxy/proxy.go#L318-L346)):

| Mode | Behaviour |
|---|---|
| `observe` | Everything forwards to upstream. Scores are still computed and recorded — you see what *would* happen without acting on it. |
| `challenge` | Score ≥ `score_challenge_threshold` → challenge tier. Below → real. |
| `tarpit` | Score ≥ `score_tarpit_threshold` → tarpit; ≥ challenge threshold → challenge; below → real. |
| `auto` | Same as `tarpit` — full three-tier routing. The most common production mode. |

**YAML:**
```yaml
mode: "auto"
```

**Defaults to `observe`.** This is intentional — fresh installs
should run in observe first to tune thresholds before any traffic is
diverted. See [How-to: Observe-mode rollout](../how-to/observe-and-tune.md).

**What happens when included:** the `decide()` function consults
this string on every request. Switching from observe to auto is the
moment traffic starts being diverted; do it carefully with metrics
in front of you.

---

### `rules_dir`

**What it is:** an override path for the rules YAML files.

**How it works:** at startup, each rules file is loaded via
`readOrEmbed(rules_dir, "<file>.yaml", embeddedDefault)`
([loader.go:198](../../internal/rules/loader.go#L198)). If `rules_dir`
is empty, the embedded defaults are used. If it's set, the binary
reads `rules_dir/<file>.yaml` from disk; missing files fall back to
the embedded default per-file.

**YAML:**
```yaml
rules_dir: "/etc/veilgate/rules"
```

**Defaults to empty** (embedded-only).

**What happens when included:** the binary watches `rules_dir` for
file changes via fsnotify and hot-reloads any file that changes. The
override is **full-file replacement, not merge** — see
[docs/config/overrides.md](../config/overrides.md) for the resolution
model.

---

## TLS termination + JA3/JA4 fingerprinting

### `tls.enabled` / `tls.cert_file` / `tls.key_file`

**What it is:** HTTPS termination at the veilgate listener, with TLS
ClientHello capture for fingerprinting.

**How it works:** when enabled, veilgate wraps its TCP listener with
a custom `tlsfp.Listener` that peeks at the first bytes (the
ClientHello) before handing the connection to Go's `crypto/tls`
stack. The peeked bytes are parsed for JA3 and JA4 fingerprints and
stored in a per-remote-address cache. Later, the scorer's
`scoreTLS` consults this cache when scoring the HTTP request that
arrived on the same connection ([scorer.go:494](../../internal/detector/scorer.go#L494)).

**YAML:**
```yaml
tls:
  enabled: true
  cert_file: "/etc/veilgate/cert.pem"
  key_file:  "/etc/veilgate/key.pem"
```

**Defaults to disabled.** Most deployments terminate TLS at an
upstream load balancer (nginx, Envoy, ALB) and run veilgate plain
HTTP behind it — in that setup, JA3/JA4 fingerprinting at the
veilgate layer doesn't work because the terminator does its own
TLS handshake.

**What happens when included:**

- Listener now requires HTTPS connections.
- For every connection, a JA3 and JA4 string are computed and
  classified against `rules/tls_fingerprints.yaml`.
- The `tls_agent` / `tls_bot` / `tls_non_browser` detection signals
  start firing on the score (worth 20–45 points each).
- Without TLS termination here, none of those signals contribute.

---

## Detector (the score system)

### `detector.score_challenge_threshold`

**What it is:** the floor at which a request gets challenged (in
challenge / auto mode).

**How it works:** the proxy's `decide()` compares `score >=
score_challenge_threshold` and routes the request to the challenge
handler if true (and below the tarpit threshold).

**YAML:**
```yaml
detector:
  score_challenge_threshold: 40
```

**Defaults to `40`.**

**What happens when included:** in challenge or auto mode, requests
scoring 40 to 69 get the PoW challenge page (HTML for navigation,
401 JSON for fetch). Below 40, request reaches upstream untouched.

---

### `detector.score_tarpit_threshold`

**What it is:** the floor at which a request gets tarpitted.

**How it works:** same as above, but for the tarpit handler.

**YAML:**
```yaml
detector:
  score_tarpit_threshold: 70
```

**Defaults to `70`.**

**What happens when included:** in tarpit or auto mode, requests
scoring ≥70 get the decoy. **Crucial invariant:** a passing PoW
cookie OR a successful verifier (HMAC etc.) only demotes Challenge→Real
— it does NOT demote Tarpit→Real. So this threshold is also the
"hard ceiling" beyond which no credential can save the client.

---

### `detector.window_seconds`

**What it is:** how long the per-client event tracker remembers
requests.

**How it works:** the `detector.Tracker` keeps a rolling per-client
event buffer of the last N seconds. Many history-dependent signals
(`regular_timing`, `path_bruteforce`, `toolchain`, `ua_rotation`,
`cookie_ecology`, etc.) compute over this window.

**YAML:**
```yaml
detector:
  window_seconds: 90
```

**Defaults to `90`.**

**What happens when included:** longer windows mean signals catch
slower attacks (low-rate scrapers that pace themselves out of a
short window) at the cost of more memory per client and stale-state
risk. 90s is the sweet spot for most deployments.

---

### `detector.honeypot_paths`

**What it is:** paths that should *never* legitimately be hit. A
request for any of these gets +50 points on first hit, +80 on
subsequent.

**How it works:** the list is loaded into a `map[string]struct{}` at
startup. The scorer checks `r.URL.Path` against this map and bumps
the score directly (no rules-file lookup needed for the hot path).

**YAML:**
```yaml
detector:
  honeypot_paths:
    - "/admin-panel-v2"
    - "/api/internal/debug"
    - "/.git/config"
    - "/.env.backup"
    - "/wp-admin-old"
    - "/phpmyadmin-backup"
```

**Defaults to a starter list** of six common targets if you leave it
empty (see `config.applyDefaults`).

**What happens when included:** a single request to any of these
paths puts the client into tarpit territory immediately. Tune the
list to match paths your real app would never serve.

---

### `detector.trusted_ips`

**What it is:** an allowlist that returns `score=0` short-circuited.

**How it works:** at the top of `Scorer.Score()`, before any signals
run, the client IP is checked against this map. If matched, scoring
returns immediately with `{Total: 0, Signals: [trusted_ip]}` —
nothing else fires.

**YAML:**
```yaml
detector:
  trusted_ips:
    - "127.0.0.1"
    - "::1"
    - "10.0.0.5"      # internal health-check from monitoring
```

**Defaults to empty.**

**What happens when included:** matching clients bypass the entire
score system and go straight to upstream. **Be careful** — this is a
total bypass, not a score reduction. Use for trusted internal
loopback / monitoring only.

---

### `detector.trusted_proxies`

**What it is:** CIDRs (or exact IPs) whose `X-Forwarded-For` header
veilgate should honor.

**How it works:** when a request arrives, `resolveClientIP()`
([proxy.go:362](../../internal/proxy/proxy.go#L362)) checks whether
the direct `RemoteAddr` is inside any trusted-proxy CIDR. If yes,
it walks the `X-Forwarded-For` right-to-left and returns the first
non-trusted hop as the effective client IP. If no, XFF is ignored
entirely (defends against Log4Shell-style header injection).

**YAML:**
```yaml
detector:
  trusted_proxies:
    - "10.0.0.0/8"       # internal network — your load balancer lives here
    - "192.168.1.100"    # exact IP also fine
```

**Defaults to empty** (= never honor XFF).

**What happens when included:** behind a load balancer, you need
this set or veilgate will see every client as "the load balancer's
IP" and the score system collapses (one IP looks like fleet rotation,
all clients share one rate limit, etc.). Without trusted_proxies,
veilgate is XSS/injection-safe but loses true client identity.

---

## Tarpit handler

### `tarpit.min_latency_ms` / `tarpit.max_latency_ms`

**What it is:** the slow-drip latency window applied to tarpitted
responses.

**How it works:** the tarpit handler renders a decoy response, then
sleeps for a random duration in `[min, max]` before writing it. This
burns the attacker's time and (for LLM agents) their context budget.

**YAML:**
```yaml
tarpit:
  min_latency_ms: 500
  max_latency_ms: 3000
```

**Defaults to `500` / `3000`.**

**What happens when included:** every tarpitted response takes
between 0.5 and 3 seconds. Higher values waste more attacker time
but cost veilgate one connection-slot per attacker. 0.5–3s is
reasonable for most deployments; bump it on heavy automated traffic.

---

### `tarpit.max_body_bytes`

**What it is:** ceiling on the rendered tarpit response body size.

**How it works:** the template renderer caps body bytes after
template expansion + payload injection. Prevents an unbounded
fake-data template from generating multi-MB responses.

**YAML:**
```yaml
tarpit:
  max_body_bytes: 102400
```

**Defaults to `102400` (100 KB).**

**What happens when included:** tarpit responses are at most this
big. Operators rarely tune this — the templates are normally
small.

---

## Challenge handler (PoW + cookie + header)

### `challenge.secret`

**What it is:** the HMAC key used to sign both the challenge nonce
(prevents forged challenges) and the issued cookie (prevents forged
auth tokens).

**How it works:** all HMACs in the challenge subsystem use
`HMAC-SHA256(secret, payload)`. Rotating this invalidates every
outstanding cookie immediately — useful for incident response.

**YAML:**
```yaml
challenge:
  secret: ${VEILGATE_SECRET}
```

**Defaults to placeholder** that veilgate refuses to start with in
non-observe modes. Set via the `VEILGATE_SECRET` env var (preferred)
or directly in YAML.

**What happens when included:** every challenge-mint and cookie-mint
uses this secret. **If unset**, veilgate exits at startup in any
mode other than `observe`.

---

### `challenge.difficulty`

**What it is:** the number of leading hex zeros the PoW solution
must produce.

**How it works:** the JS in the challenge page hashes `sha256(challenge + ":" + nonce)`
and increments `nonce` until the hex prefix matches `"0" * difficulty`.
Expected hashes: `2^(4 * difficulty)`. The verify endpoint recomputes
and checks the prefix matches.

**YAML:**
```yaml
challenge:
  difficulty: 4
```

**Defaults to `4`.**

**What happens when included:**

| Difficulty | Expected ops | Real browser solve time |
|---|---|---|
| 3 | 4 096 | <100 ms |
| 4 | 65 536 | ~500 ms |
| 5 | 1 048 576 | ~5 s |
| 6 | 16 777 216 | too slow for users |

`4` is the sweet spot. Higher difficulties raise attacker cost
proportionally but also hurt real users.

---

### `challenge.ttl_minutes`

**What it is:** how long the issued PoW cookie/token stays valid.

**How it works:** the cookie format is `<RFC3339 ts>.<HMAC-SHA256(secret, ts)>`.
`Passed()` rejects cookies whose `ts` is older than `ttl_minutes` ago.

**YAML:**
```yaml
challenge:
  ttl_minutes: 30
```

**Defaults to `30`.**

**What happens when included:** longer TTLs are friendlier to real
users (fewer re-solves) but extend the value of a stolen cookie.
Drop to `5` in high-threat deployments. The token-header transport
honors the same TTL.

---

## Metrics + dashboard

### `metrics.listen`

**What it is:** the listener address for the Prometheus `/metrics`
endpoint and the live HTML dashboard.

**How it works:** a separate `http.Server` (NOT the proxy listener)
binds this address. Routes:
- `/metrics` → Prometheus exposition format
- `/` → live HTML dashboard (auto-refresh, charts, recent-events
  table) — see [`rules/dashboard.yaml`](../config/README.md) for
  layout config.

**YAML:**
```yaml
metrics:
  listen: ":9090"
```

**Defaults to `:9090`.**

**What happens when included:** Prometheus can scrape `:9090/metrics`
immediately. Operators can open `:9090/` in a browser for the live
view. **Never expose this to the public internet** — it leaks
detection-signal state.

---

## Request capture (JSONL)

### `capture.enabled` / `capture.path` / `capture.max_mb`

**What it is:** JSONL log of every request's metadata + score +
signals fired. Used as training data for the ML signal and for
post-mortem investigation.

**How it works:** when enabled, the proxy writes one JSON line per
request to the configured path. Each line has client IP, method,
path, UA, referer, accept-* headers, score, fired signal names, and
final decision. The file rotates when it exceeds `max_mb`.

**YAML:**
```yaml
capture:
  enabled: true
  path: "/var/log/veilgate/requests.jsonl"
  max_mb: 100
```

**Defaults:** disabled, `max_mb: 100`.

**What happens when included:** the proxy adds a synchronous-write
hop on the hot path (write goes to a buffered file). Disk usage
grows with traffic — plan retention via `retention_hours`. **Don't
enable both `capture` and `persist`** — they overlap; pick one.

---

### `capture.retention_hours` / `capture.janitor_every`

**What it is:** rotation-file retention.

**How it works:** a background janitor goroutine wakes every
`janitor_every` (duration string like `"1h"`), lists files matching
the rotation suffix, and deletes any older than `retention_hours`.
The active file is never touched.

**YAML:**
```yaml
capture:
  retention_hours: 168    # one week
  janitor_every: "1h"
```

**Defaults:** retention is `0` = forever, janitor disabled.

**What happens when included:** disk usage stays bounded.

---

### `capture.scrub`

**What it is:** regex/replace pairs applied to each JSONL line
before writing. PII redaction.

**How it works:** at startup, each pattern is compiled; bad regexes
are silently dropped (so a typo doesn't break the proxy). On each
write, every compiled regex runs over the line text and substitutes
`replace`.

**YAML:**
```yaml
capture:
  scrub:
    - regex: 'Bearer [A-Za-z0-9_\-\.]{20,}'
      replace: 'Bearer <REDACTED>'
    - regex: 'password=[^&\s]+'
      replace: 'password=<REDACTED>'
```

**Defaults:** empty (no redaction).

**What happens when included:** matching token shapes are replaced
in-place before the line is written. Note: the scrub is *post-hoc*,
so a payload that doesn't match any pattern still lands on disk in
the clear — operators are responsible for the regex catalogue.

---

### `capture.file_mode`

**What it is:** POSIX permission bits on the capture file.

**How it works:** passed straight to `os.OpenFile` mode argument.

**YAML:**
```yaml
capture:
  file_mode: 0o600    # default; only the veilgate user can read
```

**Defaults to `0o600`.** Set `0o644` if other system users
(log-shipping daemons, monitoring agents) need read access.

**What happens when included:** new capture files are created with
this mode. Existing files keep their current mode.

---

## Persistence (SQLite event store)

### `persist.enabled` / `persist.path`

**What it is:** SQLite-backed event store. Replaces capture JSONL
for most operators; carries extra tables (canary, audit, ML rollups)
that JSONL can't.

**How it works:** when enabled, a `persist.Store` opens the given
SQLite file. The proxy enqueues each scored event into a buffered
channel; a background goroutine batches inserts every
`flush_every_ms`. Drop-on-full back-pressure keeps the hot path free
of disk stalls.

**YAML:**
```yaml
persist:
  enabled: true
  path: "/var/lib/veilgate/events.db"
```

**Defaults to disabled.**

**What happens when included:**

- Every request decision is persisted (async, drop-on-full).
- The `canary` table starts tracking tarpit-served canary tokens;
  the `canary_replay` detection signal becomes available.
- The `audit_log` table captures every operator action (config
  reload, process start/stop) in a hash-chained sequence.
- The ML miner gains access to historical features for retraining.

---

### `persist.retention_days`

**What it is:** how long to keep event rows before trimming.

**How it works:** a background goroutine wakes every 6 hours, runs
`DELETE FROM events WHERE ts < cutoff`, and runs SQLite WAL
checkpoints. If `dump_path` is set, the rows are exported to a
compressed CSV first.

**YAML:**
```yaml
persist:
  retention_days: 30
```

**Defaults to `30`.** Setting `0` *enables* retention with 30 days
(see `applyDefaults`); use a positive integer to override.

**What happens when included:** the database stays bounded. The trim
runs every 6 hours so it never holds a long write transaction.

---

### `persist.dump_path`

**What it is:** directory where rotated CSV.gz dumps land before
trim.

**How it works:** before each trim, all rows that *would* be deleted
are appended to a date-stamped `events-YYYYMMDD-HHMMSS.csv.gz` file
in this directory. Operators can ship these to long-term storage
(S3, etc.) without consuming proxy disk.

**YAML:**
```yaml
persist:
  dump_path: "/var/lib/veilgate/dumps"
```

**Defaults to empty** (= no dump).

**What happens when included:** trim becomes lossless from the
operator's perspective — the data moves to dumps rather than being
deleted.

---

### `persist.queue_size` / `persist.cache_size_kb`

**What it is:** tuning knobs for ingest throughput and read
performance.

**How it works:**

- `queue_size`: capacity of the buffered channel between the proxy
  hot path and the persist goroutine. When full, new events are
  dropped (and counted in a Prometheus metric).
- `cache_size_kb`: SQLite's `PRAGMA cache_size` — page cache for
  hot reads. Higher = faster dashboard queries at the cost of RAM.

**YAML:**
```yaml
persist:
  queue_size: 2048
  cache_size_kb: 32768   # 32 MB cache
```

**Defaults:** `2048` queue / 64 MB cache.

**What happens when included:** under sustained burst load, larger
queue absorbs spikes before drops start. Larger cache speeds up the
dashboard's recent-events queries.

---

### Canary tokens (auto-on with persist)

**What it is:** the tarpit serves randomly-generated tokens in its
fake-credential responses ("admin password: …"). Any client that
later submits one of these tokens is unambiguously an attacker — a
real user has no way to have seen them.

**How it works:** the tarpit handler records every issued token in
the `canary` table with the issuing client ID. The scorer's
`canary_replay` signal queries this table on every request. Match
score is +50 (cross-session replay) or +60 (cross-client replay).

**YAML:** no direct config; auto-on when `persist.enabled: true`.

**What happens when included:** one of the strongest signals in the
system fires. Cross-client replays in particular point at credential
sharing or paste-into-LLM behaviour.

---

### Audit log (auto-on with persist)

**What it is:** hash-chained append-only log of every operator
action. SHA-256 over canonical JSON; each row's `prev_hash` links
to the previous one, so an external auditor can detect tampering
without trusting the server clock or filesystem.

**How it works:** two backends ship — a JSONL file (`/var/lib/veilgate/audit.log`,
mode 0600) for SIEM ingestion and a SQLite table for local query.
Every config reload, process start/stop, and miner promotion lands
in both.

**YAML:** no direct config; the JSONL path is derived from
`persist.path` (sibling directory). Disable by leaving `persist.enabled: false`.

**What happens when included:** compliance-friendly tamper-evidence.
Operators can prove "no one changed the score thresholds between
incident A and incident B" by replaying the hash chain.

---

## Verifier chain (server-to-server auth)

### `verifiers.hmac.enabled` and parameters

**What it is:** Stripe-style HMAC signature verification for
server-to-server callers. Lets internal services, mobile apps, and
webhooks bypass the PoW challenge with a shared-secret signature
instead.

**How it works:** the proxy's `serve()` consults the verifier chain
before the existing PoW cookie check. The HMAC verifier reads
`X-Veilgate-Signature: t=<unix>,v1=<hex>` plus
`X-Veilgate-Client: <name>`, loads the client's secret from
`clients_dir/<name>.secret`, recomputes
`HMAC_SHA256(secret, "<t>.<method>.<path>.<sha256(body)>")`,
and compares with `hmac.Equal`. On match, the request becomes
`DecisionReal` (subject to the Tarpit override).

**YAML:**
```yaml
verifiers:
  hmac:
    enabled: true
    header_signature: "X-Veilgate-Signature"
    header_client:    "X-Veilgate-Client"
    clock_skew_sec:   300
    max_body_bytes:   1048576
    clients_dir:      "/etc/veilgate/clients"
```

**Defaults:** disabled. When enabled, header names default to the
ones shown, `clock_skew_sec` to 300, `max_body_bytes` to 1 MiB.
`clients_dir` is required.

**What happens when included:**

- Every request is checked against the chain first.
- Valid signature → request reaches upstream (skipping challenge).
- Invalid signature → falls through to the score system normally.
- **Tarpit-tier score still tarpits**, regardless of verifier
  acceptance.

Full reference at [docs/config/verifiers.md](../config/verifiers.md);
task walkthrough at [docs/how-to/server-to-server-hmac.md](../how-to/server-to-server-hmac.md).

---

## Detection signals

These all live under `rules/detector.yaml` (which is hot-reloadable)
plus `rules/ip_reputation.yaml`. They don't appear in `veilgate.yaml`
directly — but they're the substance of "what the score system is
doing." Listed with their typical point contributions; tune in the
rules file.

### Header-based signals

| Signal | What it catches | Points |
|---|---|---|
| `sparse_headers` | Missing browser-typical headers (Sec-Fetch-*, Sec-Ch-UA, etc.) | 5–15, tiered |
| `empty_ua` | No User-Agent at all | 15 |
| `suspicious_ua` | UA substring matches a known tool (`sqlmap`, `nikto`, `curl/`, `python-requests`, …) | 35 |
| `ae_browser_empty` | Browser-shaped UA but Accept-Encoding empty | 12 |
| `ae_browser_no_br` | Browser-shaped UA but no brotli | 8 |
| `sec_fetch_absent` | Browser UA but all three Sec-Fetch-* missing | 12 |
| `sec_fetch_partial` | Browser UA but Sec-Fetch-* incomplete | 6 |

### Path-based signals

| Signal | What it catches | Points |
|---|---|---|
| `honeypot_hit` | Path in `detector.honeypot_paths` | 50 first / 80 repeat |
| `wordlist_path` | Path matches dirsearch/nikto wordlist marker | 25 |
| `injection_marker` | SQLi / XSS / LFI / SSTI / log4shell pattern in path/query/headers | 45 |
| `oob_interaction` | Burp Collaborator / interactsh / webhook.site host | 50 |

### History-based signals (need ≥ N requests in window)

| Signal | What it catches | Points |
|---|---|---|
| `regular_timing` | LLM-paced gaps (low coefficient of variation) | 15–30 |
| `toolchain_partial` | Two of {recon, probe, exploit} stages observed | 15 |
| `toolchain_full` | All three stages observed | 30 |
| `toolchain_hmm_partial` | Two-stage ordered sub-sequence (recon→probe, probe→exploit) | 8–12 |
| `toolchain_hmm` | Full ordered recon→probe→exploit | 20 |
| `path_bruteforce` | Many distinct paths in window | 15–30, tiered |
| `fanout_high` | 60+ distinct paths in last 60s | 15 |
| `fanout_extreme` | 200+ distinct paths in last 60s | 30 |
| `graph_flat` | Zero subresource fetches across many requests | 10 |
| `graph_doc_heavy` | Document fetches dominate subresource fetches | 6 |
| `cookie_stateless` | Many requests, no Cookie ever | 8 |
| `recovery_pivot` | Shape-change retry after a 4xx | 6 |
| `ua_rotation` | One IP sent N+ distinct UAs in window | configurable |
| `canary_replay` | Submitted a previously-served tarpit canary | 50/60 |

### TLS / HTTP/2 fingerprint signals

| Signal | What it catches | Points |
|---|---|---|
| `tls_agent` | JA3/JA4 match for known agent (`requests`, `curl`, etc.) | 30–45 |
| `tls_bot` | JA3/JA4 match for known bot | 25 |
| `tls_non_browser` | JA3/JA4 doesn't match any known browser | 20 |
| `h2_agent` | HTTP/2 SETTINGS match a known agent | 22–35 |
| `h2_bot` | HTTP/2 SETTINGS match a known bot | 18 |
| `h2_non_browser` | HTTP/2 SETTINGS look library-shaped | 15 |
| `h3_mismatch` | Browser UA but stays on H1/H2 across multiple Alt-Svc hints | 8 |

### ML signal

| Signal | What it catches | Points |
|---|---|---|
| `ml_agent_score` | Online Naive Bayes + Isolation Forest agreement | configurable, capped |

**How they combine:** total score is the sum of every signal's
points, capped at 100. The `decide()` function then routes based on
the configured thresholds.

**How to tune:** edit `rules/detector.yaml` (full reference at
[docs/config/rules/detector.md](../config/rules/detector.md)). Changes
hot-reload within ~500 ms.

---

## IP reputation, fleet rotation, UA rotation

Driven by [`rules/ip_reputation.yaml`](../config/rules/ip-reputation.md).

### `ip_reputation`

**What it does:** classifies the client IP against operator-editable
CIDR lists (`tor_exits`, `cloud`, `vpn`, `anonymizer`, `rfc1918_leak`,
…). Each category has a points contribution.

**Enable:** add CIDRs and category points under `categories:` in
`rules/ip_reputation.yaml`.

**What happens:** matching IPs contribute the category's points to
their score. Cloud-tagged IPs (AWS, GCP, etc.) typically score
~15, Tor exits ~30, anonymizers ~40.

### `ip_rotation_fleet`

**What it does:** detects N distinct IPs sharing one *behavioural
fingerprint* (UA family + JA4 prefix + header bitmap + method) in a
rolling window. The fingerprint deliberately excludes the client IP,
so a rotating attacker behind a proxy farm collapses to one entry.

**Enable:**
```yaml
fleet_rotation:
  enabled: true
  window_seconds: 600
  max_fingerprints: 20000
  tiers:
    - distinct_ips: 50
      points: 40
    - distinct_ips: 20
      points: 25
    - distinct_ips: 10
      points: 15
```

**What happens:** an attacker rotating through 50+ residential
proxies all running the same scraper hits the highest tier and
tarpits.

### `ua_rotation`

**What it does:** detects one client IP cycling through N+ distinct
User-Agents inside the tracker window. Dirsearch / ffuf with a UA
pool look like nothing else.

**Enable:**
```yaml
ua_rotation:
  enabled: true
  distinct_uas_for_fire: 3
  points: 30
```

**What happens:** any client whose `state.UniqueUAs` set reaches the
threshold gets a flat 30-point bump.

---

## Online ML signal

Driven by [`rules/ml.yaml`](../config/rules/ml.md). Auto-on when `enabled: true`.

**What it does:** combines online Naive Bayes + Isolation Forest
over per-request feature vectors. The NB classifier learns the
"agent vs human" boundary from weak-label training (any request that
exceeds the rule-based challenge threshold is labelled "agent" for
the NB); the iso-forest scores anomaly. Both contribute to a single
`ml_agent_score` signal.

**Enable:**
```yaml
# rules/ml.yaml
enabled: true
score_max_points: 40
min_confidence_to_fire: 0.2
bayes:
  laplace_smoothing: 1.0
  max_ngram_length: 4
iso_forest:
  tree_count: 100
  sample_size: 256
  retrain_every_n_events: 5000
```

**What happens when enabled:**

- Each request goes through the feature extractor (path n-grams,
  header bitmap, JA4 prefix, gap-since-last-request bucket, etc.).
- The NB scores `P(agent | features)`.
- The iso-forest scores anomaly (how far this point is from learned
  clusters).
- Combined confidence × `score_max_points` becomes the
  `ml_agent_score` signal.
- Below `min_confidence_to_fire`, no points are added (silent on
  uncertain classifications).
- A background goroutine refits the iso-forest every
  `retrain_every_n_events` observations.
- A miner runs periodically and proposes high-confidence rules into
  `rules/learned.yaml` for operator promotion.

**See also:** [docs/config/rules/ml.md](../config/rules/ml.md), [docs/how-to/promote-learned-rules.md](../how-to/promote-learned-rules.md).

---

## TLS fingerprint catalogue

Driven by [`rules/tls_fingerprints.yaml`](../config/rules/tls-fingerprints.md).

**What it does:** maps JA3 / JA4 hashes to known clients (`curl`,
`python-requests`, `Go-http-client`, `Chrome 145`, `Firefox 130`,
…). Categories are `agent`, `scanner`, `bot`, `browser`, `unknown`.

**Enable:** auto-on when `tls.enabled: true` (you need the TLS
listener to capture the fingerprints). Customise the catalogue by
editing the YAML.

**What happens:** the `scoreTLS` and `scoreH2` signals consult this
catalogue and contribute to the score per the table above.

---

## Tarpit content

The tarpit response — what the attacker sees when their score lands
above the tarpit threshold — is composed from three rule files.

### `rules/templates.yaml`

**What it does:** defines response templates with status, headers,
content-type, and body. Bodies use `text/template` syntax.

### `rules/injection_strategy.yaml`

**What it does:** maps request paths to template selections. Wildcard
matching + per-route payload weights so the same path can rotate
through different decoys.

### `rules/payloads.yaml`

**What it does:** the library of prompt-injection payloads inserted
into HTML comments and other unobservable response slots.
Operator-editable so you can match the threat model (anti-LLM-agent
specifically, or generic anti-scraper).

**Enable:** all three are hot-reloaded; tune to fit your decoy
strategy.

**What happens when included:** the tarpit handler renders a
combination of template + payload at request time. The result looks
like a real (but useless) response — fake `404`s with prompt
injections, fake `200`s with bogus JSON, fake config files.

---

## Cross-cutting features

### Rules hot-reload

**What it does:** any file under `rules_dir` reloads within ~500 ms
of being changed, with no proxy restart needed. Bad YAML doesn't
take the proxy down — the old value stays in the runtime holder.

**Enable:** set `rules_dir` to a path in `veilgate.yaml`. The
watcher starts automatically.

**What happens:** operators can iterate on detection rules / tarpit
templates / dashboard layout in production. fsnotify drives it; the
watcher debounces multi-event editor saves.

### HTTP/2 SETTINGS fingerprinting

**What it does:** auto-on whenever a client connects over HTTP/2.
The fingerprint database lives in code (`internal/h2fp/database.go`)
and contains known agents (`hyper`, `okhttp`, `go-http-client`) and
real browsers.

**Enable:** automatic. Requires HTTP/2 capability on the client side
to fire — HTTP/1.1-only clients won't surface this signal.

**What happens:** `h2_agent` / `h2_bot` / `h2_non_browser` signals
contribute to score. Cheap to compute, hard to spoof — agents would
have to ship a full HTTP/2 stack with browser-shaped SETTINGS frames
to bypass.

### `/__veilgate/verify` endpoint

**What it does:** the path the challenge JS POSTs the solved nonce
to. Returns `200 OK` + JSON body `{token, expires_in, header}` plus
`Set-Cookie` carrying the same token.

**Enable:** automatic; the proxy intercepts this path before
scoring.

**What happens:** real users solving a challenge transparently hit
this endpoint, receive their cookie, and the next request goes
through normally.

### `VEILGATE_SECRET` env var

**What it does:** overrides `challenge.secret` at startup.

**Enable:** set in the process environment (systemd `Environment=`
drop-in, Docker `-e`, etc.).

**What happens:** the env value wins over the YAML value. veilgate
refuses to start in non-observe modes if the resulting secret is
the documented placeholder.

---

## What's not configurable (intentionally)

For completeness — things you can't tune via YAML:

- **Tarpit-overrides-cookie rule** ([proxy.go:226-228](../../internal/proxy/proxy.go#L226-L228)).
  A valid PoW cookie or verifier acceptance can never demote a
  tarpit-tier score to real. This is the load-bearing security
  invariant; making it configurable would defeat the purpose.
- **Score cap at 100.** Signals can fire any point value, but the
  total is clamped. Otherwise a single request with all signals
  firing could reach 300+, which makes threshold tuning incoherent.
- **Constant-time comparisons.** Every HMAC check uses `hmac.Equal`.
  Not a knob.
- **PoW solve-window hard cap.** The 10-minute ceiling on how long a
  server-issued challenge can be redeemed is a code constant
  ([challenge.go:271-274](../../internal/challenge/challenge.go#L271-L274))
  — the cookie TTL is operator-tunable but the *solve* window isn't.

---

## See also

- [Configuration reference](../config/README.md) — one page per top-level section
- [How configuration is resolved](../config/overrides.md) — embedded defaults vs operator files vs env vars
- [How-to guides](../how-to/README.md) — task-oriented walkthroughs
- [Architecture](../architecture/README.md) — system-level diagrams
- [Use cases](../usecases/README.md) — objective-driven examples
