# Changelog

All notable changes to VeilGate are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.1.5] — 2026-05-29

### Added

- **Async metrics bus** (`internal/telemetry`): `DefaultBus` — a 512-slot
  non-blocking event dispatcher that fans every scored request, tarpit
  session, challenge lifecycle, ML fit, 30 s periodic gauge snapshot,
  verifier outcome, and recommender pass to all registered sinks without
  stalling the reverse-proxy hot path. Inspired by LiteLLM's async callback
  pattern. Seven `EventKind` values: `KindRequest`, `KindTarpit`,
  `KindChallenge`, `KindMLFit`, `KindPeriodic`, `KindVerifier`,
  `KindRecommender`.

- **Full OTel/Prometheus parity**: 35+ OpenTelemetry instruments now cover
  every metric that Prometheus exposes, achieved via two mechanisms:
  - **Atomic bridges** — three package-level `atomic.Int64` vars
    (`TarpitActiveCount`, `BayesEvictionsCount`, `MinerCandidatesCount`)
    are read by the 30 s periodic ticker and included in `PeriodicEvent`,
    so `OTelSink` can update gauge/counter instruments without direct
    call-site changes.
  - **Two new EventKinds** — `KindVerifier` (emitted by the upload credential
    path on every accepted/rejected/none outcome) and `KindRecommender`
    (emitted at the end of each recommender analysis pass) route previously
    Prometheus-only events to `OTelSink`.
  - Six instruments added to `OTelSink` that were previously missing:
    `veilgate.tarpit.active_sessions` (Int64Gauge),
    `veilgate.ml.bayes_evictions.total` (Int64Counter),
    `veilgate.ml.miner_candidates.total` (Int64Counter),
    `veilgate.verifier.result.total` (Int64Counter),
    `veilgate.recommender.suggestions_last` (Int64Gauge),
    `veilgate.recommender.analysis_duration` (Float64Histogram).

- **Decision-based log severity** (`internal/proxy`): request log lines now
  carry a zerolog level that reflects the routing decision —
  `tarpit → error` (red in SigNoz), `challenge → warn` (yellow),
  `real / observe → info` (blue). Previously all request lines were `info`.

- **`threat_level` log attribute**: every request log line now includes a
  `threat_level` field derived from the raw score:
  `0–29 → low`, `30–59 → medium`, `60–79 → high`, `80–100 → critical`.
  Stable string values usable as SigNoz filter values without needing to
  know the numeric threshold bands.

- **OTel log bridge** (`internal/telemetry/otel_logbridge.go`): `OTelLogWriter`
  is an `io.Writer` that intercepts each zerolog JSON line, parses the
  `level` field into an OTel `SeverityNumber`, and emits a structured
  `LogRecord` to the global `LoggerProvider` via `OTLP/HTTP`. The bridge is
  a multi-writer alongside `os.Stderr`, so logs always appear on the console
  AND flow to the remote collector when `telemetry.logs.enabled: true`.
  Severity mapping: `trace→TRACE`, `debug→DEBUG`, `info→INFO`,
  `warn→WARN`, `error→ERROR`, `fatal/panic→FATAL`.

- **`signals.yaml` in veilgate-rules**: a complete operator-facing registry of
  all 43 built-in signals, each with `enabled: true`, a multi-line
  description, and a comprehensive comment block explaining every custom-signal
  condition type. Intended as a starter file that operators copy and edit;
  shipping it in veilgate-rules means `veilgate update-rules` keeps the
  description set up to date without a binary rebuild.

### Changed

- **Prompt injection payloads removed** from tarpit responses. Both
  `payloads/prompt-injection.yaml` and the `prompt_injection` section of
  `payloads/high-risk-exposure-breadcrumbs.yaml` are cleared to empty lists.
  The injection infrastructure remains in place (ready if any operator
  has local payloads configured); the default rule set no longer ships active
  prompt injection content.

### Fixed

- **`TestVeilgateRulesPayloadInjection`** smoke test assertion updated:
  the test previously checked for `json_field`-style text ("Public Exposure of
  High-Risk Administrative") in HTML output, which can never appear because
  `injectHTML` only selects `html_comment`/`html_hidden`/`log_noise` style
  payloads. Assertion now checks for `"exposure-audit"` which is present in
  the `html_comment`-style `rabbit_hole` payload.

### Maintenance

- **`configs/dashboards/` untracked from git**: SigNoz dashboard JSON files
  are managed via the SigNoz UI and are now gitignored.  
  `git rm --cached` removes them from the index without deleting the local
  files. Operators manage dashboards through the SigNoz import workflow.

### Documentation

- `CHANGELOG.md` — this entry.
- `docs/architecture/request-processing.md` — Phase 9 updated to document
  the metrics bus, OTel log bridge, and decision-based severity.
- `docs/functionalities/detection-signals.md` — full rewrite: all 43 built-in
  signals with group, default points, what they detect, and routing impact.
- `docs/functionalities/detector-score-system.md` — added `threat_level`
  attribute reference, score tier table (low/medium/high/critical).
- `docs/how-to/opentelemetry.md` — updated to cover all three OTel signals
  (traces, structured logs, metrics push) and the v1.1.5 log severity routing.
- `docs/functionalities/metrics-dashboard.md` — OTel instrument names added
  alongside Prometheus metric names in the reference table.

---

## [1.1.4] — 2026-05-28

### Added

- **Signal recommender** (`internal/recommender`): background analysis engine
  that scans persisted request data and emits candidate custom-signal
  definitions. Runs on a configurable interval and writes suggestions to
  `rules/signals.yaml`. Two new Prometheus metrics track analysis cadence:
  `veilgate_recommender_suggestions_last` and
  `veilgate_recommender_analysis_duration_seconds`.

- **Behavioral signals** — five new session-level anomaly signals:
  - `cache_miss_anomaly` — requests that always bypass cache, consistent with
    headless polling.
  - `regular_timing` — inter-request interval coefficient of variation below
    the configured threshold, indicating scripted cadence.
  - `bundle_mining` — disproportionate requests to JS/CSS asset bundles without
    corresponding page views.
  - `recovery_pivot` — client pivots to a different path family immediately
    after a 4xx, consistent with automated probe-and-retry.
  - `graph_doc_heavy` — GraphQL introspection and schema requests dominate the
    session, consistent with API mapping.

- **Session ML dimensions**: per-session feature vector now includes 12
  additional dimensions (request entropy, path diversity, method mix, timing
  regularity, header consistency) improving Bayes and Isolation Forest
  discrimination between humans and bots.

- **Per-IP response cache** (`internal/tarpit/response_cache.go`): scored
  requests that reach the tarpit reuse a previously-rendered response for the
  same client within a short TTL. Reduces CPU and memory pressure under
  sustained single-source attacks without changing what the attacker sees.

- **API blueprint miss signal** (`internal/blueprint`): operator drops an
  OpenAPI spec or a simple routes list into `rules_dir`; VeilGate fires
  `api_blueprint_miss` (15 pts, family `recon`) whenever a client probes a
  path that is in the API namespace but not in the documented routes. Accepts
  three formats: simple `routes:` list, OpenAPI 3.x `paths:` block, and
  Swagger 2.0 with `basePath`. Priority order: `api_blueprint.yaml` →
  `api_blueprint.json` → `openapi.yaml` → `openapi.json`. Hot-reloaded on
  file change.

- **Comprehensive observability** (`internal/telemetry`):
  - **37+ Prometheus metrics** across 10 categories: traffic/latency,
    detector signals, endpoint correlation, challenge funnel, tarpit sessions,
    online ML (Bayes cap, Isolation Forest), signal recommender, persistence
    queue, verifier outcomes, and infrastructure cardinality. New metrics
    include per-decision latency histogram, challenge issued/solved/failed
    counters, tarpit active sessions gauge, ML Bayes entries/evictions, persist
    queue depth and drop rate, verifier accepted/rejected split, and four
    endpoint-correlation counters.
  - **Endpoint correlation** — four `path_bucket`-keyed counter vectors that
    share a common label for PromQL joins: `veilgate_endpoint_request_total`,
    `veilgate_endpoint_signal_total`, `veilgate_endpoint_attack_family_total`,
    `veilgate_endpoint_score_tier_total`. Path normalisation replaces UUIDs,
    numeric IDs, and long hex tokens with `{id}` and caps depth at 4 segments
    to prevent cardinality explosion. Signals are grouped into 9 attack
    families (`recon`, `auth`, `injection`, `evasion`, `fingerprint`,
    `behavioral`, `fleet`, `toolchain`, `ml`).
  - **OpenTelemetry tracing**: two spans per tarpitted or scored request —
    `veilgate.serve` (full pipeline) and `veilgate.tarpit` (delay + render,
    nested). Activated by setting `OTEL_EXPORTER_OTLP_ENDPOINT`; pure no-op
    with zero overhead when unset. Sampling controlled via
    `OTEL_TRACES_SAMPLER` (default 1 % `parentbased_traceidratio`). Each
    fired signal is attached as a span event with `name`, `points`, and
    `reason` fields. Attack families emitted as `veilgate.attack_families`
    span attribute. Status set to `Error` for tarpit and challenge decisions
    so trace UIs can filter diverted requests.

- **Scorer refactor** (`internal/detector`): monolithic `scorer.go` split into
  seven focused files — `scorer_behavioral.go`, `scorer_headers.go`,
  `scorer_network.go`, `scorer_session.go`, `scorer_timing.go`,
  `scorer_toolchain.go`, `scorer_custom.go`. Reduces merge surface and makes
  individual signal groups independently testable.

### Fixed

- **Blueprint cache DoS prevention**: cache entries are pre-claimed with an
  atomic counter before `sync.Map.LoadOrStore` so concurrent goroutines cannot
  race past the 4 096-entry cap. Under path-flooding attacks (random UUIDs in
  paths) the cache degrades gracefully rather than growing unboundedly.
- **Bayes cap hardening**: `evictLowest` uses a 16-candidate approximation
  instead of a full scan, keeping eviction O(1) regardless of cap size.
  `TotalEntries()` is now an exported accessor so the operator dashboard can
  expose live cap utilisation without locking.
- **Config-driven behavioral thresholds**: `regular_timing` coefficient of
  variation, `bundle_mining` ratio, and `recovery_pivot` error rate are now
  YAML-configurable via `detector:` rather than compiled constants. Existing
  configs that omit these keys retain the previous defaults.
- **Critical and medium reliability issues** (infra audit): nil pointer guards
  on blueprint hot-reload path; per-IP cache TTL enforced under concurrent
  eviction; ML scorer context cancellation propagated correctly through the
  refit goroutine; persist queue depth counter now tracked accurately across
  process restart.
- **Prometheus cardinality**: endpoint-correlation `path_bucket` label normalises
  variable segments before emission, preventing label-set explosion under
  UUID-heavy API traffic.

### Documentation

- `docs/how-to/opentelemetry.md` — new guide: OTLP setup, sampling config,
  span attribute reference, filter recipes for Jaeger/Tempo/SigNoz, collector
  config snippets.
- `docs/how-to/endpoint-correlation.md` — new guide: four-metric correlation
  model, path normalisation rules, attack-family table, score-tier table,
  Grafana panel recipes, 5-step investigation workflow.
- `docs/how-to/api-blueprint.md` — new guide: all three input formats, namespace
  inference, hot-reload, signal weight tuning.
- `docs/operations/prometheus-queries.md` — 12 new query sections covering
  endpoint correlation, challenge funnel, tarpit active sessions and content
  type, Bayes cap health, verifier outcomes, persist health, and recommender
  metrics.
- `docs/functionalities/metrics-dashboard.md` — full metrics reference table
  covering all 37+ metrics across 10 categories.
- `docs/config/metrics.md` — added `api_key` bearer-token parameter for
  protecting `/api/*` dashboard endpoints.

---

## [1.1.3] — 2026-05-24

### Added

- **Decoy path system** — operator-configurable bait endpoints that are
  published via `/__veilgate/.well-known` and consumed by both SDKs to inject
  realistic agent breadcrumbs across every surface: browser DOM, API response
  headers, and server-to-server contexts.

  - **`veilgate-rules/decoy_paths.yaml`**: new rules file with ~55 pre-built
    bait paths across SSRF/cloud-metadata, secrets, git/VCS, admin panels,
    OpenAPI docs, Spring Actuator, HashiCorp Vault/Consul, Kubernetes,
    Elasticsearch, Grafana, Stripe, OAuth, and OpenAI-proxy categories.
    Supports a `decoy_paths/` subdirectory for community additions (same merge
    pattern as all other rules). Hot-reloaded by the watcher on file change.

  - **`/__veilgate/.well-known` — new `tarpit` field**: the discovery document
    now includes a `tarpit.paths` array so SDKs always inject paths the proxy
    is actively tarpitting, not a disconnected default list.

  - **`@veilgate/client` — agent decoy system**: reads `tarpit.paths` from
    `.well-known` and injects a random subset as DOM breadcrumbs (`<script
    type="application/json">` + `<meta>` in `document.head`) per page load.
    Falls back to a built-in pool of ~50 paths when the server has no
    `decoy_paths.yaml` configured. New `updateDecoys(false | true |
    Partial<AgentDecoyOptions>)` export lets callers enable, disable, or
    reconfigure decoys at runtime without reinitialising the SDK; disabling
    removes the injected DOM elements via `data-vg-runtime` attribute selector.

  - **`@veilgate/node` — decoy response middleware**: three new exports for
    injecting tarpit breadcrumbs into API responses so agents probing the API
    via raw HTTP or API clients discover bait paths in response headers:
    - `fetchDecoyPaths(baseURL?)` — fetches `.well-known`, caches for 60 s.
    - `decoyResponseHeaders(paths, opts?)` — pure function; builds `Link`
      (RFC 8288), `X-Api-Documentation`, and `X-Debug-Endpoint` headers.
    - `decoyMiddleware(opts?)` — Express/Fastify/Node-compatible middleware
      that discovers paths on first request and injects headers on every
      response. Returns a `DecoyMiddlewareFn` with `.setEnabled(bool)` and
      `.update(Partial<DecoyOptions>)` for runtime control without recreating
      the middleware.

---

## [1.1.1] — 2026-05-22

### Added
- **`veilgate update` subcommand**: self-update the binary from the latest
  (or a pinned) GitHub release. Downloads the platform-specific tar.gz,
  verifies the SHA-256 checksum against `checksums.txt`, extracts the binary,
  and atomically replaces the running executable. Requires write permission to
  the install directory (typically `sudo veilgate update`).
  - `--version v1.x.y` — install a specific release instead of latest.
  - `--check` — print whether an update is available and exit without
    installing (exits 2 when an update exists, 0 when up to date).
- **Upload policies** (`upload_policies`): explicit path-based upload rules
  with method allowlists, maximum body size, MIME prefix checks,
  `require_auth`, route-specific upstream response timeout, and optional
  `skip_body_hmac` verifier policy for large streaming uploads.
- **h2c support**: plain HTTP listeners now accept HTTP/2 prior-knowledge and
  h2c upgrade clients while preserving the HTTP/1.x framing guard.
- **Configurable start interstitial template**: `challenge.yaml` can now set
  `start_page_template`; the built-in `/__veilgate/start` HTML remains the
  fallback.

### Fixed
- **CORS handling for challenged/tarpitted cross-origin traffic**: VeilGate now
  handles CORS preflights for `/__veilgate/*`, forwards application preflights
  upstream, and emits CORS headers on challenge, tarpit, WebSocket block, gRPC
  block, and upload policy block responses.
- **Upload streaming limit responses**: chunked HTTP/1.1 and HTTP/2 uploads
  with unknown `Content-Length` are counted while proxying and return `413`
  instead of surfacing as a generic `502`.
- **HTTP request smuggling hardening**: ambiguous HTTP/1.x framing is rejected
  before `net/http` normalization, including CL+TE, duplicate
  `Content-Length`, obsolete folded headers, HTTP/1.0 transfer coding, and
  non-`chunked` transfer codings.
- **HTTP/2 WebSocket extended CONNECT handling**: detected separately and
  rejected with `501 {"error":"http2_websocket_unsupported"}` rather than
  falling into the HTTP/1.1 `Hijacker` path.

### Documentation
- Added upload policy configuration and functionality documentation.
- Added request classification documentation for authentication, CORS, uploads,
  WebSocket/gRPC, tarpit, and HTTP version handling.
- Updated proxy routing and WebSocket/gRPC docs for h2c and HTTP/2 extended
  CONNECT behavior.

---

## [1.1.0] — 2026-05-22

### Added
- **WebSocket tunnelling** (`internal/proxy`): VeilGate now proxies WebSocket
  upgrade connections. The full scoring and decision pipeline runs on the
  initial HTTP upgrade request; accepted connections are hijacked and tunnelled
  to upstream over TCP (TLS when upstream URL is `https://`/`wss://`).
- **gRPC and gRPC-Web proxying** (`internal/proxy`): gRPC requests
  (`Content-Type: application/grpc*`) are routed through a dedicated reverse
  proxy with no `ResponseHeaderTimeout` and immediate flush — required for
  long-lived streaming RPCs.
- **Machine-readable block responses for WebSocket and gRPC**: challenged
  WebSocket upgrades return `503 {"error":"challenge_required"}`; tarpitted
  upgrades return `403 {"error":"forbidden"}`. Challenged gRPC calls return
  `grpc-status: 16` (UNAUTHENTICATED); tarpitted calls return `grpc-status: 7`
  (PERMISSION_DENIED). HTML challenge pages are never served to non-browser
  callers.
- **`docs/functionalities/websocket-grpc-proxy.md`**: per-mode behaviour
  tables, tarpit asymmetry explanation, SPA + socket.io integration guide,
  gRPC wire format reference.
- **`docs/usecases/replace-your-waf.md`**: use-case guide covering coverage
  map vs. signature WAFs, full rollout sequence, migration path, CDN proxy
  configuration, and operational gotchas.
- **`docs/config/verifiers.md`**: added `bearer:`, `cookies:`, and `headers:`
  config sections with field tables and YAML examples. Previously only `hmac:`
  was documented.

### Fixed
- **`--secret` flag for installer** (`scripts/install.sh`): non-interactive
  and CI installs can now pass the challenge signing secret directly instead of
  requiring a TTY prompt. Prompts interactively when omitted on a TTY; generates
  a random secret otherwise.
- **`--user` flag for installer**: allows deploying under an existing system
  user instead of always creating `veilgate`. Adapts `rules_dir` when the
  existing user's home differs from `/var/lib/veilgate`.
- **Nil-config ML guards** (`internal/ml`): `Scorer.Score`,
  `Scorer.RefitIsoForest`, `Miner.Tick`, and `Miner.interval` now return
  safe zero values when the ML config holder is nil (e.g., when `ml.yaml`
  fails to load at startup) rather than panicking.
- **ML rules load error handling** (`cmd/veilgate/main.go`): logs a warning
  and falls back to an empty `&rules.ML{}` instead of silently ignoring a
  failed `ml.yaml` load.
- **Broken cross-link** (`docs/reference/verifiers/cookie.md`): replaced
  non-existent `Challege.md` reference with the correct
  `docs/reference/endpoints/start.md` link.

---

## [1.0.0] — 2026-05-20

### Added
- **Credential bypass layer** — ships #1–9 (`internal/verifier`):
  - Ship #1: Bearer verifier (opaque static tokens, GitHub PAT / Stripe key model).
  - Ship #2: Cookie verifier (named cookie + pluggable validator).
  - Ship #3: Header verifier (arbitrary header name + pluggable validator).
  - Ship #4: JWT validator (JWKS-based, shared across cookie and header verifiers).
  - Ship #5: HTTP callout validator (delegates to an external endpoint with TTL cache).
  - Ship #6: `/__veilgate/.well-known` discovery endpoint (JSON, CORS-open, 60 s cache).
  - Ship #7: `/__veilgate/start` PoW interstitial (iframe-loadable for cross-origin SPAs).
  - Ship #8: `@veilgate/client` browser SDK (auto-discovery, XHR/fetch patching, iframe challenge flow).
  - Ship #9: `@veilgate/node` Node.js server SDK (bearer and HMAC signing modes).
- **GoReleaser release pipeline** (`.github/workflows/release.yml`): produces
  checksummed binary archives for Linux and macOS on tag push; pings
  `proxy.golang.org` post-release to trigger pkg.go.dev indexing.
- **Install script** (`scripts/install.sh`): one-line installer that downloads
  a release binary (or builds from source as fallback), creates the `veilgate`
  service user, writes a default config, installs community rules, and registers
  a systemd unit.
- **Community rules system** (`internal/rules`): replaces compiled-in defaults
  with a versioned directory layout; `veilgate update-rules` pulls the latest
  release from the `veilgate-rules` repository.
- **HMAC verifier** (`internal/verifier/hmac.go`): Stripe-style per-request
  signatures covering timestamp, method, path, and body hash; per-client secret
  files with hot-reload on mtime change.
- **Cross-origin SPA challenge support** (`internal/challenge`): `/__veilgate/verify`
  returns structured JSON for `Accept: application/json` requests, enabling the
  `@veilgate/client` SDK iframe flow.
- **Install permission recovery guide**
  (`docs/how-to/install-on-linux.md`): documents group ownership recovery
  for `/etc/veilgate` after a failed install.

### Fixed
- `set -e` / command-substitution bug in `scripts/install.sh` that caused
  early exit on some shells.
- Checksum mismatch on missing release assets (install script now falls back
  to source build cleanly).
- Docker image: pre-creates writable rules directory so the ML miner can write
  `learned.yaml` without a volume mount.
- Rules dir path normalisation — tilde expansion for `~/.veilgate/rules` was
  not applied consistently across all code paths.
- Nil-safe ML scorer: unreachable tarpit threshold now logs a warning rather
  than silently misconfiguring the decision bands.
- systemd service unit: added explicit group ownership on `/etc/veilgate` so
  the `veilgate` service user can read the config file.

---

## [0.1.0] — 2026-05-09

### Added
- Initial release.
- Reverse-proxy core with `observe`, `challenge`, `tarpit`, and `auto` modes.
- Behavioural scoring engine: path fan-out, request rate, UA fingerprint,
  IP reputation, IP fleet rotation, honeypot hits.
- TLS (JA3/JA4) and HTTP/2 fingerprinting signals.
- Proof-of-work challenge handler (JavaScript nonce search in the browser).
- Tarpit handler: per-client fake application profiles, configurable latency,
  payload injection, canary markers.
- Online ML: Naive Bayes classifier + Isolation Forest; miner writes
  `learned.yaml` on each tick.
- Persistence event store (SQLite via `modernc.org/sqlite`).
- Request capture (JSONL with scrub rules and retention janitor).
- Prometheus metrics endpoint.
- Real-time dashboard (last-N events ring buffer).
- Docker image and GitHub Actions CI pipeline.
- Full documentation set: architecture, config reference, module reference,
  operations guides, internals, and use-case pages.

---

[Unreleased]: https://github.com/C0oki3s/veilgate/compare/v1.1.5...HEAD
[1.1.5]: https://github.com/C0oki3s/veilgate/compare/v1.1.4...v1.1.5
[1.1.4]: https://github.com/C0oki3s/veilgate/compare/v1.1.3...v1.1.4
[1.1.3]: https://github.com/C0oki3s/veilgate/compare/v1.1.1...v1.1.3
[1.1.1]: https://github.com/C0oki3s/veilgate/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/C0oki3s/veilgate/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/C0oki3s/veilgate/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/C0oki3s/veilgate/releases/tag/v0.1.0
