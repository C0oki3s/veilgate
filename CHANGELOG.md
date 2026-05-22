# Changelog

All notable changes to VeilGate are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

No unreleased changes yet.

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

[Unreleased]: https://github.com/C0oki3s/veilgate/compare/v1.1.1...HEAD
[1.1.1]: https://github.com/C0oki3s/veilgate/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/C0oki3s/veilgate/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/C0oki3s/veilgate/compare/v0.1.0...v1.0.0
[0.1.0]: https://github.com/C0oki3s/veilgate/releases/tag/v0.1.0
