# VeilGate Code Map

This page maps documentation modules to implementation packages. Use it when a
configuration field needs to be traced from YAML to runtime behavior.

Repository: <https://github.com/C0oki3s/veilgate>

## Entry Points

| Path | Role |
| --- | --- |
| `cmd/veilgate/main.go` | Main proxy process, config loading, subsystem wiring, metrics server, rule watcher, TLS listener, background jobs. |
| `cmd/veilgate/forget.go` | `veilgate forget` command for deleting persisted client rows and writing an audit entry. |
| `cmd/replay/main.go` | Replay persisted events against current detector rules. |
| `cmd/mlsmoke/main.go` | ML smoke workflow for feature extraction, scoring, miner output, and persistence checks. |
| `cmd/localreq/main.go` | Local request helper. |

## Runtime Packages

| Package | Implements | Related docs |
| --- | --- | --- |
| `internal/config` | `veilgate.yaml` structs and defaults. | `veilgate_core`, config docs |
| `internal/proxy` | Reverse proxy, request pipeline, decisions, trusted proxies, capture/persist writes. | `veilgate_proxy`, request processing |
| `internal/detector` | Scoring, signal helpers, tracker integration, IP/fleet/UA rotation, TLS/H2 lookup, canary, ML hook. | `veilgate_detector` |
| `internal/challenge` | Proof-of-work challenge page, verify endpoint, token cookie/header validation. | `veilgate_challenge` |
| `internal/tarpit` | Fake profile store, route selection, response rendering, latency and body cap. | `veilgate_tarpit` |
| `internal/payloads` | Payload library and response injection. | `veilgate_tarpit`, `veilgate_rules` |
| `internal/tlsfp` | TLS ClientHello capture, JA3/JA4 parsing, fingerprint database/classifier. | `veilgate_tls_fingerprinting` |
| `internal/h2fp` | HTTP/2 SETTINGS fingerprint model and classifier. | `veilgate_http2_fingerprinting`, `veilgate_detector` |
| `internal/persist` | SQLite event store, rollups, candidates, canaries, audit mirror, retention helpers. | `veilgate_persistence` |
| `internal/telemetry` | Prometheus metrics, JSONL capture, dashboard. | `veilgate_metrics`, capture docs |
| `internal/ml` | Feature extraction, Bayes, Isolation Forest, ML scorer, rule miner. | `veilgate_ml` |
| `internal/rules` | Embedded defaults, YAML loaders, rule watcher, atomic holders. | `veilgate_rules` |
| `internal/verifier` | Verifier chain and HMAC verifier. | `veilgate_verifier` |
| `internal/audit` | Hash-chained audit logger and file/SQL backends. | `veilgate_persistence` |

## Rule Files

| Rule file | Loader | Consumed by |
| --- | --- | --- |
| `rules/detector.yaml` | `rules.LoadDetector` | `detector.Scorer` |
| `rules/ip_reputation.yaml` | `rules.LoadIPReputation` | `detector.Scorer`, `detector.FleetTracker` |
| `rules/tls_fingerprints.yaml` | `rules.LoadTLS` | `tlsfp.Database`, detector TLS lookup |
| `rules/templates.yaml` | `rules.LoadTemplates` | `tarpit.Renderer` |
| `rules/injection_strategy.yaml` | `rules.LoadInjectionStrategy` | `tarpit.Handler`, `payloads.Injector` |
| `rules/payloads.yaml` | `rules.LoadPayloads` | `payloads.Library` |
| `rules/fake_data.yaml` | `rules.LoadFakeData` | `tarpit.ProfileStore` |
| `rules/vulnerabilities.yaml` | `rules.LoadVulnerabilities` | `tarpit.Handler` |
| `rules/challenge.yaml` | `rules.LoadChallenge` | `challenge.Handler` |
| `rules/ml.yaml` | `rules.LoadML` | `ml.Scorer`, `ml.Extractor`, `ml.Miner` |
| `rules/dashboard.yaml` | `rules.LoadDashboard` | `telemetry.Dashboard` |
| `rules/learned.yaml` | `rules.LoadLearned` | `ml.Miner`, learned rule workflow |

## Config-To-Code Flow

1. `config.Load()` reads `veilgate.yaml`.
2. `applyDefaults()` fills omitted top-level values.
3. `cmd/veilgate/main.go` creates rule holders and subsystem instances.
4. `proxy.NewServer()` builds the upstream reverse proxy.
5. `proxy.Server.serve()` becomes the request hot path.
6. Background goroutines handle tracker GC, metrics cardinality, ML refit,
   miner ticks, persistence maintenance, retention trimming, and rule reload.

For complete package and command coverage, see
[Codebase coverage matrix](coverage_matrix.md). For helper command usage, see
[Operator and test tooling](tooling.md).

## Sensitive Data Locations

| Location | Why sensitive |
| --- | --- |
| `challenge.secret` / `VEILGATE_SECRET` | Signs challenge tokens. |
| `tls.key_file` | TLS private key. |
| `verifiers.hmac.clients_dir` | Shared HMAC client secrets. |
| `persist.path` | Request metadata, scores, signals, features, canaries, audit rows. |
| `capture.path` | JSONL request metadata and decisions. |
| `metrics.listen` | Exposes detector behavior and attack activity. |
| `rules/` | Security policy and deception content. |
