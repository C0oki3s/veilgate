# Codebase Coverage Matrix

This matrix maps every top-level command and internal package to the
documentation page that explains its behavior. Use it as a coverage checklist
when adding code or changing runtime behavior.

## Commands

| Code path | Purpose | Primary docs | Coverage |
| --- | --- | --- | --- |
| `cmd/veilgate/main.go` | Main proxy process, config loading, subsystem wiring, listeners, rule watcher, background jobs. | [Operator and test tooling](tooling.md), [Module veilgate_core](../modules/veilgate_core.md), [How request processing works](../architecture/request-processing.md) | Covered |
| `cmd/veilgate/forget.go` | Delete persisted client data and write audit evidence. | [Module veilgate_audit](../modules/veilgate_audit.md), [Operator and test tooling](tooling.md) | Covered |
| `cmd/replay/main.go` | Offline re-score of persisted events with current rules. | [Operator and test tooling](tooling.md) | Covered |
| `cmd/mlsmoke/main.go` | In-process ML, persistence, and miner smoke test. | [Operator and test tooling](tooling.md), [Module veilgate_ml](../modules/veilgate_ml.md) | Covered |
| `cmd/localreq/main.go` | Local traffic generator for normal, challenge, malicious, and mixed traffic. | [Operator and test tooling](tooling.md) | Covered |

## Internal Packages

| Package | Purpose | Primary docs | Coverage |
| --- | --- | --- | --- |
| `internal/audit` | Hash-chained audit events and audit backends. | [Module veilgate_audit](../modules/veilgate_audit.md) | Covered |
| `internal/challenge` | Proof-of-work challenge, signed cookies, verify endpoint, SPA response. | [Module veilgate_challenge](../modules/veilgate_challenge.md) | Covered |
| `internal/config` | Top-level `veilgate.yaml` structs, defaults, and config loading. | [Module veilgate_core](../modules/veilgate_core.md), [Configuration reference](../config/README.md) | Covered |
| `internal/detector` | Score calculation, signal helpers, tracker, fleet rotation, canary, ML and protocol hooks. | [Module veilgate_detector](../modules/veilgate_detector.md), [Decision flow](decision_flow.md) | Covered |
| `internal/h2fp` | HTTP/2 SETTINGS fingerprint store, database, and classifier. | [Module veilgate_http2_fingerprinting](../modules/veilgate_http2_fingerprinting.md) | Covered |
| `internal/ml` | Feature extraction, online scoring, Bayes, Isolation Forest, miner candidates. | [Module veilgate_ml](../modules/veilgate_ml.md) | Covered |
| `internal/payloads` | Decoy and prompt-injection payload library and injector. | [Module veilgate_tarpit](../modules/veilgate_tarpit.md), [Rule customization guide](../config/rules/customization.md) | Covered |
| `internal/persist` | SQLite store, event queue, rollups, canaries, retention, forget support. | [Module veilgate_persistence](../modules/veilgate_persistence.md) | Covered |
| `internal/proxy` | Reverse proxy, effective client identity, decision dispatch, capture/persist writes. | [Module veilgate_proxy](../modules/veilgate_proxy.md), [How request processing works](../architecture/request-processing.md) | Covered |
| `internal/rules` | Embedded defaults, YAML loaders, rule watcher, atomic holders. | [Module veilgate_rules](../modules/veilgate_rules.md), [Rule customization guide](../config/rules/customization.md) | Covered |
| `internal/tarpit` | Fake profiles, route strategy, template rendering, latency, canary output. | [Module veilgate_tarpit](../modules/veilgate_tarpit.md) | Covered |
| `internal/telemetry` | Prometheus metrics, dashboard, JSONL capture. | [Module veilgate_metrics](../modules/veilgate_metrics.md), [Module veilgate_capture](../modules/veilgate_capture.md) | Covered |
| `internal/tlsfp` | TLS ClientHello capture, JA3/JA4 parsing, TLS fingerprint database/classifier. | [Module veilgate_tls_fingerprinting](../modules/veilgate_tls_fingerprinting.md) | Covered |
| `internal/verifier` | Verifier chain and HMAC request verification. | [Module veilgate_verifier](../modules/veilgate_verifier.md) | Covered |

## Rule Files

| Rule file | Loader or owner | Primary docs | Hot reload |
| --- | --- | --- | --- |
| `rules/detector.yaml` | `rules.LoadDetector` | [Rule customization guide](../config/rules/customization.md) | Yes |
| `rules/ip_reputation.yaml` | `rules.LoadIPReputation` | [Rule customization guide](../config/rules/customization.md) | Yes |
| `rules/tls_fingerprints.yaml` | `rules.LoadTLS` | [Module veilgate_tls_fingerprinting](../modules/veilgate_tls_fingerprinting.md) | Yes, when TLS database exists |
| `rules/templates.yaml` | `rules.LoadTemplates` | [Module veilgate_tarpit](../modules/veilgate_tarpit.md) | Yes |
| `rules/injection_strategy.yaml` | `rules.LoadInjectionStrategy` | [Module veilgate_tarpit](../modules/veilgate_tarpit.md) | Yes |
| `rules/payloads.yaml` | `rules.LoadPayloads` / `payloads.NewLibraryFromDir` | [Rule customization guide](../config/rules/customization.md) | No, restart required |
| `rules/fake_data.yaml` | `rules.LoadFakeData` | [Module veilgate_tarpit](../modules/veilgate_tarpit.md) | Yes |
| `rules/vulnerabilities.yaml` | `rules.LoadVulnerabilities` | [Rule customization guide](../config/rules/customization.md) | Yes |
| `rules/challenge.yaml` | `rules.LoadChallenge` | [Module veilgate_challenge](../modules/veilgate_challenge.md) | Yes |
| `rules/ml.yaml` | `rules.LoadML` | [Module veilgate_ml](../modules/veilgate_ml.md) | Yes |
| `rules/dashboard.yaml` | `rules.LoadDashboard` | [Module veilgate_metrics](../modules/veilgate_metrics.md) | Yes |
| `rules/learned.yaml` | `ml.Miner` / `rules.LoadLearned` | [Module veilgate_ml](../modules/veilgate_ml.md) | Miner-managed |

## Current Explicit Gaps

No runtime package or command is undocumented in this matrix. The one deliberate
implementation caveat is HTTP/2 fingerprint rule loading: `internal/h2fp`
contains database and classifier types, but the current tree does not include a
YAML loader or watcher for `rules/h2_fingerprints.yaml`.
