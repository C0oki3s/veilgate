# VeilGate Module Reference

The pages in this directory use an NGINX-style reference structure:
module purpose, example configuration, directive list, syntax/default/context
blocks, implementation code path, operational notes, validation commands, and
limitations.

## Modules

| Module | Purpose |
| --- | --- |
| [veilgate_core](veilgate_core.md) | Top-level listener, upstream, mode, and rules directory. |
| [veilgate_proxy](veilgate_proxy.md) | Reverse proxy behavior, decision dispatch, trusted proxies, and client identity. |
| [veilgate_detector](veilgate_detector.md) | Score thresholds, tracker window, honeypots, and detector signals. |
| [veilgate_challenge](veilgate_challenge.md) | Proof-of-work challenge, signed tokens, cookies, and SPA header transport. |
| [veilgate_tarpit](veilgate_tarpit.md) | Fake application responses, route selection, payload injection, and latency controls. |
| [veilgate_tls_fingerprinting](veilgate_tls_fingerprinting.md) | TLS termination and JA3/JA4 classification. |
| [veilgate_http2_fingerprinting](veilgate_http2_fingerprinting.md) | HTTP/2 SETTINGS fingerprint store, classifier, detector signals, and current loader limitation. |
| [veilgate_persistence](veilgate_persistence.md) | SQLite event store, canaries, retention, dumps, and forget support. |
| [veilgate_capture](veilgate_capture.md) | JSONL request capture, rotation, retention, and scrubbing. |
| [veilgate_metrics](veilgate_metrics.md) | Prometheus metrics and built-in dashboard. |
| [veilgate_rules](veilgate_rules.md) | External YAML rule files and hot reload. |
| [veilgate_ml](veilgate_ml.md) | Optional online ML scoring and learned-rule mining. |
| [veilgate_verifier](veilgate_verifier.md) | HMAC verifier chain for trusted server-to-server callers. |
| [veilgate_audit](veilgate_audit.md) | Hash-chained audit logging and the `veilgate forget` command. |

## Related

- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [Rule customization guide](../config/rules/customization.md)
- [Top-level configuration](../config/top-level.md)
- [Configuration reference](../config/README.md)
- [Threat model](../../THREAT_MODEL.md)
