# VeilGate Documentation

VeilGate is a deception reverse proxy. It receives HTTP traffic, calculates a
request score, and then selects one of four decisions: `real`, `observe`,
`challenge`, or `tarpit`.

This documentation set follows the structure of NGINX module references:
module pages list directives, show syntax/default/context blocks, explain the
runtime behavior, and map each setting to the Go code that enforces it.

Repository: <https://github.com/C0oki3s/veilgate>

## Start Here

- [Docs Home](README.md)
- [Getting Started](getting-started/README.md)
- [Deployment](deployment/README.md)
- [How VeilGate Processes a Request](architecture/request-processing.md)
- [Module Reference](modules/README.md)
- [Configuration Reference](config/README.md)
- [Reference Index](reference/README.md)
- [Rule Customization Guide](config/rules/customization.md)
- [Internals code map](internals/code_map.md)
- [Operations](operations/README.md)
- [Model Card](model/README.md)
- [Threat Model](../THREAT_MODEL.md)

## Documentation Areas

| Area | Use |
| --- | --- |
| [architecture/](architecture/README.md) | Request flow and system structure |
| [config/](config/README.md) | Config blocks, rules, reload behavior, and customization |
| [modules/](modules/README.md) | Code-correlated module reference |
| [how-to/](how-to/README.md) | Task-oriented operator guides |
| [operations/](operations/README.md) | Runtime checks, dashboards, alerts, and Prometheus queries |
| [reference/](reference/README.md) | Full lookup pages |
| [product/](product/README.md) | Public narrative and business case |
| [internals/](internals/README.md) | Code map, tooling, and engineering notes |

## Module Reference

- [Module veilgate_core](modules/veilgate_core.md)
- [Module veilgate_proxy](modules/veilgate_proxy.md)
- [Module veilgate_detector](modules/veilgate_detector.md)
- [Module veilgate_challenge](modules/veilgate_challenge.md)
- [Module veilgate_tarpit](modules/veilgate_tarpit.md)
- [Module veilgate_tls_fingerprinting](modules/veilgate_tls_fingerprinting.md)
- [Module veilgate_http2_fingerprinting](modules/veilgate_http2_fingerprinting.md)
- [Module veilgate_persistence](modules/veilgate_persistence.md)
- [Module veilgate_capture](modules/veilgate_capture.md)
- [Module veilgate_metrics](modules/veilgate_metrics.md)
- [Module veilgate_rules](modules/veilgate_rules.md)
- [Module veilgate_ml](modules/veilgate_ml.md)
- [Module veilgate_verifier](modules/veilgate_verifier.md)
- [Module veilgate_audit](modules/veilgate_audit.md)

## Rules

- [Rule customization guide](config/rules/customization.md)
- [Rules config index](config/rules/README.md)
- [Module veilgate_rules](modules/veilgate_rules.md)

## Internals

- [Code map](internals/code_map.md)
- [Decision flow](internals/decision_flow.md)
- [Detector signal flow](internals/detector_signal_flow.md)
- [Tarpit rendering flow](internals/tarpit_rendering_flow.md)
- [Persistence flow](internals/persistence_flow.md)
- [Operator and test tooling](internals/tooling.md)
- [Codebase coverage matrix](internals/coverage_matrix.md)

## Operations

- [Operations Overview](operations/README.md)
- [Rollout Guide](operations/rollout.md)
- [Troubleshooting](operations/troubleshooting.md)
- [Security Hardening](operations/security_hardening.md)

## Community Rules

- [veilgate-rules repository](https://github.com/C0oki3s/veilgate-rules) — community-maintained YAML rules, versioned as GitHub Releases.
- [How-to: install community rules](how-to/install-community-rules.md) — `veilgate update-rules` walkthrough.
- [Community rules README template](community-rules-README.md) — schema reference for rule contributors.

## Operational Rollout

1. Configure `listen`, `upstream`, `rules_dir`, `metrics.listen`, and
   persistence.
2. Bind metrics to localhost or a private network.
3. Start with `mode: "observe"`.
4. Generate normal user traffic and scanner-shaped test traffic.
5. Review decision counts, top signal hits, score histogram, and high-score
   examples.
6. Tune `rules/detector.yaml` and thresholds.
7. Set `VEILGATE_SECRET`.
8. Enable `challenge`.
9. Review user impact.
10. Enable `tarpit` or `auto` only after score boundaries are trusted.

## Security Notes

- VeilGate is not a replacement for patching, authentication, authorization,
  rate limiting, secure coding, or WAF controls.
- Deploy it only in front of systems you own or are authorized to protect.
- Keep metrics, SQLite persistence, and JSONL capture private.
- Treat rule files as security policy. Version and review them like code.
- Use observe mode before enforcement to understand false positives.
