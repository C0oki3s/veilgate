# VeilGate Docs

This directory keeps the technical documentation needed to run, operate, and
contribute to VeilGate.

## Start Here

| Need | Read |
| --- | --- |
| Run VeilGate locally | [Getting Started](GETTING_STARTED.md) |
| Deploy on Linux with systemd | [Deployment](DEPLOYMENT.md) |
| Understand the request flow and detection model | [Architecture](ARCHITECTURE.md) |
| Monitor and tune a running instance | [Operations](OPERATIONS.md) |
| Understand ML features and limits | [Model Card](MODEL_CARD.md) |
| Review security assumptions | [Threat Model](../THREAT_MODEL.md) |

## Use Cases

Objective-driven pages — pick the one that matches your role.

| Page | For |
| --- | --- |
| [Bug-bounty triage](usecases/bug-bounty-triage.md) | AppSec lead drowning in AI-generated submissions |
| [LLM-agent defence](usecases/llm-agent-defense.md) | Security architect facing autonomous agents |
| [API recon blocking](usecases/api-recon-blocking.md) | Platform / API team |
| [Compliance & audit evidence](usecases/compliance-evidence.md) | CISO / GRC |

Index: [usecases/](usecases/README.md)

## How-To Guides

Task-oriented walk-throughs.

| Page | When |
| --- | --- |
| [Install on Linux](how-to/install-on-linux.md) | First-time install |
| [Observe-mode rollout & threshold tuning](how-to/observe-and-tune.md) | Before flipping to challenge / tarpit |
| [Promote learned rules](how-to/promote-learned-rules.md) | After a week of mining |
| [Handle a Right-to-Erasure request](how-to/handle-rtbf.md) | When a deletion arrives |
| [Monitor with Prometheus + Grafana](how-to/monitor-with-prometheus.md) | When you need history |

Index: [how-to/](how-to/README.md)

## Configuration Reference

Per-section reference for every setting in `veilgate.yaml` and the
files under `rules/`. AWS-docs-style: one page per section, with
cross-references.

Index: [config/](config/README.md)

| Top-level config | Rules directory |
| --- | --- |
| [Top-level keys](config/top-level.md) | [`rules/detector.yaml`](config/rules/detector.md) |
| [`tls:`](config/tls.md) | [`rules/ml.yaml`](config/rules/ml.md) |
| [`detector:`](config/detector.md) | [`rules/payloads.yaml`](config/rules/payloads.md) |
| [`tarpit:`](config/tarpit.md) | [`rules/templates.yaml`](config/rules/templates.md) |
| [`challenge:`](config/challenge.md) | [`rules/injection_strategy.yaml`](config/rules/injection-strategy.md) |
| [`metrics:`](config/metrics.md) | [`rules/tls_fingerprints.yaml`](config/rules/tls-fingerprints.md) |
| [`persist:`](config/persist.md) | [`rules/ip_reputation.yaml`](config/rules/ip-reputation.md) |
| [`capture:`](config/capture.md) | [`rules/challenge.yaml`](config/rules/challenge.md) |

## Documentation Policy

Public docs should be:

- Technical and runnable.
- Clear about limitations and operator responsibilities.
- Focused on the current codebase, not speculative roadmap.
- Free of private planning, commercial strategy, and unsupported claims.

When in doubt, prefer a short working example over a long explanation.
