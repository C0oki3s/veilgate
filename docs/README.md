# VeilGate Docs

This directory keeps the technical documentation needed to run, operate, and
contribute to VeilGate.

## Start Here

| Need | Read |
| --- | --- |
| Run VeilGate locally | [Getting Started](getting-started/README.md) |
| Deploy on Linux with systemd | [Deployment](deployment/README.md) |
| Understand the request flow and detection model | [Architecture](architecture/README.md) |
| Monitor and tune a running instance | [Operations](operations/README.md) |
| Understand ML features and limits | [Model Card](model/README.md) |
| Review security assumptions | [Threat Model](../THREAT_MODEL.md) |

## Functionality Reference

Detailed NGINX-style module pages with examples, directive blocks, code paths,
operational notes, validation commands, and limitations.

| Page | Use |
| --- | --- |
| [Documentation index](index.md) | Main docs landing page |
| [Reference index](reference/README.md) | Lookup-oriented references collected in one place |
| [How VeilGate processes a request](architecture/request-processing.md) | End-to-end request flow |
| [Module reference](modules/README.md) | Detailed module and directive docs |
| [Rule customization guide](config/rules/customization.md) | How to edit rule files safely |
| [Codebase coverage matrix](internals/coverage_matrix.md) | Which docs cover each command and internal package |
| [Detailed functionality index](functionalities/README.md) | Focused pages for individual runtime features |

## Folder Layout

| Folder | Contents |
| --- | --- |
| [architecture/](architecture/README.md) | System overview and request-processing flow |
| [getting-started/](getting-started/README.md) | Local setup and first validation checks |
| [deployment/](deployment/README.md) | Linux and systemd deployment |
| [operations/](operations/README.md) | Runtime operations, metrics, alerts, and query cookbook |
| [config/](config/README.md) | NGINX-style config and rule documentation |
| [modules/](modules/README.md) | Code-correlated module reference |
| [reference/](reference/README.md) | Full configuration and functionality reference pages |
| [model/](model/README.md) | ML behavior, limits, and safety notes |
| [product/](product/README.md) | Public narrative, business case, and rationale |
| [internals/](internals/README.md) | Code map, tooling, coverage, and engineering notes |
| [security/](security/) | Security design notes |

## Use Cases

Objective-driven pages - pick the one that matches your role.

| Page | For |
| --- | --- |
| [Bug-bounty triage](usecases/bug-bounty-triage.md) | AppSec lead drowning in AI-generated submissions |
| [LLM-agent defense](usecases/llm-agent-defense.md) | Security architect facing autonomous agents |
| [API recon blocking](usecases/api-recon-blocking.md) | Platform / API team |
| [Compliance and audit evidence](usecases/compliance-evidence.md) | CISO / GRC |

Index: [usecases/](usecases/README.md)

## How-To Guides

Task-oriented walk-throughs.

| Page | When |
| --- | --- |
| [Install on Linux](how-to/install-on-linux.md) | First-time install |
| [Observe-mode rollout and threshold tuning](how-to/observe-and-tune.md) | Before flipping to `challenge` or `tarpit` |
| [Protect an SPA and API on different subdomains](how-to/protect-multi-origin.md) | Frontend on `app.example.com`, API on `api.example.com` |
| [Authenticate server-to-server callers with HMAC](how-to/server-to-server-hmac.md) | Internal services, mobile apps, webhooks, and non-browser callers |
| [Promote learned rules](how-to/promote-learned-rules.md) | Once the miner has enough candidates |
| [Handle a Right-to-Erasure request](how-to/handle-rtbf.md) | When a deletion request arrives |
| [Monitor with Prometheus and Grafana](how-to/monitor-with-prometheus.md) | When you need historical metrics |

Index: [how-to/](how-to/README.md)

## Configuration Reference

NGINX-style reference for every setting in `veilgate.yaml` and every file under
`rules/`: examples, reload behavior, code path, operational notes, and
validation commands.

Index: [config/](config/README.md)

| Top-level config | Rules directory |
| --- | --- |
| [How configuration is resolved](config/overrides.md) | [Rule customization guide](config/rules/customization.md) |
| [Top-level keys](config/top-level.md) | [Rules index](config/rules/README.md) |
| [`tls:`](config/tls.md) | [`detector.yaml`](config/rules/detector.md) |
| [`detector:`](config/detector.md) | [`ip_reputation.yaml`](config/rules/ip-reputation.md) |
| [`tarpit:`](config/tarpit.md) | [`tls_fingerprints.yaml`](config/rules/tls-fingerprints.md) |
| [`challenge:`](config/challenge.md) | [`challenge.yaml`](config/rules/challenge.md) |
| [`verifiers:`](config/verifiers.md) | [`ml.yaml`](config/rules/ml.md) |
| [`metrics:`](config/metrics.md) | [`templates.yaml`](config/rules/templates.md) |
| [`persist:`](config/persist.md) | [`injection_strategy.yaml`](config/rules/injection-strategy.md) |
| [`capture:`](config/capture.md) | [`payloads.yaml`](config/rules/payloads.md) |
|  | [`fake_data.yaml`](config/rules/fake-data.md) |
|  | [`vulnerabilities.yaml`](config/rules/vulnerabilities.md) |
|  | [`dashboard.yaml`](config/rules/dashboard.md) |
|  | [`learned.yaml`](config/rules/learned.md) |

## Documentation Policy

Public docs should be:

- Technical and runnable.
- Clear about limitations and operator responsibilities.
- Focused on the current codebase, not speculative roadmap.
- Free of private planning, commercial strategy, and unsupported claims.

When in doubt, prefer a short working example over a long explanation.
