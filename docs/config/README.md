# Configuration Reference

VeilGate has two configuration surfaces:

- The top-level config file, normally `/etc/veilgate/veilgate.yaml`, defines
  the proxy listener, upstream, mode, TLS, detector thresholds, challenge
  secret, persistence, capture, metrics, and verifier chain.
- The rules directory, normally `/etc/veilgate/rules/`, defines detector
  matchers, fingerprint labels, tarpit content, challenge presentation, ML
  settings, dashboard layout, and learned candidates.

This section follows the documentation pattern from
`DOCSskill.md`: each page names the directive or file, gives examples, states
reload behavior, maps the setting to code, and calls out operational risk.

Repository: <https://github.com/C0oki3s/veilgate>

## Start Here

| Page | Purpose |
| --- | --- |
| [How configuration is resolved](overrides.md) | Startup order, embedded defaults, full-file replacement, environment override, and hot reload. |
| [Rules directory reference](rules/README.md) | One entry point for every YAML file under `rules_dir`. |
| [Rule customization guide](rules/customization.md) | Practical workflow for editing rules safely. |

## Top-Level Config

The files below document sections in `veilgate.yaml`. Changes to these settings
require a process restart unless the page states otherwise.

| Section | Page | Main code path |
| --- | --- | --- |
| core keys | [top-level.md](top-level.md) | `internal/config.Config`, `cmd/veilgate/main.go` |
| `tls:` | [tls.md](tls.md) | `cmd/veilgate.listenTLS`, `internal/tlsfp` |
| `detector:` | [detector.md](detector.md) | `internal/detector.Scorer`, `internal/detector.Tracker` |
| `tarpit:` | [tarpit.md](tarpit.md) | `internal/tarpit.Handler` |
| `challenge:` | [challenge.md](challenge.md) | `internal/challenge.Handler` |
| `verifiers:` | [verifiers.md](verifiers.md) | `internal/verifier`, `internal/proxy.Server.SetVerifiers` |
| `metrics:` | [metrics.md](metrics.md) | `internal/telemetry` |
| `persist:` | [persist.md](persist.md) | `internal/persist.Store` |
| `capture:` | [capture.md](capture.md) | `internal/telemetry.CaptureWriter` |

## Rule Files

The files below document YAML files under `rules_dir`. A file in `rules_dir`
replaces the embedded default for that one file; it is not merged with the
default.

| Rule file | Page | Reload |
| --- | --- | --- |
| `detector.yaml` | [rules/detector.md](rules/detector.md) | hot reload |
| `ip_reputation.yaml` | [rules/ip-reputation.md](rules/ip-reputation.md) | hot reload |
| `tls_fingerprints.yaml` | [rules/tls-fingerprints.md](rules/tls-fingerprints.md) | hot reload when TLS DB exists |
| `challenge.yaml` | [rules/challenge.md](rules/challenge.md) | hot reload |
| `ml.yaml` | [rules/ml.md](rules/ml.md) | hot reload |
| `templates.yaml` | [rules/templates.md](rules/templates.md) | hot reload |
| `injection_strategy.yaml` | [rules/injection-strategy.md](rules/injection-strategy.md) | hot reload |
| `payloads.yaml` | [rules/payloads.md](rules/payloads.md) | restart required |
| `fake_data.yaml` | [rules/fake-data.md](rules/fake-data.md) | hot reload |
| `vulnerabilities.yaml` | [rules/vulnerabilities.md](rules/vulnerabilities.md) | hot reload |
| `dashboard.yaml` | [rules/dashboard.md](rules/dashboard.md) | hot reload |
| `learned.yaml` | [rules/learned.md](rules/learned.md) | miner-managed |

## Reload Semantics

| Surface | Reload mechanism |
| --- | --- |
| `veilgate.yaml` | restart required, for example `sudo systemctl restart veilgate` |
| `VEILGATE_SECRET` | restart required; overrides `challenge.secret` at startup |
| supported `rules_dir` files | `internal/rules.Watcher`, debounced and atomically swapped on successful parse |
| `payloads.yaml` | restart required; loaded by `payloads.NewLibraryFromDir()` at startup |
| `learned.yaml` | read and written by the ML miner workflow |
| `verifiers.hmac.clients_dir/*.secret` | hot reload on file mtime change |

## Naming Rules

- File names follow the runtime config key or rule file name.
- Multi-word files use hyphenated Markdown names, for example
  `ip-reputation.md` documents `ip_reputation.yaml`.
- Headings use the exact config key in backticks so operators can search for
  the same name in YAML and code.
- Linux commands are used in examples because production deployments are
  documented for Linux/systemd.

## Validation

```bash
veilgate -config /etc/veilgate/veilgate.yaml
curl -i http://127.0.0.1:8080/
curl -sS http://127.0.0.1:9090/metrics | grep veilgate_requests_total
```

## Related

- [Deployment guide](../deployment/README.md)
- [How VeilGate Processes a Request](../architecture/request-processing.md)
- [Codebase coverage matrix](../internals/coverage_matrix.md)
